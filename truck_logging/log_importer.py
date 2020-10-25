# !/usr/bin/env python

import sys, os
import can
import argparse
from datetime import datetime, timezone
from can import LogReader, MessageSync
from influxdb import InfluxDBClient
import json
from canalyserJ1939 import J1939CANanalyser
from glob import glob


# V2.0 API
# from influxdb_client import InfluxDBClient, Point, WriteOptions
# from influxdb_client.client.write_api import SYNCHRONOUS


def parse_arguments():
    parser = argparse.ArgumentParser(
        "log_importer.py", description="load j1938 canlog and import in Influx DB"
    )

    parser.add_argument(
        "-f",
        "--file_name",
        dest="log_file",
        help="""Path and base log filename, for supported types see can.LogReader.""",
        default=None,
    )

    parser.add_argument(
        "-v",
        action="count",
        dest="verbosity",
        help="""loglevel""",
        default=2,
    )

    parser.add_argument(
        "-g",
        "--gap",
        type=float,
        help="""<s> minimum time between replayed frames""",
        default=0.0001,
    )
    parser.add_argument(
        "-s",
        "--skip",
        type=float,
        default=60 * 60 * 24,
        help="""<s> skip gaps greater than 's' seconds""",
    )

    parser.add_argument(
        "--ignore-timestamps",
        dest="timestamps",
        help="""Ignore timestamps (send all frames immediately with minimum gap between frames)""",
        action="store_false",
    )

    parser.add_argument(
        "infile",
        metavar="input-file",
        type=str,
        help="The file to load. For supported types see can.LogReader.",
    )

    return parser.parse_args()


def makePointfromCan(msg, cartag="B-YW", devicetag="can0"):
    timestr = datetime.fromtimestamp(msg.timestamp).astimezone(timezone.utc).isoformat()
    # .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    canid = msg.arbitration_id
    datastr = bytes(msg.data).decode('latin-1')
    jsondata = [
        {
            "measurement": canid,
            "tags": {
                "device": devicetag,
                "car": cartag
            },
            "time": timestr,
            "fields": {
                "value": datastr

            }
        }
    ]
    return jsondata


def makePointj1938(timestamp, canid, pgn, sa, da, j1939vals, data, cartag):
    timestr = datetime.fromtimestamp(timestamp).astimezone(timezone.utc).isoformat()
    # .strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    pgn_ = pgn.replace(" ", "").replace("#", "_")
    sa_ = sa.replace(" ", "").replace("#", "_")
    da_ = da.replace(" ", "").replace("#", "_")

    j1939point = {
        "measurement": pgn_,
        "tags": {
            "sa": sa_,
            "da": da_,
            "car": cartag
        },
        "time": timestr,
        "fields": {
        }
    }

    hasvalue = False
    # print(f"{pgn_}\t{sa_}\t{da_}\t")
    for name, v in j1939vals.items():

        value = v[0]
        unit = v[1]
        namesmall = name.replace(" ", "_")  # .replace("#","")

        if ("Defined Usage" in name):
            j1939point["fields"][namesmall] = data.decode('latin-1')
            # msgstr = " ".join("{:02x}".format(byte) for byte in data)
            # print(f"\t\t\t\t{name} {v[0]} {v[1]}  {msgstr}")
        else:
            value_ = None
            if len(unit):
                namesmall += "_" + unit
                value_ = float(value)
            else:
                value_ = bool(value)
            # print(f"\t\t{namesmall} {v[0]} {v[1]}")
            j1939point["fields"][namesmall] = value_
            # "value": datastr

        hasvalue = True

    if hasvalue:
        # print (j1939point)
        return j1939point
    else:
        pass  # print ("No Values:"+pgn_)


def logimport(filename, cartag="B-YW"):
    canalyse = J1939CANanalyser()

    reader = LogReader(filename)

    # in_sync = MessageSync(
    #     reader, timestamps=args.timestamps, gap=args.gap, skip=args.skip
    # )

    dbip = "10.8.0.1"
    # dbip="localhost"
    dbname = "canlogger"
    client = InfluxDBClient(host=dbip, port=8086, database=dbname)
    databaselist = client.get_list_database()
    dbfound = False
    for elem in databaselist:
        if elem.get('name') == dbname:
            dbfound = True

    if dbfound == False:
        client.create_database(dbname)

    client.switch_database(dbname)

    # client = InfluxDBClient(url="http://localhost:9999", token="test", org="gpi")
    # bucket = "logger"
    # write_api = client.write_api(write_options=SYNCHRONOUS)

    # write_client = client.write_api(write_options=WriteOptions(batch_size=500,
    # flush_interval=10_000,
    # jitter_interval=2_000,
    # retry_interval=5_000,
    # max_retries=5,
    # max_retry_delay=30_000,
    # exponential_base=2))

    # query_api = client.query_api()
    # p = Point("my_measurement").tag("location", "Prague").field("temperature", 25.3)
    # p1 = Point("my_measurement").tag("location", "Prague").field("temperature", 25.3)
    # p2 = Point("my_measurement").tag("location", "New York").field("temperature", 24.3)

    # write_api.write(bucket='canlogger', record=[p,p1,p2])

    # tables = query_api.query('from(bucket:"my-bucket") |> range(start: -10m)')

    print(f"Can LogReader (Started on {datetime.now()})")
    count = 0
    pointlist = []
    try:
        for msg in reader:
            # print(msg)
            data = bytes(msg.data)
            canid = msg.arbitration_id
            j1939vals = canalyse.translate(canid, data)
            pgn = j1939vals.pop('pgn')  # self.ids[key]
            sa = j1939vals.pop('sa')
            da = j1939vals.pop('da')

            point = makePointj1938(msg.timestamp, canid, pgn, sa, da, j1939vals, data, cartag)
            if point is not None:
                pointlist.append(point)
            if len(pointlist) > 5000:
                count += len(pointlist)
                ts = datetime.fromtimestamp(msg.timestamp)
                print(filn, ts, count)
                client.write_points(pointlist)
                pointlist = []

            # ts=datetime.fromtimestamp(msg.timestamp)
            # print(f"{ts}\tID:{canid}\t{sa}\t{da} {pgn}")
            # for name, v in j1939vals.items():
            #    value = v[0]
            #    unit = v[1]

            # if ("Defined Usage" in name):
            #     msgstr = " ".join("{:02x}".format(byte) for byte in data)
            #     print(f"\t\t\t\t{name} {v[0]} {v[1]}  {msgstr}")
            # else:
            #     print(f"\t\t\t\t{name} {v[0]} {v[1]}")

        # for m in in_sync:
        #     if m.is_error_frame:
        #         continue
        #     if args.verbosity >= 3:
        #         pass
        #     #print (datetime.fromtimestamp(m.timestamp).astimezone(timezone.utc))

        # count+=1
        # print (count)
        # json_body= makePointfromCan(msg=msg)
        # client.write_points(json_body)#, time_precision='ms')



    except KeyboardInterrupt:
        pass
    finally:
        reader.stop()

    # with LogReader(sys.argv[1]) as reader:
    #     with can.Logger(sys.argv[2]) as writer:
    #
    #         for msg in reader:
    #             writer.on_message_received(msg)


if __name__ == "__main__":

    args = parse_arguments()
    # if  args.infile

    filelist = []
    for filename in sorted(glob("logdata//logging_backup_truck//can1_2020-10-19T*_log.blf"), key=os.path.getmtime):
        filelist.append(filename)

    print(filelist)
    for filn in filelist:
        print(f"import file:{filn}")
        logimport(filn)
