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
import logging


# V2.0 API
# from influxdb_client import InfluxDBClient, Point, WriteOptions
# from influxdb_client.client.write_api import SYNCHRONOUS


def parse_arguments():
    parser = argparse.ArgumentParser(
        "log_importer.py", description="load j1938 canlog and import in Influx DB"
    )

    parser.add_argument(
        "-v",
        action="count",
        dest="verbosity",
        help="""loglevel""",
        default=0,
    )

    parser.add_argument(
        "-i",
        "--ip",
        type=str,
        dest="dbip",
        default="10.8.0.1",
        help="""InfluxDB IP"""
    )

    parser.add_argument(
        "infile",
        metavar="input-file",
        nargs='?',
        type=str,
        help="The file to load. For supported types see can.LogReader.")

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


def makePointj1938(timestamp, canid, pgn, sa, da, j1939vals, data, tagdict):
    timestr = datetime.fromtimestamp(timestamp).astimezone(timezone.utc).isoformat()
    # .strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Nice format Translated Values (remove Spaces and # for later DB inserts)
    pgn_ = pgn.replace(" ", "").replace("#", "_")
    sa_ = sa.replace(" ", "").replace("#", "_")
    da_ = da.replace(" ", "").replace("#", "_")

    j1939point = {
        "measurement": pgn_,
        "tags": {
            "sa": sa_,
            "da": da_,
        },
        "time": timestr,
        "fields": {
        }
    }

    # Add extra Tags to measurments
    j1939point["tags"].update(tagdict)

    hasvalue = False
    print(f"{canid} {pgn_}\t{sa_}\t{da_}\t")

    for name, v in j1939vals.items():

        value = v[0]
        unit = v[1]
        namesmall = name.replace(" ", "_")  # .replace("#","")

        if ("Defined Usage" in name):
            j1939point["fields"][namesmall] = data.decode('latin-1')
            msgstr = " ".join("{:02x}".format(byte) for byte in data)
            print(f"\t\t{name} {v[0]} {v[1]}  {msgstr}")
        else:
            value_ = None
            if len(unit):
                namesmall += "_" + unit
                value_ = float(value)
            else:
                if value.startswith("0x"):
                    pass
                    #value_ = int(value[2:], base=16)
                else:
                    #value_ = int(value)
                    pass
            print(f"\t\t{namesmall} {v[0]} {v[1]}")
            if value_ is not None:
                j1939point["fields"][namesmall] = value_
            # "value": datastr

                hasvalue = True
    if hasvalue:
        # print (j1939point)
        return j1939point
    else:
        pass  # print ("No Values:"+pgn_)


def logimport(filename, tagdict={}, db_info={"ip": "10.8.0.1", "port": 8086, "dbname": "canlogger"}):
    canalyse = J1939CANanalyser()

    reader = LogReader(filename)
    # for Synchronized readings
    # in_sync = MessageSync(
    #     reader, timestamps=args.timestamps, gap=args.gap, skip=args.skip
    # )

    # dbip="localhost"
    client = InfluxDBClient(host=db_info.get("ip"), port=db_info.get("port"),username="logger",password="secret___!", database=db_info.get("dbname"))
    databaselist = client.get_list_database()
    dbfound = False
    for elem in databaselist:
        if elem.get('name') == db_info.get("dbname"):
            dbfound = True

    if dbfound == False:
        client.create_database(db_info.get("dbname"))

    client.switch_database(db_info.get("dbname"))

    # only Influx DB2.0
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

            point = makePointj1938(msg.timestamp, canid, pgn, sa, da, j1939vals, data, tagdict=tagdict)
            if point is not None:
                pointlist.append(point)
            if len(pointlist) > 5000:
                count += len(pointlist)
                ts = datetime.fromtimestamp(msg.timestamp)
                print(filn, ts, count)
                client.write_points(pointlist)
                pointlist = []

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
    logger = logging.getLogger()

    # logging.basicConfig( encoding='utf-8', level=logging.DEBUG)#filename='example.log'
    filelist = []
    args = parse_arguments()

    logging_level_name = ['notset', 'debug', 'info', 'warning', 'error', 'critical'][max(0, args.verbosity)]
    loglevel = getattr(logging, logging_level_name.upper())
    # loglevel = logging.DEBUG
    logger.setLevel(loglevel)
    logging.debug(f"{args=}")

    filefilter="logdata//logging_backup_truck//can0_2020-10-19T035250_log*"
    influxdb_port = 8086
    dbname = "canlogger"
    carid = "B-YW"

    if args.infile is None:
        for filename in sorted(glob(filefilter), key=os.path.getmtime):
            #add only files >0 bytes
            if os.path.getsize(filename)>0:
                filelist.append(filename)
        print(filelist)
    else:
        filelist.append(args.infile)

    tagdict = {"car": carid}
    db_info = {"ip": args.dbip, "port": influxdb_port, "dbname": dbname}

    for filn in filelist:
        if "can0" in os.path.basename(filn):
            tagdict["interface"] = "CAN0"
        if "can1" in os.path.basename(filn):
            tagdict["interface"] = "CAN1"

        print(f"import file:{filn}, {tagdict=}")

        logimport(filn, tagdict=tagdict, db_info=db_info)
