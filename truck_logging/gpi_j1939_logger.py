#!/usr/bin/env python3

from __future__ import print_function

import argparse
import textwrap
import json
import msgpack
from datetime import datetime

import can
# from can import Bus, BusState, Logger, SizedRotatingLogger
import j1939
import os, time
import redis
# from redis_dict import RedisDict
from redis import Redis
from redis_collections import Dict
# from rq import Queue
# import serialized_redis
# from ttseries import RedisSimpleTimeSeries
from walrus import Database
import msgpack

from collections.abc import MutableMapping

from influxdb import InfluxDBClient
import re

# import xj1939 as j1939
import logging
import pretty_j1939.parse
import subprocess


# python -m can.player  -v  -c vcan0 can_zuendung_gas_500k_candump-2020-05-08_122006.log
# -c can0 --source 0 11 47 23

def dict_to_redis_hset(r, hkey, dict_to_store):
    """
    Saves `dict_to_store` dict into Redis hash, where `hkey` is key of hash.
    >>> import redis
    >>> r = redis.StrictRedis(host='localhost')
    >>> d = {'a':1, 'b':7, 'foo':'bar'}
    >>> dict_to_redis_hset(r, 'test', d)
    True
    >>> r.hgetall('test')
    {'a':1, 'b':7, 'foo':'bar'}
    """
    return all([r.hset(hkey, k, v) for k, v in dict_to_store.items()])


def run_linuxprocess(cmd):
    process = subprocess.Popen(cmd.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    returncode = process.wait(timeout=2)
    logging.debug(f"{cmd} return: {returncode}")
    retdata = process.stdout.read().decode()
    logging.debug(retdata)


def init_can_system(candev: str, baudrate=500000):
    '''

    :param candev:
    :return:
    '''

    try:
        run_linuxprocess(f'whoami')
        # run_linuxprocess(f'ip -a')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} down')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} up type can bitrate {baudrate} restart-ms 1000')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} txqueuelen 65536')
    except subprocess.CalledProcessError as e:
        logging.debug(e)


def init_slcan_system(candev: str):
    # sudo slcand -f -s6 -o  /dev/ttyACM0 can2
    # sudo ip link set can2 up
    # sudo ip link set can2 txqueuelen 65536
    pass

def sniffcalc(msg):
    """print Canmassage Callback"""
    print(msg)


def setflat_skeys(
        r: redis.Redis,
        obj: dict,
        prefix: str,
        delim: str = ":",
        *,
        _autopfix=""
) -> None:
    """Flatten `obj` and set resulting field-value pairs into `r`.
    Calls `.set()` to write to Redis instance inplace and returns None.

    `prefix` is an optional str that prefixes all keys.
    `delim` is the delimiter that separates the joined, flattened keys.
    `_autopfix` is used in recursive calls to created de-nested keys.

    The deepest-nested keys must be str, bytes, float, or int.
    Otherwise a TypeError is raised.
    """
    allowed_vtypes = (str, bytes, float, int)
    for key, value in obj.items():
        key = _autopfix + key
        if isinstance(value, allowed_vtypes):
            r.set(f"{prefix}{delim}{key}", value)
        elif isinstance(value, MutableMapping):
            setflat_skeys(
                r, value, prefix, delim, _autopfix=f"{key}{delim}"
            )
        else:
            raise TypeError(f"Unsupported value type: {type(value)}")

class J1939CANanalyser:
    '''
    Analyse can Messages with J1939
    make Canviewer-statisctic and translate
    TODO: To REDIS DB Store in Influx
    '''

    def __init__(self, can_channel="can0"):
        self.logger = logging.getLogger()
        self.start_time = None
        self.rdb = redis.Redis(host='localhost', port=6379, db=0)
        self.idb = InfluxDBClient('localhost', 8086, 'USERNAME', 'PASSWORD', 'DATABASE')
        self.can_channel = can_channel
        self.describer = None
        self.init_prettyj1939(pgns=True, spns=True)

        # self.analyse_d = Dict(redis=self.rdb, key='cansnap')
        # self.simple_series = RedisSimpleTimeSeries(client=self.rdb)
        self.wdb = Database(host='localhost', port=6379, db=0)  # Database()
        self.dbstream = None
        self.streamid = None
        self.streamlist = self.wdb.List(f'{self.can_channel}')
        self.sumcount = 0
        # self.ids=Dict(redis=self.rdb, key='cansnap')#self.wdb.Hash('cansnap')
        self.ids = {}
        self.canlogger = None

        self.initlog = 1
        self.logpath = "logdata"
        self.initcanlogger()
        # self.ids.clear()

        # self.canlogger = can.SizedRotatingLogger(
        #     base_filename=f'{self.can_channel}_{timestr}_log.blf',
        #     max_bytes=10 * 1024 ** 2,  # =5MB
        # )
        # #self.canlogger.rollover_count = 0  # start counter at 23

    def init_prettyj1939(self, pgns=True, spns=True):
        pretty_j1939.parse.init_j1939db()

        self.describer = pretty_j1939.parse.get_describer(describe_pgns=pgns, describe_spns=spns,
                                                          describe_link_layer=True,
                                                          describe_transport_layer=False,
                                                          include_transport_rawdata=False,
                                                          include_na=False)

    def initcanlogger(self):
        if self.canlogger is not None:
            try:
                self.canlogger.stop()
            except Exception as e:
                pass
        timestr = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        logfilname = f'{self.logpath}//{self.can_channel}_{timestr}_log.blf'
        self.canlogger = can.Logger(filename=logfilname)
        self.logger.debug(f"Init canlogger : {logfilname}")

    def extractmsg(self, msg):  # old
        edata = {"ts": msg.timestamp,
                 "pr": msg.arbitration_id.priority,
                 "sa": msg.source,
                 "da": msg.arbitration_id.destination_address_value,
                 "pgn": msg.pgn,
                 "data": bytes(msg.data)}
        return edata

    def statistics(self, msg):

        key = msg.arbitration_id  # .can_id
        # key = msg.pgn
        # print(msg.timestamp, msg.arbitration_id.priority, msg.source, msg.arbitration_id.destination_address_value,msg.pgn, msg.data, )
        # Sort the extended IDs at the bottom by setting the 32-bit high
        # if msg.is_extended_id:
        # key |= 1 << 32

        new_id_added, length_changed = False, False

        # Check if it is a new message or if the length is not the same
        if key not in self.ids:
            new_id_added = True
            # Set the start time when the first message has been received
            if not self.start_time:
                self.start_time = msg.timestamp
        # elif len(msg.data) != len(self.ids[key]["msg"].data):
        #    length_changed = True

        pgn = (msg.arbitration_id & 0x03FFFF00) >> 8

        pgn_f = (pgn & 0xFF00) >> 8
        pgn_s = pgn & 0x00FF

        if pgn_f < 240:
            pgn &= 0xFFFFFF00

        if new_id_added or length_changed:
            # Increment the index if it was just added, but keep it if the length just changed
            # row = len(self.ids) + 1 if new_id_added else self.ids[key]["row"]

            self.ids[key] = {"count": 0,
                             "dt": 0,
                             "ts": msg.timestamp,
                             "sa": msg.arbitration_id & 0x000000FF,  # msg.source,
                             "da": (msg.arbitration_id & 0x0000FF00) >> 8,
                             # msg.arbitration_id.destination_address_value ,
                             "pgn": pgn,
                             "msg": bytes(msg.data)}  # "row": row, #self.extractmsg(msg)
        else:
            # Calculate the time since the last message and save the timestamp
            self.ids[key]["dt"] = msg.timestamp - self.ids[key].get("ts")  # self.ids[key]["msg"].get("ts")

            # Copy the CAN-Bus dataframe
            self.ids[key]["msg"] = bytes(msg.data)  # msgpack.packb(self.extractmsg(msg))
            self.ids[key]["ts"] = msg.timestamp
            self.ids[key]["pgn"] = pgn
            self.ids[key]["sa"] = msg.arbitration_id & 0x000000FF
            self.ids[key]["da"] = (msg.arbitration_id & 0x0000FF00) >> 8
            # TODO: store changing msg Data in Redis

        # Increment frame counter
        self.ids[key]["count"] += 1

        if self.canlogger is not None:
            if self.rdb.get("logging") == b'1':
                self.canlogger(msg)
                if self.initlog == 0:
                    self.initlog = 1
                    self.logger.info("logging on ")
            else:
                if self.initlog == 1:
                    self.initcanlogger()
                    self.initlog = 0
                    self.logger.info("logging off")

        # Format the CAN-Bus ID as a hex value
        # arbitration_id_string = "0x{0:0{1}X}".format(msg.arbitration_id.can_id, 8 )
        # self.logger.info(arbitration_id_string)

    def translate(self, canid, data):
        j1939descr = self.describer(data, canid)
        # sa = j1939descr.get('SA')
        # da = j1939descr.get('DA')
        # pgn = j1939descr.get('PGN')
        # print (j1939descr)
        j1939vals = {'sa': j1939descr.get('SA'), 'da': j1939descr.get('DA'), 'pgn': j1939descr.get('PGN')}
        # j1939vals = {}      #translated data
        while j1939descr:
            name, val = j1939descr.popitem()  # get values backwards from ordered dict until 'SA'
            if 'SA' not in name:
                unit = re.search("(?<=\[).+?(?=\])", val)
                if unit is not None:
                    unit = unit.group()
                else:
                    unit = ""
                data = val.split()
                j1939vals[name] = (data[0], unit)
            else:
                break
        return j1939vals

    def startstream(self):
        if self.dbstream is None:
            self.streamid = f'{self.can_channel}:{int(time.time())}'
            self.dbstream = self.wdb.Stream(self.streamid)
            self.streamlist.append(self.streamid)
        return self.dbstream

    def writestream(self, translate=False):
        # r.set(msg.pgn, bytes(msg.data))
        self.dbstream = self.startstream()
        resultdict = {}
        sumcount = 0
        for key in self.ids.keys():
            sumcount += self.ids[key].get('count')
            # self.ids[key].get('dt')
            msg = self.ids[key].get("msg")  # Last logged CAN-Msg
            ts = self.ids[key].get("ts")  # msg.get('ts')  # last can timestamp
            pgn = self.ids[key].get('pgn')
            # sa=msg.get('sa')
            # da=msg.get('da')
            # pr=msg.get('pr')
            # cdata=msg.get('data')
            keyinfo = {"id": key, "ts": ts, "pgn": pgn, "cnt": self.ids[key].get('count'),
                       "dt": self.ids[key].get('dt'), "data": msg}
            resultdict[str(key)] = keyinfo
            if translate is True:
                j1939vals = self.translate(key, msg)
                for k, v in j1939vals.items():
                    name = k
                    value = v[0]
                    unit = v[1]

        if not (sumcount == self.sumcount):  # only store if
            self.sumcount = sumcount
            # print(self.sumcount)
            datadict = msgpack.packb(resultdict, use_bin_type=True)
            ts = int(time.time())
            msgid = self.dbstream.add({"pcount": self.sumcount, "snap": datadict})
            print(f'msgid:{msgid},sumcount:{self.sumcount}')

    def write2influx(self, data):
        json_payload = []
        time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        try:
            for name, value in data.iteritems():
                payload = {
                    "measurement": name,
                    "tags": {
                        "can": self.can_channel
                    },
                    "time": time,
                    "fields": {
                        "value": value
                    }
                }
                json_payload.append(payload)
            self.idb.write_points(json_payload)
        except Exception as exception:
            self.logger.debug(f"iflux write exception: {exception}")

    def show(self, translate=True):
        # r.set(msg.pgn, bytes(msg.data))
        #
        print(80 * "-")
        print("canid\t\tcount\t\tdt")

        for i, key in enumerate(sorted(self.ids.keys())):
            # Set the new row index, but skip the header
            # self.ids[key]["row"] = i + 1
            msg = self.ids[key].get("msg")

            if translate:
                j1939vals = self.translate(key, msg)
                pgn = j1939vals.pop('pgn')  # self.ids[key]
                sa = j1939vals.pop('sa')
                da = j1939vals.pop('da')
                # pr = msg.get('pr')

                print(
                    f"{key:08x} {self.ids[key].get('count'): 4}\t{self.ids[key].get('dt'):.2f}\t{sa}\t{da} {pgn}")  # \t{msgstr}, end='')

                if 'WWH-OBD' in sa or 'WWH-OBD' in da:
                    msgstr = " ".join("{:02x}".format(byte) for byte in msg)
                    print(f"\t\t\t\t{msgstr}")

                for k, v in j1939vals.items():
                    if ("Defined Usage" in k):
                        msgstr = " ".join("{:02x}".format(byte) for byte in msg)
                        print(f"\t\t\t\t{k} {v[0]} {v[1]}  {msgstr}")
                    else:
                        print(f"\t\t\t\t{k} {v[0]} {v[1]}")

                    if "can0" in self.can_channel and '61443' in pgn:
                        if "Estimated Pumping" in k:
                            if int(v[0]) > 30:
                                self.rdb.set("logging", 1)
                            if int(v[0]) < 20:
                                self.rdb.set("logging", 0)

            else:
                msgstr = " ".join("{:02x}".format(byte) for byte in msg)
                print(
                    f"{key:08x} {self.ids[key].get('count'): 4} {self.ids[key].get('dt'):.1f} {self.ids[key].get('sa'):3} {self.ids[key].get('da'):3} {self.ids[key].get('pgn'):6} 0x{self.ids[key].get('pgn'):04x}  {msgstr}")


# 65282,65280, 65281,65296,65226,65284, Exhaust Emission Controller( 61)
def setlogging(level_name):
    logger = logging.getLogger()
    loglevel = logging.DEBUG
    try:
        loglevel = getattr(logging, level_name.upper())
        logger.setLevel(loglevel)  # type: ignore
    except AttributeError:
        logger.setLevel(loglevel)

    logger.debug("Logging set to {}".format(logging.getLevelName(loglevel)))

    # logging.basicConfig( level= logging.getLevelName(levelstr))#filename=logfile,
    ch = logging.StreamHandler()
    ch.setLevel(loglevel)
    chformatter = logging.Formatter('%(name)25s | %(threadName)10s | %(levelname)5s | %(message)s')
    ch.setFormatter(chformatter)
    logger.addHandler(ch)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-v", action="count", dest="verbosity",
                        help=textwrap.dedent('''\
    command line verbosity
    How much information do you want to see at the command line?
    You can add several of these e.g., -vv is DEBUG'''), default=3)

    parser.add_argument('-x', '--hex-out',
                        action='store_true',
                        default=False)

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument('--pgn', nargs='+')
    filter_group.add_argument('--source', nargs='+')
    filter_group.add_argument('--filter', type=argparse.FileType('r'))
    parser.add_argument('-c', '--channel', default='can0')
    parser.add_argument('-b', '--baud', type=int, default=500000)
    parser.add_argument('-i', '--interface', dest="interface", default='socketcan')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    verbosity = args.verbosity
    logging_level_name = ['critical', 'error', 'warning', 'info', 'debug', 'subdebug'][min(3, verbosity)]
    setlogging(logging_level_name)
    can.set_logging_level('error')  # logging_level_name)

    logging.info("Start")

    # r_dic = RedisDict(namespace='app_name')
    # r = redis.Redis(host='localhost', port=6379, db=0)
    # r.set('startlogging', 1)
    # q = Queue(connection=Redis())

    filters = []
    if args.pgn is not None:
        print('Have to filter pgns: ', args.pgn)
        for pgn in args.pgn:
            if pgn.startswith('0x'):
                pgn = int(pgn[2:], base=16)
            filters.append({'pgn': int(pgn)})
    if args.source is not None:
        for src in args.source:
            if src.startswith("0x"):
                src = int(src[2:], base=16)
            filters.append({"source": int(src)})
    if args.filter is not None:
        filters = json.load(args.filter)
        print("Loaded filters from file: ", filters)

    print("args.channel  : ", args.channel)
    print("args.baud     : ", args.baud)
    print("args.interface: ", args.interface)
    print("filter PGN's  : ", args.pgn)
    print("filter source : ", args.source)
    print("filters       : ", filters)

    if args.channel != 'vcan0':
        init_can_system(args.channel, args.baud)

    canalyse = J1939CANanalyser(args.channel)
    # bus = j1939.Bus(channel=args.channel, bustype=args.interface, j1939_filters=filters, timeout=0.5)
    bustype = args.interface
    can_filters = []

    # if results.filter:
    #     print(f"Adding filter(s): {results.filter}")
    #     for filt in results.filter:
    #         if ":" in filt:
    #             _ = filt.split(":")
    #             can_id, can_mask = int(_[0], base=16), int(_[1], base=16)
    #         elif "~" in filt:
    #             can_id, can_mask = filt.split("~")
    #             can_id = int(can_id, base=16) | 0x20000000  # CAN_INV_FILTER
    #             can_mask = int(can_mask, base=16) & socket.CAN_ERR_FLAG
    #         can_filters.append({"can_id": can_id, "can_mask": can_mask})

    config = {"can_filters": can_filters, "single_handle": True}
    bus = can.Bus(channel=args.channel, **config)

    logging.info(f"channel info  : {bus.channel_info} ")  # {bus.can_bus.channel_info}
    log_start_time = datetime.now()
    logging.info(f'can.j1939 logger started on {log_start_time}')
    # describer=init_prettyj1939(pgns=True,spns=False)
    notifier = can.Notifier(bus, [canalyse.statistics])  # sniffcalc can.Logger("logfile.asc") can.Printer()

    try:
        while True:
            # for msg in bus:
            #    if args.hex_out:
            #        msg.display_radix = 'hex'
            #    else:
            #        msg.display_radix = 10
            # print(msg.timestamp, msg.arbitration_id.priority, msg.source, msg.arbitration_id.destination_address_value,msg.pgn, msg.data, )
            # r.set(msg.pgn, bytes(msg.data))
            # description = describer(msg.data, msg.arbitration_id.can_id)
            # print(description)
            #    if bool(description) is True:
            #        # print(description)
            #        pedal = description.get("Accelerator Pedal Position 1")
            #        if pedal:
            #            pass
            # print (msg.timestamp,pedal)

            # print(msg)
            # logging.info("looop")
            canalyse.show()
            #canalyse.writestream()

            time.sleep(2)
    except KeyboardInterrupt:

        bus.shutdown()
