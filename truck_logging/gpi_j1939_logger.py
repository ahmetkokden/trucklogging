#!/usr/bin/env python3

from __future__ import print_function

import argparse
import datetime
import textwrap
import json

import can
import j1939
import os,time
import redis
from redis_dict import RedisDict
from redis import Redis
from redis_collections import Dict
from rq import Queue
from influxdb import InfluxDBClient
import re

#import xj1939 as j1939
import logging
import pretty_j1939.parse
import subprocess

#python -m can.player  -v  -c vcan0 can_zuendung_gas_500k_candump-2020-05-08_122006.log

def store2influx():
    pass
    #if (!influxDB.describeDatabases().contains(dbName)) {
    #...
    #}

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
    retdata=process.stdout.read().decode()
    logging.debug(retdata)

def init_can_system(candev:str):

    '''

    :param candev:
    :return:
    '''
    try:
        run_linuxprocess(f'whoami')
        #run_linuxprocess(f'ip -a')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} down')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} up type can bitrate 500000 restart-ms 1000')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} txqueuelen 65536')
    except subprocess.CalledProcessError as e:
        logging.debug(e)

    #sudo ip link set can1 txqueuelen 65536
#sudo ip link set can0 up type can bitrate 500000



def sniffcalc(msg):
    """Regular callback function. Can also be a coroutine."""
    print(msg)



class J1939CANanalyser:
    '''
    Analyse can Messages with J1939

    '''
    def __init__(self,can_channel="can0"):
        self.logger= logging.getLogger()
        self.start_time = None
        self.rdb = redis.Redis(host='localhost', port=6379, db=0)
        self.idb = InfluxDBClient('localhost', 8086, 'USERNAME', 'PASSWORD', 'DATABASE')
        self.can_channel=can_channel
        self.describer=None
        self.init_prettyj1939(pgns=True, spns=True)
        self.ids = {}
        self.analyse_d=Dict(redis=r, key=f'pgn_{can_channel}')

    def init_prettyj1939(self,pgns=True, spns=True):
        pretty_j1939.parse.init_j1939db()

        self.describer = pretty_j1939.parse.get_describer(describe_pgns=pgns, describe_spns=spns,
                                                     describe_link_layer=True,
                                                     describe_transport_layer=False,
                                                     include_transport_rawdata=False,
                                                     include_na=False)


    def write2influx(self,data):
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

    def extractmsg(self,msg):
        edata= {"ts":msg.timestamp,
                "pr":msg.arbitration_id.priority,
                "sa":msg.source,
                "da":msg.arbitration_id.destination_address_value,
                "pgn":msg.pgn,
                "data":bytes(msg.data)}
        return edata


    def statistics(self,msg,sorting=False):
        key = msg.arbitration_id.can_id
        #key = msg.pgn
        # print(msg.timestamp, msg.arbitration_id.priority, msg.source, msg.arbitration_id.destination_address_value,msg.pgn, msg.data, )
        # Sort the extended IDs at the bottom by setting the 32-bit high
        #if msg.is_extended_id:
        #key |= 1 << 32

        new_id_added, length_changed = False, False
        if not sorting:
            # Check if it is a new message or if the length is not the same
            if key not in self.ids:
                new_id_added = True
                # Set the start time when the first message has been received
                if not self.start_time:
                    self.start_time = msg.timestamp
            #elif len(msg.data) != len(self.ids[key]["msg"].data):
            #    length_changed = True

            if new_id_added or length_changed:
                # Increment the index if it was just added, but keep it if the length just changed
                row = len(self.ids) + 1 if new_id_added else self.ids[key]["row"]

                self.ids[key] = {"row": row, "count": 0, "msg": self.extractmsg(msg), "dt": 0}
            else:
                # Calculate the time since the last message and save the timestamp
                self.ids[key]["dt"] = msg.timestamp - self.ids[key]["msg"].get("ts")

                # Copy the CAN-Bus frame - this is used for sorting
                self.ids[key]["msg"] = self.extractmsg(msg)

            # Increment frame counter
            self.ids[key]["count"] += 1

        # Format the CAN-Bus ID as a hex value
        #arbitration_id_string = "0x{0:0{1}X}".format(msg.arbitration_id.can_id, 8 )
        #self.logger.info(arbitration_id_string)

    def show(self,translate=True):
        #r.set(msg.pgn, bytes(msg.data))
        #
        print(80 * "-")
        print("canid\t\tcount\t\tdt")
        for i, key in enumerate(sorted(self.ids.keys())):
            # Set the new row index, but skip the header
            self.ids[key]["row"] = i + 1
            msg=self.ids[key].get("msg")
            msgstr = " ".join("{:02x}".format(byte) for byte in msg.get("data"))

            if translate:
                j1939descr = self.describer(msg.get("data"), key)
                sa = j1939descr.get('SA')
                da = j1939descr.get('DA')
                pgn = j1939descr.get('PGN')
                #print (j1939descr)

                j1939vals={}
                while j1939descr:
                    name,val=j1939descr.popitem()   #get values backwards from ordered dict until 'SA'
                    if  'SA' not in name :
                        unit=re.search("(?<=\[).+?(?=\])", val)
                        if unit is not None:
                            unit=unit.group()
                        else:
                            unit=""
                        data=val.split()
                        j1939vals[name]=(data[0],unit)
                    else:
                        break

                print(
                    f"{key:08x} {self.ids[key].get('count'): 4}\t{self.ids[key].get('dt'):.2f}\t{sa}\t{da} {pgn}")  # \t{msgstr}, end='')

                for k,v in j1939vals.items():
                    print(f"\t\t\t\t{k} {v[0]} {v[1]}")

            else:
                print(f"{key:08x} {self.ids[key].get('count'): 4} {self.ids[key].get('dt'):.1f} {msg.get('sa'):3} {msg.get('da'):3} {msg.get('pgn'):6} 0x{msg.get('pgn'):04x}  {msgstr}")


#65282,65280, 65281,65296,65226,65284, Exhaust Emission Controller( 61)
def setlogging(level_name):
    logger = logging.getLogger()
    loglevel = logging.DEBUG
    try:
        loglevel=getattr(logging, level_name.upper())
        logger.setLevel(loglevel) # type: ignore
    except AttributeError:
        logger.setLevel(loglevel)

    logger.debug("Logging set to {}".format(logging.getLevelName(loglevel)))

    #logging.basicConfig( level= logging.getLevelName(levelstr))#filename=logfile,
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
    filter_group.add_argument('--pgn',nargs='+')
    filter_group.add_argument('--source', nargs='+')
    filter_group.add_argument('--filter',type=argparse.FileType('r'))
    parser.add_argument('-c', '--channel',default='can0')
    parser.add_argument('-i', '--interface', dest="interface",default='socketcan')

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    verbosity = args.verbosity
    logging_level_name = ['critical', 'error', 'warning', 'info', 'debug', 'subdebug'][min(5, verbosity)]
    setlogging('error')
    can.set_logging_level('error')#logging_level_name)

    logging.info("Start")

    #r_dic = RedisDict(namespace='app_name')
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.set('startlogging', 1)
    q = Queue(connection=Redis())

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
    print("args.interface: ", args.interface)
    print("filter PGN's  : ", args.pgn)
    print("filter source : ", args.source)
    print("filters       : ", filters)

    if args.channel != 'vcan0':
        init_can_system(args.channel)

    canalyse=J1939CANanalyser(args.channel)
    bus = j1939.Bus(channel=args.channel, bustype=args.interface, j1939_filters=filters, timeout=0.5)

    logging.info(f"channel info  : {bus.can_bus.channel_info} ")
    log_start_time = datetime.datetime.now()
    logging.info(f'can.j1939 logger started on {log_start_time}')
    #describer=init_prettyj1939(pgns=True,spns=False)
    notifier = can.Notifier(bus, [canalyse.statistics])#sniffcalc can.Logger("logfile.asc") can.Printer()
    try:
        while True:
        #for msg in bus:
        #    if args.hex_out:
        #        msg.display_radix = 'hex'
        #    else:
        #        msg.display_radix = 10
            #print(msg.timestamp, msg.arbitration_id.priority, msg.source, msg.arbitration_id.destination_address_value,msg.pgn, msg.data, )
            #r.set(msg.pgn, bytes(msg.data))
            #description = describer(msg.data, msg.arbitration_id.can_id)
            #print(description)
        #    if bool(description) is True:
        #        # print(description)
        #        pedal = description.get("Accelerator Pedal Position 1")
        #        if pedal:
        #            pass
                    # print (msg.timestamp,pedal)

            # print(msg)
            #logging.info("looop")
            canalyse.show()

            time.sleep(5)
    except KeyboardInterrupt:
        bus.shutdown()
