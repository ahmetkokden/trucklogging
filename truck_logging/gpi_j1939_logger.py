#!/usr/bin/env python3

# from __future__ import print_function

import argparse
import textwrap
import json
from datetime import datetime
from canalyserJ1939 import J1939CANanalyser
from canalyserJ1939 import Canlogger
import filterlist

import can
# from can import Bus, BusState, Logger, SizedRotatingLogger
# import j1939
import os, time
# import xj1939 as j1939
import logging
import subprocess

import redis
# from redis_dict import RedisDict
from redis import Redis
from redis_collections import Dict
# from rq import Queue
# import serialized_redis
# from ttseries import RedisSimpleTimeSeries

from collections.abc import MutableMapping


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

    if "vcan" not in args.channel:
        init_can_system(args.channel, args.baud)

    canalyse = J1939CANanalyser(args.channel)
    mycanlogger = Canlogger(args.channel, "logdata")
    # bus = j1939.Bus(channel=args.channel, bustype=args.interface, j1939_filters=filters, timeout=0.5)
    bustype = args.interface

    if "0" in args.channel:
        can_filters = filterlist.getcan0filter()

    if "1" in args.channel:
        can_filters = filterlist.getcan1filter()

    config = {"can_filters": can_filters, "single_handle": True}
    bus = can.Bus(channel=args.channel, **config)

    logging.info(f"channel info  : {bus.channel_info} ")  # {bus.can_bus.channel_info}
    log_start_time = datetime.now()
    logging.info(f'can.j1939 logger started on {log_start_time}')
    # describer=init_prettyj1939(pgns=True,spns=False)
    notifier = can.Notifier(bus, [canalyse.statistics,
                                  mycanlogger.logging])  # sniffcalc can.Logger("logfile.asc") can.Printer()

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

            time.sleep(5)
    except KeyboardInterrupt:

        bus.shutdown()
