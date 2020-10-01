#!/usr/bin/env python3

from __future__ import print_function

import argparse
import datetime
import textwrap
import json

import can
import j1939
import os,time


#import xj1939 as j1939
import logging
import pretty_j1939.parse
import subprocess

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

def init_prettyj1939(pgns=True,spns=True):
    pretty_j1939.parse.init_j1939db()


    describer = pretty_j1939.parse.get_describer(describe_pgns=pgns, describe_spns=spns,
                                                 describe_link_layer=True,
                                                 describe_transport_layer=False,
                                                 include_transport_rawdata=False,
                                                 include_na=False)
    return describer




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
    parser = argparse.ArgumentParser(
        description=textwrap.dedent("""\
        Log J1939 tpython actrosj1939/python-j1939/bin/gpi_j1939_logger.py -c vcan0raffic, printing messages to stdout or to a given file.

        Values for SOURCE and PGN can be provided as either hex or decimals.
        e.g. 0xEE00 or 60928

        The interface or channel can also be loaded from
        a configuration file - see the README for detail.
        """),
        epilog="""Pull requests and issues
        https://github.com/hardbyte/python-can""",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-v", action="count", dest="verbosity",
                        help=textwrap.dedent('''\
    command line verbosity
    How much information do you want to see at the command line?
    You can add several of these e.g., -vv is DEBUG'''), default=1)

    parser.add_argument('-x', '--hex-out',
                        action='store_true',
                        help=textwrap.dedent('''\
    hex data in output
    when dumping output display data in hex'''), default=False)

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument('--pgn',
                              help=textwrap.dedent('''\
    Filter messages with given Parameter Group Number (PGN).
    Can be passed multiple times. Only messages that match will
    be logged.'''), action="append")

    filter_group.add_argument('--source', help=textwrap.dedent('''\
    Only listen for messages from the given Source address
    Can be used more than once.'''), action="append")

    filter_group.add_argument('--filter',
                              type=argparse.FileType('r'),
                              help=textwrap.dedent('''\
    Provide a json file with filtering rules.

    An example file that subscribes to all messages from SRC=0
    and two particular PGNs from SRC=1:

    [
      {
        "source": 1,
        "pgn": 61475
      }
      {
        "source": 1,
        "pgn": 61474
      }
      {
        "source": 0
      }
    ]
    
    

    '''))

    parser.add_argument('-c', '--channel',default='can0',
                        help=textwrap.dedent('''\
    Most backend interfaces require some sort of channel.
    For example with the serial interface the channel might be a rfcomm device: "/dev/rfcomm0"
    With the socketcan interfaces valid channel examples include: "can0", "vcan0".

    Alternatively the CAN_CHANNEL environment variable can be set.
    '''))

    parser.add_argument('-i', '--interface', dest="interface",
                        default='socketcan',
                        #choices=can.interfaces.VALID_INTERFACES,
                        help=textwrap.dedent('''\
    Specify the backend CAN interface to use.

    Valid choices:
        {}

    Alternatively the CAN_INTERFACE environment variable can be set.
    '''.format(can.interfaces.VALID_INTERFACES)))

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    verbosity = args.verbosity
    logging_level_name = ['critical', 'error', 'warning', 'info', 'debug', 'subdebug'][min(5, verbosity)]
    can.set_logging_level(logging_level_name)
    setlogging(logging_level_name)
    logging.info("Start")

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

    bus = j1939.Bus(channel=args.channel, bustype=args.interface, j1939_filters=filters, timeout=0.1)
    logging.info(f"channel info  : {bus.can_bus.channel_info} ")
    log_start_time = datetime.datetime.now()
    logging.info(f'can.j1939 logger started on {log_start_time}')

    describer=init_prettyj1939(pgns=True,spns=False)
    notifier = can.Notifier(bus, [ can.Printer()])#can.Logger("logfile.asc")
    try:
        while True:
        #for msg in bus:
        #    if args.hex_out:
        #        msg.display_radix = 'hex'
        #    else:
        #        msg.display_radix = 10
        #    description = describer(msg.data, msg.arbitration_id.can_id)
        #    print(description)
        #    if bool(description) is True:
        #        # print(description)
        #        pedal = description.get("Accelerator Pedal Position 1")
        #        if pedal:
        #            pass
                    # print (msg.timestamp,pedal)
            # print (msg.timestamp,msg.arbitration_id.priority,msg.source,msg.arbitration_id.destination_address_value,msg.pgn,msg.data,)
            # print(msg)
            # logger.info(msg)
            time.sleep(0.2)
    except KeyboardInterrupt:
        bus.shutdown()
        print()
