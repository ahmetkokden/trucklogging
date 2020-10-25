#!/usr/bin/env python
# -*- coding: utf-8 -*-

# from car_config import config
import car_tools as ctools
import decoder
import can
import time
import pytz
from datetime import datetime

import logging, sys
import argparse
import os
import subprocess
import logging
from table_logger import TableLogger

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
    # baudrate=500000
    try:
        run_linuxprocess(f'whoami')
        # run_linuxprocess(f'ip -a')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} down')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} up type can bitrate {baudrate} restart-ms 1000')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} txqueuelen 65536')
    except subprocess.CalledProcessError as e:
        logging.debug(e)


def init_slcan_system(candev: str):
    try:
        # sudo slcand -f -s6 -o  /dev/ttyACM0 can2
        # sudo ip link set can2 up
        # sudo ip link set can2 txqueuelen 65536
        run_linuxprocess(f'sudo killall slcand')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} down')
        run_linuxprocess(f'sudo /usr/bin/slcand -f -s6 -o  /dev/ttyACM0 {candev}')

        run_linuxprocess(f'sudo /sbin/ip link set {candev} up')
        run_linuxprocess(f'sudo /sbin/ip link set {candev} txqueuelen 65536')
    except subprocess.CalledProcessError as e:
        logging.debug(e)


def udsreqtest(canbus="can2", filename="log.csv"):
    disp, uds_i = ctools.initCAN_UDSInterface(canbus, 0x18DA3DF1, 0x18DAF13D, extended_id=True)

    # interface_ok= ctools.check_Interface(uds_i)
    # start extended Session
    logging.debug(f"start extended Session on  {canbus}")

    resultdict = {}
    response = ctools.doDiagnosticSessionControl(uds_i)
    print(response)
    time.sleep(0.5)
    # Bilder Actros4 IMG_20200613_083901_TemperaturIstwerte.jpg
    data = ctools.read_by_identifier(uds_i, 0x1d09, decoder=decoder.hexli,
                                     debug=True)  # Abgastemp nach Dieselpartikelfilter
    print(data)
    logging.debug(f"0x1d09: {data}")
    resultdict[0x1d09] = data

    data = ctools.read_by_identifier(uds_i, 0x1d08, decoder=decoder.hexli, debug=True)  # Abgastemp nach Diseloxkat
    print(data)
    resultdict[0x1d08] = data
    data = ctools.read_by_identifier(uds_i, 0x1d07, decoder=decoder.hexli, debug=True)  # Abgas vor Dieseloxkat
    print(data)
    resultdict[0x1d07] = data
    data = ctools.read_by_identifier(uds_i, 0x1d35, decoder=decoder.hexli, debug=True)  # Umgebungstemperatur
    print(data)
    resultdict[0x1d35] = data
    data = ctools.read_by_identifier(uds_i, 0x1d16, decoder=decoder.hexli, debug=True)  # Temperatur AdBlue Behälter
    print(data)
    resultdict[0x1d16] = data
    data = ctools.read_by_identifier(uds_i, 0x1d97, decoder=decoder.hexli, debug=True)  # Signalspannung des Bauteils
    print(data)
    resultdict[0x1d97] = data

    data = ctools.read_by_identifier(uds_i, 0x1d13, decoder=decoder.hexli, debug=True)  # Abgas nach SCR-Kat
    print(data)
    resultdict[0x1d13] = data

    response = ctools.check_Interface(uds_i)
    print(response)

    disp.stop()

    with open(filename, 'a+', encoding='ISO-8859-1') as csvfile:
        # tbl = TableLogger(file=csvfile, csv=True,  timestamp=True,columns='addr,values')

        timestr = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        resultstr = f'{timestr}\n'
        for k, v in resultdict.items():
            if type(v) == dict:
                resultstr += f'{k:d},{v["value"]}\n'
            else:
                resultstr += f'{k:d},{v}\n'

        # resultstr+="\n"
        csvfile.write(resultstr)
        logging.debug(resultstr)


def udsreqraw():
    # s 18DA3DF1  # 021003FFFFFFFFFF
    # r 18DAF13D  # 065003001400C8FF

    bus = can.interface.Bus()

    # Using specific buses works similar:
    # bus = can.interface.Bus(bustype='socketcan', channel='vcan0', bitrate=250000)
    # bus = can.interface.Bus(bustype='pcan', channel='PCAN_USBBUS1', bitrate=250000)
    # bus = can.interface.Bus(bustype='ixxat', channel=0, bitrate=250000)
    # bus = can.interface.Bus(bustype='vector', app_name='CANalyzer', channel=0, bitrate=250000)
    # ...

    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x02, 0x10, 0x03, 0x55, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    try:
        bus.send(msg)
        print("Message sent on {}".format(bus.channel_info))
    except can.CanError:
        print("Message NOT sent")

    time.sleep(0.5)
    # s 18DAF13D  03221D09
    # r 18DAF13D  07621D090000002E
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x09, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))
    time.sleep(0.5)
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x07, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))

    time.sleep(0.5)
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x97, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))

    time.sleep(0.5)
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x08, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))

    time.sleep(0.5)
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x13, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))
    time.sleep(0.5)
    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x16, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))
    time.sleep(0.5)

    msg = can.Message(arbitration_id=0x18DA3DF1,
                      data=[0x03, 0x22, 0x1d, 0x35, 0x55, 0x55, 0x55, 0x55],
                      is_extended_id=True)

    bus.send(msg)
    print("Message sent on {}".format(bus.channel_info))
    time.sleep(0.5)



# udsreqtest()
if __name__ == "__main__":
    # logger = logging.getLogger()
    logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d %(threadName)s %(message)s')
    # loglevel = logging.DEBUG
    canbus = "can2"

    logging.debug(f"start exhaust logging on {canbus}")
    init_slcan_system(canbus)
    timestr = datetime.now().strftime("%Y-%m-%dT%H%M%S")
    logpath = "logdata"
    logfilename = f'{logpath}//exhaust_log{timestr}.csv'
    try:
        while (1):
            # udsreqraw()
            udsreqtest(canbus, logfilename)
            logging.debug("waiting some seconds")
            time.sleep(2)

    except KeyboardInterrupt:
        logging.debug("stop exhaust logging")
        # bus.shutdown()
