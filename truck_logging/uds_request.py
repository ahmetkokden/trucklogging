#!/usr/bin/env python
# -*- coding: utf-8 -*-

#from car_config import config
import car_tools as ctools
import decoder
import can
import time
import pytz
from datetime import datetime

import logging,sys
import argparse
import os


def udsreqtest():
    disp, uds_i = ctools.initCAN_UDSInterface('can2', 0x18DA3DF1, 0x18DAF13D, extended_id=True)


    #interface_ok= ctools.check_Interface(uds_i)
    # start extended Session
    response=ctools.doDiagnosticSessionControl(uds_i)
    print (response)
    time.sleep(0.5)
    data = ctools.read_by_identifier(uds_i, 0x1d09, decoder=decoder.hexli, debug=True)
    print (data)

    data = ctools.read_by_identifier(uds_i, 0x1d08, decoder=decoder.hexli, debug=True)
    print(data)
    data = ctools.read_by_identifier(uds_i, 0x1d07, decoder=decoder.hexli, debug=True)
    print(data)
    data = ctools.read_by_identifier(uds_i, 0x1d35, decoder=decoder.hexli, debug=True)
    print(data)
    data = ctools.read_by_identifier(uds_i, 0x1d16, decoder=decoder.hexli, debug=True)
    print(data)
    data = ctools.read_by_identifier(uds_i, 0x1d97, decoder=decoder.hexli, debug=True)
    print(data)

    data = ctools.read_by_identifier(uds_i, 0x1d13, decoder=decoder.hexli, debug=True)
    print(data)
    disp.stop()

def udsreqraw():
    #s 18DA3DF1  # 021003FFFFFFFFFF
    #r 18DAF13D  # 065003001400C8FF

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
    #s 18DAF13D  03221D09
    #r 18DAF13D  07621D090000002E
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
#udsreqtest()

while(1):
    #udsreqraw()
    udsreqtest()
