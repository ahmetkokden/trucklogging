

"""
This shows how message filtering works.
"""

import time
import can
from can.bus import BusState
import logging
import argparse

def main(args):
    """Send some messages to itself and apply filtering."""
    with can.Bus(bustype='socketcan', channel='can0', bitrate=500000, receive_own_messages=False) as bus:

        can_filters = [{"can_id": 0x14ff0331, "can_mask": 0xF, "extended": True}]
        bus.set_filters(can_filters)
        # set to read-only, only supported on some interfaces
        #bus.state = BusState.PASSIVE

        # print all incoming messages, wich includes the ones sent,
        # since we set receive_own_messages to True
        # assign to some variable so it does not garbage collected
        #notifier = can.Notifier(bus, [can.Printer()])  # pylint: disable=unused-variable


        notifier = can.Notifier(bus, [can.Logger("logfile.asc"), can.Printer()]) #can.Logger("recorded.log")

        #bus.send(can.Message(arbitration_id=1, is_extended_id=True))
        #bus.send(can.Message(arbitration_id=2, is_extended_id=True))
        #bus.send(can.Message(arbitration_id=1, is_extended_id=False))


        try:
            while True:
                #msg = bus.recv(1)
                #if msg is not None:
                #    print(msg)
                time.sleep(1.0)
        except KeyboardInterrupt:
            logging.debug(f"KeyboardInterrupt")
        except Exception as e:
            logging.debug(f"other exception")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
    description="logging Candata ")
    parser.add_argument('-d', help='activate debug', action='store_true', default=True, dest='debug')
    parser.add_argument('-c', help='configfile', dest="configpath", action='store', default="config.ini")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    main(args)

