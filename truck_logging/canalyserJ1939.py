#!/usr/bin/env python3

import logging
import redis
from walrus import Database
import msgpack
from influxdb import InfluxDBClient
import re
import pretty_j1939.parse
from datetime import datetime
import time
import can


class Canlogger:
    def __init__(self, can_channel="can0", logpath=""):
        self.canlogger = None
        self.rdb = redis.Redis(host='localhost', port=6379, db=0)
        self.logger = logging.getLogger()
        self.can_channel = can_channel
        self.logpath = logpath
        # self.initcanlogger()
        self.initlog = 0

    def initcanlogger(self):
        ''' stop old if running and create new logger with filename from timestamp'''
        if self.canlogger is not None:  # stop old logging
            try:
                self.canlogger.stop()
            except Exception as e:
                pass

        timestr = datetime.now().strftime("%Y-%m-%dT%H%M%S")
        logfilname = f'{self.logpath}//{self.can_channel}_{timestr}_log.blf'
        self.canlogger = can.Logger(filename=logfilname)
        self.logger.debug(f"Init canlogger : {logfilname}")

    def logging(self, msg):
        '''logging only if redisDB enabled it an canlogger is activated'''
        if self.canlogger is not None:
            if self.rdb.get("logging") == b'1':  # logging enabled from redisflag
                self.canlogger(msg)
                if self.initlog == 0:
                    self.initlog = 1
                    self.logger.info("logging on ")
            else:
                if self.initlog == 1:
                    self.initcanlogger()
                    self.initlog = 0
                    self.logger.info("logging off")
        else:
            self.initcanlogger()


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

        # TODO: logging in extra Process

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
        if "65175" in j1939descr.get('PGN'):
            print(j1939descr)

        if "65132" in j1939descr.get('PGN'):    #vehiclespeed
            print(j1939descr)

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

        if not (sumcount == self.sumcount):  # only store if new packets received
            self.sumcount = sumcount
            # print(self.sumcount)
            datadict = msgpack.packb(resultdict, use_bin_type=True)
            # ts = int(time.time())
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
                            if int(v[0]) > 29:
                                self.rdb.set("logging", 1)
                            if int(v[0]) < 28:
                                self.rdb.set("logging", 0)
            else:
                msgstr = " ".join("{:02x}".format(byte) for byte in msg)
                print(
                    f"{key:08x} {self.ids[key].get('count'): 4} {self.ids[key].get('dt'):.1f} {self.ids[key].get('sa'):3} {self.ids[key].get('da'):3} {self.ids[key].get('pgn'):6} 0x{self.ids[key].get('pgn'):04x}  {msgstr}")
