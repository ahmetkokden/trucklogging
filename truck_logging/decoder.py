# -*- coding: utf-8 -*-

from udsoncan import DidCodec,DataIdentifier,AsciiCodec
import struct

class voltage(DidCodec):
    def decode(self, payload):
        val = struct.unpack(">H",payload)[0]/1000.
        return val

class voltage_12(DidCodec):
    def decode(self, payload):
        if len(payload)==2:
            val = struct.unpack(">H",payload)[0]/10.
        if len(payload)==1:
            val = struct.unpack("B", payload)[0] / 10.
        return val

class voltall(DidCodec):
    def decode(self, payload):
        val = struct.unpack(">I",b'\x00'+payload)[0]/1000.
        return val

class int8(DidCodec):
    def decode(self, payload):
        val = struct.unpack("B",payload)[0]
        return val

class temp(DidCodec):
    def decode(self, payload):
        val = struct.unpack("B",payload)[0]
        return val-100.

class current(DidCodec):
    def decode(self, payload):
        val = struct.unpack(">I",b'\x00'+payload)[0]
        return (val-150000)/100.

class hexli(DidCodec):
    def decode(self, payload):
        datahex = ''.join('{:02X}'.format(a) for a in payload)
        #val = struct.unpack(">I",b'\x00'+payload)[0]
        return datahex