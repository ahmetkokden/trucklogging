#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import struct

#Pyvit for readdatabyidentifier
from pyvit.proto.uds import *           #Achtung Überschneidung mit udsoncan
from pyvit.hw import socketcan
from pyvit.dispatch import Dispatcher
#from decoder import *

#udsoncan for DTC reading
import can
import isotp
import udsoncan
from udsoncan.client import Client
from udsoncan.connections import PythonIsoTpConnection
from udsoncan import DidCodec,DataIdentifier,AsciiCodec
from udsoncan.exceptions import *


logger =logging.getLogger(__name__)


def initCAN_UDSInterface(candevice,tx_id,rx_id,extended_id=False,timeout=2):
    ''' CAN Hardware für Steuergerät tx_id aktivieren'''
    dev = socketcan.SocketCanDev(candevice)
    disp = Dispatcher(dev,single_process = False)
    uds_i = UDSInterface(disp, tx_id, rx_id, extended_id=extended_id, functional_timeout=timeout)
    disp.start()

    return disp,uds_i

def check_Interface(interface):
    '''Steuergerät testen'''

    response = doDiagnosticSessionControl(interface,DiagnosticSessionControl.DiagnosticSessionType.defaultSession)

    #logger.debug("requestDiagnosticSessionType.defaultSession on Interface")
    if response is not None:
        if response.name=='DiagnosticSessionControl':
            return True
    return False

def doEcuReset(uds_i, type=ECUReset.ResetType.hardReset):
    try:
        response = uds_i.request(ECUReset.Request(type), 1)
        if isinstance(response, GenericResponse):
            pass#logger.debug('[<-] Response [%s / 0x%X]' % (response.name, response.SID))
    except Exception as e:
        pass#logger.debug(e)

def doReadDTCInformation(uds_i): #7E5#031902AE55555555  #031902AE55555555
    pass#logger.debug("doReadDTCInformation")
    try:
        response = uds_i.request(ReadDTCInformation.Request(),2)
        #logger.debug (response)
        if isinstance(response, GenericResponse):
            #logger.debug('[<-] Response [%s / 0x%X]' % (response.name))
            return response
    except Exception as e:
        pass#logger.debug("Exception ReadDTCInformation:", e)


def doDiagnosticSessionControl(uds_i, type=DiagnosticSessionControl.DiagnosticSessionType.extendedDiagnosticSession):
    try:
        response = uds_i.request(DiagnosticSessionControl.Request(type), 1)
        if isinstance(response, GenericResponse):
            #logger.debug('[<-] Response [%s / 0x%X]' % (response.name, response.SID))
            for k in response.keys():
                if isinstance(response[k], list):
                    pass#logger.debug('\t%s: %s' % (k, [hex(x) for x in response[k]]))
                else:
                    pass#logger.debug('\t%s: %s' % (k, response[k]))

        return response

    except Exception as e:
        pass#logger.debug("Exception doDiagnosticSessionControl:", e)

# uds_i.request(TesterPresent.Request(False))

def read_by_identifier(uds_i, addr, decoder=None,debug=False,resp_timeout=2):
    '''
        retval= dict with value or values
        reval=  -1 ->NegativeResponseException
                -2 -> timeout
                -3 -> unknown
                -4 -> general exception
    '''
    try:
        if debug:
            logger.debug ("ReadDataByIdentifier:{}".format(addr))#:2x
        response=None
        timeout=False

        response = uds_i.request(ReadDataByIdentifier().Request(addr), resp_timeout)
        start = time.time()
        while response is None:
            try:
                response = uds_i.decode_response()
                logger.debug("wait for data...response:{}".format(response))
            except ResponsePendingException as e:
                # response pending, go for next
                response = None

            timediff=time.time() - start
            if timediff> resp_timeout:
                #if debug:
                logger.debug(".........timeout {}".format(timediff))
                timeout=True
                break

        #logger.debug ("Response:{}".format(response))
        if isinstance(response, GenericResponse):
            id = response['dataIdentifier']
            if debug:
                logger.debug('-- Response [{} / 0x{:2x} / {} ,{}]'.format(response.name, response.SID, id,response.values()))
            value = None
            if decoder is not None:
                codec = DidCodec.from_config(decoder)
                binarydata = struct.pack('%sB' % len(response['dataRecord']), *response['dataRecord'])
                datahex = ''.join('{:02X}'.format(a) for a in response['dataRecord'])
                logger.debug ("Data: 0x{}".format(datahex))
                value = codec.decode(binarydata)
            else:
                value = response["dataRecordASCII"]

            return {"value": value}

        elif isinstance(response, NegativeResponseException):
            if debug:
                logger.debug('\n[!!] %s' % response)
            return -1
        elif response is None:
            if timeout ==True:
                logger.info('Timeout {}\n' .format(response))
            if debug:
                logger.debug('\n[??] Unknown Service: %s\n' % response)
            return -2

        else:
            if debug:
                logger.debug('\n[!?] Strange stuff: %s\n' % response)
            return -3
    except Exception as e:
        if debug:
            logger.debug ("exception:{}".format(e))
        return -4

def get_DTC_byStatusMask(candevice='can0', txid=0x7E0, rxid=0x7E8,statusMask=0xae):
    dtcdict={}
    isotp_params = {
        'stmin': 32,
        # Will request the sender to wait 32ms between consecutive frame. 0-127ms or 100-900ns with values from 0xF1-0xF9
        'blocksize': 8,  # Request the sender to send 8 consecutives frames before sending a new flow control message
        'wftmax': 0,  # Number of wait frame allowed before triggering an error
        'll_data_length': 8,  # Link layer (CAN layer) works with 8 byte payload (CAN 2.0)
        'tx_padding': 0x00,  # Will pad all transmitted CAN messages with byte 0x00. None means no padding # VW-AG need Padding !! M.M.
        'rx_flowcontrol_timeout': 1000,
        # Triggers a timeout if a flow control is awaited for more than 1000 milliseconds
        'rx_consecutive_frame_timeout': 1000,
        # Triggers a timeout if a consecutive frame is awaited for more than 1000 milliseconds
        'squash_stmin_requirement': True
        # When sending, respect the stmin requirement of the receiver. If set to True, go as fast as possible.
    }

    config = dict(udsoncan.configs.default_client_config)

    bus = can.interface.Bus(candevice, bustype='socketcan')
    tp_addr = isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=rxid)
    stack = isotp.CanStack(bus=bus, address=tp_addr, params=isotp_params)

    conn = PythonIsoTpConnection(stack)
    try:
        with Client(conn, request_timeout=2, config=config) as client:  # Application layer (UDS protocol)

            #DiagnosticSessionControl.Session.extendedDiagnosticSession  ->überschneidung mit pyvituds
            client.change_session(3)
            response = client.get_dtc_by_status_mask(statusMask)
            print(response.service_data.dtc_count,
                  response.service_data.dtcs)  # [<DTC ID=0x001ca4, Status=0x20, Severity=0x00 at 0xb3dceed0>]
            if response.service_data.dtc_count>0:
                dtclist_str=[]
                for el in response.service_data.dtcs:
                    dtclist_str.append("{}".format(el))
                dtcdict["DTC"]=dtclist_str
            else:
                dtcdict["DTC"] =[""]
        return  dtcdict
    except NegativeResponseException as e:
        print(
            "NegativeResponseException")  # print('Server refused our request for service %s with code "%s" (0x%02x)' % (e.response.service.get_name(), e.response.code_name, e.response.code))
    except (InvalidResponseException, UnexpectedResponseException) as e:
        print('Server sent an invalid payload : %s' % e.response.original_payload)
    except TimeoutException as e:
         print("Timeout")

