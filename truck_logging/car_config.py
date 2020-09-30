#!/usr/bin/env python
# -*- coding: utf-8 -*-

# config Etron
from decoder import *



#tx_arb_id = 0x7e5  # 0x714   #0x7DF
#rx_arb_id = 0x7ed  # 0x77e   #0x7E8

# tx_arb_id = 0x710#0x714   #0x7DF
# rx_arb_id = 0x77a#0x77e   #0x7E8
#7731-7732,20836,29768,29876-29877,62555,62618
#646,690

'''
'01':{
            "name": "Motorelektronik",
            "tx_id":0x7E0,
            "rx_id":0x7E8,
            "identifiers":
                {
                    61831:{"decoder":None, "name": "Teilenummer"},
                    61833:{"decoder":None, "name": "Softwareversion"},
                    61835:{"decoder":None, "name": "ECUManufacturingDate"},
                    61836:{"decoder":None, "name": "ECUSerialNumber"},
                    61854:{"decoder":None, "name": "ECU Name"},
                    61859:{"decoder":None, "name": "Hardwareversion"},
                    61847:{"decoder":None, "name": "Beschreibung"},
                }
            },
        '08':{
            "name": "Klima-Heizungselektronik",
            "tx_id":0x746,
            "rx_id":0x7B0,
            "identifiers":
                {
                    61831:{"decoder":None, "name": "Teilenummer"},
                    61833:{"decoder":None, "name": "Softwareversion"},
                    61835:{"decoder":None, "name": "ECUManufacturingDate"},
                    61836:{"decoder":None, "name": "ECUSerialNumber"},
                    61854:{"decoder":None, "name": "ECU Name"},
                    61859:{"decoder":None, "name": "Hardwareversion"},
                    61847:{"decoder":None, "name": "Beschreibung"},
                }
            },
'''


config={'17':{
            "name": "Schalttafeleinsatz",
            "tx_id":0x714,      #ExtendedID 17FC007B
            "rx_id":0x77E,      #17FE007B
            "ex_tx_id":0,      #29BitID
            "ex_rx_id":0,      #29BitID
            "identifiers":
                {
                    61840: {"decoder": None,"name":"VIN"},
                    61833: {"decoder": None, "name": "Softwareversion"},
                    61859: {"decoder": None, "name": "Hardwareversion"},
                    62530: {"decoder": voltage_12, "name": "SpannungKlemme30", "unit":"Volt"},
                    62469: {"decoder": hexli, "name": "Kühlmitteltemperatur","unit":"hex"},

                }
            },

        '19':{
            "name": "Diagnoseinterface für Datenbus",
            "tx_id":0x710,      #ExtendedID 17FC007B
            "rx_id":0x77a,      #17FE007B
            "ex_tx_id":0,      #29BitID
            "ex_rx_id":0,      #29BitID
            "identifiers":
                {
                    61840:{"decoder":None,"name":"VIN"},
                    61833: {"decoder": None, "name": "Softwareversion"},
                    61859: {"decoder": None, "name": "Hardwareversion"},
                    62530: {"decoder": voltage_12, "name": "SpannungKlemme30", "unit":"Volt"},

                }
            },

        '8C':{
            "name": "Hybrid Batteriemanagement",
            "tx_id":0x7e5,      #11Bit ID
            "rx_id":0x7ed,      #
            "ex_tx_id":0x17FC007B,      #29BitID
            "ex_rx_id":0x17FE007B,      #29BitID
            "identifiers":
                {
                    646:  {"decoder":voltage_12, "name": "Spannung_Klemme30"},
                    7731: {"decoder":hexli, "unit": "V", "name": "max_Zellspannung"},
                    7732: {"decoder":hexli, "unit": "V", "name": "min_Zellspannung"}, # 10 13 00 0f  0x0f=15 ->index  0x1013=4114->4,114 Volt  1. 4Byte Spannung, 2. 4Byte Zellenindex bzw. letzte Byte
                    7740: {"decoder":voltall, "unit": "V", "name": "Spannung_Main"},
                    7744: {"decoder":voltage, "unit": "V", "name": "voltage_cell", "addrcount": 108},
                    7854: {"decoder":temp, "unit": "°C", "name": "temp", "addrcount": 15},
                    16967:{"decoder":hexli, "unit": "_", "name": "Modus_HochvoltBatterie_Sollwert"},
                    29770:{"decoder":int8, "unit": "%", "name": "soc_cell","addrcount": 108},
                    29768:{"decoder":hexli, "unit": "_", "name": "Modus_HochvoltBatterie_Istwert"},
                    61831:{"decoder":None, "name": "Teilenummer"},
                    61833:{"decoder":None, "name": "Softwareversion"},
                    61835:{"decoder":None, "name": "ECUManufacturingDate"},
                    61836:{"decoder":None, "name": "ECUSerialNumber"},
                    61854:{"decoder":None, "name": "ECU Name"},
                    61859:{"decoder":None, "name": "Hardwareversion"},
                    61847:{"decoder":None, "name": "Beschreibung"},

                    #29733:{"decoder":hexli,"unit":"°C","name":"Temperaturgeber17","addrcount":11},#egolf 29733 Temperatur 17-27
                    #0x1e3d:{"decoder":current,"unit":"A","name":"Strom(hex)"},
                    #0x1e3d:{"decoder":hexli,"unit":"A","name":"Strom"},       # 7741 Strom der Hochvoltbatterie
                    #0x1e3e:{"decoder":current,"unit":"A","name":"Strom2 Cells (hex)"},
                    #0x1e3e:{"decoder":current,"unit":"A","name":"Strom2 Cells (hex)"},
                    #0xF17C:{"decoder":None,"name":"Advanced_Identification"},
                    #63498:{"decoder":None,"name":"ECU Name"}
                    #0x1e32:{"decoder":hexli,"name":"BatterieHistoriendaten"},#7730 ...Zähler Ladung/Entladung Ah/kwh
                    #0x28c:{"decoder":hexli,"unit":"%","name":"soc_all"},#652 Socarche
                    #0xF187:{"decoder":None,"name":"ECU SW Number"},
                    #0xF191:{"decoder":None,"name":"ECU HW Number"},
                    #0xF197:{"decoder":None,"name":"HW Number"},
                    #0x500:{"decoder":None,"name":"Serialnumber"},
                    #0xF190:{"decoder":None,"name":"VIN"}
                    #0x1eb7:{"decoder":int8,"unit":"V","name":"Spannung_Klemme_30C"},
                        #0xF187:"VehicleManufacturerSparePartNumber",
                    #0xF18B:"ECUManufacturingDate",
                    #0xF18c:"ECUSerialNumber",
                    #0xf191:"VehicleManufacturerECUHardwareNumber",
                    #0xf197:"SystemNameOrEngineType",
                    #0xf19e:"ODXFile",
                }
            }
        }


if __name__ == '__main__':
    print (config.get())
