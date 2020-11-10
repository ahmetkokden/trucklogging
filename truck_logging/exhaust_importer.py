
import sys, os
import argparse
from datetime import datetime,timezone



#AS07   0x1d07 7431 Abgas vor Dieseloxkat                       0x19=25°C
#AS08   0x1d08 7432 Abgastemp nach Diseloxkat
#AS09   0x1d09 7433 Abgastemp nach Dieselpartikelfilter         0x1B=27°C
#AS019  0x1d13 7443 Abgas nach SCR-Kat
#AS022  0x1d16 7446 Temperatur AdBlue Behälter                  0x17=22°C
#AS053  0x1d35 7477 Umgebungstemperatur                     0x5e0=1504=22.5°C
#AS151  0x1d97 7575 Signalspannung des Bauteils (Umgebungssensor)


valuenames={7433:"Temp_after_Partikelfilter",
            7432:"Temp_after_DieseloxKat",
            7431:"Temp_before_DieseloxKat",     #-35 -700°C
            7477:"Temp_outside",
            7446:"Temp_AdBlue",                 #-30-60°C
            7575:"Signalspannung Bauteil_V",      #3V       0x3ff=1023=3.0V
            7443:"Temp_after_SCR-Kat_C"}

timeformat="%Y-%m-%dT%H%M%S"

A60_point = {
        "measurement": "Exhaust_aftertreatment" ,
        "tags": {
            "sa": "A60",
        },
        #"time":tiestr,
        #"fields": {}
    }

if __name__ == "__main__":
    parser= argparse.ArgumentParser()
    parser.add_argument(
        "infile",
        metavar="input-file",
        #nargs='?',
        type=str,
        help="The file to load")

    args= parser.parse_args()
    pointlist=[]
    groupdata={"fields":{}}
    dataerror=False
    with open(args.infile) as file:
        elemcount=0
        for nr,line in enumerate(file):
            nr=nr%8

            if nr == 0:
                #print (line)
                timestr = datetime.strptime(line.rstrip(), timeformat).astimezone(timezone.utc).isoformat()
                #print(timestr)
                groupdata["time"]=timestr
            if nr!=0:
                data=line.split(",")
                value=int(data[1], base=16)
                if value<0:
                    dataerror=True
                groupdata["fields"][valuenames.get(int(data[0]))]=value
            if nr==7:
                #print(groupdata)
                if dataerror==False:
                    pointlist.append(groupdata)
                dataerror=False
                groupdata = {"fields": {}}


        for el in pointlist:
            print(el)