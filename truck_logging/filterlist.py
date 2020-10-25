#!/usr/bin/env python3

import json

filterlist_can0 = [
    0x00000004,
    0x08f0090b,
    0x08f01d13,
    0x08fe6e0b,
    0x14febf0b,
    0x0cf00400,
    0x10f00300,
    0x14f00000,
    0x14f0010b,
    0x14f00500,
    0x14fdc40b,
    0x14fe4f0b,
    0x14fe5a2f,
    0x14feae17,
    0x18e00019,
    0x18fee617,
    0x18fef34a,
    0x18fef519,
    0x18fef521,
    0x18fef721,
    0x18fec134,
    0x14ff0044,
    0x14ff000f
]


def make_canfilter(filterlist, mask=0x1FFFFFFF, extended=True):
    canfilter = []
    for el in filterlist:
        canfilter.append({"can_id": int(el), "can_mask": mask, "extended": extended})
    return canfilter


def getcan0filter():
    return make_canfilter(filterlist_can0)


def getcan1filter():
    return []


if __name__ == "__main__":
    with open("filter.json", "r") as jsonfile:
        filters = json.load(jsonfile)
    print("Loaded filters from file: ", filters)
    # print (filterlist)
    filterdict = dict.fromkeys(filterlist, True)
    # print (filterdict.get("asdf"))
    # print (filterdict.get(4))
    print(make_canfilter(filterlist))
