# Python j1939 Tools logging

### SAE J1939 for Python

* https://github.com/benkfra/j1939

    Simulate ElectronicControlUnit
    works on python can

    pip install j1939

### python-j1939

* https://github.com/milhead2/python-j1939/tree/master

    This package is dependent on, was a part of, and broken out from, the [python-can](https://github.com/hardbyte/python-can/) project that Brian Thorne has maintained for years..
    This codce currently is compatable with the python-can version 3.3.2. After you clone the python-can repo be sure to checkout the 'release-3.3.2' branch
    Filtering J1939 messages
    Conflict with j1939 Package

    from can.protocols import j1939

    becomes

    import j1939


### pretty-j1939

* https://github.com/nmfta-repo/pretty_j1939

    python3 libs and scripts for pretty-printing J1939 candump logs.

    uses J1939db.json      converted from Digital Annex(J1939DA_202003.xls) into a JSON (DB)

1. pretty-print J1939 traffic captured in candump logs AND
2. convert a J1939 Digital Annex (Excel) file into a JSON structure for use in the above


    pip install pretty-j1939
    
  test123