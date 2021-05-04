# IXanalytics

These scripts are needed to read traffic stats exported by IXmon, ship them
to a separate machine (if needed), convert them into a format suitable for
storage into InfluxDB, and also process the traffic for detecting DDoS attacks
and other traffic anomalies.

### Dependencies
_Note: this list may be incomplete_

* System dependencies
    * python3-dev
    * influxdb

* pip install's
    * inotify
    * pyasn
    * influxdb 

### InfluxDB
```
influx
> CREATE DATBASE ixmon
```

### Import script
```
./ixmon_tcp_import.py
Usage: ./ixmon_tcp_import.py serv_port
Example: ./ixmon_tcp_import.py 55555
```

Listens for IXmon exports and stores them into InfluxDB.

### Export script
```
./ixmon_tcp_export.py 
Usage: ./ixmon_tcp_export.py serv_ip serv_port ixmon_exports_dir
Example: ./ixmon_tcp_export.py 127.0.0.1 55555 /tmp/ixmon-exports/
```

Monitors the directory where IXmon exports traffic stats files 
(see `ixmon.conf`). Every time a new file is exported by IXmon, it will be
shipped to the TCP server started by the import script.

_Note: run the import script first, before running the export scipt_

