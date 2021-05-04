#!/bin/bash

T=$(date +%Y%m%d)
Y=$(date -d 'yesterday' +%Y%m%d)
TODAY=$(date -d $T +%s)
YESTERDAY=$(date -d $Y +%s)
TNS=$TODAY"000000000"
YNS=$YESTERDAY"000000000"

DB="ixmon"
HOST="localhost"
DBQUERY="SELECT * FROM AS_AS_dst_sdports WHERE protocol='udp' AND time>=$YNS AND time<$TNS"

FILEPATH="/path/to/ixmon_data/"
FILEPREFIX="AS_AS_UDP_"

echo "Running influx query:"
echo "$DBQUERY"

influx -host "$HOST" -database "$DB" -format csv -precision s -execute "$DBQUERY" >& $FILEPATH$FILEPREFIX$Y.csv
gzip -f $FILEPATH$FILEPREFIX$Y.csv

