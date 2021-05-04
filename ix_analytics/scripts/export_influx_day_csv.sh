#!/bin/bash

DATE=$(date -d "-1 days" +%Y%m%d)

cd /data/ixmon_data
touch $DATE.test
influx -execute "select * from ixmon.ixmon_retention.AS_AS_dst_sdports where protocol='udp' and time >= now()-2d and time <= now()" -precision 's' -format csv > AS_AS_UDP_$DATE.csv
gzip AS_AS_UDP_$DATE.csv
