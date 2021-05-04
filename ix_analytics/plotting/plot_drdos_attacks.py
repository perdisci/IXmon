#!/usr/bin/env python3

""" Plot traffic for a given combination of srcPort, dstAS.

Only traffic within a specified time interval is considered.
A curve is plot for each srcAS that sent traffic from srcPort to dstAS.
srcASes that sent less than vol_th Mbps of traffic are filtered out.

E.g.:
./plot_drdos_attacks.py -a 20190214-sungt-drdos_alerts.json

"""

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import json
import operator
import argparse
import subprocess

import time
from pprint import pprint
from datetime import datetime, timedelta

import matplotlib.pyplot as plt

_DATE_STR_FORMAT = "%Y-%m-%d %H:%M:%S"


def find_attacks(alerts, time_delta=600):
    attacks = dict()
    current_attacks = dict()
    for a in alerts:
        if a['attack_type'] != 'DRDoS':
            continue
        dst_as = a['dstAS']
        src_port = a['sport']
        start_time = a['time']
        end_time = a['time']
        volume = a['volume']
        src_as_bytes = a['srcAS_bytes']
        key = str(dst_as)+':'+str(src_port)
        if key not in current_attacks:
            current_attacks[key] = dict()
            current_attacks[key]['dst_as'] = dst_as
            current_attacks[key]['src_port'] = src_port
            current_attacks[key]['start_time'] = start_time
            current_attacks[key]['end_time'] = end_time
            current_attacks[key]['max_volume'] = volume
            current_attacks[key]['contributions'] = [(end_time,src_as_bytes)]
        else:
            end_time_ts = time.mktime(datetime.strptime(end_time, _DATE_STR_FORMAT).timetuple())
            curr_atk_end_time_ts = time.mktime(datetime.strptime(current_attacks[key]['end_time'], _DATE_STR_FORMAT).timetuple())
            if end_time_ts < (curr_atk_end_time_ts + time_delta):
                # still same attack
                current_attacks[key]['end_time'] = end_time
                if volume > current_attacks[key]['max_volume']:
                    current_attacks[key]['max_volume'] = volume
                current_attacks[key]['contributions'].append((end_time,src_as_bytes))
            else:
                key_time = key + '--' + current_attacks[key]['start_time']
                attacks[key_time] = current_attacks[key]
                del current_attacks[key]

                atk_start_time_ts = time.mktime(datetime.strptime(attacks[key_time]['start_time'], _DATE_STR_FORMAT).timetuple())
                atk_end_time_ts = time.mktime(datetime.strptime(attacks[key_time]['end_time'], _DATE_STR_FORMAT).timetuple())
                attacks[key_time]['duration'] = atk_end_time_ts - atk_start_time_ts + 60

    return attacks


def load_alerts(alerts_file):
    alerts = []
    with open(alerts_file) as f:
        line = f.readline()
        while line:
            d = json.loads(line)
            alerts.append(d)
            line = f.readline()
    return alerts

def main():

    parser = argparse.ArgumentParser(
        description='Find and plot DRDoS attacks from alert logs')
    parser.add_argument('-a', '--alerts_file',
                        dest='alerts_file',
                        required=True,
                        help='DRDoS alerts file (json)')

    args = parser.parse_args()

    alerts = load_alerts(args.alerts_file)

    attacks_dict = find_attacks(alerts)
    pprint(attacks_dict)

    with open('attacks_output-'+args.alerts_file, 'w') as f:
        json.dump(attacks_dict, f)

    # we should make these as cli parameters
    min_mbps = 1.0
    timezone = 0
    for a in attacks_dict:
        d = attacks_dict[a]
        sys.stdout.flush()
        stime = time.mktime(datetime.strptime(d['start_time'], _DATE_STR_FORMAT).timetuple()) - 30*60
        etime = time.mktime(datetime.strptime(d['end_time'], _DATE_STR_FORMAT).timetuple()) + 30*60
        stime_str = datetime.fromtimestamp(stime).strftime('%Y-%m-%d-%H:%M')
        etime_str = datetime.fromtimestamp(etime).strftime('%Y-%m-%d-%H:%M')
        dstAS = d['dst_as']
        srcPort = d['src_port']
        date = datetime.fromtimestamp(stime).strftime('%Y%m%d')
        influx_file = '~/ixmon_data/AS_AS_UDP_'+date+'.csv.gz'

        command = './plot_traffic_window_from_influx.py'
        command += ' '+str(srcPort)+' '+str(dstAS)+' '+stime_str+' '+etime_str+' '+str(timezone)+' '+str(min_mbps)+' '+influx_file
        print(command)
        process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)

if __name__ == "__main__":
    main()
