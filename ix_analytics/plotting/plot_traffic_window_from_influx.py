#!/usr/bin/env python3

""" Plot traffic for a given combination of srcPort, dstAS.

Only traffic within a specified time interval is considered.
A curve is plot for each srcAS that sent traffic from srcPort to dstAS.
srcASes that sent less than vol_th Mbps of traffic are filtered out.

"""

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import operator

import time
from datetime import datetime, timedelta, timezone

import pandas as pd
import pandasql as pdsql
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


_EPS = 1E-6
_TIME_STR_FORMAT = "%Y-%m-%d-%H:%M"
_TOP_SRCAS_LIMIT = 10

def _ts_to_datetime(ts, tz):
    """ unix time to datetime conversion """
    return datetime.utcfromtimestamp(ts)

def _truncate_time_to_min(t):
    """ remove seconds from datetime t """
    t_str = t.strftime(_TIME_STR_FORMAT+":00")
    return datetime.strptime(t_str, _TIME_STR_FORMAT+":00")

def plot(data, srcPort, dstAS, start_time, end_time, tzone, vol_th=5):
    """ Plots traffic volume for flows from srcPort (any srcAS) to dstAS

    Parameters:
    -----------
    data: DataFrame containing traffic flows information
    start/end_time: only consider traffic with timestamp between start/end_time
                    expected format: %Y-%m-%d-%H:%M
    timezone = number of hours w.r.t. GMT (e.g., -4)
    vol_th: plot only traffic from srcASes with max traffic > vol_th Mbps
    """

    plot_begin_time = start_time
    plot_end_time = end_time

    pbt = datetime.strptime(plot_begin_time, _TIME_STR_FORMAT)
    pet = datetime.strptime(plot_end_time, _TIME_STR_FORMAT)
    # pbt = pbt.replace(tzinfo=timezone.utc).astimezone(tz=None)
    # pet = pet.replace(tzinfo=timezone.utc).astimezone(tz=None)
    pbt = datetime(pbt.year, pbt.month, pbt.day, pbt.hour, pbt.minute, pbt.second)
    pet = datetime(pet.year, pet.month, pet.day, pet.hour, pet.minute, pet.second)

    # print(pbt, pet)

    pbt_ts = pbt.replace(tzinfo=timezone.utc).timestamp()
    pet_ts = pet.replace(tzinfo=timezone.utc).timestamp()

    # print(pbt_ts, pet_ts)

    srcport = srcPort
    dstAS = dstAS

    # the GROUP BY clause below expects time to have a
    # minute granularity
    sql_query = """
                SELECT time, srcAS, SUM(bytes) AS bytes
                FROM data
                WHERE sport=%s AND dstAS=%s AND
                    time >= '%s' AND time <= '%s'
                GROUP BY time, srcAS
                ORDER BY time;
                """ % (srcport, dstAS, pbt_ts, pet_ts)

    attack_info = pdsql.sqldf(sql_query, locals())

    # print(attack_info)

    # compute traffic peak per each srcAS
    # sort srcASes by peak volume
    srcAS_peak_vol_dict = dict()
    for srcAS in set(attack_info['srcAS']):
        srcAS_bytes = attack_info[attack_info['srcAS'] == srcAS]['bytes']
        srcAS_peak_vol_dict[srcAS] = max(srcAS_bytes)

    sorted_srcAS_peak_vol = sorted(srcAS_peak_vol_dict.items(),
                                   key=operator.itemgetter(1),
                                   reverse=True)

    # we plot a separate line for each srcAS (limited to top srcASes by volume)
    df = pd.DataFrame()
    min_time = pbt
    max_time = pet
    for srcAS, max_vol in sorted_srcAS_peak_vol[:_TOP_SRCAS_LIMIT]:

        attack_srcAS = attack_info[attack_info['srcAS'] == srcAS].copy()
        del attack_srcAS['srcAS']

        time_col = attack_srcAS['time']
        time_col = [_ts_to_datetime(t, tzone) for t in time_col]
        attack_srcAS['time'] = [_truncate_time_to_min(t) for t in time_col]
        att = attack_srcAS.set_index('time')
        att = att.astype('float')

        # print(att)

        idx = pd.date_range(min_time, max_time, freq='min')
        srcAS_reidx = att.reindex(idx, fill_value=_EPS)

        # print(srcAS_reidx)

        scaling_factor = 1E6*60/8
        srcAS_reidx['bytes'] = \
            srcAS_reidx['bytes']/(scaling_factor)
        # rename columns for plotting the legend correctly
        srcAS_reidx.columns = ['srcAS: '+str(srcAS)]
        if max(srcAS_reidx['srcAS: '+str(srcAS)]) >= vol_th:
            if len(df) == 0:
                df = pd.DataFrame(srcAS_reidx['srcAS: '+str(srcAS)].copy())
            else:
                df['srcAS: '+str(srcAS)] = \
                    srcAS_reidx['srcAS: '+str(srcAS)].copy()

    # print("df=")
    # print(df)
    fig = df.plot(legend=True,
                  title='dstAS: '+str(dstAS)+' - srcPort: '+str(srcport))
    fig.set_xlabel(plot_begin_time + ' - ' + plot_end_time)
    fig.set_ylabel('~Mbps')
    plt.tight_layout()

    plot_file_name = start_time+'-'+str(srcPort)+'-'+str(dstAS)+'.pdf'
    plt.savefig(plot_file_name)
    # print("Plot saved to " + plot_file_name)

def _load_raw_data(data_file):
    data = pd.read_csv(data_file, compression='gzip')
    del data['name']
    return data



def main():

    def _print_usage():
        print("Parameters list:")
        print("srcPort dstAS start_time end_time timezone vol_th data_file")
        print("-----------")
        print("Example usage:")
        print(sys.argv[0] + " 389 12005 "
              "'2018-05-02-13:30' '2018-05-02-14:30' -4 5.0 "
              "../path/to/AS_AS_UDP_20180502.csv.gz")

    if len(sys.argv) < 8:
        _print_usage()
        return

    srcPort = int(sys.argv[1])
    dstAS = int(sys.argv[2])
    start_time = sys.argv[3]
    end_time = sys.argv[4]
    timezone = int(sys.argv[5])
    vol_th = float(sys.argv[6])
    data_file = sys.argv[7]

    data = _load_raw_data(data_file)
    plot(data, srcPort, dstAS, start_time, end_time, timezone, vol_th)

if __name__ == "__main__":
    main()
