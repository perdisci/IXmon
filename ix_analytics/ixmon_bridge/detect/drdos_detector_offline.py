#!/bin/python

import sys
import os.path
import pickle
from datetime import datetime

import matplotlib
import matplotlib.pyplot as plt

import numpy as np
import pandas as pd
import pandasql as pdsql


EPS = 1E-6
scaling = 1E6*60/8 # scales from bytes/minute to Mbps

def load_raw_data(csv_file, compression='gzip'):

    print "Reading raw data from ", csv_file

    raw_data = pd.read_csv(csv_file, compression=compression)
    del raw_data['name']
    idx = raw_data['time']
    raw_data['time'] = [datetime.fromtimestamp(t) for t in raw_data['time']]
    
    # remove seconds form timestamps
    # since they only have minute granularity
    idx = raw_data['time']
    raw_data['time'] = idx.map(lambda t: t.strftime('%Y-%m-%d %H:%M:00'))

    print raw_data
    return raw_data


def load_srcPort_dstAS_data(raw_data):

    print "Loading srcPort_dstAS data"

    sql_query = """
                SELECT time, sport, dstAS, 
                       SUM(bytes) AS bytes, 
                       SUM(packets) AS packets 
                FROM raw_data 
                GROUP BY time,sport,dstAS 
                ORDER BY time;
                """
    udp_sports_dstas_data = pdsql.sqldf(sql_query, locals())

    print "udp_sports_dstas_data size =", udp_sports_dstas_data.shape

    return udp_sports_dstas_data


def build_udp_ts(udp_sports_dstas_data, sport, dstAS):

    print "Building udp_ts for sport=%s and dstAS=%s" % (sport, dstAS)

    filter_idx = (udp_sports_dstas_data['sport'] == sport) & (udp_sports_dstas_data['dstAS'] == dstAS)
    udp_sp_das = udp_sports_dstas_data.loc[filter_idx]

    udp_ts_time = udp_sp_das['time']
    udp_ts_bytes = [x/float(scaling) for x in list(udp_sp_das['bytes'])]
    udp_ts = pd.Series(data=udp_ts_bytes, index=udp_ts_time)

    # reindex to fill missing minutes with 0s
    min_time = min(udp_sports_dstas_data['time'])
    max_time = max(udp_sports_dstas_data['time'])
    idx = pd.date_range(min_time, max_time, freq='min')
    # remove seconds form timestamps
    # since they only have minute granularity
    idx = idx.map(lambda t: t.strftime('%Y-%m-%d %H:%M:00'))
    udp_ts = udp_ts.reindex(idx, fill_value=0)

    return udp_ts
            

def detect_attacks_offline(ts, anomaly_th=0.9, vol_th=10):

    # compute ewm avg and std
    alpha=0.01
    ts_ewm_avg = ts.ewm(alpha=alpha).mean()
    ts_ewm_std = ts.ewm(alpha=alpha).std()

    # Create series of futre predicitons
    # Each future point value is predicted as the 
    # immediately preceding known value

    ts_predict_avg = ts_ewm_avg.copy()
    for i in range(len(ts_predict_avg)-1):
        ts_predict_avg.iat[i+1] = ts_ewm_avg.iat[i]

    ts_predict_std = ts_ewm_std.copy()
    for i in range(len(ts_predict_std)-1):
        ts_predict_std.iat[i+1] = ts_ewm_std.iat[i]


    # compute how ewma predictions differ from observed value
    # we use the theta*std to find only highly anomalous values
    theta = 3
    delta_dev_ts = (ts - (ts_predict_avg + theta*ts_predict_std))/(ts+EPS)
    # and we are only interested in positive prediction errors
    delta_dev_ts = delta_dev_ts.apply(lambda x: max(0,x))
    # delta_dev_ts.replace([np.inf, -np.inf, np.nan], 0)

    # if we find a ts distribution anomaly AND the traffic volume
    # is higher than a minimum vol_th for the attack to be meaningful
    # THEN we raise an alert
    ts_anom = ts[(ts>vol_th) & (delta_dev_ts>anomaly_th)]
    ts_anom.name = "Estimated Mbps"

    delta_dev_anom = delta_dev_ts[(ts>vol_th) & (delta_dev_ts>anomaly_th)]
    delta_dev_anom.name = "Anomaly Score"

    attack_info = pd.concat([ts_anom, delta_dev_anom], axis=1)

    return attack_info


def plot_udp_ts(udp_ts, sport, dstAS):

    print "Plotting for sport=%s and dstAS=%s " % (sport, dstAS)

    title = "sport=%s - dstAS=%s" % (sport, dstAS)
    
    axes = udp_ts.plot(title=title)
    plt.ylabel('Estimated Mbps')

    plt.savefig('udp_ts.pdf', format='pdf')


def main():

    sport = int(sys.argv[1])
    dstAS = int(sys.argv[2])
    dataset_file = sys.argv[3]

    pickle_file = 'udp_sports_dstas_data.pkl'

    if os.path.isfile(pickle_file):
        print "Loading from pickle file:", pickle_file

        dataset, udp_sports_dstas_data = pickle.load(open(pickle_file,'rb'))

    else:
        print "Pickle file does not exist:", pickle_file
        print "Loading from raw data..."

        dataset = load_raw_data(dataset_file)

        udp_sports_dstas_data = load_srcPort_dstAS_data(dataset)
        pickle.dump((dataset,udp_sports_dstas_data), open(pickle_file,'wb'))

    udp_ts = build_udp_ts(udp_sports_dstas_data, sport, dstAS)
    udp_ts.name = "Mbps"

    anomaly_th = 0.9
    vol_th = 5 # Mbps 
    attack_info = detect_attacks_offline(udp_ts, anomaly_th, vol_th)

    if len(attack_info) > 0:
        print "===================================================="
        print attack_info
        print "===================================================="

        for ts in attack_info.index:
            idx = (dataset['time']==ts) & (dataset['sport']==sport) & (dataset['dstAS']==dstAS)
            src_info = dataset[idx][['srcAS','bytes']] 
            src_info = src_info.sort_values(by=['bytes'],ascending=False)
            print ts, "- srcAS list :"
            print src_info.to_string(index=False)
            print "===================================================="

    else:
        print "No attack found!"

    plot_udp_ts(udp_ts, sport, dstAS)



if __name__ == "__main__":
    main()



