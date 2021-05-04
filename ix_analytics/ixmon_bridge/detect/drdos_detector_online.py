#!/usr/bin/env python3

""" Online DRDoS detection """

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import operator
from datetime import datetime

import math
import pandas as pd


class UDPDataStream:
    """ Reads a stream of UDP flow stats and aggregates them per minute

    Parameters:
    -----------
    raw_data_csv_file: a gzipped csv file containing the raw UDP flow stats
        exported from influxDB
    callback: a callback function to be called every minute, once the 
        per-minute stats have been aggregated. If None, callback should
        be registered using register_callback()
    """


    def __init__(self, raw_data_csv_file, callback=None):
        self.raw_data = self._load_raw_data(raw_data_csv_file)
        self.callback = callback

    def _load_raw_data(self, csv_file, compression='gzip'):

        print("Reading raw udp data from ", csv_file)

        raw_data = pd.read_csv(csv_file, compression=compression)
        del raw_data['name']
        idx = raw_data['time']
        raw_data['time'] = [datetime.fromtimestamp(t) for t in raw_data['time']]
        
        # remove seconds form timestamps
        # since they only have minute granularity
        # TODO(Roberto): find a better way to do this, than 
        # converting to string and back to datetime
        idx = raw_data['time']
        raw_data['time'] = idx.map(lambda t: t.strftime('%Y-%m-%d %H:%M:00'))
        idx = raw_data['time']
        raw_data['time'] = \
            idx.map(lambda t: datetime.strptime(t, '%Y-%m-%d %H:%M:%S'))

        # print raw_data
        return raw_data

    def register_callback(self, callback):
        self.callback = callback

    def process_raw_data(self):
        
        print("Processing raw UDP data ...") 

        srcPort_dstAS_sum_buffer = dict()
        curr_sumbuf_time = datetime.strptime('2000-01-01 00:00:00', 
                                             '%Y-%m-%d %H:%M:%S')

        for idx, e in self.raw_data.iterrows():

            time = e['time']
            sport = e['sport']
            dstAS = e['dstAS']
            srcAS = e['srcAS']
            num_bytes = e['bytes']
            num_packets = e['packets']

            if math.isnan(sport):
                sport = 0
            
            # at the next minute, call the callback function
            # and reset data structure for aggregating the next minute of stats
            if time > curr_sumbuf_time:
                self.callback(time, srcPort_dstAS_sum_buffer)
                srcPort_dstAS_sum_buffer = dict()
                curr_sumbuf_time = time
            elif time == curr_sumbuf_time:
                if sport not in srcPort_dstAS_sum_buffer:
                    srcPort_dstAS_sum_buffer[sport] = dict()
                if dstAS not in srcPort_dstAS_sum_buffer[sport]:
                    srcPort_dstAS_sum_buffer[sport][dstAS] = dict()
                    srcPort_dstAS_sum_buffer[sport][dstAS]['bytes'] = 0
                    srcPort_dstAS_sum_buffer[sport][dstAS]['packets'] = 0
                    srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes'] = \
                        dict()
                if srcAS not in \
                   srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes']:
                    srcPort_dstAS_sum_buffer[sport][dstAS]\
                        ['srcAS_bytes'][srcAS] = 0
                srcPort_dstAS_sum_buffer[sport][dstAS]['bytes'] += num_bytes
                srcPort_dstAS_sum_buffer[sport][dstAS]['packets'] += num_packets
                srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes'][srcAS] += num_bytes


class DRDoSDetector:
    """ Detect DRDoS attack in a stream of UDP flows """

    _ALPHA = 0.01
    _MIN_SAMPLES = 30

    _EPSILON = 1E-6
    _SCALING = 1E6*60/8 # scales from bytes/minute to Mbps

    ewm_avg = dict()
    ewm_var = dict()
    # ewm_count counts how many periods we have observed
    # we need to observe at least a minimum number of periods, 
    # before detection
    ewm_count = 0
    stream_last_time = 0


    def __init__(self, alert_callback):
        self.alert_callback = alert_callback

    def stream_callback(self, time, e):
        """ Process one minute of traffic to check if a DRDoS attack is present
        
        Parameters:
        -----------
        time: a datetime timestamp
        e: an event, which represents a minute of aggregated UDP traffic stats
        """

        #shortening name for convenience
        alpha = self._ALPHA

        # update the number of observed measurements
        self.ewm_count += 1

        # add new events to ewm dictionaries
        for sport in e:
            if sport not in self.ewm_avg:
                self.ewm_avg[sport] = dict()
                self.ewm_var[sport] = dict()
            for dstAS in e[sport]:
                if dstAS not in self.ewm_avg[sport]:
                    self.ewm_avg[sport][dstAS] = dict()
                    self.ewm_var[sport][dstAS] = dict()
                    self.ewm_avg[sport][dstAS]['bytes'] = 0
                    self.ewm_var[sport][dstAS]['bytes'] = 0

        for sport in self.ewm_avg:
            for dstAS in self.ewm_avg[sport]:

                if sport not in e or dstAS not in e[sport]:
                    x = 0
                else:
                    x = e[sport][dstAS]['bytes']/float(self._SCALING)
        
                alert = False
                if x > 0 and self.ewm_count >= self._MIN_SAMPLES:
                    # check if there is an attack
                    mean = self.ewm_avg[sport][dstAS]['bytes']
                    std = math.sqrt(self.ewm_var[sport][dstAS]['bytes'])
                    alert = self._detect_dos(time, x, mean, std, sport, dstAS, 
                                             e[sport][dstAS]['srcAS_bytes'])
                    if alert:
                        self.alert_callback(alert)

                # update moving average only if no attack is present
                # this will allow us to detect both when the attack
                # starts and when it finishes
                # during a sustained attack, this will also cause an
                # alert to be issued at every time slot
                if not alert:
                    # update moving average
                    ewma_t0 = self.ewm_avg[sport][dstAS]['bytes']
                    ewma_t1 = alpha*x+(1-alpha)*ewma_t0
                    self.ewm_avg[sport][dstAS]['bytes'] = ewma_t1

                    # update moving variance
                    # see http://people.ds.cam.ac.uk/\
                    # fanf2/hermes/doc/antiforgery/stats.pdf
                    mean = ewma_t0
                    diff = x - mean
                    var_t0 = self.ewm_var[sport][dstAS]['bytes']
                    var_t1 = (1-alpha) * (var_t0 + alpha*diff*diff)
                    self.ewm_var[sport][dstAS]['bytes'] = var_t1


    def _detect_dos(self, time, x, mean, std, sport, dstAS, srcAS_bytes):

        vol_th = 5
        anomaly_th = 0.9
        theta = 3
        srcAS_entropy_th = 0.4

        srcAS_entropy = self._srcAS_entropy(srcAS_bytes)
        dev = (x - (mean + theta * std))/(x+self._EPSILON)
        dev = max(0, dev)

        attack = None
        if x > vol_th and dev > anomaly_th:
            attack = dict()
            if srcAS_entropy > srcAS_entropy_th:
                attack['type'] = 'DRDoS'
            else:
                attack['type'] = 'Anomaly'
            sorted_srcAS_bytes = \
                sorted(srcAS_bytes.items(), key=operator.itemgetter(1), 
                       reverse=True)

            attack['vol_th'] = vol_th
            attack['anomaly_th'] = anomaly_th
            attack['dev_std_mult_factor'] = theta
            attack['srcAS_entropy_th'] = srcAS_entropy_th

            attack['time'] = time
            attack['volume'] = x
            attack['mean'] = mean
            attack['std'] = std
            attack['dev'] = dev
            attack['dstAS'] = dstAS
            attack['src_port'] = sport
            attack['srcAS_entropy'] = srcAS_entropy
            attack['srcAS_bytes'] = srcAS_bytes

        return attack
            

    def _srcAS_entropy(self, srcAS_bytes):
        
        tot_bytes = 0
        for s in srcAS_bytes:
            tot_bytes += srcAS_bytes[s]

        # normalize values and compute entropy
        entropy = 0.0

        if len(srcAS_bytes) <= 1:
            return entropy

        for s in srcAS_bytes:
            p = srcAS_bytes[s]/float(tot_bytes)
            entropy += -p * math.log(p, 2) 
        
        # normalize entropy
        entropy /= math.log(len(srcAS_bytes), 2)
        # assert(entropy <= 1.0)

        return entropy


def alert_reporting(attack):
        
        attack_type = attack['type']
        time = attack['time']
        volume = attack['volume']
        deviation = attack['dev']
        sport = int(attack['src_port'])
        dstAS = int(attack['dstAS'])
        srcAS_entropy = attack['srcAS_entropy']
        srcAS_bytes = attack['srcAS_bytes']

        print("====================")
        if attack_type == 'DRDoS':
            print("=== DRDoS ATTACK ===")
        elif attack_type == 'Anomaly':
            print("====== ANOMALY =====")
        print("time: %s\n"
              "srcPort: %s\n"
              "dstAS: %s\n"
              "volume (Mbps): %s\n"
              "deviation: %s\n"
              "srcAS_ent: %s\n" % 
              (time, sport, dstAS, volume, deviation, srcAS_entropy))
        sorted_srcAS_bytes = \
            sorted(srcAS_bytes.items(), key=operator.itemgetter(1), 
                   reverse=True)
        print("srcASes: ", sorted_srcAS_bytes)
        print("====================")


def print_usage():
    print("Usage:", sys.argv[0], "influxdb_export.csv.gz")

def main():

    if len(sys.argv) < 2:
        print_usage()
        return

    # expects a csv.gz file exported from InfluxDB using the following query:
    # SELECT * FROM AS_AS_dst_sdports 
    # WHERE protocol='udp' AND time>=$D2 AND time<$D2
    dataset_file = sys.argv[1]

    stream = UDPDataStream(dataset_file)
    detector = DRDoSDetector(alert_reporting)
    stream.register_callback(detector.stream_callback)
    stream.process_raw_data()

if __name__ == "__main__":
    main()

