""" Online DRDoS detection """

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import operator
from datetime import datetime

import math
import json
import socket
import struct


class DRDoSDetector:
    """ Detect DRDoS attack in a stream of UDP flows """

    # TODO(Roberto): do not assume a time slot is equal to one minute
    # make the analysis generic, and read time slot duration from
    # ixmon export messages

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

    srcPort_dstAS_sum_buffer = dict()
    curr_sumbuf_time = datetime.strptime('2000-01-01 00:00:00',
                                         '%Y-%m-%d %H:%M:%S')

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        if not alert_callback:
            self.alert_callback = self._alert_reporting

    def _ixmon_msg_to_dict_list(self, ixmon_msg):
        """ Translates an IXmon message into a list of dictionary """

        if not ixmon_msg.strip():
            return []


        if not "srcAS_dstAS_stats" in ixmon_msg:
            return []

        msg_list = []
        ixmon_msg = json.loads(ixmon_msg)

        m = dict()

        time_ts = datetime.fromtimestamp(ixmon_msg['export_time'])
        # remove seconds from timestamp
        # time_str = time_ts.strftime('%Y-%m-%d %H:%M:00'))
        # time = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
        m['time'] = time_ts
        m['srcAS'] = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
        m['srcIP24'] = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
        m['srcIP24str'] = None
        if m['srcIP24'] > 0:
            m['srcIP24str'] = socket.inet_ntoa(struct.pack('!L', int(m['srcIP24'])))
        else:
            m['srcIP24'] = None
        m['dstAS'] = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
        m['dstIP24'] = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
        m['dstIP24str'] = None
        if m['dstIP24'] > 0:
            m['dstIP24str'] = socket.inet_ntoa(struct.pack('!L', int(m['dstIP24'])))
        else:
            m['dstIP24'] = None

        udp_sport_counters = ixmon_msg['srcAS_dstAS_stats']['udp_sport_counters']
        for port_stats in udp_sport_counters:
            if port_stats:
                for p in port_stats:
                    m['sport'] = p
                    m['packets'] = port_stats[p][0]
                    m['bytes'] = port_stats[p][1]
                    m['protocol'] = "udp"
                    msg_list.append(m.copy())

        return msg_list

    def process_ixmon_msgs(self, ixmon_msg_list):

        print("Processing IXmon-exported traffic stats ...")

        for msg in ixmon_msg_list:
            dict_list = self._ixmon_msg_to_dict_list(msg)
            for m in dict_list:
                time = m['time']
                sport = m['sport']
                dstAS = m['dstAS']
                dstIP24 = m['dstIP24str']
                srcAS = m['srcAS']
                srcIP24 = m['srcIP24str']
                num_bytes = m['bytes']
                num_packets = m['packets']

                if math.isnan(float(sport)):
                    sport = 0

                # at the next time slot, call the callback function
                # and reset data structure for aggregating the next slot of stats
                if time > self.curr_sumbuf_time:
                    self._update_traffic_models(time, self.srcPort_dstAS_sum_buffer)
                    self.srcPort_dstAS_sum_buffer = dict()
                    self.curr_sumbuf_time = time
                elif time == self.curr_sumbuf_time:
                    if sport not in self.srcPort_dstAS_sum_buffer:
                        self.srcPort_dstAS_sum_buffer[sport] = dict()
                    if dstAS not in self.srcPort_dstAS_sum_buffer[sport]:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS] = dict()
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['bytes'] = 0
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['packets'] = 0
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes'] = dict()
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['dstIP24_bytes'] = dict()
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcIP24_bytes'] = dict()
                    if srcAS not in \
                       self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes']:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes'][srcAS] = 0
                    if dstIP24 and dstIP24 not in \
                       self.srcPort_dstAS_sum_buffer[sport][dstAS]['dstIP24_bytes']:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['dstIP24_bytes'][dstIP24] = 0
                    if srcIP24 and srcIP24 not in \
                       self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcIP24_bytes']:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcIP24_bytes'][srcIP24] = 0
                    self.srcPort_dstAS_sum_buffer[sport][dstAS]['bytes'] += num_bytes
                    self.srcPort_dstAS_sum_buffer[sport][dstAS]['packets'] += num_packets
                    self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcAS_bytes'][srcAS] += num_bytes
                    if dstIP24:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['dstIP24_bytes'][dstIP24] += num_bytes
                    if srcIP24:
                        self.srcPort_dstAS_sum_buffer[sport][dstAS]['srcIP24_bytes'][srcIP24] += num_bytes

    def _update_traffic_models(self, time, e):
        """ Process one minute of traffic to check if a DRDoS attack is present

        Parameters:
        -----------
        time: a datetime timestamp
        e: an event, which represents a time slot of aggregated UDP traffic stats
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

                alert = None 
                if x > 0 and self.ewm_count >= self._MIN_SAMPLES:
                    # check if there is an attack
                    mean = self.ewm_avg[sport][dstAS]['bytes']
                    std = math.sqrt(self.ewm_var[sport][dstAS]['bytes'])
                    alert = self._detect_dos(time, x, mean, std, sport, dstAS,
                                             e[sport][dstAS]['srcAS_bytes'],
                                             e[sport][dstAS]['dstIP24_bytes'],
                                             e[sport][dstAS]['srcIP24_bytes'])
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

    def _detect_dos(self, time, x, mean, std, sport, dstAS, 
                    srcAS_bytes, dstIP24_bytes, srcIP24_bytes):

        vol_th = 5
        anomaly_th = 0.5
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
            attack['dstIP24_bytes'] = dstIP24_bytes
            attack['srcIP24_bytes'] = srcIP24_bytes

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


    def _alert_reporting(self, attack):

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
