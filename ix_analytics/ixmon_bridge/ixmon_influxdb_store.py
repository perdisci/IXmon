""" Store IXmon's exported stats into InfluxDB measurements """

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import socket
import struct
import json
import random
import datetime
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBServerError

class InfluxDBStore(object):
    """ Store IXmon's exported stats into InfluxDB

    The reason why we store multiple versions of the same measurement is
    because we need to limit the number of keys per measurement.
    If the key combination is very large, then the number of series stored
    in the DB is very large, which causes query performance degradation.
    See X for more details.

    """

    # TODO(Roberto): read this from a config file
    # INFLUXDB
    IDB_HOST = '127.0.0.1'
    IDB_PORT = 8086
    IDB_USER = 'ixmon_writer'
    IDB_PSW = '1xm0n!'
    IDB_DB = 'ixmon'
    MSG_BATCH = 5000

    # TODO(Roberto): read this from a config file
    # NF_CLIENT_IPS

    # only NetFlow clients in this list are allowed to
    # store flow stats into InfluxDB
    
    ## Update this IP address 
    nf_clients = ['192.168.1.0']

    def __init__(self):
        self.idbc = \
            InfluxDBClient(self.IDB_HOST, self.IDB_PORT,
                           self.IDB_USER, self.IDB_PSW, self.IDB_DB)

    @staticmethod
    def _is_valid_json_msg(msg):
        try:
            json.loads(msg)
        except Exception as e:
            print("INVALID JSON:", e)
            print(msg)
            return False
        return True

    @staticmethod
    def _get_idb_msg(measurement, tags, fields, time):
        """ Prepare measurement to be stored into InfluxDB """

        # we use us and ns in the timestamp
        # to store a random nonce that is needed
        # to avoid collision and resulting overwrites
        # on records that share the same combination of tag values
        r = random.randint(0, 1E6)
        time = int(time*1E9 + r)

        # InfluxDB message
        idb_meas = {
            "measurement": measurement,
            "tags"  : tags,
            "fields": fields,
            "time"  : time
            }

        return idb_meas

    def _as_nfif_src_measurement(self, ixmon_msg):

        if not "as_nfif_stats" in ixmon_msg:
            print("ERROR: as_nfif_stats not in ixmon_msg!")
            return None

        time = ixmon_msg['export_time']
        counters = ixmon_msg['as_nfif_stats']['counters']

        # interface info
        srcID = ixmon_msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['source_id']
        ifID = ixmon_msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['interface_id']
        client_ip = ixmon_msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['client_ip']

        if not client_ip in self.nf_clients:
            # print("INFO: client_ip not in nf_clients!")
            return None

        srcAS = ixmon_msg['as_nfif_stats']['as_nfif_pair']['srcAS']
        srcIP24 = ixmon_msg['as_nfif_stats']['as_nfif_pair']['srcIP24']
        srcIP24str = None
        if srcIP24 > 0:
            srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
        else:
            srcIP24 = None
        dstAS = ixmon_msg['as_nfif_stats']['as_nfif_pair']['dstAS']
        dstIP24 = ixmon_msg['as_nfif_stats']['as_nfif_pair']['dstIP24']
        dstIP24str = None
        if dstIP24 > 0:
            dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
        else:
            dstIP24 = None

        measurement_name = "AS_NIC_src"

        tags = {
            "source_id" : srcID,
            "interface_id": ifID,
            "nf_client_addr": client_ip
            }

        fields = {
            "srcAS": srcAS,
            "srcIP24": srcIP24,
            "srcIP24str": srcIP24str,

            "dstAS": dstAS,
            "dstIP24": dstIP24,
            "dstIP24str": dstIP24str,

            "tot_packets":counters[0],
            "tot_bytes":counters[1],
            "tcp_packets":counters[2],
            "tcp_syn":counters[3],
            "tcp_bytes":counters[4],
            "udp_packets":counters[5],
            "udp_bytes":counters[6],
            "icmp_packets":counters[7],
            "icmp_bytes":counters[8]
            }

        return self._get_idb_msg(measurement_name, tags, fields, time)

    def _as_as_src_measurement(self, ixmon_msg):

        if not "srcAS_dstAS_stats" in ixmon_msg:
            return None

        time = ixmon_msg['export_time']
        counters = ixmon_msg['srcAS_dstAS_stats']['counters']
        nf_client_addr = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

        if not nf_client_addr in self.nf_clients:
            return None

        srcAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
        srcIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
        srcIP24str = None
        if srcIP24 > 0:
            srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
        else:
            srcIP24 = None
        dstAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
        dstIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
        dstIP24str = None
        if dstIP24 > 0:
            dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
        else:
            dstIP24 = None


        measurement_name = "AS_AS_src"

        tags = {
            "srcAS": srcAS,
            "srcIP24": srcIP24,
            "srcIP24str": srcIP24str,
            "nf_client_addr": nf_client_addr
            }

        fields = {
            "dstAS": dstAS,
            "dstIP24": dstIP24,
            "dstIP24str": dstIP24str,

            "tot_packets":counters[0],
            "tot_bytes":counters[1],
            "tcp_packets":counters[2],
            "tcp_syn":counters[3],
            "tcp_bytes":counters[4],
            "udp_packets":counters[5],
            "udp_bytes":counters[6],
            "icmp_packets":counters[7],
            "icmp_bytes":counters[8]
            }

        return self._get_idb_msg(measurement_name, tags, fields, time)

    def _as_as_dst_measurement(self, ixmon_msg):

        if not "srcAS_dstAS_stats" in ixmon_msg:
            return None

        time = ixmon_msg['export_time']
        counters = ixmon_msg['srcAS_dstAS_stats']['counters']
        nf_client_addr = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

        if not nf_client_addr in self.nf_clients:
            return None

        srcAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
        srcIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
        srcIP24str = None
        if srcIP24 > 0:
            srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
        else:
            srcIP24 = None
        dstAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
        dstIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
        dstIP24str = None
        if dstIP24 > 0:
            dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
        else:
            dstIP24 = None

        measurement_name = "AS_AS_dst"

        tags = {
            "dstAS": dstAS,
            "dstIP24": dstIP24,
            "dstIP24str": dstIP24str,
            "nf_client_addr": nf_client_addr
            }

        fields = {
            "srcAS": srcAS,
            "srcIP24": srcIP24,
            "srcIP24str": srcIP24str,

            "tot_packets":counters[0],
            "tot_bytes":counters[1],
            "tcp_packets":counters[2],
            "tcp_syn":counters[3],
            "tcp_bytes":counters[4],
            "udp_packets":counters[5],
            "udp_bytes":counters[6],
            "icmp_packets":counters[7],
            "icmp_bytes":counters[8]
            }

        return self._get_idb_msg(measurement_name, tags, fields, time)

    def _as_as_src_sdports_measurement(self, ixmon_msg):

        idb_msg_list = []

        if not "srcAS_dstAS_stats" in ixmon_msg:
            return idb_msg_list


        time = ixmon_msg['export_time']
        nf_client_addr = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

        if not nf_client_addr in self.nf_clients:
            return None

        # only port-specific counters are used in this measurement
        # counters = ixmon_msg['srcAS_dstAS_stats']['counters']

        srcAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
        srcIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
        srcIP24str = None
        if srcIP24 > 0:
            srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
        else:
            srcIP24 = None
        dstAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
        dstIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
        dstIP24str = None
        if dstIP24 > 0:
            dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
        else:
            dstIP24 = None

        # we do not consider tcp_sport as it is less interesting for DDoS detection
        tcp_dport_counters = ixmon_msg['srcAS_dstAS_stats']['tcp_sport_counters']
        udp_sport_counters = ixmon_msg['srcAS_dstAS_stats']['udp_sport_counters']
        udp_dport_counters = ixmon_msg['srcAS_dstAS_stats']['udp_dport_counters']


        measurement = "AS_AS_src_sdports"

        # examle: "tcp_dport_counters": [ {"443": [8, 0, 368]}, {} ]
        for port_stats in tcp_dport_counters:
            if port_stats:
                for p in port_stats:
                    dport = p
                    packets = port_stats[p][0]
                    syn_packets = port_stats[p][1]
                    bytes_sent = port_stats[p][2]


                    tags = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "tcp",
                        "dport": dport
                        }

                    fields = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,

                        "packets": packets,
                        "syn_packets": syn_packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)


        for port_stats in udp_dport_counters:
            if port_stats:
                for p in port_stats:
                    dport = p
                    packets = port_stats[p][0]
                    bytes_sent = port_stats[p][1]

                    tags = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "udp",
                        "dport": dport
                        }

                    fields = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,

                        "packets": packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)


        for port_stats in udp_sport_counters:
            if port_stats:
                for p in port_stats:
                    sport = p
                    packets = port_stats[p][0]
                    bytes_sent = port_stats[p][1]

                    tags = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "udp",
                        "sport": sport
                        }

                    fields = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,

                        "packets": packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)

        return idb_msg_list

    def _as_as_dst_sdports_measurement(self, ixmon_msg):

        idb_msg_list = []

        if not "srcAS_dstAS_stats" in ixmon_msg:
            return idb_msg_list


        time = ixmon_msg['export_time']
        nf_client_addr = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

        if not nf_client_addr in self.nf_clients:
            return None

        # only port-specific counters are used in this measurement
        # counters = ixmon_msg['srcAS_dstAS_stats']['counters']

        srcAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
        srcIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
        srcIP24str = None
        if srcIP24 > 0:
            srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
        else:
            srcIP24 = None
        dstAS = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
        dstIP24 = ixmon_msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
        dstIP24str = None
        if dstIP24 > 0:
            dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
        else:
            dstIP24 = None

        # we do not consider tcp_sport as it is less interesting for DDoS detection
        tcp_dport_counters = ixmon_msg['srcAS_dstAS_stats']['tcp_sport_counters']
        udp_sport_counters = ixmon_msg['srcAS_dstAS_stats']['udp_sport_counters']
        udp_dport_counters = ixmon_msg['srcAS_dstAS_stats']['udp_dport_counters']


        measurement = "AS_AS_dst_sdports"

        # examle: "tcp_dport_counters": [ {"443": [8, 0, 368]}, {} ]
        for port_stats in tcp_dport_counters:
            if port_stats:
                for p in port_stats:
                    dport = p
                    packets = port_stats[p][0]
                    syn_packets = port_stats[p][1]
                    bytes_sent = port_stats[p][2]


                    tags = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "tcp",
                        "dport": dport
                        }

                    fields = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,

                        "packets": packets,
                        "syn_packets": syn_packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)


        for port_stats in udp_dport_counters:
            if port_stats:
                for p in port_stats:
                    dport = p
                    packets = port_stats[p][0]
                    bytes_sent = port_stats[p][1]

                    tags = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "udp",
                        "dport": dport
                        }

                    fields = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,

                        "packets": packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)

        for port_stats in udp_sport_counters:
            if port_stats:
                for p in port_stats:
                    sport = p
                    packets = port_stats[p][0]
                    bytes_sent = port_stats[p][1]

                    tags = {
                        "dstAS": dstAS,
                        "dstIP24": dstIP24,
                        "dstIP24str": dstIP24str,
                        "nf_client_addr": nf_client_addr,

                        "protocol": "udp",
                        "sport": sport
                        }

                    fields = {
                        "srcAS": srcAS,
                        "srcIP24": srcIP24,
                        "srcIP24str": srcIP24str,

                        "packets": packets,
                        "bytes": bytes_sent
                        }

                    idb_msg = self._get_idb_msg(measurement, tags, fields, time)
                    idb_msg_list.append(idb_msg)

        return idb_msg_list

    def _translate_ixmon_msg_to_influxdb_format(self, ixmon_msg):

        msg = json.loads(ixmon_msg)

        idb_msg = []

        if "srcAS_dstAS_stats" in msg:

            m = self._as_as_src_measurement(msg)
            if m:
                idb_msg.append(m)
            # print("as_as_src_measurement", m)

            m = self._as_as_dst_measurement(msg)
            if m:
                idb_msg.append(m)
            # print("as_as_dst_measurement", m)

            m = self._as_as_src_sdports_measurement(msg)
            if m:
                idb_msg.extend(m)
            # print("as_as_src_sdports_measurement", m)

            m = self._as_as_dst_sdports_measurement(msg)
            if m:
                idb_msg.extend(m)
            # print("as_as_dst_sdports_measurement", m)

        elif "as_nfif_stats" in msg:

            m = self._as_nfif_src_measurement(msg)
            if m:
                idb_msg.append(m)
            # print("as_nfif_src_measurement", m)

        return idb_msg

    # TODO(Roberto): build a consumer-producer mechanism
    #   to write several ixmon_msg at a time into influxdb
    def store_into_influxdb(self, ixmon_msg_list):
        print("==> Storing ixmon_msg_list into influxdb:", len(ixmon_msg_list))
        start = datetime.datetime.now()

        idb_msg_list = []
        for m in ixmon_msg_list:
            # skip empty messages
            m = m.strip()
            if not m:
                continue
            # only process valid json messages message
            if InfluxDBStore._is_valid_json_msg(m):
                idb_msg = self._translate_ixmon_msg_to_influxdb_format(m)
                idb_msg_list.extend(idb_msg)

        if idb_msg_list and self.idbc:
            try:
                # precision is in ns because the us and ns digits are used
                # to store a random nonce, to avoid same-tag collisions
                # that result in undesired entry overwrites
                self.idbc.write_points(idb_msg_list, time_precision='n')
            except InfluxDBServerError as e:
                print("===>>> INFLUXDB EXCEPTION: ", e)
            except Exception as e:
                print("===>>> INFLUXDB EXCEPTION: "
                      "Caught INFLUXDB exception wile writing to DB")
                print("Exception:", e)
                print("sys.exc_info()[0] =", sys.exc_info()[0])

        end = datetime.datetime.now()
        deltat = (end-start).microseconds / float(1000)
        print("==> Done storing ixmon_msg_list into influxdb:", deltat)
        sys.stdout.flush()
