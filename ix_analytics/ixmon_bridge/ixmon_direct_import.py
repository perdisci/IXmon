# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import os
import socket
import struct
import json
import time
import random
import datetime
import inotify.adapters
import inotify.constants
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBServerError

# UDP SOCKET
SERVER_IP = "127.0.0.1"
UDP_PORT = 55555
RCV_BUFFER_SIZE = 1024

# TODO(Roberto): read this from a config file
# INFLUXDB 
IDB_HOST = '127.0.0.1'
IDB_PORT = 8086
IDB_USER = 'ixmon_writer'
IDB_PSW  = 'psw'
IDB_DB   = 'ixmon'
MSG_BATCH = 5000

# TODO(Roberto): read this from a config file
# NF_CLIENT_IPS
nf_clients = ['192.168.0.1']

#IXMON
IXMON_BEGIN_MSG = "==BEGIN=="
IXMON_END_MSG = "==END=="



def is_valid_json_msg(msg):
    try:
        j = json.loads(msg)
    except Exception as e: 
        print "INVALID JSON:", e
        return False
    return True


def get_idb_msg(measurement, tags, fields, time):

    # we use us and ns in the timestamp
    # to store a random nonce that is needed
    # to avoid collision and resulting overwrites
    # on record that share the same combination of tag values
    r = random.randint(0,1E6)
    time = int(time*1E9 + r)

    
    # InfluxDB message
    idb_msg = { 
                "measurement": measurement, 
                "tags"  : tags, 
                "fields": fields,
                "time"  : time
              }

    return idb_msg




################################################################################
def as_nfif_src_insert(msg):

    if not "as_nfif_stats" in msg:
        print "ERROR: as_nfif_stats not in msg!"
        return None

    time = msg['export_time']
    counters = msg['as_nfif_stats']['counters']

    # interface info
    srcID = msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['source_id'] 
    ifID =  msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['interface_id'] 
    client_ip = msg['as_nfif_stats']['as_nfif_pair']['nfif_id']['client_ip']   

    if not client_ip in nf_clients:
        # print "INFO: client_ip not in nf_clients!"
        return None

    srcAS = msg['as_nfif_stats']['as_nfif_pair']['srcAS'] 
    srcIP24 = msg['as_nfif_stats']['as_nfif_pair']['srcIP24']
    srcIP24str = None
    if srcIP24 > 0:
        srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
    else:
        srcIP24 = None
    dstAS = msg['as_nfif_stats']['as_nfif_pair']['dstAS'] 
    dstIP24 = msg['as_nfif_stats']['as_nfif_pair']['dstIP24']
    dstIP24str = None
    if dstIP24 > 0:
        dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
    else:
        dstIP24 = None


    measurement = "AS_NIC_src"

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

    return get_idb_msg(measurement, tags, fields, time)




################################################################################
def as_as_src_insert(msg):

    if not "srcAS_dstAS_stats" in msg:
        return None

    time = msg['export_time']
    counters = msg['srcAS_dstAS_stats']['counters']
    nf_client_addr = msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

    if not nf_client_addr in nf_clients:
        return None

    srcAS = msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
    srcIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
    srcIP24str = None
    if srcIP24 > 0:
        srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
    else:
        srcIP24 = None
    dstAS = msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
    dstIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
    dstIP24str = None
    if dstIP24 > 0:
        dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
    else:
        dstIP24 = None


    measurement = "AS_AS_src"

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

    return get_idb_msg(measurement, tags, fields, time)




################################################################################
def as_as_dst_insert(msg):

    if not "srcAS_dstAS_stats" in msg:
        return None

    time = msg['export_time']
    counters = msg['srcAS_dstAS_stats']['counters']
    nf_client_addr = msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

    if not nf_client_addr in nf_clients:
        return None

    srcAS = msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
    srcIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
    srcIP24str = None
    if srcIP24 > 0:
        srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
    else:
        srcIP24 = None
    dstAS = msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
    dstIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
    dstIP24str = None
    if dstIP24 > 0:
        dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
    else:
        dstIP24 = None

    measurement = "AS_AS_dst"

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

    return get_idb_msg(measurement, tags, fields, time)




################################################################################
def as_as_src_sdports_insert(msg):

    idb_msg_list = []

    if not "srcAS_dstAS_stats" in msg:
        return idb_msg_list


    time = msg['export_time']
    nf_client_addr = msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']

    if not nf_client_addr in nf_clients:
        return None
    
    # only port-specific counters are used in this measurement
    # counters = msg['srcAS_dstAS_stats']['counters']

    srcAS = msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
    srcIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
    srcIP24str = None
    if srcIP24 > 0:
        srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
    else:
        srcIP24 = None
    dstAS = msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
    dstIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
    dstIP24str = None
    if dstIP24 > 0:
        dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
    else:
        dstIP24 = None
    
    # we do not consider tcp_sport as it is less interesting for DDoS detection
    tcp_dport_counters = msg['srcAS_dstAS_stats']['tcp_sport_counters']
    udp_sport_counters = msg['srcAS_dstAS_stats']['udp_sport_counters']
    udp_dport_counters = msg['srcAS_dstAS_stats']['udp_dport_counters']


    measurement = "AS_AS_src_sdports"

    # examle: "tcp_dport_counters": [ {"443": [8, 0, 368]}, {} ]
    for port_stats in tcp_dport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)


    for port_stats in udp_dport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)
    

    for port_stats in udp_sport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)

    return idb_msg_list





################################################################################
def as_as_dst_sdports_insert(msg):

    idb_msg_list = []

    if not "srcAS_dstAS_stats" in msg:
        return idb_msg_list


    time = msg['export_time']
    nf_client_addr = msg['srcAS_dstAS_stats']['as_as_pair']['nf_client_addr']
    
    if not nf_client_addr in nf_clients:
        return None

    # only port-specific counters are used in this measurement
    # counters = msg['srcAS_dstAS_stats']['counters']

    srcAS = msg['srcAS_dstAS_stats']['as_as_pair']['srcAS']
    srcIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['srcIP24']
    srcIP24str = None
    if srcIP24 > 0:
        srcIP24str = socket.inet_ntoa(struct.pack('!L', int(srcIP24)))
    else:
        srcIP24 = None
    dstAS = msg['srcAS_dstAS_stats']['as_as_pair']['dstAS']
    dstIP24 = msg['srcAS_dstAS_stats']['as_as_pair']['dstIP24']
    dstIP24str = None
    if dstIP24 > 0:
        dstIP24str = socket.inet_ntoa(struct.pack('!L', int(dstIP24)))
    else:
        dstIP24 = None
    
    # we do not consider tcp_sport as it is less interesting for DDoS detection
    tcp_dport_counters = msg['srcAS_dstAS_stats']['tcp_sport_counters']
    udp_sport_counters = msg['srcAS_dstAS_stats']['udp_sport_counters']
    udp_dport_counters = msg['srcAS_dstAS_stats']['udp_dport_counters']


    measurement = "AS_AS_dst_sdports"

    # examle: "tcp_dport_counters": [ {"443": [8, 0, 368]}, {} ]
    for port_stats in tcp_dport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)


    for port_stats in udp_dport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)
    

    for port_stats in udp_sport_counters:
        if len(port_stats) > 0:
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

                idb_msg = get_idb_msg(measurement, tags, fields, time)
                idb_msg_list.append(idb_msg)

    return idb_msg_list



def translate_to_influxdb_format(ixmon_msg):

    msg = json.loads(ixmon_msg)

    # print "============================================================"
    # print msg

    idb_msg = []

    if "srcAS_dstAS_stats" in msg:

        m = as_as_src_insert(msg)
        if(m and len(m) > 0):
            idb_msg.append(m)
        # print "as_as_src_insert", m

        m = as_as_dst_insert(msg)
        if(m and len(m) > 0):
            idb_msg.append(m)
        # print "as_as_dst_insert", m

        m = as_as_src_sdports_insert(msg)
        if(m and len(m) > 0):
            idb_msg.extend(m)
        # print "as_as_src_sdports_insert", m

        m = as_as_dst_sdports_insert(msg)
        if(m and len(m) > 0):
            idb_msg.extend(m)
        # print "as_as_dst_sdports_insert", m

    elif "as_nfif_stats" in msg:

        m = as_nfif_src_insert(msg)
        if(m and len(m) > 0):
            idb_msg.append(m)
        # print "as_nfif_src_insert", m

    return idb_msg
        


# TODO(Roberto): build a consumer-producer mechanism
#   to write several ixmon_msg at a time into influxdb
def store_into_influxdb(influxdb_client, ixmon_msg_list):
    print "==> Storing ixmon_msg_list into influxdb:", len(ixmon_msg_list)
    start = datetime.datetime.now()

    idb_msg_list = []
    for m in ixmon_msg_list:
        if is_valid_json_msg(m):
            idb_msg = translate_to_influxdb_format(m)
            idb_msg_list.extend(idb_msg)

    if influxdb_client:
        try:
            # precision is in ns because the us and ns digits are used 
            # to store a random nonce, to avoid same-tag collisions
            # that result in undesired entry overwrites
            influxdb_client.write_points(idb_msg_list,time_precision='n')
        except InfluxDBServerError as e:
            print "===>>> INFLUXDB EXCEPTION: ", e
        except Exception as e:
            print "===>>> INFLUXDB EXCEPTION: Caught INFLUXDB exception wile writing to DB"
            print "Exception:", e
            print "sys.exc_info()[0] =", sys.exc_info()[0]

    end = datetime.datetime.now()
    deltat = (end-start).microseconds / float(1000)
    print "==> Done storing ixmon_msg_list into influxdb:", deltat



def main():


    idbc = InfluxDBClient(IDB_HOST, IDB_PORT, IDB_USER, IDB_PSW, IDB_DB)
    if not idbc:
        print "Unable to connect to influxDB!"
        return

    notify_path = '/data/tmp_test_dir/'
    notify = inotify.adapters.Inotify()
    notify.add_watch(notify_path,inotify.constants.IN_CLOSE_WRITE)

    print "Listening for IXmon export files... " 

    for event in notify.event_gen():
        if event is not None:
            (header, type_names, watch_path, filename) = event
            if not filename.startswith("ixmon-export."):
                continue

            print "Detected new IXmon export file:", filename

            msg_count = 0
            ixmon_msg_list = []

            fn = notify_path+filename
            with open(fn,"r") as f:
                for line in f:
                    ixmon_msg = line.strip()
                    if(msg_count < MSG_BATCH):
                        ixmon_msg_list.append(ixmon_msg)
                        msg_count += 1
                    else:
                        store_into_influxdb(idbc, ixmon_msg_list)
                        msg_count = 0
                        ixmon_msg_list = []
                if msg_count>0:
                    store_into_influxdb(idbc, ixmon_msg_list)
            os.remove(fn)



###############################################################################

def udp_input():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, UDP_PORT))

    idbc = InfluxDBClient(IDB_HOST, IDB_PORT, IDB_USER, IDB_PSW, IDB_DB)

    print "Listening for IXmon messages on %s:%s " % (SERVER_IP,UDP_PORT)

    ixmon_msg_list = []
    while True:
        ixmon_msg, client_addr = sock.recvfrom(RCV_BUFFER_SIZE)
        # print "received message %s: %s" % (client_addr, ixmon_msg)
        if ixmon_msg == IXMON_BEGIN_MSG:
            ixmon_msg_list = []
        elif ixmon_msg == IXMON_END_MSG:
            store_into_influxdb(idbc, ixmon_msg_list)
            ixmon_msg_list = []
        elif is_valid_json_msg(ixmon_msg):
            ixmon_msg_list.append(ixmon_msg)



def test():
    assert is_valid_json_msg("===") is False
    assert is_valid_json_msg('{"foo":1, "bar":2}') is True

    msg = '{ "export_time": 1507860385, "export_timeout": 30, "srcAS_dstAS_stats": { "as_as_pair": { "srcAS": 509, "dstAS": 1005 }, "counters": [ 4, 208, 4, 0, 208, 0, 0, 0, 0 ] } }'
    assert is_valid_json_msg(msg)

    print translate_to_influxdb_format(msg)

    msg = '{ "export_time": 1507860475, "export_timeout": 30, "as_nfif_stats": { "as_nfif_pair": { "asn": 234 , "nfif_id": { "source_id": 5236, "interface_id": 94, "client_ip": "198.162.1.12" } }, "counters": [ 4, 208, 4, 208, 208, 0, 0, 0, 0 ] } }'
    assert is_valid_json_msg(msg)

    print translate_to_influxdb_format(msg)

    print "Passed all tests!"


# test()

main()



