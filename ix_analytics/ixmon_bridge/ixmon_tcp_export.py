#!/usr/bin/env python3
"""
Script to export ixmon traffic stats over TCP.
This is going to be particularly useful when, to isolate access to raw flows,
ixmon and ix_analytics run on two different machines
"""

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import os
import socket
import inotify.adapters
import inotify.constants
from ixmon_export_anonymizer import IXmonStatsAnonymizer

import time

# send at most this many messages in one TCP connection
MSG_BATCH = 5000

REMOVE_TMP_FILE = True

class TCPSocket(object):
    """ Very simple TCP client that sends a batch of data and
    then automatically closes the connection. 
    """

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def send(self, msg):
        """ Connects to the server, sends msg, and closes the connection """

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        tot_sent = 0
        while tot_sent < len(msg):
            sent = sock.send(msg[tot_sent:])
            if sent == 0:
                raise RuntimeError("TCP send error!")
            tot_sent += sent
        sock.close()
        return tot_sent

def tcp_export(serv_ip, serv_port, msg_list, anonym_key=None):

    anonymizer = None
    if anonym_key:
        anonymizer = IXmonStatsAnonymizer(anonym_key)

    try:
        tcp_sock = TCPSocket(serv_ip, serv_port)
        msg_str = ''
        for m in msg_list:
            if anonymizer:
                m = anonymizer.anonymize_ixmon_msg(m)
            msg_str += m+'\n'
        msg_bytes = str.encode(msg_str)
        tcp_sock.send(msg_bytes)
        print("Sent", len(msg_bytes), "bytes")
    except Exception as e:
        print("TCP socket error:", e)

def print_usage():
    print("Usage:", sys.argv[0], "serv_ip serv_port ixmon_exports_dir [anonym_key]")
    print("Example:", sys.argv[0], "127.0.0.1 55555 /tmp/ixmon-exports/")

def main():
    """ IXmon aggregate stats are ready from tmp files and exported
    via TCP to a separate machine.
    """

    if len(sys.argv) < 4:
        print_usage()
        return

    serv_ip = sys.argv[1]
    serv_port = int(sys.argv[2])

    # dir where export files will be dropped
    notify_path = sys.argv[3]

    anonym_key = None
    if len(sys.argv) > 4:
        anonym_key = sys.argv[4]

    notify = inotify.adapters.Inotify()
    notify.add_watch(notify_path, inotify.constants.IN_CLOSE_WRITE)

    print("Listening for IXmon export files... ")

    for event in notify.event_gen():
        if event is not None:
            (header, type_names, watch_path, filename) = event
            if not 'ixmon-export' in filename:
                continue

            print("Detected new IXmon export file:", filename)

            msg_count = 0
            ixmon_msg_list = []

            fn = os.path.join(watch_path, filename)
            with open(fn, 'r') as f:
                for line in f:
                    ixmon_msg = line.strip()
                    if msg_count < MSG_BATCH:
                        ixmon_msg_list.append(ixmon_msg)
                        msg_count += 1
                    else:
                        tcp_export(serv_ip, serv_port, 
                                   ixmon_msg_list, anonym_key)
                        msg_count = 0
                        ixmon_msg_list = []
                if msg_count > 0:
                    tcp_export(serv_ip, serv_port, 
                               ixmon_msg_list, anonym_key)
    
            if REMOVE_TMP_FILE:
                os.remove(fn)
            else:
                new_fn = os.path.join(watch_path, 
                                      "archive/"+str(int(time.time()))+"_"+filename)
                os.rename(fn, new_fn)

if __name__ == "__main__":
    main()

