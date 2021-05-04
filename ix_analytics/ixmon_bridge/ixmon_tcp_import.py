#!/usr/bin/env python3
"""
Script to import ixmon traffic stats over TCP.
This is going to be particularly useful when, to isolate access to raw flows,
ixmon and ix_analytics run on two different machines
"""

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import socket
from ixmon_influxdb_store import InfluxDBStore
from drdos_detector import DRDoSDetector
from alert_reporting import AlertReporting

class TCPServer(object):
    """ Very simple TCP server that handles only one client and one connection
    at a time.

    Parameters:
    -----------
    serv_port = TCP port on which to listen for ixmon export messages
    recv_callbacks_list = list of callback functions to be called at every
        batch of messages received from ixmon. The listed functions are
        called sequentially (in the same order as they appear in the list)

    """

    _SERV_LISTEN_BUFF = 5
    _RCV_BUFFER_SIZE = 1024

    def __init__(self, serv_port, recv_callbacks_list):
        self.port = serv_port
        self.recv_callbacks_list = recv_callbacks_list

        self.serv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serv_socket.bind(('', self.port))
        self.serv_socket.listen(self._SERV_LISTEN_BUFF)

    def start(self):
        while True:
            (client_sock, address) = self.serv_socket.accept()
            msg_bytes = self._recv(client_sock)
            msg_list = msg_bytes.decode('utf-8').split('\n')
            print("Received", len(msg_list), "messages", 
                  "(", len(msg_bytes), "bytes ) from", address)
            for callback in self.recv_callbacks_list:
                callback(msg_list)
            
    def _recv(self, client_sock):
        """ Reads from a client until the client closes the connection """

        msg_list = []
        bytes_read = 0
        while True:
            msg = client_sock.recv(self._RCV_BUFFER_SIZE)
            if not msg:
                break
            bytes_read = bytes_read + len(msg)
            msg_list.append(msg)
        return b''.join(msg_list)


def test_recv_from_ixmon(msg_list):
    print(msg_list)

def print_usage():
    print("Usage:", sys.argv[0], "serv_port")
    print("Example:", sys.argv[0], "55555")

def main():

    if len(sys.argv) < 2:
        print_usage()
        return

    serv_port = int(sys.argv[1])

    print("Listening for IXmon TCP exports on port", serv_port)
   
    alert_export = AlertReporting(['json'], './drdos_alerts.json')
    alert_callback = alert_export.alert 
    drdos = DRDoSDetector(alert_callback)
    dbstore = InfluxDBStore()
    # server = TCPServer(serv_port, test_recv_from_ixmon)
    server = TCPServer(serv_port, 
                       [drdos.process_ixmon_msgs, dbstore.store_into_influxdb])
    server.start()


if __name__ == "__main__":
    main()

