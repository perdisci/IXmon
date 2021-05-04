#!/usr/bin/env python3

""" Anonymizes IXmon's exported stats """

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import sys
import json
import hmac
import struct
from ipaddress import IPv4Address

class IXmonStatsAnonymizer(object):
    """ Anonymizes srcAS, dstAS, srcIP24, dstIP24, and nf_client_addr

    Anonymization algorithm:
    Given a key K (provided by the operator) we first compute h=HMAC(K,field),
    where field is the field to be anonymized (e.g., srcAS). Then, we map
    h back to field's data type (e.g., an integer or IP string representation).

    Arguments
    ---------
    key: Anonymization key (used in HMAC)

    """

    def __init__(self, key):
        self.key = key

    @staticmethod
    def _is_valid_json_msg(msg):
        try:
            json.loads(msg)
        except Exception as e:
            print("INVALID JSON:", e)
            print(msg)
            return False
        return True

    def _anonymize_int(self, integer):
        """ Anonymizes a 32-bit integer """

        h = hmac.new(str.encode(self.key), str.encode(str(integer)))
        anon_int = struct.unpack('<I', h.digest()[:4])[0] & 0x00FFFFFFFF
        return anon_int

    def _anonymize_ip(self, ip):
        """ Anonymizes an IP address """

        ip_int = int(IPv4Address(ip))
        anon_ip_str = str(IPv4Address(self._anonymize_int(ip_int)))
        return anon_ip_str

    def anonymize_ixmon_msg(self, ixmon_msg):
        """ Anonymizes potentially sensitive fields in ixmon messages """

        if not self._is_valid_json_msg(ixmon_msg):
            return None

        ixmon_msg = json.loads(ixmon_msg)

        idx1 = None
        idx2 = None

        if 'as_nfif_stats' in ixmon_msg:
            idx1 = 'as_nfif_stats'
            idx2 = 'as_nfif_pair'
            client_ip = ixmon_msg[idx1][idx2]['nfif_id']['client_ip']
            anon_client = self._anonymize_ip(client_ip)
            ixmon_msg[idx1][idx2]['nfif_id']['client_ip'] = anon_client
        elif 'srcAS_dstAS_stats' in ixmon_msg:
            idx1 = 'srcAS_dstAS_stats'
            idx2 = 'as_as_pair'
            client_ip = ixmon_msg[idx1][idx2]['nf_client_addr']
            anon_client = self._anonymize_ip(client_ip)
            ixmon_msg[idx1][idx2]['nf_client_addr'] = anon_client

        srcAS = ixmon_msg[idx1][idx2]['srcAS']
        dstAS = ixmon_msg[idx1][idx2]['dstAS']
        srcIP24 = ixmon_msg[idx1][idx2]['srcIP24']
        dstIP24 = ixmon_msg[idx1][idx2]['dstIP24']

        anon_srcAS = self._anonymize_int(srcAS)
        anon_dstAS = self._anonymize_int(dstAS)

        anon_srcIP = 0
        if srcIP24 != 0:
            anon_srcIP = self._anonymize_int(srcIP24) & 0xFFFFFF00

        anon_dstIP = 0
        if dstIP24 != 0:
            anon_dstIP = self._anonymize_int(dstIP24) & 0xFFFFFF00

        ixmon_msg[idx1][idx2]['srcAS'] = anon_srcAS
        ixmon_msg[idx1][idx2]['dstAS'] = anon_dstAS
        ixmon_msg[idx1][idx2]['srcIP24'] = anon_srcIP
        ixmon_msg[idx1][idx2]['dstIP24'] = anon_dstIP

        return json.dumps(ixmon_msg)


def main():
    """ Test anonymization of an IXmon export file """

    key = sys.argv[1]
    export_file = sys.argv[2]

    ixanon = IXmonStatsAnonymizer(key)

    with open(export_file, 'r') as f:
        for msg in f.readlines():
            print("------------------------------------")
            if IXmonStatsAnonymizer._is_valid_json_msg(msg):
                print ("msg:", msg)
                anon_msg = ixanon.anonymize_ixmon_msg(msg)
                print("anon_msg:", anon_msg)
            print("------------------------------------")


if __name__ == "__main__":
    main()
