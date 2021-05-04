""" DDoS alert reporting """

# Author: Roberto Perdisci (perdisci@cs.uga.edu)

import json
import operator

class AlertReporting:
    """ Report DDoS alerts 

    Arguments:
    ----------
    export_formats = a list of format, e.g., ['json','email']
    export_file = a file were alerts will be appended

    """

    def __init__(self, export_formats, export_file=None):
        self.export_formats = export_formats
        self.export_file = export_file

    def alert(self, attack):

        srcAS_bytes = attack['srcAS_bytes']
        sorted_srcAS_bytes = \
            sorted(srcAS_bytes.items(), key=operator.itemgetter(1),
                   reverse=True)
        dstIP24_bytes = attack['dstIP24_bytes']
        sorted_dstIP24_bytes = \
            sorted(dstIP24_bytes.items(), key=operator.itemgetter(1),
                   reverse=True)
        srcIP24_bytes = attack['srcIP24_bytes']
        sorted_srcIP24_bytes = \
            sorted(srcIP24_bytes.items(), key=operator.itemgetter(1),
                   reverse=True)

        alert_dict = {
            'attack_type': attack['type'],
            'time': str(attack['time']),
            'volume': attack['volume'],
            'deviation': attack['dev'],
            'sport': int(attack['src_port']),
            'dstAS': int(attack['dstAS']),
            'srcAS_entropy': attack['srcAS_entropy'],
            'srcAS_bytes': sorted_srcAS_bytes,
            'dstIP24_bytes': sorted_dstIP24_bytes,
            'srcIP24_bytes': sorted_srcIP24_bytes
        }

        if 'json' in self.export_formats:
            self._export_json_alert(alert_dict)
        if 'email' in self.export_formats:
            self._export_email_alert(alert_dict)

    def _export_json_alert(self, alert_dict):
        json_alert = json.dumps(alert_dict)
        if self.export_file:
            with open(self.export_file, 'a') as f:
                f.write(json_alert+'\n')

    def _export_email_alert(self, alert_dict):
        # TODO(Roberto): per each target AS there should be one POC email. 
        # We need to read these from a config file...
        pass

