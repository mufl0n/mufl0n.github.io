#!/usr/bin/python3

import subprocess
import json
import re
import base64

SHARED_KEY=73

tshark = subprocess.run(['tshark', '-r', 'capture_file.pcap', '-T', 'json'],
                        capture_output=True, text=True, check=True)
for pkt in json.loads(tshark.stdout):
    if 'http' in pkt['_source']['layers']:
        http = pkt['_source']['layers']['http']
        for req in http.keys():
            req = req.split(' ')
            if req[0] in ['GET', 'POST']:
                print('\033[1;32m'+req[0]+' \033[1;34m'+req[1]+'\033[0m ', end='')
            elif req[0].startswith('HTTP'):
                print('  \033[1;33mOK\033[0m ', end='')
        if 'http.file_data' in http:
            data = http['http.file_data'].replace(':', '')
            data = bytes.fromhex(data).decode('utf-8')
            try:
                data = json.loads(data)
                for key in ['encrypted_command', 'data']:
                    if key in data:
                        data[key] = ''.join(chr(c^SHARED_KEY) for c in base64.b64decode(data[key]))
                print(data)
            except:
                print(data)
