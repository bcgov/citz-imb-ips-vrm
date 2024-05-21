import os
import os.path
import hashlib
import argparse
import json
import sys
from datetime import datetime
import requests

from decouple import config

try:
    remote_url = config('REMOTE_URL', default='http://localhost:5555')
    client_encoding = config('CLIENT_ENCODING', default='utf-8')
except KeyboardInterrupt:
    # Handle the KeyboardInterrupt exception gracefully.
    # Log a message indicating that the user has requested an interrupt.
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument('--filename', help="Specify the file name to process. Default is an empty string.", default='')
parser.add_argument('--source', help="Specify the data source, e.g., 'tenable'. Default is an empty string.", default='')
parser.add_argument('--buffer_size', help="Specify the buffer size for processing data. Default is 8192 bytes.", default=8192, type=int)

args = parser.parse_args()
buffer_size = args.buffer_size
filename = args.filename
source = args.source

def jsonrpc2_create_id(data):
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()

def jsonrpc2_encode(method, params = None):
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    id = jsonrpc2_create_id(data)
    data['id'] = id
    return (id, json.dumps(data))

def main(args):
    if filename and os.path.isfile(filename):
        data = {
            'method': 'vrmprocess'
        }
        files = {
            'file': open(filename, 'rb')
        }
        
        response = requests.post(remote_url + '/upload', data=data, files=files)
        print (response.text)

    elif source and source == "tenable":

        _, message = jsonrpc2_encode('vrmprocess', {
            "source": source,
        })

        response = requests.post(remote_url + '/jsonrpc2', data=message, headers={'Content-type': 'application/json'})
        print (response.text)

    print("[*] Done")

if __name__== "__main__":
    main(sys.argv)