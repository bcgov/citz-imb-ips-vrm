import socket
import os
import os.path
import hashlib
import argparse
import json
import sys

from decouple import config

try:
    client_encoding = config('CLIENT_ENCODING', default='utf-8')
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument('--filename', help="file name", default='')
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

args = parser.parse_args()
buffer_size = args.buffer_size
filename = args.filename

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

def read_in_chunks(file_object, chunk_size=8192):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def main(args):
    if os.path.isfile(filename):
        # make the message
        id, message = jsonrpc2_encode('vrmprocess', {
            "filename": filename
        })
        print (message)

        # connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 5555))

        # send a message
        sock.send(message.encode(client_encoding))
        response = sock.recv(buffer_size)
        jsondata = json.loads(response.decode(client_encoding))
        print (jsondata)

        # read the file
        if jsondata['method'] == "vrmprocess_accept" and jsondata['params']['success'] == True:
            with open(filename, 'rb') as f:
                for chunk in read_in_chunks(f):
                    sock.send(chunk)
                sock.send(b'')

        # close the connection
        sock.close()

    print ("[*] Done")

if __name__== "__main__":
    main(sys.argv)