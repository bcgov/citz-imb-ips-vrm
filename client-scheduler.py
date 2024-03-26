import socket
import os
import os.path
import hashlib
import argparse
import json
import sys
import logging
from datetime import datetime

from decouple import config

# Creating log file name based on current date
log_filename = datetime.now().strftime("./logs/client/%Y-%m-%d.txt")

# Logging configuration
logging.basicConfig(filename=log_filename, level=logging.DEBUG, 
                    format="[ %(asctime)s | %(levelname)s ] %(message)s", 
                    datefmt="%Y-%m-%d %H:%M:%S")

logger = logging.getLogger()

try:
    # Attempt to retrieve the client encoding from configuration, defaulting to 'utf-8' if not specified.
    client_encoding = config('CLIENT_ENCODING', default='utf-8')
except KeyboardInterrupt:
    # Handle the KeyboardInterrupt exception gracefully.
    # Log a message indicating that the user has requested an interrupt.
    logger.info("\n[*] User has requested an interrupt")
    logger.info("[*] Application Exiting.....")
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
    """
    Creates a unique identifier for JSON-RPC 2.0 requests based on the provided data.

    Parameters:
        data (dict): Data to be encoded into the JSON-RPC request.

    Returns:
        str: A unique identifier generated using SHA-1 hash algorithm.
    """
    return hashlib.sha1(json.dumps(data).encode(client_encoding)).hexdigest()

def jsonrpc2_encode(method, params = None):
    """
    Encodes the provided method and parameters into a JSON-RPC 2.0 request.

    Parameters:
        method (str): The method to be invoked on the server.
        params (dict): Optional parameters to be passed to the method.

    Returns:
        tuple: A tuple containing the request ID and the encoded JSON-RPC request.
    """
    data = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params
    }
    id = jsonrpc2_create_id(data)
    data['id'] = id
    return (id, json.dumps(data))

def read_in_chunks(file_object, chunk_size=8192):
    """
    Generator function to read a file in chunks of specified size.

    Parameters:
        file_object (file): The file object to read from.
        chunk_size (int): The size of each chunk in bytes. Defaults to 8192 bytes.

    Yields:
        bytes: Data read from the file in chunks.
    """
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

def main(args):
    
    # Check if filename is provided and it corresponds to an existing file.
    # If both conditions are met, proceed with the file processing logic.
    # This ensures that the file processing operation occurs only when a valid filename is provided.
    if filename and os.path.isfile(filename):
        # make the message
        id, message = jsonrpc2_encode('vrmprocess', {
            "filename": filename,
        })
        logger.info (message)

        # connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 5555))

        # send a message
        sock.send(message.encode(client_encoding))
        response = sock.recv(buffer_size)
        jsondata = json.loads(response.decode(client_encoding))
        logger.info (jsondata)

        # read the file and send to server if accepted
        if jsondata['method'] == "vrmprocess_accept" and jsondata['params']['success'] == True:
            with open(filename, 'rb') as f:
                for chunk in read_in_chunks(f):
                    sock.send(chunk)
                sock.send(b'')

        # close the connection
        sock.close()

    # Check if the source parameter is provided and it equals "tenable".
    # If both conditions are satisfied, proceed with handling the data from the Tenable.io API.
    # This ensures that the Tenable.io API data processing logic is executed when the source is specified as "tenable".
    elif source and source == "tenable":
        # make the message
        id, message = jsonrpc2_encode('vrmprocess', {
            "source": source,
        })
        logger.info (message)

        # connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 5555))

        # send a message
        sock.send(message.encode(client_encoding))
        response = sock.recv(buffer_size)
        jsondata = json.loads(response.decode(client_encoding))
        logger.info (jsondata)

        # close the connection
        sock.close()

    logger.info ("[*] Done")

if __name__== "__main__":
    main(sys.argv)