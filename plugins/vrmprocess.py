import datetime
import time
import pandas as pd
import json
import requests
import psycopg2
import pytz
import datetime
from requests.auth import HTTPBasicAuth
from decouple import config
from server import Extension, jsonrpc2_result_encode

try: 
    # Attempt to retrieve configuration values from environment variables
    JIRA_API_URL = config("JIRA_API_URL")
    JIRA_API_SEARCH_URL = config("JIRA_API_SEARCH_URL")
    JIRA_API_EDIT_URL = config("JIRA_API_EDIT_URL")
    JIRA_API_USERNAME = config("JIRA_API_USERNAME")
    JIRA_API_KEY = config("JIRA_API_KEY")
    PG_HOST = config("PG_HOST")
    PG_DBNAME = config("PG_DBNAME")
    PG_USER = config("PG_USER")
    PG_PASSWORD = config("PG_PASSWORD")
    PG_PORT = config("PG_PORT", default=5432, cast=int)
    TENABLE_APIKEY = config("TENABLE_API_KEY", default='')
    client_encoding = config("CLIENT_ENCODING", default='utf-8')
except Exception as e:
    # Handle exceptions raised during configuration retrieval
    print ("[*] Exception: %s" % (str(e)))

# Set up JIRA authentication and headers
JIRA_AUTH = HTTPBasicAuth(JIRA_API_USERNAME, JIRA_API_KEY)
JIRA_API_HEADER = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

class VRMProcess(Extension):
    """
    Class for handling VRM (Vulnerability Risk Management) process.

    This class extends the Extension class and provides methods for processing
    files related to VRM, such as Excel and JSON files containing vulnerability
    data. It includes functionality to dispatch incoming data for processing,
    saving assets, resolving IP addresses, creating and editing parent & subtask tickets.

    """
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "vrmprocess"
        self.pg_connection = psycopg2.connect(host=PG_HOST, dbname=PG_DBNAME, user=PG_USER, password=PG_PASSWORD, port=PG_PORT)

    # Dispatches the incoming data for processing.
    def dispatch(self, type, id, params, conn):
        result = {}

        if 'filename' in params:
            # Send acceptance response
            Extension.send_accept(conn, self.method, True)

            # Get file data
            data = Extension.readall(conn)
            now = datetime.now().strftime("%Y%m%d%H%M%S")
            received_filename = params['filename']
            received_filetype = received_filename.split('.')[-1]
            out_filename = "./data/%s.%s" % (now, received_filetype)

            # Save file locally
            print ("[*] writing the file: ", out_filename)
            with open(out_filename, 'wb') as f:
                f.write(data)

            print ("[*] processing the file: ", out_filename)
            if received_filetype == "xlsx":
                assets = self.process_asset_file(out_filename)
                result = self.save_assets(assets)
            elif received_filetype == "json":
                tickets = self.process_json_file(out_filename)
            print ("[*] save done")
        
        elif 'source' in params and params['source'] == 'tenable':
            export_uuid = self.request_export_uuid_from_tenable()
            filename=None

            if export_uuid:
                print ("Queued. export_uuid: %s" % (export_uuid))
                status = None
                finished_chunks = 0
                while status != "FINISHED":
                    print ("Not finished. Please wait...")
                    _status, _finished_chunks = self.get_status_by_export_uuid_from_tenable(export_uuid)
                    status = _status
                    finished_chunks = _finished_chunks
                    time.sleep(3)
                print ("Finished. Trying download %s chunks..." % (str(finished_chunks)))

                if finished_chunks > 0:
                    for chunk_id in range(1, finished_chunks + 1):
                        print ("Downloading the chunk %s..." % (str(chunk_id)))
                        filename = self.download_exported_data_from_tenable(export_uuid, chunk_id)
                print ("Done.")
                print("filename : ",filename)
                tickets = self.process_api_json_file(filename)
                print ("[*] api data save done")



        return jsonrpc2_result_encode(result, id)

    # Resolve reverse IP address to obtain asset information.
    def resolve_reverse_ip(self, ip_address):
        cur = self.pg_connection.cursor()
        cur.execute('select id, client_name, vip_members, ip_address, customer_contact, technical_contact from asset where ip_address = %s limit 1', (ip_address,))
        row = cur.fetchone()

        fieldnames = ['id', 'client_name', 'vip_members', 'ip_address', 'customer_contact', 'technical_contact']
        if row:
            asset = dict(zip(fieldnames, row))
        else:
            asset = dict(zip(fieldnames, [None, "Unknown Host", '', '', '', '']))

        return asset

    # Save asset information to the database.
    def save_assets(self, assets):
        for asset in assets:
            # save the asset
            values = (
                # the `id` is auto_increment
                asset['client_name'],
                asset['vip_members'],
                asset['ip_address'],
                asset['customer_contact'],
                asset['technical_contact']
            )
            cur = self.pg_connection.cursor()
            cur.execute(
                "INSERT INTO asset(client_name, vip_members, ip_address, customer_contact, technical_contact) values(%s, %s, %s, %s, %s)",
                values
            )

        # commit all changes
        self.pg_connection.commit()

        return {
            "success": True
        }
    
    # Process an Excel file containing asset information.
    def process_asset_file(self, file_path):
        # Read data from the Excel file
        df = pd.read_excel(file_path)

        # Extract necessary columns
        extracted_data = df[["Client CI Name", "VIP Members", "TXTIPADDRESS", "Customer Contact", "Technical Contact"]]

        # Create a list to store the processed data
        assets = []

        # Iterate over each row in the extracted data
        for index, row in extracted_data.iterrows():
            client_name = row["Client CI Name"]
            vip_members = row["VIP Members"]
            ip_address = row["TXTIPADDRESS"]
            customer_contact = row["Customer Contact"]
            technical_contact = row["Technical Contact"]

            print('index: ', index)
            print('client_name: ', client_name)
            print('vip_members: ', vip_members)
            print('ip_address: ', ip_address)
            print('customer_contact: ', customer_contact)
            print('technical_contact: ', technical_contact)

            # Create a dictionary for each asset
            asset = {
                'client_name': client_name,
                'vip_members': vip_members,
                'ip_address': ip_address,
                'customer_contact': customer_contact,
                'technical_contact': technical_contact
            }

            # Append the asset dictionary to the assets list
            assets.append(asset)

        return assets

    # Parse a JSON file containing vulnerability data. 
    # Create JIRA API tickets for each entry.
    def process_json_file(self, file_path):
        # Load JSON data from the file
        jsondata = []
        with open(file_path, 'r') as file:
            jsondata = json.load(file)

        tickets = []
        for entry in jsondata:
            # Initialize parent ticket key and ticket object
            parent_ticket_key = None
            ticket = {}

            # Extract data from JSON entry
            output = entry.get("output")
            severity = entry.get("severity")
            state = entry.get("state")
            name = entry.get("definition", {}).get("name") 
            solution = entry.get("definition", {}).get("solution") 
            description = entry.get("definition", {}).get("description") 
            synopsys = entry.get("definition", {}).get("synopsis")
            plugin_id = entry.get("definition", {}).get("id")
            ip_address = entry.get("asset", {}).get("display_ipv4_address") 
            first_seen = entry.get("first_observed")
            last_seen = entry.get("last_seen")
            cvssv2_score = entry.get("definition", {}).get("cvss2", {}).get("base_score")
            cvssv3_score = entry.get("definition", {}).get("cvss3", {}).get("base_score")
            vpr_score = entry.get("definition", {}).get("vpr", {}).get("score")
            asset_id = entry.get("asset", {}).get("id")
            vulnerability_id = entry.get("id")

            # Resolve asset details using IP address
            asset = self.resolve_reverse_ip(ip_address)
            
            # Check if parent ticket exists using client name
            parent_ticket_key = self.get_parent_ticket_key(asset['client_name'])

            # Map data to ticket object    
            ticket = {
                'client_name': asset['client_name'],
                'name': name,
                'ip_address': ip_address,
                'description': description,
                'synopsys': synopsys,
                'solution': solution,
                'output': output,
                'plugin_id': plugin_id,
                'state': state,
                'severity': severity,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'cvssv2_score': cvssv2_score,
                'cvssv3_score': cvssv3_score,
                'vpr_score': vpr_score,
                'asset_id': asset_id,
                'vulnerability_id': vulnerability_id,
            }

            # Create parent ticket if it doesn't exist
            if not parent_ticket_key:
                parent_ticket_key = self.create_parent_ticket(asset) 
                
            # Check for sub-task ticket
            subtask_ticket_key= self.get_sub_ticket_key(vulnerability_id)

            # Create sub-task ticket if it doesn't exist, otherwise edit existing sub-task ticket
            if not subtask_ticket_key:
                created_subtask_ticket_key = self.create_subtask_ticket(ticket, parent_ticket_key)
            else: 
                subtask_ticket_key = self.edit_subtask_ticket(ticket, parent_ticket_key, subtask_ticket_key)
            
            # Add extracted values to ticket_data dictionary
            tickets.append({
                "output": output,
                "description": description,
                "severity": severity,
                "ip_address": ip_address,
                "state": state,
                "name": name,
                "solution": solution,
                "parent_ticket_key": parent_ticket_key
            })

        return tickets
    
    # Retrieve the key of the parent ticket associated with the given hostname.
    def get_parent_ticket_key(self, hostname):
        ticket_key = None

        # JQL query to search for tickets with hostname field containing an empty string across all projects
        jql_query =  f'cf[10234] ~ "{hostname}"'

        # Define the payload for the POST request (containing the JQL query)
        payload = {
            "jql": jql_query,
            "fields": ["key", "summary"]  # Optional: specify fields to retrieve
        }
        
        # Send POST request to execute the JQL query and retrieve matching issues
        response = requests.post(JIRA_API_SEARCH_URL, json=payload, auth=JIRA_AUTH)

        # Check if the request was successful (status code 200)
        if response.status_code == 200 and response.json().get('issues'):
            # Get the key of the first issue
            ticket_key = response.json()['issues'][0]['key']
            print('ticket key : ',ticket_key)
        else:
            # Handle other error cases
            print(f"Error: {response.status_code} - {response.text}")

        return ticket_key
    
    # Retrieve the key of the sub-task ticket associated with the given vulnerability ID.
    def get_sub_ticket_key(self, vulnerability_id):

        ticket_key = None

        # JQL query to search for tickets with hostname field containing an empty string across all projects
        jql_query =  f'cf[10201] ~ "{vulnerability_id}"'

        # Define the payload for the POST request (containing the JQL query)
        payload = {
            "jql": jql_query,
            "fields": ["key", "summary"]  # Optional: specify fields to retrieve
        }
        
        # Send POST request to execute the JQL query and retrieve matching issues
        response = requests.post(JIRA_API_SEARCH_URL, json=payload, auth=JIRA_AUTH)

        # Check if the request was successful (status code 200)
        if response.status_code == 200 and response.json().get('issues'):
            # Get the key of the first issue
            ticket_key = response.json()['issues'][0]['key']
        else:
            # Handle other error cases
            print(f"Error: {response.status_code} - {response.text}")

        return ticket_key    
    
        # Retrieve the key of the sub-task ticket associated with the given vulnerability ID.
    def find_sub_ticket_key_with_pluginID(self, plugin_id, ip_address):

        ticket_key = None

        # JQL query to search for tickets with hostname field containing an empty string across all projects
        jql_query =  f'cf[10215] ~ "{plugin_id}" AND cf[10207] ~ "{ip_address}"'

        # Define the payload for the POST request (containing the JQL query)
        payload = {
            "jql": jql_query,
            "fields": ["key", "summary"]  # Optional: specify fields to retrieve
        }
        
        # Send POST request to execute the JQL query and retrieve matching issues
        response = requests.post(JIRA_API_SEARCH_URL, json=payload, auth=JIRA_AUTH)

        # Check if the request was successful (status code 200)
        if response.status_code == 200 and response.json().get('issues'):
            # Get the key of the first issue
            ticket_key = response.json()['issues'][0]['key']
        else:
            # Handle other error cases
            print(f"Error: {response.status_code} - {response.text}")

        return ticket_key    

    # Create a parent ticket based on the provided asset information.
    def create_parent_ticket(self, asset):
        ticket_key = None
        description = ""
        vip_members = asset.get('vip_members')

        if asset and 'id' in asset:
            # If 'vip_members' value is empty or NaN, use 'client_name'
            if vip_members in ["NaN", None]:
               description = "Task related to asset {}".format(asset.get('client_name', 'Unknown Host'))
            
        # Define the payload for the POST request to create the parent ticket
        payload = {
            "fields": {
                "project": {
                    "key": "VULNA"  # Replace with your project key
                },
                "summary": asset['client_name'],
                "description": description,
                "issuetype": {
                    "name": "Task"  # Replace with the appropriate issue type
                },
                "customfield_10234": asset['client_name'],  # Host Name
                "customfield_10235": asset['vip_members'],  # VIP Members
                "customfield_10236": asset['customer_contact'],  # Customer Contact
                "customfield_10237": asset['technical_contact']  # Technical Contact
            }
        }

        # Send POST request to create the parent ticket
        response = requests.post(JIRA_API_URL, json=payload, headers=JIRA_API_HEADER, auth=JIRA_AUTH)

        # Check if the request was successful (status code 201 for created)
        if response.status_code == 201:
            # Extract and return the key of the created ticket
            ticket_key = response.json()["key"]
        else:
            # Handle other error cases
            print(f"Error: {response.status_code} - {response.text}")
        
        return ticket_key

    # Create a sub-task ticket based on the provided ticket and parent ticket key.
    def create_subtask_ticket(self, ticket, parent_ticket_key):
        ticket_key = None

        data_fields = {
            "project": {
                "key": "VULNA"
            },
            "summary": f"{ticket['ip_address']} - {ticket['client_name']} - {ticket['name']}",  # Use 'ip_adress' - 'client_ci_name' - 'vulnerability name' field as summary
            "description": f"\n{ticket['name']}\n\nSynopsys:\n{ticket['synopsys']}\n\n Description:\n{ticket['description']}\n\n Solution:\n{ticket['solution']} \n\nOutput:{ticket['output']}",
            "customfield_10200": ticket['asset_id'], # asset_id
            "customfield_10201": ticket['vulnerability_id'], # vulnerability_id
            "customfield_10211": f"{ticket['cvssv2_score']}", # cvssv2_score
            "customfield_10213": f"{ticket['cvssv3_score']}", # cvssv3_score
            "customfield_10215" : f"{ticket['plugin_id']}", # plugin_id
            "customfield_10221": ticket['first_seen'], # first_seen
            "customfield_10222": ticket['last_seen'], # last_seen
            "customfield_10228": f"{ticket['severity']}", # severity
            "customfield_10230": ticket['state'], # state
            "customfield_10207": ticket['ip_address'], # ip_address
            "issuetype": {
                "name": "Sub-task"  
            }
        }

        if parent_ticket_key:
            data_fields['parent'] = {
                "key": parent_ticket_key     # Specify the parent ticket key
            }

        response = requests.post(JIRA_API_URL, json={"fields": data_fields}, headers=JIRA_API_HEADER, auth=JIRA_AUTH)
        if response.status_code == 200:
            ticket_key = response.json()['key']

        return ticket_key
    
    # Edit an existing sub-task ticket with updated information.
    def edit_subtask_ticket(self, ticket, parent_ticket_key, subtask_ticket_key):
        ticket_key = None

        data_fields = {
            "customfield_10222": ticket["last_seen"],
            "customfield_10228": ticket["severity"],
            "customfield_10230": ticket["state"]
        }

        if parent_ticket_key:
            data_fields['parent'] = {
                "key": parent_ticket_key     # Specify the parent ticket key
            }

        response = requests.put(f"{JIRA_API_EDIT_URL}/{subtask_ticket_key}", json={"fields": data_fields}, headers=JIRA_API_HEADER, auth=JIRA_AUTH)
        if response.status_code == 200:
            ticket_key = response.json()['key']

        return ticket_key
    
    def request_export_uuid_from_tenable(self, num_assets = 86299710):

        # API endpoint
        url = 'https://cloud.tenable.com/vulns/export'

        # API request headers
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "X-ApiKeys": TENABLE_APIKEY
        }


        # Get the current time.
        current_time = datetime.datetime.now()

        # Calculate the time 24 hours ago from the current time.
        time_24_hours_ago = current_time - datetime.timedelta(hours=24)

        # Convert the time 24 hours ago to Unix timestamp.
        since_time = int(time_24_hours_ago.timestamp())

        # Print the Unix timestamp for the past 24 hours.
        print("Unix timestamp for the last 24 hours:", since_time)

        # API request body
        data = {
            'num_assets': num_assets,
            "filters": {
                "severity": ["high", "critical","medium"],
                "since": since_time
            }
        }

        try:
            # Make the API call
            response = requests.post(url, headers=headers, data=json.dumps(data, indent=4, sort_keys=True))
            response.raise_for_status()  # Raise an exception if there's an error

            # Get the URL to the exported file from the response
            export_uuid = response.json().get('export_uuid')

            return export_uuid  # Return the download URL of the exported file

        except requests.exceptions.RequestException as e:
            print(f"An error occurred during API request: {e}")
            return None

    def get_status_by_export_uuid_from_tenable(self, export_uuid):
        # API endpoint
        url = f'https://cloud.tenable.com/vulns/export/{export_uuid}/status'

        # API request headers
        headers = {
            "accept": "application/json",
             "X-ApiKeys": TENABLE_APIKEY
        }

        try:
            # Make the API call
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception if there's an error

            # Return the response JSON
            data = response.json()
            return data.get('status'), data.get('finished_chunks')

        except requests.exceptions.RequestException as e:
            print(f"An error occurred during API request: {e}")
            return None, None
        
    def download_exported_data_from_tenable(self, export_uuid, chunk_id=1):
        # API endpoint
        url = f'https://cloud.tenable.com/vulns/export/{export_uuid}/chunks/{chunk_id}'

        # API request headers
        headers = {
             "accept": "application/octet-stream",
             "X-ApiKeys": TENABLE_APIKEY
        }

        try:
            # Make the API call to download the chunk
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception if there's an error

            # Generate filename based on current date and time
            current_datetime = datetime.datetime.now(pytz.timezone('America/Vancouver')).strftime("%m_%d_%Y_%H_%M_%S_%Z")

            # Save the downloaded file
            filename = f"./data/vrm_list/vulnerability-{current_datetime}.json"
            with open(filename, 'wb') as f:
                f.write(response.content)

            print(f"Exported vulnerabilities chunk {chunk_id} downloaded and saved as {filename}")

        except requests.exceptions.RequestException as e:
            print(f"An error occurred during API request: {e}")
    
        return filename

    # Parse a JSON file containing vulnerability data. 
    # Create JIRA API tickets for each entry.
    def process_api_json_file(self, file_path):
        # Load JSON data from the file
        jsondata = []
        with open(file_path, 'r') as file:
            jsondata = json.load(file)

        tickets = []
        for entry in jsondata:
            # Initialize parent ticket key and ticket object
            parent_ticket_key = None
            ticket = {}

            # Extract data from JSON entry
            output = entry.get("output")
            severity = entry.get("severity")
            state = entry.get("state")
            name = entry.get("plugin", {}).get("name") 
            solution = entry.get("plugin", {}).get("solution") 
            description = entry.get("plugin", {}).get("description") 
            synopsys = entry.get("plugin", {}).get("synopsis")
            plugin_id = entry.get("plugin", {}).get("id")
            ip_address = entry.get("asset", {}).get("ipv4") 
            first_seen = entry.get("first_found")
            last_seen = entry.get("last_found")
            cvssv2_score = entry.get("plugin", {}).get("cvss_base_score")
            cvssv3_score = entry.get("plugin", {}).get("cvss3_base_score")
            vpr_score = entry.get("plugin", {}).get("vpr", {}).get("score")
            asset_id = entry.get("asset", {}).get("uuid")
            #vulnerability_id = entry.get("id")

            # Resolve asset details using IP address
            asset = self.resolve_reverse_ip(ip_address)
            
            # Check if parent ticket exists using client name
            parent_ticket_key = self.get_parent_ticket_key(asset['client_name'])

            # Map data to ticket object    
            ticket = {
                'client_name': asset['client_name'],
                'name': name,
                'ip_address': ip_address,
                'description': description,
                'synopsys': synopsys,
                'solution': solution,
                'output': output,
                'plugin_id': plugin_id,
                'state': state,
                'severity': severity,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'cvssv2_score': cvssv2_score,
                'cvssv3_score': cvssv3_score,
                'vpr_score': vpr_score,
                'asset_id': asset_id,
                #'vulnerability_id': vulnerability_id,
            }

            print("api에서 가져온거 : ",ticket)

            # Create parent ticket if it doesn't exist
            if not parent_ticket_key:
                parent_ticket_key = self.create_parent_ticket(asset) 
                
            # Check for sub-task ticket
            subtask_ticket_key= self.find_sub_ticket_key_with_pluginID(plugin_id, ip_address)

            # Create sub-task ticket if it doesn't exist, otherwise edit existing sub-task ticket
            if not subtask_ticket_key:
                created_subtask_ticket_key = self.create_api_subtask_ticket(ticket, parent_ticket_key)
            else: 
                subtask_ticket_key = self.edit_subtask_ticket(ticket, parent_ticket_key, subtask_ticket_key)
            
            # Add extracted values to ticket_data dictionary
            tickets.append({
                "output": output,
                "description": description,
                "severity": severity,
                "ip_address": ip_address,
                "state": state,
                "name": name,
                "solution": solution,
                "parent_ticket_key": parent_ticket_key
            })

        return tickets
    
    # Create a sub-task ticket based on the provided ticket and parent ticket key.
    def create_api_subtask_ticket(self, ticket, parent_ticket_key):
        ticket_key = None

        data_fields = {
            "project": {
                "key": "VULNA"
            },
            "summary": f"{ticket['ip_address']} - {ticket['client_name']} - {ticket['name']}",  # Use 'ip_adress' - 'client_ci_name' - 'vulnerability name' field as summary
            "description": f"\n{ticket['name']}\n\nSynopsys:\n{ticket['synopsys']}\n\n Description:\n{ticket['description']}\n\n Solution:\n{ticket['solution']} \n\nOutput:{ticket['output']}",
            "customfield_10200": ticket['asset_id'], # asset_id
            "customfield_10211": f"{ticket['cvssv2_score']}", # cvssv2_score
            "customfield_10213": f"{ticket['cvssv3_score']}", # cvssv3_score
            "customfield_10215" : f"{ticket['plugin_id']}", # plugin_id
            "customfield_10221": ticket['first_seen'], # first_seen
            "customfield_10222": ticket['last_seen'], # last_seen
            "customfield_10228": f"{ticket['severity']}", # severity
            "customfield_10230": ticket['state'], # state
            "customfield_10207": ticket['ip_address'], # ip_address
            "issuetype": {
                "name": "Sub-task"  
            }
        }

        if parent_ticket_key:
            data_fields['parent'] = {
                "key": parent_ticket_key     # Specify the parent ticket key
            }

        response = requests.post(JIRA_API_URL, json={"fields": data_fields}, headers=JIRA_API_HEADER, auth=JIRA_AUTH)
        if response.status_code == 200:
            ticket_key = response.json()['key']

        return ticket_key