import time
import pandas as pd
import json
import requests
import psycopg2
import pytz
from datetime import datetime
import datetime as dt
from requests.auth import HTTPBasicAuth
from decouple import config
from server import Extension, jsonrpc2_result_encode

try: 
    # Attempt to retrieve configuration values from environment variables
    JIRA_API_URL = config("JIRA_API_URL") # URL for JIRA API
    JIRA_API_SEARCH_URL = config("JIRA_API_SEARCH_URL") # URL for JIRA search API
    JIRA_API_EDIT_URL = config("JIRA_API_EDIT_URL") # URL for JIRA edit API
    JIRA_API_USERNAME = config("JIRA_API_USERNAME") # Username for JIRA API
    JIRA_API_KEY = config("JIRA_API_KEY") # Key for JIRA API authentication
    PG_HOST = config("POSTGRES_HOST") # PostgreSQL host
    PG_DBNAME = config("POSTGRES_DBNAME") # PostgreSQL database name
    PG_USER = config("POSTGRES_USER") # PostgreSQL username
    PG_PASSWORD = config("POSTGRES_PASSWORD") # PostgreSQL password
    PG_PORT = config("POSTGRES_PORT", default=5432, cast=int) # PostgreSQL port, default is 5432
    TENABLE_APIKEY = config("TENABLE_API_KEY") # Tenable API key, default is empty string
    client_encoding = config("CLIENT_ENCODING", default='utf-8') # Client encoding, default is utf-8
    # Set up JIRA authentication and headers
    JIRA_AUTH = HTTPBasicAuth(JIRA_API_USERNAME, JIRA_API_KEY)

    JIRA_API_HEADER = {
    "Accept": "application/json",
    "Content-Type": "application/json"
    }
except Exception as e:
    # Handle exceptions raised during configuration retrieval
    print ("[*] Exception: %s" % (str(e)))

class VRMProcess(Extension):
    """
    Class for handling VRM (Vulnerability Risk Management) process.

    This class extends the Extension class and provides methods for processing
    files related to VRM, such as Excel and JSON files containing vulnerability
    data. It includes functionality to dispatch incoming data for processing,
    saving assets, resolving IP addresses, creating and editing parent & subtask tickets.

    """
    def __init__(self):
        # Initializing attributes
        self.type = "rpcmethod" # Type attribute
        self.method = "vrmprocess" # Method attribute
        # Establishing a PostgreSQL database connection
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
            print("[*] writing the file: ", out_filename)
            with open(out_filename, 'wb') as f:
                f.write(data)

            print("[*] processing the file: ", out_filename)
            # Processing XLSX file
            if received_filetype == "xlsx":
                assets = self.process_asset_file(out_filename)
                result = self.save_assets(assets)
            elif received_filetype == "json":
                # Processing JSON file
                tickets = self.process_json_file(out_filename)
            print("[*] save done")
        
        elif 'source' in params and params['source'] == 'tenable':
            # Requesting export UUID from Tenable
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
                print("Finished. Trying download %s chunks..." % (str(finished_chunks)))

                if finished_chunks > 0:
                    for chunk_id in range(1, finished_chunks + 1):
                        print("Downloading the chunk %s..." % (str(chunk_id)))
                        filename = self.download_exported_data_from_tenable(export_uuid, chunk_id)
                print("Done.")
                print("filename : ",filename)
                # Processing API JSON file
                tickets = self.process_api_json_file(filename)
                print("[*] api data save done")

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

            print(
                f"=======index: {index} ==============\n"
                f"client_name: {client_name}\n"
                f"vip_members: {vip_members}\n"
                f"ip_address: {ip_address}\n"
                f"customer_contact: {customer_contact}\n"
                f"technical_contact: {technical_contact}\n"
                "========================================"
            )

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
            fqdn = entry.get("asset", {}).get("fqdn")

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
                'fqdn': fqdn
            }

            # Create parent ticket if it doesn't exist
            if not parent_ticket_key:
                parent_ticket_key = self.create_parent_ticket(asset) 
                
            # Check for sub-task ticket
            subtask_ticket_key= self.get_sub_ticket_key(plugin_id, ip_address)

            # Create sub-task ticket if it doesn't exist, otherwise edit existing sub-task ticket
            if not subtask_ticket_key:
                created_subtask_ticket_key = self.create_subtask_ticket(ticket, parent_ticket_key)
            else: 
                subtask_ticket_key = self.edit_subtask_ticket(ticket, parent_ticket_key, subtask_ticket_key)

            # Check the status of the Jira issue with subtask_ticket_key.
            # Transition the status of the Jira issue
            transition_response = self.transition_jira_status(ticket, subtask_ticket_key)
            print(transition_response)
            
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
        #sandbox account
        #jql_query =  f'cf[10234] ~ "{hostname}"'
        #service account
        jql_query =  f'cf[10293] ~ "{hostname}"'

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
            print('Get Parent-Ticket Key : ',ticket_key)
        else:
            # Handle other error cases
            print(f"get_parent_ticket_key Response: {response.status_code} - {response.text}")

        return ticket_key
    
    # Retrieve the key of the sub-task ticket associated with the given vulnerability ID.
    def get_sub_ticket_key(self, plugin_id, ip_address):

        ticket_key = None

        # JQL query to search for tickets with hostname field containing an empty string across all projects
        #sandbox account
        #jql_query =  f'cf[10215] ~ "{plugin_id}" AND cf[10207] ~ "{ip_address}"'
        #service account
        jql_query =  f'cf[10275] ~ "{plugin_id}" AND cf[10267] ~ "{ip_address}"'

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
            print('Get Sub-Ticket Key : ',ticket_key)
        else:
            # Handle other error cases
            print(f"get_sub_ticket_key Response: {response.status_code} - {response.text}")

        return ticket_key    
    
        # Retrieve the key of the sub-task ticket associated with the given vulnerability ID.
    def find_sub_ticket_key_with_pluginID(self, plugin_id, ip_address):

        ticket_key = None

        # JQL query to search for tickets with hostname field containing an empty string across all projects
        #sandbox account
        #jql_query =  f'cf[10215] ~ "{plugin_id}" AND cf[10207] ~ "{ip_address}"'
        #service account
        jql_query =  f'cf[10275] ~ "{plugin_id}" AND cf[10267] ~ "{ip_address}"'

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
            print('Find Sub-Ticket Key : ',ticket_key)
        else:
            # Handle other error cases
            print(f"find_sub_ticket_key_with_pluginID Response: {response.status_code} - {response.text}")

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
                    #"key": "VULNA"  # Replace with your project key
                     "key": "VULN" 
                },
                "summary": asset['client_name'],
                "description": description,
                "issuetype": {
                    "name": "Task"  # Replace with the appropriate issue type
                },
                # "customfield_10234": asset['client_name'],  # SandBox Host Name
                # "customfield_10235": asset['vip_members'],  # SandBox VIP Members
                # "customfield_10236": asset['customer_contact'],  # SandBox Customer Contact
                # "customfield_10237": asset['technical_contact']  # SandBox Technical Contact
                "customfield_10293": asset['client_name'],  # Service Host Name
                "customfield_10294": asset['vip_members'],  # Service VIP Members
                "customfield_10295": asset['customer_contact'],  # Service Customer Contact
                "customfield_10296": asset['technical_contact']  # Service Technical Contact
            }
        }

        # Send POST request to create the parent ticket
        response = requests.post(JIRA_API_URL, json=payload, headers=JIRA_API_HEADER, auth=JIRA_AUTH)

        # Check if the request was successful (status code 201 for created)
        if response.status_code == 201 :
            # Extract and return the key of the created ticket
            ticket_key = response.json()["key"]
            print('Create Parent-Ticket Key : ',ticket_key)
        else:
            # Handle other error cases
            print(f"create_parent_ticket Response: {response.status_code} - {response.text}")
        
        return ticket_key

    # Create a sub-task ticket based on the provided ticket and parent ticket key.
    def create_subtask_ticket(self, ticket, parent_ticket_key):
        ticket_key = None

        data_fields = {
            "project": {
                #"key": "VULNA"
                "key": "VULN"
            },
            "summary": f"{ticket['ip_address']} - {ticket['fqdn']} - {ticket['name']}",  # Use 'ip_adress' - 'client_ci_name' - 'vulnerability name' field as summary
            "description": f"\n{ticket['name']}\n\n*Synopsys:*\n{ticket['synopsys']}\n\n *Description:*\n{ticket['description']}\n\n *Solution:*\n{ticket['solution']} \n\n*Output:*{ticket['output']}",
            
            #service account
            "customfield_10263": ticket['asset_id'], # asset_id
            "customfield_10264": ticket['vulnerability_id'], # vulnerability_id
            "customfield_10271": f"{ticket['cvssv2_score']}", # cvssv2_score
            "customfield_10273": f"{ticket['cvssv3_score']}", # cvssv3_score
            "customfield_10275" : f"{ticket['plugin_id']}", # plugin_id
            "customfield_10281": ticket['first_seen'], # first_seen
            "customfield_10282": ticket['last_seen'], # last_seen
            "customfield_10288": f"{ticket['severity']}", # severity
            "customfield_10289": ticket['state'], # state
            "customfield_10267": ticket['ip_address'], # ip_address
            #sandbox account
            # "customfield_10200": ticket['asset_id'], # asset_id
            # "customfield_10201": ticket['vulnerability_id'], # vulnerability_id
            # "customfield_10211": f"{ticket['cvssv2_score']}", # cvssv2_score
            # "customfield_10213": f"{ticket['cvssv3_score']}", # cvssv3_score
            # "customfield_10215" : f"{ticket['plugin_id']}", # plugin_id
            # "customfield_10221": ticket['first_seen'], # first_seen
            # "customfield_10222": ticket['last_seen'], # last_seen
            # "customfield_10228": f"{ticket['severity']}", # severity
            # "customfield_10230": ticket['state'], # state
            # "customfield_10207": ticket['ip_address'], # ip_address
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
            print('Create Sub-Ticket Key : ',ticket_key)

        return ticket_key
    
    # Edit an existing sub-task ticket with updated information.
    def edit_subtask_ticket(self, ticket, parent_ticket_key, subtask_ticket_key):
        print('===========edit_subtask_ticket=================')
        ticket_key = None

        data_fields = {
            #service account
            "customfield_10282": ticket["last_seen"],
            "customfield_10288": ticket["severity"],
            "customfield_10289": ticket["state"]
            #sandbox account
            # "customfield_10222": ticket["last_seen"],
            # "customfield_10228": ticket["severity"],
            # "customfield_10230": ticket["state"]
        }

        if parent_ticket_key:
            data_fields['parent'] = {
                "key": parent_ticket_key     # Specify the parent ticket key
            }
        
        # Check the status of the Jira issue with subtask_ticket_key.
        # Transition the status of the Jira issue
        transition_response = self.transition_jira_status(ticket, subtask_ticket_key)
        print("transition_response : ",transition_response)

        response = requests.put(f"{JIRA_API_EDIT_URL}/{subtask_ticket_key}", json={"fields": data_fields}, headers=JIRA_API_HEADER, auth=JIRA_AUTH)
        if response.status_code == 200:
            ticket_key = response.json()['key']
            print("edit_subtask_ticket_key : ",ticket_key)

        return ticket_key
    
    def request_export_uuid_from_tenable(self, num_assets = 86299710):

        # API endpoint
        url = "https://cloud.tenable.com/vulns/export"

        # API request headers
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "X-ApiKeys": TENABLE_APIKEY
        }

        # Get the current time.
        current_time = dt.datetime.now()

        # Set the time to the beginning of the day (midnight) for today.
        beginning_of_day = dt.datetime(current_time.year, current_time.month, current_time.day)

        # Convert the beginning of the day to Unix timestamp.
        since_time = int(beginning_of_day.timestamp())

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
            current_datetime = dt.datetime.now(pytz.timezone('America/Vancouver')).strftime("%m_%d_%Y_%H_%M_%S_%Z")

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
            fqdn = entry.get("asset", {}).get("fqdn")
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
                'fqdn': fqdn
                #'vulnerability_id': vulnerability_id,
            }

            print("TICKET API INFO : ",ticket)

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

            # Check the status of the Jira issue with subtask_ticket_key.
            # Transition the status of the Jira issue
            transition_response = self.transition_jira_status(ticket, subtask_ticket_key)

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
                # "key": "VULNA"
                "key": "VULN"
            },
            "summary": f"{ticket['ip_address']} - {ticket['fqdn']} - {ticket['name']}",  # Use 'ip_adress' - 'fqdn' - 'vulnerability name' field as summary
            "description": f"\n{ticket['name']}\n\n*Synopsys:*\n{ticket['synopsys']}\n\n *Description:*\n{ticket['description']}\n\n *Solution:*\n{ticket['solution']} \n\n*Output:*{ticket['output']}",
            "customfield_10263": ticket['asset_id'], # asset_id
            "customfield_10271": f"{ticket['cvssv2_score']}", # cvssv2_score
            "customfield_10273": f"{ticket['cvssv3_score']}", # cvssv3_score
            "customfield_10275" : f"{ticket['plugin_id']}", # plugin_id
            "customfield_10281": ticket['first_seen'], # first_seen
            "customfield_10282": ticket['last_seen'], # last_seen
            "customfield_10288": f"{ticket['severity']}", # severity
            "customfield_10289": ticket['state'], # state
            "customfield_10267": ticket['ip_address'], # ip_address            
            # "customfield_10200": ticket['asset_id'], # asset_id
            # "customfield_10211": f"{ticket['cvssv2_score']}", # cvssv2_score
            # "customfield_10213": f"{ticket['cvssv3_score']}", # cvssv3_score
            # "customfield_10215" : f"{ticket['plugin_id']}", # plugin_id
            # "customfield_10221": ticket['first_seen'], # first_seen
            # "customfield_10222": ticket['last_seen'], # last_seen
            # "customfield_10228": f"{ticket['severity']}", # severity
            # "customfield_10230": ticket['state'], # state
            # "customfield_10207": ticket['ip_address'], # ip_address
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
    
    # Transition a Jira status to a specific status.
    def transition_jira_status(self, ticket, issue_key):
        transition_id = None
        # Check the status of the Jira issue with subtask_ticket_key.
        # If the status is "Fixed", transition the status to a different state.
        if ticket['state'] == "Fixed":
        # Transition the status of the Jira issue
            transition_id = "41" # Mitigated
        else:
            transition_id = "21" # Active

        # Request body
        data = {
            "transition": {
                "id": transition_id  # Mitigated
            }
        }

        # Send POST request to transition the issue
        response = requests.post(f"{JIRA_API_URL}/{issue_key}/transitions", json=data, headers=JIRA_API_HEADER, auth=JIRA_AUTH)
        response_message = None
        # Check if the request was successful
        if response.status_code == 204:
            response_message = f"{issue_key} : Issue transitioned successfully."
        else:
            response_message = f""
            
        return response_message
    

    # This method fetches all asset data from the database.
    def fetch_asset_data(self):
        # Establish a cursor for executing SQL commands
        cur = self.pg_connection.cursor()

        # Execute SQL command to select data from the 'asset' table
        cur.execute('select id, client_name, vip_members, ip_address, customer_contact, technical_contact from asset')

        # Fetch all rows from the executed SQL command
        row = cur.fetchall()

        # Define field names for the asset data
        fieldnames = ['id', 'client_name', 'vip_members', 'ip_address', 'customer_contact', 'technical_contact']
        if row:
            asset = dict(zip(fieldnames, row))
        else:
            asset = dict(zip(fieldnames, [None, "Unknown Host", '', '', '', '']))

        return asset
    