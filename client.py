import socket
import os
import os.path
import hashlib
import argparse
import json
import sys
from decouple import config
from tkinter import *
from tkinter import filedialog
import tkinter.messagebox
import customtkinter


customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"



try:
    client_encoding = config('CLIENT_ENCODING', default='utf-8')
except KeyboardInterrupt:
    print("\n[*] User has requested an interrupt")
    print("[*] Application Exiting.....")
    sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument('--filename', help="file name", default='')
parser.add_argument('--source', help="data source", default='')
parser.add_argument('--buffer_size', help="Number of samples to be used", default=8192, type=int)

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

def read_in_chunks(file_object, chunk_size=8192):
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("VRM Integration")
        self.geometry(f"{1100}x{580}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # create sidebar frame with widgets
        self.sidebar_frame = customtkinter.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="VRM", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        self.asset_button = customtkinter.CTkButton(self.sidebar_frame, text="Upload Asset Register File", command=self.asset_button_event)
        self.asset_button.grid(row=1, column=0, padx=20, pady=10)
        self.tenable_button = customtkinter.CTkButton(self.sidebar_frame, text="Auto-Generate Jira tickets", command=lambda: self.processAPI_from_tenable_button_event("tenable"))
        self.tenable_button.grid(row=2, column=0, padx=20, pady=10)
           
        # sidebar - appearence mode
        self.appearance_mode_label = customtkinter.CTkLabel(self.sidebar_frame, text="Appearance Mode:", anchor="w")
        self.appearance_mode_label.grid(row=5, column=0, padx=20, pady=(10, 0))
        self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["Light", "Dark", "System"],
                                                                        command=self.change_appearance_mode_event)
        self.appearance_mode_optionemenu.grid(row=6, column=0, padx=20, pady=(10, 10))

        # sidebar - scaling option
        self.scaling_label = customtkinter.CTkLabel(self.sidebar_frame, text="UI Scaling:", anchor="w")
        self.scaling_label.grid(row=7, column=0, padx=20, pady=(10, 0))
        self.scaling_optionemenu = customtkinter.CTkOptionMenu(self.sidebar_frame, values=["80%", "90%", "100%", "110%", "120%"],
                                                                command=self.change_scaling_event)
        self.scaling_optionemenu.grid(row=8, column=0, padx=20, pady=(10, 20))

        # create main entry and button
        # self.entry = customtkinter.CTkEntry(self, placeholder_text="CTkEntry")
        # self.entry.grid(row=3, column=1, columnspan=2, padx=(20, 0), pady=(20, 20), sticky="nsew")

        # self.main_button_1 = customtkinter.CTkButton(master=self, fg_color="transparent", text="Process Tenable API", border_width=2, text_color=("gray10", "#DCE4EE"))
        # self.main_button_1.grid(row=3, column=3, padx=(20, 20), pady=(20, 20), sticky="nsew")

        # create textbox
        self.textbox = customtkinter.CTkTextbox(self, width=50)
        self.textbox.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        self.asset_textbox = customtkinter.CTkTextbox(self, width=50)
        self.asset_textbox.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # self.textbox2 = customtkinter.CTkTextbox(self, width=300)
        # self.textbox2.grid(row=0, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")

        # 
        # create tabview
        # self.tabview = customtkinter.CTkTabview(self, width=250)
        # self.tabview.grid(row=0, column=2, padx=(20, 0), pady=(20, 0), sticky="nsew")
        # self.tabview.add("CTkTabview")
        # self.tabview.add("Tab 2")
        # self.tabview.add("Tab 3")
        # self.tabview.tab("CTkTabview").grid_columnconfigure(0, weight=1)  # configure grid of individual tabs
        # self.tabview.tab("Tab 2").grid_columnconfigure(0, weight=1)

        # self.optionmenu_1 = customtkinter.CTkOptionMenu(self.tabview.tab("CTkTabview"), dynamic_resizing=False,
        #                                                 values=["Value 1", "Value 2", "Value Long Long Long"])
        # self.optionmenu_1.grid(row=0, column=0, padx=20, pady=(20, 10))
        # self.combobox_1 = customtkinter.CTkComboBox(self.tabview.tab("CTkTabview"),
        #                                             values=["Value 1", "Value 2", "Value Long....."])
        # self.combobox_1.grid(row=1, column=0, padx=20, pady=(10, 10))
        # self.string_input_button = customtkinter.CTkButton(self.tabview.tab("CTkTabview"), text="Open CTkInputDialog",
        #                                                 command=self.open_input_dialog_event)
        # self.string_input_button.grid(row=2, column=0, padx=20, pady=(10, 10))
        # self.label_tab_2 = customtkinter.CTkLabel(self.tabview.tab("Tab 2"), text="CTkLabel on Tab 2")
        # self.label_tab_2.grid(row=0, column=0, padx=20, pady=20)

        # create slider and progressbar frame
        # self.slider_progressbar_frame = customtkinter.CTkFrame(self, fg_color="transparent")
        # self.slider_progressbar_frame.grid(row=1, column=1, padx=(20, 0), pady=(20, 0), sticky="nsew")
        # self.slider_progressbar_frame.grid_columnconfigure(0, weight=1)
        # self.slider_progressbar_frame.grid_rowconfigure(4, weight=1)
        # self.seg_button_1 = customtkinter.CTkSegmentedButton(self.slider_progressbar_frame)
        # self.seg_button_1.grid(row=0, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")
        # self.progressbar_1 = customtkinter.CTkProgressBar(self.slider_progressbar_frame)
        # self.progressbar_1.grid(row=1, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")
        # self.progressbar_2 = customtkinter.CTkProgressBar(self.slider_progressbar_frame)
        # self.progressbar_2.grid(row=2, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")
        # self.slider_1 = customtkinter.CTkSlider(self.slider_progressbar_frame, from_=0, to=1, number_of_steps=4)
        # self.slider_1.grid(row=3, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")
        # self.slider_2 = customtkinter.CTkSlider(self.slider_progressbar_frame, orientation="vertical")
        # self.slider_2.grid(row=0, column=1, rowspan=5, padx=(10, 10), pady=(10, 10), sticky="ns")
        # self.progressbar_3 = customtkinter.CTkProgressBar(self.slider_progressbar_frame, orientation="vertical")
        # self.progressbar_3.grid(row=0, column=2, rowspan=5, padx=(10, 20), pady=(10, 10), sticky="ns")

        # create scrollable frame
        # self.scrollable_frame = customtkinter.CTkScrollableFrame(self, label_text="CTkScrollableFrame")
        # self.scrollable_frame.grid(row=1, column=2, padx=(20, 0), pady=(20, 0), sticky="nsew")
        # self.scrollable_frame.grid_columnconfigure(0, weight=1)
        # self.scrollable_frame_switches = []
        # self.appearance_mode_optionemenu.set("Dark")
        # self.scaling_optionemenu.set("100%")
        # self.optionmenu_1.set("CTkOptionmenu")
        # self.combobox_1.set("CTkComboBox")
        # self.slider_1.configure(command=self.progressbar_2.set)
        # self.slider_2.configure(command=self.progressbar_3.set)
        # self.progressbar_1.configure(mode="indeterminnate")
        # self.progressbar_1.start()
        self.textbox.insert("0.0", "[Tenable VRM Integration for JIRA Cloud]\n\n" + "The Tenable VRM integration with Jira Cloud automates the process of pulling vulnerability data from Tenable.io and generating corresponding Jira Tasks and sub-tasks based on the current state of vulnerabilities. Once a vulnerability is marked as \"fixed\" in Tenable.io, the associated Jira Tasks are automatically closed.\n\n"+"Here's how the integration works:\n\n"+"1. Project Setup: The integration creates a Vulnerability Management Business project with the project key VULNA and utilizes the Simplified Task Tracking template. It establishes custom fields and links them to the appropriate screen for storing and displaying necessary information.\n\n"+"2.Ticket Creation: For each host server, a header ticket is created containing details such as Host Server Name, VIP Members, Customer Contact, and Technical Contact. Additionally, each vulnerability instance is created as a Sub-task. For example, if there is one host, the integration generates one parent ticket and multiple sub-task tickets, each corresponding to a specific IP address of a vulnerability on that host.\n\n"+"3. Automatic Closure: Vulnerability Instances (Sub-tasks) are automatically closed by the integration once the vulnerability is fixed in Tenable.io.\n\n"+"4. Re-opened Vulnerabilities: If a vulnerability is re-opened, the status and state of the existing ticket are updated accordingly.\n\n"+"5. Data Synchronization: All data imported from Tenable.io utilizes the last_found/last_seen fields to ensure that issues are updated whenever new information becomes available, unless overridden with the --first-discovery flag.\n\n"+"6. Task and Sub-task Summaries: Task summaries are generated using the formula [Host Server Name], while sub-task summaries are generated using the formula [IP Address - Fqdn - Issue Name].")
        self.asset_textbox.insert("0.0", "'Upload Asset Register File' Button feature enables the storage of data containing Host Server Name, VIP Members, Customer Contact, and Technical Contact information into the database.")
        # self.seg_button_1.configure(values=["CTkSegmentedButton", "Value 2", "Value 3"])
        # self.seg_button_1.set("Value 2")


    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def asset_button_event(self):
        print("asset button is clicked!")

        # List of valid file extensions that are allowed for upload.
        valid_extensions = ['.json', '.xlsx', '.csv']

        # display a file selection dialog box
        filename = filedialog.askopenfilename()
        # Extract the file name from the file path
        filename_only = os.path.basename(filename)
        
        print("Selected filepath:", filename)

        if filename and os.path.isfile(filename):
            # Check if file extension is valid
            file_extension = os.path.splitext(filename)[1]
            if file_extension.lower() in valid_extensions:
            # Your existing file sending logic goes here
                # make the message
                id, message = jsonrpc2_encode('vrmprocess', {
                    "filename": filename,
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
                        # Your existing file sending logic goes here
                        tkinter.messagebox.showinfo("File Uploaded", f"{filename_only} has been saved successfully.")
                # close the connection
                sock.close()
                 
            else: tkinter.messagebox.showerror("Error", "Please upload a file with valid extension (json, xlsx, csv).")
        else:
            tkinter.messagebox.showerror("Error", "Please enter a valid file.")

    def processAPI_from_tenable_button_event(self, source):
        print("processAPI_from_tenable_button_event!!!!!!!!!!!! > ", source)

        if source and source == "tenable":
        # make the message
            id, message = jsonrpc2_encode('vrmprocess', {
                "source": source,
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

            tkinter.messagebox.showinfo("Processing...", f"Jira Tickets are generated from Tenable API Vulnerability List now...")
            # close the connection
            sock.close()

    # def send_file(self):
    #     global filename
    #     filename = self.entry.get()
    #     if filename and os.path.isfile(filename):
    #         # Your existing file sending logic goes here
    #         tkinter.messagebox.showinfo("File Sent", f"{filename} has been sent successfully.")
    #     else:
    #         tkinter.messagebox.showerror("Error", "Please enter a valid filename.")


def main(args):

    root = customtkinter.CTk()
    root.geometry("500x350")

    app = App()

    app.mainloop()
    
    # if filename and os.path.isfile(filename):
    #     # make the message
    #     id, message = jsonrpc2_encode('vrmprocess', {
    #         "filename": filename,
    #     })
    #     print (message)

    #     # connect to server
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     sock.connect(('localhost', 5555))

    #     # send a message
    #     sock.send(message.encode(client_encoding))
    #     response = sock.recv(buffer_size)
    #     jsondata = json.loads(response.decode(client_encoding))
    #     print (jsondata)

    #     # read the file
    #     if jsondata['method'] == "vrmprocess_accept" and jsondata['params']['success'] == True:
    #         with open(filename, 'rb') as f:
    #             for chunk in read_in_chunks(f):
    #                 sock.send(chunk)
    #             sock.send(b'')

    #     # close the connection
    #     sock.close()

    # elif source and source == "tenable":
    #     # make the message
    #     id, message = jsonrpc2_encode('vrmprocess', {
    #         "source": source,
    #     })
    #     print (message)

    #     # connect to server
    #     sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     sock.connect(('localhost', 5555))

    #     # send a message
    #     sock.send(message.encode(client_encoding))
    #     response = sock.recv(buffer_size)
    #     jsondata = json.loads(response.decode(client_encoding))
    #     print (jsondata)

    #     # close the connection
    #     sock.close()

if __name__== "__main__":
    main(sys.argv)