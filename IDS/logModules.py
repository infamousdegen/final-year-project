import datetime
import pickle
import os
from scapy.all import *
import uuid
import stat

def log_packet(rule, pkt):
    # Generate a unique filename using UUID
    unique_id = str(uuid.uuid4())  
    msg = f"SID: {rule.sid}\nSummary: {pkt.summary()}"
    
    # Ensure the 'logs' directory exists
    directory = "logs"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    # Create the log file with a UUID as the name
    filename = os.path.join(directory, f"{unique_id}.txt")
    with open(filename, 'w') as file:
        file.write(msg)
    
    # Set file permissions to be modifiable by everyone
    os.chmod(filename, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
