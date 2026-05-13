import csv
import time
import numpy as np
import random
import time
import hmac
import hashlib
import os
import sys
import shlex
import base64
from collections import defaultdict

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from sympy import symbols, Eq, expand
from py_ecc.optimized_bn128 import G1, G2, add, multiply
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad




start = time.time()
# Check for the 'controller' argument
def parse_arguments():
    message = None
    signature = None
    hashval = None
    msg_type = 0
    is_controller = False
    create_security_manager_controller = False
    netsize = None
    nid = 0
    port_id = 0
    other_node_id = 0
    generate_dig_ecc_key_pair = False
    generate_dig_rsa_key_pair = False
    generate_own_aes_key = False
    encrypt_ECDH = False
    decrypt_ECDH = False
    sign_data = False
    verify_HMAC = False
    verify_signature = False
    initiate_session1 = False
    initiate_session2 = False
    create_hmac_global = False
    create_hmac_set1 = False
    create_hmac_set2 = False
    verify_key_expiry = False
    is_node = False
    pid = 0
    get_rsa_keys = False
    encrypt_rsa = False
    set_aes_key_for_pair = False
    encrypt_controller_data = False
    decrypt_controller_data = False
    generate_global_HMAC_secret_key = False
    get_digital_public_key = False
    get_session_HMAC_1 = False
    get_session_HMAC_2 = False
    create_global_HMAC_node = False
    decrypt_rsa = False
    get_aes_keys = False
    encrypt_aes_node_pair = False
    decrypt_aes_node_pair = False
    
    # Combine command-line arguments into a single string and split by spaces
    args = " ".join(sys.argv[1:])  # Combine all arguments into a single string
    print(args)
    parsed_args = shlex.split(args)  # Split respecting spaces and quoted substrings
    print(parsed_args)

    for arg in parsed_args:
        if arg.startswith("is_controller="):
            #print(arg.split("=")[1])
            is_controller = arg.split("=")[1] == "true"
            #print(is_controller)
        if arg.startswith("verify_HMAC="):
            #print(arg.split("=")[1])
            verify_HMAC = arg.split("=")[1] == "true"
            #print(is_controller)
        if arg.startswith("create_security_manager_con="):
            #print(arg.split("=")[1])
            create_security_manager_controller = arg.split("=")[1] == "true"
            #print(create_security_manager_controller)
        if arg.startswith("netsize="):
            #print(arg.split("=")[1])
            netsize = int(arg.split("=")[1])
            print(netsize)
        if arg.startswith("node_id="):
            #print(arg.split("=")[1])
            nid = int(arg.split("=")[1])
            print(f"node id {nid}")
        if arg.startswith("port_id="):
            #print(arg.split("=")[1])
            port_id = int(arg.split("=")[1])
            print(f"port id {port_id}")
        if arg.startswith("other_node_id="):
            #print(arg.split("=")[1])
            other_node_id = int(arg.split("=")[1])
            print(other_node_id)
        if arg.startswith("generate_dig_rsa_key_pair="):
            #print(arg.split("=")[1])
            generate_dig_rsa_key_pair = arg.split("=")[1] == "true"
            print(generate_dig_rsa_key_pair)
        if arg.startswith("generate_dig_ecc_key_pair="):
            #print(arg.split("=")[1])
            generate_dig_ecc_key_pair = arg.split("=")[1] == "true"
            print(generate_dig_ecc_key_pair)
        if arg.startswith("encrypt_ECDH="):
            #print(arg.split("=")[1])
            encrypt_ECDH = arg.split("=")[1] == "true"
            print(encrypt_ECDH)
        if arg.startswith("decrypt_ECDH="):
            #print(arg.split("=")[1])
            decrypt_ECDH = arg.split("=")[1] == "true"
            print(decrypt_ECDH)
        if arg.startswith("generate_own_aes_key="):
            #print(arg.split("=")[1])
            generate_own_aes_key = arg.split("=")[1] == "true"
            print(generate_own_aes_key)
        if arg.startswith("sign_data="):
            #print(arg.split("=")[1])
            sign_data = arg.split("=")[1] == "true"
            print(sign_data)
        if arg.startswith("verify_signature="):
            #print(arg.split("=")[1])
            verify_signature = arg.split("=")[1] == "true"
            print(verify_signature)
        if arg.startswith("initiate_session1="):
            #print(arg.split("=")[1])
            initiate_session1 = arg.split("=")[1] == "true"
            print(initiate_session1)
        if arg.startswith("initiate_session2="):
            #print(arg.split("=")[1])
            initiate_session2 = arg.split("=")[1] == "true"
            print(initiate_session2)  
        if arg.startswith("create_hmac_global="):
            #print(arg.split("=")[1])
            create_hmac_global = arg.split("=")[1] == "true"
            print(create_hmac_global)
        if arg.startswith("create_hmac_set1="):
            #print(arg.split("=")[1])
            create_hmac_set1 = arg.split("=")[1] == "true"
            print(create_hmac_set1)
        if arg.startswith("create_hmac_set2="):
            #print(arg.split("=")[1])
            create_hmac_set2 = arg.split("=")[1] == "true"
            print(create_hmac_set2)
        if arg.startswith("verify_key_expiry="):
            #print(arg.split("=")[1])
            verify_key_expiry = arg.split("=")[1] == "true"
            print(verify_key_expiry)
        if arg.startswith("is_node="):
            #print(arg.split("=")[1])
            is_node = arg.split("=")[1] == "true"
            print(is_node)
        if arg.startswith("pid="):
            #print(arg.split("=")[1])
            pid = int(arg.split("=")[1])
            print(pid)
        if arg.startswith("get_rsa_keys="):
            #print(arg.split("=")[1])
            get_rsa_keys = arg.split("=")[1] == "true"
            print(get_rsa_keys)
        if arg.startswith("encrypt_rsa="):
            #print(arg.split("=")[1])
            encrypt_rsa = arg.split("=")[1] == "true"
            print(encrypt_rsa)
        if arg.startswith("set_aes_key_for_pair="):
            #print(arg.split("=")[1])
            set_aes_key_for_pair = arg.split("=")[1] == "true"
            print(set_aes_key_for_pair)
        if arg.startswith("encrypt_controller_data="):
            #print(arg.split("=")[1])
            encrypt_controller_data = arg.split("=")[1] == "true"
            print(encrypt_controller_data)
        if arg.startswith("decrypt_controller_data="):
            #print(arg.split("=")[1])
            decrypt_controller_data = arg.split("=")[1] == "true"
            print(decrypt_controller_data)
        if arg.startswith("generate_global_HMAC_secret_key="):
            #print(arg.split("=")[1])
            generate_global_HMAC_secret_key = arg.split("=")[1] == "true"
            print(generate_global_HMAC_secret_key)
        if arg.startswith("get_digital_public_key="):
            #print(arg.split("=")[1])
            get_digital_public_key = arg.split("=")[1] == "true"
            print(get_digital_public_key)
        if arg.startswith("get_session_HMAC_1="):
            #print(arg.split("=")[1])
            get_session_HMAC_1 = arg.split("=")[1] == "true"
            print(get_session_HMAC_1)
        if arg.startswith("get_session_HMAC_2="):
            #print(arg.split("=")[1])
            get_session_HMAC_2 = arg.split("=")[1] == "true"
            print(get_session_HMAC_2)
        if arg.startswith("create_global_HMAC_node="):
            #print(arg.split("=")[1])
            create_global_HMAC_node = arg.split("=")[1] == "true"
            print(create_global_HMAC_node)
        if arg.startswith("decrypt_rsa="):
            #print(arg.split("=")[1])
            decrypt_rsa = arg.split("=")[1] == "true"
            print(decrypt_rsa)
        if arg.startswith("get_aes_keys="):
            #print(arg.split("=")[1])
            get_aes_keys = arg.split("=")[1] == "true"
            print(get_aes_keys)
        if arg.startswith("encrypt_aes_node_pair="):
            #print(arg.split("=")[1])
            encrypt_aes_node_pair = arg.split("=")[1] == "true"
            print(encrypt_aes_node_pair)
        if arg.startswith("decrypt_aes_node_pair="):
            #print(arg.split("=")[1])
            decrypt_aes_node_pair = arg.split("=")[1] == "true"
            print(decrypt_aes_node_pair)
        if arg.startswith("message="):
            message = arg.split("=", 1)[1]  # Extract the actual message string
            print("Received message:", message)
        if arg.startswith("hashval="):
            hashval = arg.split("=", 1)[1]  # Extract the actual message string
            print("Hash value:", hashval)
        if arg.startswith("signature="):
            signature = arg.split("=", 1)[1]  # Extract the actual message string
            print("Received signature:", signature)
        if arg.startswith("msg_type="):
            msg_type = int(arg.split("=")[1])  # Extract the actual message type
            print("message type:", msg_type)
    return is_controller, create_security_manager_controller, netsize, message, signature, verify_HMAC, msg_type, nid, port_id, other_node_id, generate_dig_rsa_key_pair, generate_dig_ecc_key_pair, generate_own_aes_key, encrypt_ECDH, decrypt_ECDH, sign_data, verify_signature, initiate_session1, initiate_session2, create_hmac_global, create_hmac_set1, create_hmac_set2, verify_key_expiry, is_node, pid, get_rsa_keys, encrypt_rsa, set_aes_key_for_pair, encrypt_controller_data, decrypt_controller_data, generate_global_HMAC_secret_key, get_digital_public_key, get_session_HMAC_1, get_session_HMAC_2, create_global_HMAC_node, decrypt_rsa, get_aes_keys, encrypt_aes_node_pair, decrypt_aes_node_pair, hashval

# Parse the 'controller' argument
is_controller, create_security_manager_controller, netsize, message, signature, verify_HMAC, msg_type, nid, port_id, other_node_id,  generate_dig_rsa_key_pair, generate_dig_ecc_key_pair, generate_own_aes_key, encrypt_ECDH, decrypt_ECDH, sign_data, verify_signature, initiate_session1, initiate_session2, create_hmac_global, create_hmac_set1, create_hmac_set2, verify_key_expiry, is_node, pid, get_rsa_keys, encrypt_rsa, set_aes_key_for_pair, encrypt_controller_data, decrypt_controller_data, generate_global_HMAC_secret_key, get_digital_public_key, get_session_HMAC_1, get_session_HMAC_2, create_global_HMAC_node, decrypt_rsa, get_aes_keys, encrypt_aes_node_pair, decrypt_aes_node_pair, hashval = parse_arguments()

print(f"node id {nid},generate_digrsa {generate_dig_rsa_key_pair}, other node id {other_node_id}")

message = str(message)
#max = 40
n = 4
ID = list()
PX = list()
PY = list()
VX = list()
VY = list()
AX = list()
AY = list()
mobility_scenario = 1;
d_max = 270

csv_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_data.csv"#All other keys

csv_AES_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_AES_data.csv"#AES key pairs

csv_HMAC2_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_HMAC2_data.csv"#HMAC2 keys

csv_HMAC2_other_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data4.csv"#HMAC2 keys



csv_con_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_con_dig_sig_data.csv"

csv_node1_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node1_dig_sig_data.csv"

csv_node2_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node2_dig_sig_data.csv"

csv_global_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_global_HMAC_data.csv"

csv_global_HMAC_verification_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_global_HMAC_verification_data.csv"

csv_node1_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node1_HMAC_data.csv"

csv_node2_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node2_HMAC_data.csv"

csv_nodepair_AES_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_nodepair_AES_data.csv"

csv_ASCON_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data.csv"

csv_ECDH_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ECDH_data.csv"

def search_csv_nodeid(csv_file_path, node_id):
    print(f"searching for node id {node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
                	#print("Found the node ID")
                	return index, True
    f.close()
    print("Node ID not found")
    return -1, False
    
def search_other_csv_nodeid(csv_file_path, node_id, other_node_id):
    print(f"searching for node id {node_id} other node id {other_node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))} and other_node_id is {repr(str(other_node_id))}")
            	if(row[0] == str(node_id)):
            	        if(row[1] == str(other_node_id)):
                           #print("Found the node IDs")
                           return index, True
    f.close()
    print("Node ID not found")
    return -1, False


def search_csv_nodeid_and_key(csv_file_path, node_id, col_index):
    print(f"searching for node id {node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
                	print("Found the node ID")
                	return row[col_index], True
    f.close()
    print("Node ID not found")
    return -1, False
    
def search_csv_nodeid_othernodeid_and_key(csv_file_path, node_id, other_node_id, col_index):
    print(f"searching for node id {node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
            	        if(row[1] == str(other_node_id)):
                	      #print("Found the node ID")
                	      return row[col_index], True
    f.close()
    print("Node ID not found")
    return -1, False


def search_other_other_csv_nodeid(csv_file_path, node_id, other_node_id, port_id):
    print(f"searching for node id {node_id} other node id {other_node_id} port id {port_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))} and other_node_id is {repr(str(other_node_id))}")
            	if(row[0] == str(node_id)):
            	        if(row[1] == str(other_node_id)):
            	            if(row[2] == str(port_id)):
                                #print("Found the node IDs and port ID")
                                return index, True
    f.close()
    print("Node ID and port IDs not found")
    return -1, False    
    
def search_csv_item(csv_file_path, node_id, col_index):
    print(f"searching for node id {node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
                	#print("Found the node ID")
                	return row[col_index], True
    f.close()
    print("Node ID or item not found")
    return -1, False


def search_other_csv_item(csv_file_path, node_id, other_node_id, col_index):
    print(f"searching for node id {node_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
            	       if(row[1] == str(other_node_id)):
                            #print("Found the node ID")
                            return row[col_index], True
    f.close()
    print("Node ID or item not found")
    return -1, False
    
def search_other_other_csv_item(csv_file_path, node_id, other_node_id, port_id, col_index):
    print(f"searching for source node id {node_id} other node id {other_node_id} and port_id {port_id}")
    with open(csv_file_path, 'r', encoding='UTF8') as f:
        reader = csv.reader(f, delimiter=',')
        for index, row in enumerate(reader):
            #print(len(row))
            if len(row) > 0:
            	#print(f"index is {index} and row[0]  is {repr(str(row[0]))} and node_id is {repr(str(node_id))}")
            	if(row[0] == str(node_id)):
            	       if(row[1] == str(other_node_id)):
            	             if(row[2] == str(port_id)):
                                 #print("Found the node ID")
                                 return row[col_index], True
    f.close()
    print("Node ID or item not found")
    return -1, False
    

def add_csv_element(csv_file_path, node_id, col_index, new_value):
    print("Adding csv element")
    # Step 1: Read existing rows
    with open(csv_file_path, 'r', encoding='UTF8', newline='') as f:
        rows = list(csv.reader(f))

    # Step 2: Determine total number of columns
    max_columns = max((len(row) for row in rows), default=0)
    total_columns = max(max_columns, col_index + 1)

    # Step 3: Create new row filled with spaces
    new_row = [" "] * total_columns
    new_row[0] = str(node_id)
    new_row[col_index] = new_value

    # Step 4: Append the new row
    rows.append(new_row)

    # Step 5: Write all rows back to the CSV
    with open(csv_file_path, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)  # uses default comma delimiter
        writer.writerows(rows)
        
        
def add_other_csv_element(csv_file_path, node_id, other_node_id, col_index, new_value):
    print("Adding csv element")
    # Step 1: Read existing rows
    with open(csv_file_path, 'r', encoding='UTF8', newline='') as f:
        rows = list(csv.reader(f))

    # Step 2: Determine total number of columns
    max_columns = max((len(row) for row in rows), default=0)
    total_columns = max(max_columns, col_index + 1)

    # Step 3: Create new row filled with spaces
    new_row = [" "] * total_columns
    new_row[0] = str(node_id)
    new_row[1] = str(other_node_id)
    new_row[col_index] = new_value

    # Step 4: Append the new row
    rows.append(new_row)

    # Step 5: Write all rows back to the CSV
    with open(csv_file_path, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)  # uses default comma delimiter
        writer.writerows(rows)

def add_other_other_csv_element(csv_file_path, node_id, other_node_id, port_id, col_index, new_value):
    print("Adding csv element")
    # Step 1: Read existing rows
    with open(csv_file_path, 'r', encoding='UTF8', newline='') as f:
        rows = list(csv.reader(f))

    # Step 2: Determine total number of columns
    max_columns = max((len(row) for row in rows), default=0)
    total_columns = max(max_columns, col_index + 1)

    # Step 3: Create new row filled with spaces
    new_row = [" "] * total_columns
    new_row[0] = str(node_id)
    new_row[1] = str(other_node_id)
    new_row[2] = str(port_id)
    new_row[col_index] = new_value

    # Step 4: Append the new row
    rows.append(new_row)

    # Step 5: Write all rows back to the CSV
    with open(csv_file_path, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)  # uses default comma delimiter
        writer.writerows(rows)   

def update_csv_element(file_path, row_index, col_index, new_value):
    print("Updating CSV element")

    # Read all rows from the CSV
    with open(file_path, 'r', encoding='UTF8') as csvfile:
        rows = list(csv.reader(csvfile))

    # Validate row and column indices
    if row_index < 0 or row_index >= len(rows):
        raise IndexError("Row index out of bounds.")
    
    if col_index < 0:
        raise IndexError("Column index must be non-negative.")

    # Expand row if necessary
    while len(rows[row_index]) <= col_index:
        rows[row_index].append(" ")

    # Update the specific cell
    #print(f"Before update: {rows[row_index]}")
    rows[row_index][col_index] = str(new_value)
    #print(f"After update: {rows[row_index]}")

    # Write back to the CSV
    with open(file_path, 'w', encoding='UTF8', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(rows)
    
    # Write the updated rows back to the CSV file
    with open(file_path, 'w', encoding='UTF8', newline='') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        print("writing to csv")
        for i in range(len(rows)):
                 #print(i)
                 #print(rows[i])
                 writer.writerow(rows[i])
    csvfile.close()
    





class SecurityManager_controller:
    
    @staticmethod
    def nested_dict():
        return defaultdict(SecurityManager_controller.nested_dict)
    def __init__(self, net_size):
        """
        with open("/root/ns-allinone-3.35/ns-3.35/scratch/controller_security_data.csv",'r',encoding='UTF8') as csvfile:
            csvreader = csv.reader(csvfile,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)
            for row in csvreader:
               p = str(row)
               q = p.split(", ")
               r =0
               for sh in q:
                   if (r==0):
                        print(sh[2:-1])
                        n = int(sh[2:-1])
                   elif (r==1):
                        print(sh[2:-1])
                        ID.append(int(sh[2:-1]))
                   elif (r==2):
              	         PX.append(float(sh[2:-1]))
                   elif (r==3):
                        PY.append(float(sh[2:-1]))
                   elif (r==4):
                        VX.append(float(sh[2:-1]))		
                   elif (r==5):
              	         VY.append(float(sh[2:-1]))
                   elif (r==6):
                        AX.append(float(sh[2:-1]))
                   elif (r==7):
                        AY.append(float(sh[2:-1]))
                   elif (r==8):
                        mobility_scenario = int(sh[2:-1])
                   r = r + 1
        csvfile.close();
        """
        print("Creating controller security instant")
        self.node_IDs = {i for i in range(0, net_size-1)}
        self.own_aes_key = {}
        self.global_hmac_keys = {} #Global HMAC keys
        self.session_hmac_keys_set1 = {}   # Session-based keys set 1
        self.session_hmac_keys_set2 = SecurityManager_controller.nested_dict()
        self.dig_rsa_public_keys = {} #digital signature public keys
        self.dig_rsa_private_keys = {} #digital signature private keys
        self.dig_ecc_alice_private_keys = {} #ECC alice private keys
        self.dig_ecc_bob_private_keys = {} #ECC bob private keys
        self.dig_ecc_alice_public_keys = {} #ECC alice public keys
        self.dig_ecc_bob_public_keys = {} #ECC bob public keys
        self.rsa_public_keys = {}  #RSA-2048 keys between each node and the controller
        self.aes_keys = {} #AES key pairs between node pairs
        self.dig_key_expiry = {}  #Track key expiry times of session-based HMACs
        self.session_hmac1_key_expiry = {}  #Track key expiry times of session-based HMACs set 1
        self.session_hmac2_key_expiry = {}  #Track key expiry times of session-based HMACs set 2
    
    def generate_secret_key(self):
        #print("Generate a random secret key for HMAC.")
        return get_random_bytes(32)  # 256-bit HMAC key
        
    def generate_dig_rsa_key_pair(self, node_id):
        print("Generating digital signature RSA-2048 public/private key pair")
        key = RSA.generate(2048)
        private_key = key.export_key()
        print(f"digital private key size is {len(private_key)}")
        public_key = key.publickey().export_key()
        print(f"digital public key size is {len(public_key)}")
        self.dig_rsa_public_keys[node_id] = public_key
        self.dig_rsa_private_keys[node_id] = private_key
        public_key = public_key.hex()   
        private_key = private_key.hex()
        
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
           if status==True:
           	update_csv_element(csv_file_path, row_index, col_index=1, new_value=public_key)#self.dig_rsa_public_keys[node_id])
           	#update_csv_element(csv_file_path, row_index, col_index=1, new_value=2)
           	update_csv_element(csv_file_path, row_index, col_index=2, new_value=private_key)#self.dig_rsa_private_keys[node_id])
           else:
           	add_csv_element(csv_file_path, node_id, col_index=1, new_value=public_key)#self.dig_rsa_public_keys[node_id])
           	#add_csv_element(csv_file_path, node_id, col_index=1, new_value=2)
           	row_index, status = search_csv_nodeid(csv_file_path, node_id)
           	update_csv_element(csv_file_path, row_index, col_index=2, new_value=private_key)#self.dig_rsa_private_keys[node_id])
          
           print("CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")

    def generate_own_aes_key(self):
        print("Generating AES-256 symmetric key for the controller.")
        self.own_aes_key = get_random_bytes(32)  # 256-bit AES key

    def sign_data(self, data, node_id, port_id, other_node_id, save=False):
        print("Signing data using the RSA private key for node " + str(node_id))
        h = SHA256.new(data.encode('utf-8'))
        private_key, sh = search_csv_nodeid_and_key(csv_file_path, node_id, 2)
        private_key = bytes.fromhex(private_key)
        signature = pkcs1_15.new(RSA.import_key(private_key)).sign(h)
        signature = signature.hex()
        if(save==True):
           try:
               row_index, status = search_other_other_csv_nodeid(csv_con_dig_sig_file_path, node_id, port_id, other_node_id)
           
               if status==True:
           	    update_csv_element(csv_con_dig_sig_file_path, row_index, col_index=3, new_value=signature)
               else:
           	    add_other_other_csv_element(csv_con_dig_sig_file_path, node_id, port_id, other_node_id, col_index=3, new_value=signature)
      
               print("CSV updated successfully!")
           
           except Exception as e:
               print(f"Error: {e}")
        return signature

    def verify_signature(self, data, signature, node_id, port_id, other_node_id):
        print("Verifying signature using RSA public key.")
        #signature, sh1 = search_csv_nodeid_othernodeid_and_key(csv_con_dig_sig_file_path, nid, port_id, 2)
        signature = bytes.fromhex(signature)
        public_key, sh = search_csv_nodeid_and_key(csv_file_path, node_id, 1)
        public_key = bytes.fromhex(public_key)
        h = SHA256.new(data.encode('utf-8'))
        result = False
        try:
            pkcs1_15.new(RSA.import_key(public_key)).verify(h, signature)
            result = True
            print("Signature verified")
        except (ValueError, TypeError):
            result = False
            print("Signature not verified")
        try:
            row_index, status = search_other_other_csv_nodeid(csv_con_dig_sig_file_path, node_id, port_id, other_node_id)
            if status==True:
                update_csv_element(csv_con_dig_sig_file_path, row_index, col_index=4, new_value=result)	
            else:
                add_other_other_csv_element(csv_con_dig_sig_file_path, node_id, port_id, other_node_id, col_index=4, new_value=result)
            print("CSV updated successfully!")
        except Exception as e:
           print(f"Error: {e}")
        
        return result
        
    def set_global_hmac_keys(self, node_id):
        
        self.global_hmac_keys[node_id] = bytes([random.getrandbits(8) for _ in range(32)])
        key = self.global_hmac_keys[node_id].hex()
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
           if status==True:
           	update_csv_element(csv_file_path, row_index, col_index=9, new_value=key)

           else:
           	add_csv_element(csv_file_path, node_id, col_index=9, new_value=key)
           print("CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
            
    def set_session_hmac_keys_set1(self, node_id):
        print("Generate and assign session HMAC keys set 1.")
        self.session_hmac_keys_set1[node_id] = self.generate_secret_key()
        key = self.session_hmac_keys_set1[node_id].hex()
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
           if status==True:
           	update_csv_element(csv_file_path, row_index, col_index=10, new_value=key)

           else:
           	add_csv_element(csv_file_path, node_id, col_index=10, new_value=key)
           print("CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
        print(self.session_hmac_keys_set1[node_id])
        
    def set_session_hmac_keys_set2(self, node_id, other_node_id, port_id):
        print("Generate and assign session HMAC keys set 2.")
        self.session_hmac_keys_set2[node_id][other_node_id][port_id] = self.generate_secret_key()
        key = self.session_hmac_keys_set2[node_id][other_node_id][port_id].hex()
        print(self.session_hmac_keys_set2[node_id][other_node_id][port_id])
        try:
           print("Setting HMAC2 key pairs")
           row_index, status = search_other_other_csv_nodeid(csv_HMAC2_file_path, node_id, other_node_id, port_id)
           if status==True:
                update_csv_element(csv_HMAC2_file_path, row_index, col_index=3, new_value=key)
           else:
                add_other_other_csv_element(csv_HMAC2_file_path, node_id, other_node_id, port_id, col_index=3, new_value=key)
          
           print("CSV updated successfully!")
        except Exception as e:
           print(f"Error: {e}")

    def create_hmac(self, message, key_set, node_id, other_node_id, port_id, store):
        print("Generating HMAC based on a key set (global or session).")
        h = "sh"
        if key_set == 'global':
            key, s1 = search_csv_nodeid_and_key(csv_file_path, node_id, 9)
            print(f"HMAC key is {key}")
            print(f"key size is {len(key)}")
            key = bytes.fromhex(key)
            #key = self.global_hmac_keys[node_id]
            h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
            h = h.hexdigest()
            if store== True:
                try:
                      row_index, status = search_other_other_csv_nodeid(csv_global_HMAC_file_path, node_id, other_node_id, port_id)
		   
                      if status==True:
                           update_csv_element(csv_global_HMAC_file_path, row_index, col_index=3, new_value=h)
		   	
                      else:
                           add_other_other_csv_element(csv_global_HMAC_file_path, node_id, other_node_id, port_id, col_index=3, new_value=h)
	      
                      print("CSV updated successfully!")
		   
                except Exception as e:
                      print(f"Error: {e}")
        elif key_set == 'set1':
            #key = self.session_hmac_keys_set1[node_id]
            key, s1 = search_csv_nodeid_and_key(csv_file_path, node_id, 10)
            print(f"HMAC key is {key}")
            print(f"key size is {len(key)}")
            key = bytes.fromhex(key)
            h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
            h = h.hexdigest()
            if store==True:
                try:
                      row_index, status = search_other_other_csv_nodeid(csv_node1_HMAC_file_path, node_id, port_id, other_node_id)
		   
                      if status==True:
                           update_csv_element(csv_node1_HMAC_file_path, row_index, col_index=3, new_value=h)
		   	
                      else:
                           add_other_other_csv_element(csv_node1_HMAC_file_path, node_id, port_id, other_node_id, col_index=3, new_value=h)
	      
                      print("CSV updated successfully!")
		   
                except Exception as e:
                      print(f"Error: {e}")
		    
        elif key_set == 'set2':
            #key = self.session_hmac_keys_set2[node_id][other_node_id]
            key, s2 = search_other_other_csv_item(csv_HMAC2_other_file_path, node_id, other_node_id, port_id, 4)
            print(f"HMAC key is {key}")
            print(f"key size is {len(key)}")
            key = bytes.fromhex(key)
            h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
            h = h.hexdigest()
            if store==True:
                try:
                      row_index, status = search_other_other_csv_nodeid(csv_node2_HMAC_file_path, node_id, other_node_id, port_id)
		   
                      if status==True:
                           update_csv_element(csv_node2_HMAC_file_path, row_index, col_index=3, new_value=h)
		   	
                      else:
                           add_other_other_csv_element(csv_node2_HMAC_file_path, node_id, other_node_id, port_id, col_index=3, new_value=h)
	      
                      print("CSV updated successfully!")
		   
                except Exception as e:
                      print(f"Error: {e}")
        else:
            raise ValueError("Unknown key set")
        
        
        return h

    def verification_hmac(self, h1, h2, msg_type, node_id, other_node_id, port_id):
        result = (h1==h2)
        print(f"HMAC verification is {result}")
        if msg_type == 1:
           try:
                 row_index, status = search_other_other_csv_nodeid(csv_global_HMAC_verification_file_path, node_id, other_node_id, port_id)
		   
                 if status==True:
                      update_csv_element(csv_global_HMAC_verification_file_path, row_index, col_index=3, new_value=result)
		   	
                 else:
                      add_other_other_csv_element(csv_global_HMAC_verification_file_path, node_id, other_node_id, port_id, col_index=3, new_value=result)
	      
                 print("HMAC verification: CSV updated successfully!")
		   
           except Exception as e:
                 print(f"Error: {e}")
        elif msg_type == 2:
           try:
                 row_index, status = search_other_other_csv_nodeid(csv_node1_HMAC_file_path, node_id, port_id, other_node_id)
		   
                 if status==True:
                      update_csv_element(csv_node1_HMAC_file_path, row_index, col_index=4, new_value=result)
		   	
                 else:
                      add_other_other_csv_element(csv_node1_HMAC_file_path, node_id, port_id, other_node_id, col_index=4, new_value=result)	      
                 print("CSV updated successfully!")
		   
           except Exception as e:
                 print(f"Error: {e}")
		    
        elif msg_type == 3:
           try:
                 row_index, status = search_other_other_csv_nodeid(csv_node2_HMAC_file_path, node_id, other_node_id, port_id)
		   
                 if status==True:
                       update_csv_element(csv_node2_HMAC_file_path, row_index, col_index=4, new_value=result)
		   	
                 else:
                       add_other_other_csv_element(csv_node2_HMAC_file_path, node_id, other_node_id, port_id, col_index=4, new_value=result)
	      
                 print("CSV updated successfully!")
		   
           except Exception as e:
                 print(f"Error: {e}")
        else:
            raise ValueError("Unknown key set")

    def set_dig_key_expiry(self, node_id, expiry_time):
        print("Set the expiry time for Digital Signature keys.")
        self.dig_key_expiry[node_id] = time.time() + expiry_time  # expiry_time in seconds
        
    def set_HMAC_key1_expiry(self, node_id, expiry_time):
        print("Set the expiry time for RSA key set 1.")
        self.session_hmac1_key_expiry[node_id] = time.time() + expiry_time  # expiry_time in seconds
        
    def set_HMAC_key2_expiry(self, node_id, expiry_time):
        print("Set the expiry time for RSA key set 2.")
        self.session_hmac2_key_expiry[node_id] = time.time() + expiry_time  # expiry_time in seconds

    def is_dig_key_expired(self, node_id):
        print("Check if the digital signature key is expired based on its expiry time.")
        status = time.time() > self.dig_key_expiry[node_id]
        if status==False:
        	print("digital signature not expired")
        else:
        	print("digital signature expired")
        return status
    
    def is_HMAC_key1_expired(self, node_id):
        print("Check if the RSA key set 1 is expired based on its expiry time.")
        status = time.time() > self.session_hmac1_key_expiry[node_id]
        if status==False:
        	print("HMAC key 1 not expired")
        else:
        	print("HMAC key 1 expired")
        return status
        
    def is_HMAC_key2_expired(self, node_id):
        print("Check if the RSA key set 2 is expired based on its expiry time.")
        status = time.time() > self.session_hmac2_key_expiry[node_id]
        if status==False:
        	print("HMAC key 2 not expired")
        else:
        	print("HMAC key 2 expired")
        return status
        
    def get_rsa_keys(self, public_key, node_id):
    	print("Getting RSA public key for the controller.")
    	self.rsa_public_keys[node_id] = public_key
    	

    def encrypt_rsa(self, data, node_id):
        print("Encrypting data using RSA public key.")
        rsa_key = RSA.import_key(self.rsa_public_keys[node_id])
        # Using PKCS1_OAEP for encryption (more secure than PKCS1 v1.5)
        cipher = PKCS1_OAEP.new(rsa_key)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))  # Encoding string to bytes
        return encrypted_data
    

    def set_aes_key_for_pair(self, node_id, peer_node_id, port_id):
        print("Generating AES key for a pair of nodes.")
        aes_key = get_random_bytes(32)  #Random 256-bit AES key
        if node_id not in self.aes_keys:
             self.aes_keys[node_id] = {}  # Initialize a nested dictionary for the node
        if peer_node_id not in self.aes_keys[node_id]:
             self.aes_keys[node_id][peer_node_id] = {}
        self.aes_keys[node_id][peer_node_id][port_id] = base64.b64encode(aes_key).decode('utf-8')
        try:
           print("Setting AES key pairs")
           row_index1, status1 = search_other_other_csv_nodeid(csv_AES_file_path, node_id, peer_node_id, port_id)
           row_index2, status2 = search_other_other_csv_nodeid(csv_AES_file_path, peer_node_id, node_id, port_id)
           if status1==True:
                update_csv_element(csv_AES_file_path, row_index1, col_index=3, new_value=self.aes_keys[node_id][peer_node_id][port_id])
           else:
                add_other_other_csv_element(csv_AES_file_path, node_id, peer_node_id, port_id, col_index=3, new_value=self.aes_keys[node_id][peer_node_id][port_id])
           
           if status2==True:
                update_csv_element(csv_AES_file_path, row_index2, col_index=3, new_value=self.aes_keys[node_id][peer_node_id][port_id])
           else:
                add_other_other_csv_element(csv_AES_file_path, peer_node_id, node_id, port_id, col_index=3, new_value=self.aes_keys[node_id][peer_node_id][port_id])
          
           print("CSV updated successfully!")

        except Exception as e:
           print(f"Error: {e}")

    def encrypt_aes(self, data, node_id, other_node_id, port_id):
        print("Encrypt controller data using AES-256")
        print("Reading AES key pairs for encryption")
        aes_key, status1 = search_other_other_csv_item(csv_AES_file_path, node_id, other_node_id, port_id, 3)
        if status1==True:
               aes_key = base64.b64decode(aes_key)
        else:
               aes_key = get_random_bytes(32)
        print(f"AES key is {aes_key} and its length is {len(aes_key)}")
        message_bytes = data.encode('utf-8')
        padded_message = pad(message_bytes, AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_message)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        try:
              row_index, status = search_other_other_csv_nodeid(csv_nodepair_AES_file_path, node_id, other_node_id, port_id)
		   
              if status==True:
                  update_csv_element(csv_nodepair_AES_file_path, row_index, col_index=3, new_value=ciphertext)
		   	
              else:
                  add_other_other_csv_element(csv_nodepair_AES_file_path, node_id, other_node_id, port_id, col_index=3, new_value=ciphertext)
	      
              print("CSV updated successfully!")
		   
        except Exception as e:
              print(f"Error: {e}")
        return ciphertext

    def decrypt_aes(self, message, node_id, other_node_id, port_id):
        print("Decrypt controller data using AES-256")
        print("Reading AES key pairs for decryption")
        aes_key, status1 = search_other_other_csv_item(csv_AES_file_path, node_id, other_node_id, port_id, 3)
        if status1==True:
               aes_key = base64.b64decode(aes_key)
        else:
               aes_key = get_random_bytes(32)
        encrypted_data, status2 = search_other_other_csv_item(csv_nodepair_AES_file_path, node_id, other_node_id, port_id, 3)
        if status2 and encrypted_data:
               encrypted_data = base64.b64decode(encrypted_data)
               ciphertext = encrypted_data;
               if len(ciphertext)!=0:
                   cipher_dec = AES.new(aes_key, AES.MODE_ECB)
                   decrypted_data_padded = cipher_dec.decrypt(ciphertext)
                   decrypted_data = unpad(decrypted_data_padded, AES.block_size)
               else:
                   decrypted_data = b"Nothing decrypted"
        else:
               decrypted_data = b"Nothing decrypted"

        try:
              try:
                  decrypted_data = decrypted_data.decode("utf-8")   # preferred
              except UnicodeDecodeError:
                  decrypted_data = decrypted_data.hex()
                  
              row_index, status = search_other_other_csv_nodeid(csv_nodepair_AES_file_path, node_id, other_node_id, port_id)   
              if status==True:
                  update_csv_element(csv_nodepair_AES_file_path, row_index, col_index=4, new_value=decrypted_data)
		   	
              else:
                  add_other_other_csv_element(csv_nodepair_AES_file_path, node_id, other_node_id, port_id, col_index=4, new_value=decrypted_data)
	      
              print("CSV updated successfully!")
		   
        except Exception as e:
              print(f"Error: {e}")
        
        return decrypted_data
        
    def derive_key(self, shared_point):
    	shared_bytes = int(shared_point.x).to_bytes(32, byteorder='big')
    	return HKDF(shared_bytes, 32, b'', SHA256)
    
    def generate_ecc_key_pair(self, node_id):   
        # Generate ECC key pairs for both parties
        self.dig_ecc_alice_private_keys[node_id] = ECC.generate(curve='P-256')
        alice_private_key = self.dig_ecc_alice_private_keys[node_id].export_key(format='PEM')
        alice_private_key = alice_private_key.replace("\n", "AKDANEBA")
        #print(alice_private_key)
        #alice_private_key = ECC.import_key(alice_private_key)
        self.dig_ecc_bob_private_keys[node_id] = ECC.generate(curve='P-256')
        bob_private_key = self.dig_ecc_bob_private_keys[node_id].export_key(format='PEM')
        bob_private_key = bob_private_key.replace("\n", "AKDANEBA")
   
        # Exchange public keys
        self.dig_ecc_alice_public_keys[node_id] = self.dig_ecc_alice_private_keys[node_id].public_key()
        alice_public_key = self.dig_ecc_alice_public_keys[node_id].export_key(format='PEM')
        alice_public_key = alice_public_key.replace("\n", "AKDANEBA")
        
        self.dig_ecc_bob_public_keys[node_id] = self.dig_ecc_bob_private_keys[node_id].public_key()
        bob_public_key = self.dig_ecc_bob_public_keys[node_id].export_key(format='PEM')
        bob_public_key = bob_public_key.replace("\n", "AKDANEBA")
        
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           if status==True:
               update_csv_element(csv_file_path, row_index, col_index=3, new_value=alice_public_key)
               update_csv_element(csv_file_path, row_index, col_index=4, new_value=alice_private_key)
               update_csv_element(csv_file_path, row_index, col_index=5, new_value=bob_public_key)
               update_csv_element(csv_file_path, row_index, col_index=6, new_value=bob_private_key)
           else:
               add_csv_element(csv_file_path, node_id, col_index=3, new_value=alice_public_key)
               row_index, status = search_csv_nodeid(csv_file_path, node_id)
               update_csv_element(csv_file_path, row_index, col_index=4, new_value=alice_private_key)
               update_csv_element(csv_file_path, row_index, col_index=5, new_value=bob_public_key)
               update_csv_element(csv_file_path, row_index, col_index=6, new_value=bob_private_key)
	  
           print("CSV updated successfully!")
	   
        except Exception as e:
           print(f"Error: {e}")

    def compute_ecc_symmetric_key(self, my_secret_key, other_public_key):
	# Each party computes the shared secret
	
        shared_secret = my_secret_key.d * other_public_key.pointQ
        symmetric_key = self.derive_key(shared_secret)
        """
        alice_shared_secret = alice_key.d * bob_public.pointQ
        bob_shared_secret = bob_key.d * alice_public.pointQ

        alice_symmetric_key = derive_key(alice_shared_secret)
        bob_symmetric_key = derive_key(bob_shared_secret)
	
        # Verify that both keys are identical
        assert alice_symmetric_key == bob_symmetric_key
        """
        return symmetric_key

    def encrypt_ecc(self, message, alice_symmetric_key, node_id, other_node_id, port_id):
        # Encrypt a message using the derived symmetric key
        message = message.encode()
        padded_message = pad(message, AES.block_size)
        cipher = AES.new(alice_symmetric_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_message)
        ciphertext = ciphertext.hex()
        print("Ciphertext size:", len(ciphertext))
        try:
           row_index, status = search_other_other_csv_nodeid(csv_ECDH_file_path, node_id, other_node_id, port_id)
           
           if status==True:
               update_csv_element(csv_ECDH_file_path, row_index, col_index=3, new_value=ciphertext) 	
           else:
           	add_other_other_csv_element(csv_ECDH_file_path, node_id, other_node_id, port_id, col_index=3, new_value=ciphertext)
           print("ECDH Encrypt: CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
        return ciphertext

    def decrypt_ecc(self, ciphertext, bob_symmetric_key, node_id, other_node_id, port_id):
        # Decrypt the message using the symmetric key
        ciphertext = bytes.fromhex(ciphertext)
        cipher_dec = AES.new(bob_symmetric_key, AES.MODE_ECB)
        decrypted_padded = cipher_dec.decrypt(ciphertext)

        # Unpad to retrieve original message
        plaintext = unpad(decrypted_padded, AES.block_size)
        print("Decrypted message:", plaintext.decode())
        try:
           row_index, status = search_other_other_csv_nodeid(csv_ECDH_file_path, node_id, other_node_id, port_id)
           
           if status==True:
               update_csv_element(csv_ECDH_file_path, row_index, col_index=4, new_value=plaintext.decode()) 	
           else:
           	add_other_other_csv_element(csv_ECDH_file_path, node_id, other_node_id, port_id, col_index=4, new_value=plaintext.decode())
           print("ECDH Decrypt: CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")

        return(plaintext.decode())



class SecurityManager_node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.global_hmac_key = None # Global HMAC Key (Self-generated)
        self.session_hmac_keys_set1 = None # Session-based keys
        self.session_hmac_keys_set2 = {} # Session-based keys
        self.public_key, self.private_key = None, None  # RSA key pair
        self.digital_public_key = None
        self.aes_keys = {}  # AES-256 keys between node pairs

    def derive_key(shared_point):
	    shared_bytes = int(shared_point.x).to_bytes(32, byteorder='big')
	    return HKDF(shared_bytes, 32, b'', SHA256)
	    
    def generate_rsa_key_pair(self):
        print("Generating Encryption RSA-2048 public/private key pair")
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        return self.public_key, self.private_key
        
    #Global HMAC key
    def generate_global_HMAC_secret_key(self):
        print("Generate a global random secret key for HMAC.")
        return get_random_bytes(32)  # 256-bit HMAC key

    def generate_aes_key(self):
        print("Generating AES-256 symmetric key for node itself.")
        self.global_hmac_key = get_random_bytes(32)  # 256-bit AES key

    def get_digital_public_key(self, public_key):
    	self.digital_public_key = public_key

    def verify_signature(self, data, signature):
        print("Verifying signature using RSA public key.")
        h = SHA256.new(data.encode('utf-8'))
        try:
            pkcs1_15.new(RSA.import_key(self.digital_public_key)).verify(h, signature)
            print("Signature verified")
            return True
        except (ValueError, TypeError):
            print("Signature not verified")
            return False
            
    def get_session_HMAC_1(self, HMAC_key1):
    	print("Getting session HMAC key 1")
    	self.session_hmac_keys_set1 = HMAC_key1
    	
    def get_session_HMAC_2(self, HMAC_key2, other_node_id):
    	print("Getting session HMAC key 2")
    	self.session_hmac_keys_set2[other_node_id] = HMAC_key2

    def create_hmac(self, message, key_set, other_node_id):
        print("Creating HMAC")
        if key_set == 'global':
            key = self.global_hmac_key
            print("HMAC key is {key}")
        elif key_set == 'set1': 
             key = self.session_hmac_keys_set1
             print("HMAC key is {key}")
        elif key_set == 'set2':
            key = self.session_hmac_keys_set2[other_node_id]
            print("HMAC key is {key}")
            print("Session key")
        else:
            raise ValueError("Unknown key set")
        
        h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()


    def decrypt_rsa(self, encrypted_data, private_key):
        print("Decrypting data using RSA private key.")
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

    def get_aes_keys(self, node_id, peer_node, aes_key):
        print("Getting AES pair keys")
        if node_id not in self.aes_keys:
             self.aes_keys[node_id] = {}
        self.aes_keys[node_id][peer_node] = aes_key
    

    def encrypt_aes(self, data, node_id, peer_node_id):
        print("Encrypting data for link using AES-256 with a specific key")
        aes_key = self.aes_keys[node_id][peer_node_id]
        message_bytes = data.encode('utf-8')
        padded_message = pad(message_bytes, AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext


    def decrypt_aes(self, encrypted_data, node_id, peer_node_id):
        print("Decrypting data for link using AES-256 with a specific key")
        aes_key = self.aes_keys[node_id][peer_node_id]
        ciphertext = encrypted_data;
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_data_padded = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_data_padded, AES.block_size)
        return decrypted_data.decode('utf-8')

ses1_expir_time = 10
ses2_expir_time = 5
dig_expir_time = 10


controller = None
node = [None] * netsize
#node = True
ECDH_ciphertext = "sh"


if is_controller:
    print("Controller mode is enabled")
    #message = "Hello, this is a test message!"
    if create_security_manager_controller:
    	controller = SecurityManager_controller(netsize)
    	print(f"node id id {nid}")
    if generate_global_HMAC_secret_key:
        controller.set_global_hmac_keys(nid)
    if generate_dig_rsa_key_pair:
    	controller.generate_dig_rsa_key_pair(nid)
    	
    if generate_dig_ecc_key_pair:
    	controller.generate_ecc_key_pair(nid)
    	output = search_csv_item(csv_file_path, nid, 1)
    	print(f"output is {output}")
    if encrypt_ECDH:
        alice_private_key, sh1 = search_csv_nodeid_and_key(csv_file_path, nid, 4)
        alice_private_key = alice_private_key.replace("AKDANEBA", "\n")
        alice_private_key = ECC.import_key(alice_private_key)
        bob_public_key, sh = search_csv_nodeid_and_key(csv_file_path, nid, 5)
        bob_public_key = bob_public_key.replace("AKDANEBA", "\n")
        bob_public_key = ECC.import_key(bob_public_key)
        alice_symmetric_key = controller.compute_ecc_symmetric_key(alice_private_key, bob_public_key)
        ECDH_ciphertext = controller.encrypt_ecc(message, alice_symmetric_key, nid, other_node_id, port_id)
        print(f"ECDH ciphertext length is {len(ECDH_ciphertext)}")
    if decrypt_ECDH:
        bob_private_key, sh = search_csv_nodeid_and_key(csv_file_path, nid, 6)
        bob_private_key = bob_private_key.replace("AKDANEBA", "\n")
        bob_private_key = ECC.import_key(bob_private_key)
        alice_public_key, sh = search_csv_nodeid_and_key(csv_file_path, nid, 3)
        alice_public_key = alice_public_key.replace("AKDANEBA", "\n")
        alice_public_key = ECC.import_key(alice_public_key)
        bob_symmetric_key = controller.compute_ecc_symmetric_key(bob_private_key, alice_public_key)
        if encrypt_ECDH:
            ECDH_ciphertext = ECDH_ciphertext
        else:
            ECDH_ciphertext = message
        Decrypted_message = controller.decrypt_ecc(ECDH_ciphertext, bob_symmetric_key, nid, other_node_id, port_id)
        print(f"Decrypted message is {Decrypted_message}")
        print(f"node id id {nid}")
    if generate_own_aes_key:
        controller.generate_own_aes_key()
        print(f"node id id {nid}")
    if sign_data:
        signature = controller.sign_data(message, nid, port_id, other_node_id, True)
        print(f"digital signature size is {len(signature)}")
        controller.set_dig_key_expiry(nid, dig_expir_time)
        print(f"node id id {nid}")
    if verify_signature:
        message = str(message)
        #signature = controller.sign_data(message, nid, port_id, False)
        controller.verify_signature(message, signature, nid, port_id, other_node_id)
        print(f"node id id {nid}")
    if initiate_session1:
    	controller.set_session_hmac_keys_set1(nid)
    	controller.set_HMAC_key1_expiry(nid, ses1_expir_time)
    	print(f"node id id {nid}")
    if initiate_session2:
    	controller.set_session_hmac_keys_set2(nid, other_node_id, port_id)
    	controller.set_HMAC_key2_expiry(nid, ses2_expir_time)
    	nid = nid
    	print(f"node id id {nid}")
    
    if create_hmac_global:
        h1 = controller.create_hmac(message, 'global', nid, other_node_id, port_id, True)
        print(f"HMAC size is {len(h1)}")
    
    if create_hmac_set1:
        h2 = controller.create_hmac(message, 'set1', nid, other_node_id, port_id, True)
        print(f"HMAC size is {len(h2)}")
    
    if create_hmac_set2:
        h3 = controller.create_hmac(message, 'set2', nid, other_node_id, port_id, True)
        print(f"HMAC size is {len(h3)}")
    
    if verify_key_expiry:
    	controller.is_dig_key_expired(nid)
    	controller.is_HMAC_key1_expired(nid)
    	controller.is_HMAC_key2_expired(nid)
    if verify_HMAC:
       h1 = hashval
       if msg_type==1:
           h2 = controller.create_hmac(message, 'global', nid, other_node_id, port_id, store=False)
       if msg_type==2:
           h2 = controller.create_hmac(message, 'set1', nid, other_node_id, port_id, store=False)
       if msg_type==3:
           h2 = controller.create_hmac(message, 'set2', nid, other_node_id, port_id, False)
       controller.verification_hmac(h1, h2, msg_type, nid, other_node_id, port_id)
       print(f"h1 is {h1}")
       print(f"h2 is {h2}")
    if encrypt_aes_node_pair:
       AES_encrypted = controller.encrypt_aes(message, nid, other_node_id, port_id)
    if decrypt_aes_node_pair:
       decrypted_aes_data = controller.decrypt_aes(message, nid, other_node_id, port_id)
       print(f"Decrypted AES data: {decrypted_aes_data}")
    if set_aes_key_for_pair:
       controller.set_aes_key_for_pair(nid, other_node_id, port_id)
           
           
       
           
"""   
if is_node:
	
	print(f"Node mode is enabled node id id {nid}")
	node[nid] = SecurityManager_node(nid)
	node[nid].generate_rsa_key_pair()
	node[nid].generate_aes_key()
	if get_rsa_keys:
		controller.get_rsa_keys(node[nid].public_key, nid)
	if encrypt_rsa:
		encrypted_data = controller.encrypt_rsa(message, nid)
		encrypted_HMAC = controller.encrypt_rsa(str(controller.session_hmac_keys_set1[nid]), nid)
		print(f"Encrypted HMAC size is {len(encrypted_HMAC)}")
		#encrypted_dig_public_key = controller.encrypt_rsa(str(controller.dig_public_keys[nid]), nid)
		#print(f"Encrypted dig public key size is {len(encrypted_dig_public_key)}")
		#encrypted_signature = controller.encrypt_rsa(str(signature), nid)
		#print(f"Encrypted signature size is {len(encrypted_signature)}")
		#encrypted_node_id = controller.encrypt_rsa(str(8), nid)
		#print(f"Encrypted node id size is {len(encrypted_node_id)}")
	if  set_aes_key_for_pair:
		controller.set_aes_key_for_pair(nid, pid)
	if encrypt_controller_data:
		con_enc_data = controller.encrypt_aes(message, nid, other_node_id, port_id)
		print(f"size of message is {len(message)} and size of aes encrypted content is {len(con_enc_data)}")
	if decrypt_controller_data:
		con_dec_data = controller.decrypt_aes(con_enc_data, nid, other_node_id, port_id)
	#print(str(con_dec_data))
	if generate_global_HMAC_secret_key:
		controller.global_hmac_keys[nid] = node[nid].generate_global_HMAC_secret_key()
	if get_digital_public_key:
		node[nid].get_digital_public_key(controller.dig_rsa_public_keys[nid])
		node[nid].verify_signature(message, signature)
	if get_session_HMAC_1:
		node[nid].get_session_HMAC_1(controller.session_hmac_keys_set1[nid])
		HMAC1 = node[nid].create_hmac(message, 'set1', nid)
	if get_session_HMAC_2:
		node[nid].get_session_HMAC_2(controller.session_hmac_keys_set2[nid][other_node_id], other_node_id)
		HMAC2 = node[nid].create_hmac(message, 'set2', other_node_id)
	if create_global_HMAC_node:
		global_HMAC = node[nid].create_hmac(message, 'global', nid)
	if decrypt_rsa:
		decrypted_data =node[nid].decrypt_rsa(encrypted_data, node[nid].private_key)
		print(f"Decrypted RSA data: {decrypted_data}")
	if get_aes_keys:
		node[nid].get_aes_keys(nid, pid, controller.aes_keys[nid][pid])

"""
try:
	
	'''
	# Example of usage
	zk_snark_hmac = ZKSNARKHMAC()

	# Define a session key for 'set1'
	zk_snark_hmac.session_hmac_keys['set1'] = zk_snark_hmac.generate_global_HMAC_secret_key()

	# Prover: Define message and select key set
	message_new = "Hello, zk-SNARK!"
	key_set = 'set1'

	# Prover: Generate HMAC for the message
	hmac_value = zk_snark_hmac.create_hmac(message_new, 'global')
	print(f"Generated HMAC: {hmac_value}")
	
	# Prover: Create arithmetic constraints for HMAC
	hmac_constraint = zk_snark_hmac.create_hmac_constraints(message_new)
	print(f"Arithmetic Constraint: {hmac_constraint}")
	
	# Convert the constraints into QAP
	qap = zk_snark_hmac.create_qap(hmac_constraint)
	print(f"QAP Polynomial: {qap}")


	# Prover: Generate zk-SNARK proof
	secret_key = int.from_bytes(zk_snark_hmac.global_hmac_key, "big")
	#msg_hash = zk_snark_hmac.get_msg_hash(message_new)
	proof = zk_snark_hmac.generate_proof(qap, hmac_value, secret_key,5)
	print(f"Generated Proof: {proof}")
	

	# Verifier: Verify the proof
	is_valid = zk_snark_hmac.verify_proof(proof, qap)
	print(f"Proof is valid: {is_valid}")
	print("Implemented security.")
	'''

	


except AttributeError:
    print('Encountered an attribute error')
    
    
end = time.time()
execution_time_us = (end - start) * 1_000_000  # convert seconds → microseconds
print(f"Execution time: {execution_time_us:.0f} µs")

