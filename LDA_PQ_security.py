import os
import sys
import csv
import time
import numpy as np
import random
import time
import shlex
import oqs
import os
from ascon import encrypt, decrypt
start = time.time()
"""
# Generate a 16-byte key and nonce
key = os.urandom(16)
nonce = os.urandom(16)
associated_data = b"header"
plaintext = b"Hello from ASCON-128!"

# Encrypt
ciphertext = encrypt(key, nonce, associated_data, plaintext, variant="Ascon-128")
print("Ciphertext:", ciphertext.hex())

# Decrypt
decrypted = decrypt(key, nonce, associated_data, ciphertext, variant="Ascon-128")
print("Decrypted:", decrypted.decode())

"""
"""
print("Enabled KEM mechanisms:")
for kem in oqs.get_enabled_kem_mechanisms():
    print(" -", kem)
print("\nEnabled Signature mechanisms:")
for sig in oqs.get_enabled_sig_mechanisms():
    print(" -", sig)
"""

"""
# Function to encrypt (encapsulate) using recipient's public key
def pq_encrypt(public_key: bytes, kem_alg: str = "Kyber1024"):
    with oqs.KeyEncapsulation(kem_alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        print(f"Ciphertext length: {len(ciphertext)} bytes")
        print(f"shared_secret length: {len(shared_secret)} bytes")
    return ciphertext, shared_secret

# Function to decrypt (decapsulate) using own secret key
def pq_decrypt(ciphertext: bytes, secret_key: bytes, kem_alg: str = "Kyber1024"):
    with oqs.KeyEncapsulation(kem_alg, secret_key) as kem:
        # Decapsulate the shared secret using the ciphertext
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


# Generate key pair (simulate receiver side, e.g., Alice)
with oqs.KeyEncapsulation("Kyber1024") as kem:
    public_key = kem.generate_keypair()  # Generate keypair
    secret_key = kem.export_secret_key()  # Export the secret key
    print(f"secret key length: {len(secret_key)} bytes")

# Encrypt using public key (simulate sender side, e.g., Bob)
ciphertext, bob_shared = pq_encrypt(public_key)

# Decrypt using secret key (receiver side)
alice_shared = pq_decrypt(ciphertext, secret_key)
print("Shared key (Bob):   ", bob_shared.hex())
print("Shared key (Alice): ", alice_shared.hex())
print("Match:", bob_shared == alice_shared)
"""

"""
# Function to sign a message using the private key
def pq_sign(message: bytes, secret_key: bytes, sig_alg: str = "Falcon-1024"):
    with oqs.Signature(sig_alg, secret_key) as signer:
        signature = signer.sign(message)
    return signature

# Function to verify a signature using the public key
def pq_verify(message: bytes, signature: bytes, public_key: bytes, sig_alg: str = "Falcon-1024"):
    with oqs.Signature(sig_alg) as verifier:
        return verifier.verify(message, signature, public_key)

# Generate key pair
with oqs.Signature("Falcon-1024") as signer:
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()
    print(f"Public key length: {len(public_key)} bytes")
    print(f"Secret key length: {len(secret_key)} bytes")
    

# Message to be signed
message = b"Quantum-safe signature test"

# Sign the message
signature = pq_sign(message, secret_key)
print(f"Signature length: {len(signature)} bytes")


# Verify the signature
is_valid = pq_verify(message, signature, public_key)
print("Signature valid:", is_valid)

"""

# Check for the 'controller' argument
def parse_arguments():
    is_controller = False
    message = None
    signature = None
    msg_type = 0
    create_security_manager_controller = False
    netsize = None
    nid = 0
    port_id = 0
    sign_FALCON=False
    verify_FALCON=False
    generate_FALCON=False
    encrypt_ASCON = False
    decrypt_ASCON = False
    generate_ASCON_key = False
    other_node_id = 0
    generate_dig_ecc_key_pair = False
    generate_dig_rsa_key_pair = False
    generate_own_aes_key = False
    encrypt_ECDH = False
    decrypt_ECDH = False
    sign_data = False
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
            print(nid)
        if arg.startswith("port_id="):
            #print(arg.split("=")[1])
            port_id = int(arg.split("=")[1])
            print(f"port id {port_id}")
        if arg.startswith("encrypt_ASCON="):
            #print(arg.split("=")[1])
            encrypt_ASCON = arg.split("=")[1] == "true"
            print(encrypt_ASCON)
        if arg.startswith("decrypt_ASCON="):
            #print(arg.split("=")[1])
            decrypt_ASCON = arg.split("=")[1] == "true"
            print(decrypt_ASCON)
        if arg.startswith("generate_ASCON_key="):
            #print(arg.split("=")[1])
            generate_ASCON_key = arg.split("=")[1] == "true"
            print(generate_ASCON_key)
        if arg.startswith("sign_FALCON="):
            #print(arg.split("=")[1])
            sign_FALCON = arg.split("=")[1] == "true"
            print(sign_FALCON)
        if arg.startswith("verify_FALCON="):
            #print(arg.split("=")[1])
            verify_FALCON = arg.split("=")[1] == "true"
            print(verify_FALCON)
        if arg.startswith("generate_FALCON="):
            #print(arg.split("=")[1])
            generate_FALCON = arg.split("=")[1] == "true"
            print(generate_FALCON)
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
        if arg.startswith("signature="):
            signature = arg.split("=", 1)[1]  # Extract the actual message string
            print("Received signature:", signature)
        if arg.startswith("msg_type="):
            msg_type = int(arg.split("=")[1])  # Extract the actual message type
            print("message type:", msg_type)
    return is_controller, create_security_manager_controller, netsize, message, signature, msg_type, nid, port_id, encrypt_ASCON, decrypt_ASCON, generate_ASCON_key, sign_FALCON, verify_FALCON, generate_FALCON,other_node_id, generate_dig_rsa_key_pair, generate_dig_ecc_key_pair, generate_own_aes_key, encrypt_ECDH, decrypt_ECDH, sign_data, verify_signature, initiate_session1, initiate_session2, create_hmac_global, create_hmac_set1, create_hmac_set2, verify_key_expiry, is_node, pid, get_rsa_keys, encrypt_rsa, set_aes_key_for_pair, encrypt_controller_data, decrypt_controller_data, generate_global_HMAC_secret_key, get_digital_public_key, get_session_HMAC_1, get_session_HMAC_2, create_global_HMAC_node, decrypt_rsa, get_aes_keys, encrypt_aes_node_pair, decrypt_aes_node_pair

# Parse the 'controller' argument
is_controller, create_security_manager_controller, netsize, message, signature, msg_type, nid, port_id, encrypt_ASCON, decrypt_ASCON, generate_ASCON_key, sign_FALCON, verify_FALCON, generate_FALCON, other_node_id, generate_dig_rsa_key_pair, generate_dig_ecc_key_pair, generate_own_aes_key, encrypt_ECDH, decrypt_ECDH, sign_data, verify_signature, initiate_session1, initiate_session2, create_hmac_global, create_hmac_set1, create_hmac_set2, verify_key_expiry, is_node, pid, get_rsa_keys, encrypt_rsa, set_aes_key_for_pair, encrypt_controller_data, decrypt_controller_data, generate_global_HMAC_secret_key, get_digital_public_key, get_session_HMAC_1, get_session_HMAC_2, create_global_HMAC_node, decrypt_rsa, get_aes_keys, encrypt_aes_node_pair, decrypt_aes_node_pair = parse_arguments()


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


csv_con_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_con_dig_sig_data.csv"

csv_node1_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node1_dig_sig_data.csv"

csv_node2_dig_sig_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node2_dig_sig_data.csv"

csv_global_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_global_HMAC_data.csv"

csv_node1_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node1_HMAC_data.csv"

csv_node2_HMAC_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_node2_HMAC_data.csv"

csv_nodepair_AES_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_nodepair_AES_data.csv"

csv_ASCON_file_path1 = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data1.csv"
csv_ASCON_file_path2 = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data2.csv"
csv_ASCON_file_path3 = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data3.csv"
csv_ASCON_file_path4 = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ASCON_data4.csv"

csv_ECDH_file_path = "/root/ns-allinone-3.35/ns-3.35/scratch/security_ECDS_data.csv"

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
    
def search_csv_nodeid_and_key(csv_file_path, node_id, col_index):
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
                            #print("Found the node IDs")
                            return row[col_index], True
    f.close()
    print("Node ID or item not found")
    return -1, False
    

def search_other_csv_item_portid(csv_file_path, node_id, other_node_id, port_id, col_index):
    print(f"searching for node ids {node_id} and port_id {port_id}")
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
        self.ascon_key = {}
        self.ascon_nonce = {}
        #self.session_hmac_keys_set2 = defaultdict(dict)
        self.dig_Falcon1024_public_keys = {} #digital signature public keys
        self.dig_Falcon1024_private_keys = {} #digital signature private keys
    
    # Generate key pair
    def generate_FALCON1024_key_pair(self, node_id):
        with oqs.Signature("Falcon-1024") as signer:
            self.dig_Falcon1024_public_keys[node_id] = signer.generate_keypair()
            self.dig_Falcon1024_private_keys[node_id] = signer.export_secret_key()
            self.dig_Falcon1024_public_keys[node_id] = self.dig_Falcon1024_public_keys[node_id].hex()
            self.dig_Falcon1024_private_keys[node_id] =  self.dig_Falcon1024_private_keys[node_id].hex()
            print(f"Public key length: {len(self.dig_Falcon1024_public_keys[node_id])} bytes")
            print(f"Secret key length: {len(self.dig_Falcon1024_private_keys[node_id])} bytes") 
            
            try:
                row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
                if status==True:
                    update_csv_element(csv_file_path, row_index, col_index=7, new_value=self.dig_Falcon1024_public_keys[node_id])
                    #update_csv_element(csv_file_path, row_index, col_index=1, new_value=2)
                    update_csv_element(csv_file_path, row_index, col_index=8, new_value=self.dig_Falcon1024_private_keys[node_id])
                else:
                    add_csv_element(csv_file_path, node_id, col_index=7, new_value=self.dig_Falcon1024_public_keys[node_id])
                    #add_csv_element(csv_file_path, node_id, col_index=1, new_value=2)
                    row_index, status = search_csv_nodeid(csv_file_path, node_id)
                    update_csv_element(csv_file_path, row_index, col_index=8, new_value=self.dig_Falcon1024_private_keys[node_id])
          
                print("FALCON key generation: CSV updated successfully!")
            except Exception as e:
                print(f"Error: {e}")
    # Function to sign a message using the private key
    
    def pq_sign(self, message: bytes, secret_key: bytes, sig_alg: str = "Falcon-1024", node_id=nid, other_node_id=other_node_id, port_id=port_id):
        with oqs.Signature(sig_alg, secret_key) as signer:
            signature = signer.sign(message)
            signature = signature.hex()
        try:
           row_index, status = search_other_other_csv_nodeid(csv_node1_dig_sig_file_path, node_id, other_node_id, port_id)
           
           if status==True:
           	#update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=1, new_value=port_id)
           	update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=3, new_value=signature)
           	update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=5, new_value=len(signature))
           	
           else:
           	add_other_other_csv_element(csv_node1_dig_sig_file_path, node_id, other_node_id, port_id, col_index=3, new_value=signature)
           	row_index, status = search_other_other_csv_nodeid(csv_node1_dig_sig_file_path, node_id, other_node_id, port_id)
           	update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=5, new_value=len(signature))
      
           print("FALCON sign node 1: CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
        return signature
    def pq_sign_node2(self, message: bytes, secret_key: bytes, sig_alg: str = "Falcon-1024", node_id=nid, other_node_id=other_node_id, port_id=port_id):
        with oqs.Signature(sig_alg, secret_key) as signer:
            signature = signer.sign(message)
            signature = signature.hex()
        try:
           row_index, status = search_other_other_csv_nodeid(csv_node2_dig_sig_file_path, node_id, other_node_id, port_id)
           
           if status==True:
               #update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=1, new_value=other_id)
               #update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=1, new_value=port_id)
               update_csv_element(csv_node2_dig_sig_file_path, row_index, col_index=3, new_value=signature)
               update_csv_element(csv_node2_dig_sig_file_path, row_index, col_index=5, new_value=len(signature))
           	
           else:
           	add_other_other_csv_element(csv_node2_dig_sig_file_path, node_id, other_node_id, port_id, col_index=3, new_value=signature)
           	row_index, status = search_other_other_csv_nodeid(csv_node2_dig_sig_file_path, node_id, other_node_id, port_id)
           	update_csv_element(csv_node2_dig_sig_file_path, row_index, col_index=5, new_value=len(signature))
      
           print("Falcon sign node 2: CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
        return signature

    # Function to verify a signature using the public key
    def pq_verify(self, message: bytes, signature: bytes, public_key: bytes, sig_alg: str = "Falcon-1024", node_id=nid, other_node_id=other_node_id, port_id=port_id):
        with oqs.Signature(sig_alg) as verifier:
            result = verifier.verify(message, signature, public_key)
            try:
               row_index, status = search_other_other_csv_nodeid(csv_node1_dig_sig_file_path, node_id, other_node_id, port_id)
           
               if status==True:
           	      #update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=1, new_value=port_id)
           	      update_csv_element(csv_node1_dig_sig_file_path, row_index, col_index=4, new_value=result)
           	
               else:
           	      add_other_other_csv_element(csv_node1_dig_sig_file_path, node_id, other_node_id, port_id, col_index=4, new_value=result)
      
               print("Falcon node1 verify: CSV updated successfully!")
           
            except Exception as e:
               print(f"Error: {e}")
            return result
            
    def pq_verify_node2(self, message: bytes, signature: bytes, public_key: bytes, sig_alg: str = "Falcon-1024", node_id=nid, other_node_id=other_node_id, port_id=port_id):
        with oqs.Signature(sig_alg) as verifier:
            result = verifier.verify(message, signature, public_key)
            try:
               row_index, status = search_other_other_csv_nodeid(csv_node2_dig_sig_file_path, node_id, other_node_id, port_id)
           
               if status==True:
                     update_csv_element(csv_node2_dig_sig_file_path, row_index, col_index=4, new_value=result)  	
               else:
           	      add_other_other_csv_element(csv_node2_dig_sig_file_path, node_id, other_node_id, port_id, col_index=4, new_value=result)
      
               print("Falcon node2 verify: CSV updated successfully!")
           
            except Exception as e:
               print(f"Error: {e}")
            return result
  
    def generate_ASCON_secret_key(self, node_id):
        # Generate a 16-byte key and nonce
        self.ascon_key[node_id] = os.urandom(16)
        print(self.ascon_key[node_id].hex())
        self.ascon_nonce[node_id] = os.urandom(16)
        print(self.ascon_nonce[node_id].hex())
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
           if status==True:
           	update_csv_element(csv_file_path, row_index, col_index=11, new_value=self.ascon_key[node_id].hex())
           	update_csv_element(csv_file_path, row_index, col_index=12, new_value=self.ascon_nonce[node_id].hex())

           else:
           	add_csv_element(csv_file_path, node_id, col_index=11, new_value=self.ascon_key[node_id].hex())
           	#add_csv_element(csv_file_path, node_id, col_index=1, new_value=2)
           	row_index, status = search_csv_nodeid(csv_file_path, node_id)
           	update_csv_element(csv_file_path, row_index, col_index=12, new_value=self.ascon_nonce[node_id].hex())
           print("ASCON key generation: CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
           print("error occurred.")
        
    # Encrypt
    def encrypt_ASCON(self, plaintext, associated_data, node_id, other_node_id, port_id, msg_type):
        csv_p = "sh"
        if(msg_type == 1):
            csv_p =  csv_ASCON_file_path1
        if(msg_type == 2):
            csv_p = csv_ASCON_file_path2
        if(msg_type == 3):
            csv_p = csv_ASCON_file_path3
        if(msg_type == 4):
            csv_p = csv_ASCON_file_path4
        key, s1 = search_csv_nodeid_and_key(csv_file_path, node_id, 11)
        key = bytes.fromhex(key)
        #print(f"{key} and {len(key)} and {len(self.ascon_key[node_id])}")
        nonce, s2 = search_csv_nodeid_and_key(csv_file_path, node_id, 12)
        nonce = bytes.fromhex(nonce)
        #print(f"{nonce} and {len(nonce)} and {len(self.ascon_nonce[node_id])}")
        ciphertext = encrypt(key, nonce, associated_data, plaintext, variant="Ascon-128")
        print("ASCON Ciphertext:", ciphertext.hex())
        print("ASCON Ciphertext length:", len(ciphertext.hex()))
        try:
           if(msg_type != 4):
                  row_index, status = search_other_csv_nodeid(csv_p, node_id, port_id)
                  if status==True:
                       update_csv_element(csv_p, row_index, col_index=2, new_value=ciphertext.hex()) 	
                  else:
                       add_other_csv_element(csv_p, node_id, port_id, col_index=2, new_value=ciphertext.hex())
           else:
                  row_index, status = search_other_other_csv_nodeid(csv_p, node_id, other_node_id, port_id)
                  if status==True:
                       update_csv_element(csv_p, row_index, col_index=3, new_value=ciphertext.hex()) 	
                  else:
                       add_other_other_csv_element(csv_p, node_id, other_node_id, port_id, col_index=3, new_value=ciphertext.hex())
           
           print("ASCON: encryption: CSV ASCON updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")
        return ciphertext.hex()
    
    # Decrypt
    def decrypt_ASCON(self, ciphertext, associated_data, node_id, other_node_id, port_id, msg_type):
        ciphertext = bytes.fromhex(ciphertext)
        key, s1 = search_csv_nodeid_and_key(csv_file_path, node_id, 11)
        key = bytes.fromhex(key)
        nonce, s2 = search_csv_nodeid_and_key(csv_file_path, node_id, 12)
        nonce = bytes.fromhex(nonce)
        print(f"node_id={node_id}, key={key}, nonce={nonce}, ciphertext={ciphertext.hex()}, ciphertext_length={len(ciphertext.hex())} msg_type={msg_type}")
        decrypted = decrypt(key, nonce, associated_data, ciphertext, variant="Ascon-128")
        csv_p = "sh"
        if(msg_type == 1):
            csv_p =  csv_ASCON_file_path1
        if(msg_type == 2):
            csv_p = csv_ASCON_file_path2
        if(msg_type == 3):
            csv_p = csv_ASCON_file_path3
        if(msg_type == 4):
            csv_p = csv_ASCON_file_path4
        try:
           if(msg_type !=4):
                  row_index, status = search_other_csv_nodeid(csv_p, node_id, port_id)
                  if status==True:
                        update_csv_element(csv_p, row_index, col_index=3, new_value=decrypted.decode()) 	
                  else:
                        add_other_csv_element(csv_p, node_id, port_id, col_index=3, new_value=decrypted.decode())
           else:
                  row_index, status = search_other_other_csv_nodeid(csv_p, node_id, other_node_id, port_id)
                  if status==True:
                        update_csv_element(csv_p, row_index, col_index=4, new_value=decrypted.decode()) 	
                  else:
                        add_other_other_csv_element(csv_p, node_id, other_node_id, port_id, col_index=4, new_value=decrypted.decode())
           print("ASCON decryption: CSV updated successfully!")
        except Exception as e:
           print(f"Error: {e}")
        print("Decrypted:", decrypted.decode())
        


"""         
    def generate_dig_rsa_key_pair(self, node_id):
        print("Generating digital signature RSA-2048 public/private key pair")
        key = RSA.generate(2048)
        private_key = key.export_key()
        print(f"digital private key size is {len(private_key)}")
        public_key = key.publickey().export_key()
        print(f"digital public key size is {len(public_key)}")
        self.dig_rsa_public_keys[node_id] = public_key
        self.dig_rsa_private_keys[node_id] = private_key
        
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           
           if status==True:
           	update_csv_element(csv_file_path, row_index, col_index=1, new_value=self.dig_rsa_public_keys[node_id])
           	#update_csv_element(csv_file_path, row_index, col_index=1, new_value=2)
           	update_csv_element(csv_file_path, row_index, col_index=2, new_value=self.dig_rsa_private_keys[node_id])
           else:
           	add_csv_element(csv_file_path, node_id, col_index=1, new_value=self.dig_rsa_public_keys[node_id])
           	#add_csv_element(csv_file_path, node_id, col_index=1, new_value=2)
           	row_index, status = search_csv_nodeid(csv_file_path, node_id)
           	update_csv_element(csv_file_path, row_index, col_index=2, new_value=self.dig_rsa_private_keys[node_id])
          
           print("CSV updated successfully!")
           
        except Exception as e:
           print(f"Error: {e}")

    def generate_own_aes_key(self):
        print("Generating AES-256 symmetric key for the controller.")
        self.own_aes_key = get_random_bytes(32)  # 256-bit AES key

    def sign_data(self, data, node_id):
        print("Signing data using the RSA private key for node " + str(node_id))
        h = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(RSA.import_key(self.dig_rsa_private_keys[node_id])).sign(h)
        return signature

    def verify_signature(self, data, signature, node_id):
        print("Verifying signature using RSA public key.")
        h = SHA256.new(data.encode('utf-8'))
        try:
            pkcs1_15.new(RSA.import_key(self.dig_rsa_public_keys[node_id])).verify(h, signature)
            print("Signature verified")
            return True
        except (ValueError, TypeError):
            print("Signature not verified")
            return False
            
    def set_session_hmac_keys_set1(self, node_id):
        print("Generate and assign session HMAC keys set 1.")
        self.session_hmac_keys_set1[node_id] = self.generate_secret_key()
        print(self.session_hmac_keys_set1[node_id])
        
    def set_session_hmac_keys_set2(self, node_id, other_node_id):
        print("Generate and assign session HMAC keys set 2.")
        self.session_hmac_keys_set2[node_id][other_node_id] = self.generate_secret_key()
        print(self.session_hmac_keys_set2[node_id][other_node_id])

    def create_hmac(self, message, key_set, node_id, other_node_id):
        print("Generating HMAC based on a key set (global or session).")
        if key_set == 'global':
            key = self.global_hmac_keys[node_id]
        elif key_set == 'set1':
            key = self.session_hmac_keys_set1[node_id]
        elif key_set == 'set2':
            key = self.session_hmac_keys_set2[node_id][other_node_id]
        else:
            raise ValueError("Unknown key set")
        
        h = hmac.new(key, message.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()



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
    

    def set_aes_key_for_pair(self, node_id, peer_node_id):
        print("Generating AES key for a pair of nodes.")
        aes_key = get_random_bytes(32)  #Random 256-bit AES key
        if node_id not in self.aes_keys:
             self.aes_keys[node_id] = {}  # Initialize a nested dictionary for the node
        self.aes_keys[node_id][peer_node_id] = aes_key

    def encrypt_aes(self, data):
        print("Encrypt controller data using AES-256")
        aes_key = self.own_aes_key
        message_bytes = data.encode('utf-8')
        padded_message = pad(message_bytes, AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    def decrypt_aes(self, encrypted_data):
        print("Decrypt controller data using AES-256")
        aes_key = self.own_aes_key
        ciphertext = encrypted_data;
        cipher_dec = AES.new(self.own_aes_key, AES.MODE_ECB)
        decrypted_data_padded = cipher_dec.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_data_padded, AES.block_size)
        return decrypted_data.decode('utf-8')
        
    def derive_key(self, shared_point):
    	shared_bytes = int(shared_point.x).to_bytes(32, byteorder='big')
    	return HKDF(shared_bytes, 32, b'', SHA256)
    
    def generate_ecc_key_pair(self, node_id):   
        # Generate ECC key pairs for both parties
        self.dig_ecc_alice_private_keys[node_id] = ECC.generate(curve='P-256')
        self.dig_ecc_bob_private_keys[node_id] = ECC.generate(curve='P-256')
        # Exchange public keys
        self.dig_ecc_alice_public_keys[node_id] = self.dig_ecc_alice_private_keys[node_id].public_key()
        self.dig_ecc_bob_public_keys[node_id] = self.dig_ecc_bob_private_keys[node_id].public_key()
        
        try:
           row_index, status = search_csv_nodeid(csv_file_path, node_id)
           if status==True:
               update_csv_element(csv_file_path, row_index, col_index=3, new_value=self.dig_ecc_alice_public_keys[node_id])
               update_csv_element(csv_file_path, row_index, col_index=4, new_value=self.dig_ecc_alice_private_keys[node_id])
               update_csv_element(csv_file_path, row_index, col_index=5, new_value=self.dig_ecc_bob_public_keys[node_id])
               update_csv_element(csv_file_path, row_index, col_index=6, new_value=self.dig_ecc_bob_private_keys[node_id])
           else:
               add_csv_element(csv_file_path, node_id, col_index=3, new_value=self.dig_ecc_alice_public_keys[node_id])
               row_index, status = search_csv_nodeid(csv_file_path, node_id)
               update_csv_element(csv_file_path, row_index, col_index=4, new_value=self.dig_ecc_alice_private_keys[node_id])
               update_csv_element(csv_file_path, row_index, col_index=5, new_value=self.dig_ecc_bob_public_keys[node_id])
               update_csv_element(csv_file_path, row_index, col_index=6, new_value=self.dig_ecc_bob_private_keys[node_id])
	  
           print("CSV updated successfully!")
	   
        except Exception as e:
           print(f"Error: {e}")

    def compute_ecc_symmetric_key(self, my_secret_key, other_public_key):
	# Each party computes the shared secret
	
        shared_secret = my_secret_key.d * other_public_key.pointQ
        symmetric_key = self.derive_key(shared_secret)
        return symmetric_key

    def encrypt_ecc(self, message, alice_symmetric_key):
        # Encrypt a message using the derived symmetric key
        message = message.encode()
        padded_message = pad(message, AES.block_size)
        cipher = AES.new(alice_symmetric_key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(padded_message)
        print("Ciphertext size:", len(ciphertext))
        return(ciphertext)

    def decrypt_ecc(self, ciphertext, bob_symmetric_key):
        # Decrypt the message using the symmetric key
        cipher_dec = AES.new(bob_symmetric_key, AES.MODE_ECB)
        decrypted_padded = cipher_dec.decrypt(ciphertext)

        # Unpad to retrieve original message
        plaintext = unpad(decrypted_padded, AES.block_size)
        print("Decrypted message:", plaintext.decode())
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
            print("Global key")
        elif key_set == 'set1': 
             key = self.session_hmac_keys_set1
        elif key_set == 'set2':
            key = self.session_hmac_keys_set2[other_node_id]
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

"""
controller = None
node = [None] * netsize
#node = True
ECDH_ciphertext = "sh"

if is_controller:
    print("Controller mode is enabled")
    message = str(message)
    message = message.encode()
    if create_security_manager_controller:
    	controller = SecurityManager_controller(netsize)
    associated_data = b"header"
    plaintext = b"Hello from ASCON-128!"
    if generate_ASCON_key:
       controller.generate_ASCON_secret_key(nid)
    ASCON_ciphertext = "sh"
    msg_type = int(msg_type)
    if encrypt_ASCON:
    	ASCON_ciphertext = controller.encrypt_ASCON(message, associated_data, nid, other_node_id, port_id, msg_type)
    	
    if decrypt_ASCON:
       if encrypt_ASCON:
            controller.decrypt_ASCON(ASCON_ciphertext, associated_data, nid, other_node_id, port_id, msg_type)
       else:
            message = message.decode()
            print(f"message is {message}")
            controller.decrypt_ASCON(message, associated_data, nid, other_node_id, port_id, msg_type)
       
    # Message to be signed
    if generate_FALCON:
       controller.generate_FALCON1024_key_pair(nid)
    #message = b"Quantum-safe signature test"

            
    # Sign the message
    #print(controller.dig_Falcon1024_private_keys[nid])
    if sign_FALCON:
       #print(controller.dig_Falcon1024_private_keys[nid]==dig_Falcon1024_private_key)
       if msg_type==1:
           dig_Falcon1024_private_key, sh = search_csv_nodeid_and_key(csv_file_path, nid, 8)
           dig_Falcon1024_private_key = bytes.fromhex(dig_Falcon1024_private_key)
           signature = controller.pq_sign(message, dig_Falcon1024_private_key, "Falcon-1024", nid, other_node_id, port_id)
           print(f"Signature length: {len(signature)}")
       elif msg_type==2:
           dig_Falcon1024_private_key, sh = search_csv_nodeid_and_key(csv_file_path, other_node_id, 8)
           dig_Falcon1024_private_key = bytes.fromhex(dig_Falcon1024_private_key)
           signature2 = controller.pq_sign_node2(message, dig_Falcon1024_private_key, "Falcon-1024", nid, other_node_id, port_id)
           print(f"Signature length: {len(signature2)}")
       

    if verify_FALCON:
    # Verify the signature
       if msg_type==1:
           dig_Falcon1024_public_key, sh = search_csv_nodeid_and_key(csv_file_path, nid, 7)
           dig_Falcon1024_public_key = bytes.fromhex(dig_Falcon1024_public_key)
           signature = str(signature)
           signature = signature.strip()
           length, status = search_other_csv_item_portid(csv_node1_dig_sig_file_path, nid, other_node_id, port_id, 5)
           print(length)
           length = int(length)
           print(f"signature size is {length}")
           signature = bytes.fromhex(signature[:length])
       elif msg_type==2:
           dig_Falcon1024_public_key, sh = search_csv_nodeid_and_key(csv_file_path, other_node_id, 7)
           dig_Falcon1024_public_key = bytes.fromhex(dig_Falcon1024_public_key)
           signature = str(signature)
           signature = signature.strip()
           length, status = search_other_csv_item_portid(csv_node2_dig_sig_file_path, nid, other_node_id, port_id, 5)
           print(length)
           length = int(length)
           print(f"signature size is {length}")
           signature = bytes.fromhex(signature[:length])
       if sign_FALCON:       
           if msg_type==1:
               is_valid = controller.pq_verify(message, signature, dig_Falcon1024_public_key, "Falcon-1024", nid, other_node_id, port_id)
               print("Signature valid:", is_valid)
           elif msg_type==2:
               is_valid2 = controller.pq_verify_node2(message, signature, dig_Falcon1024_public_key, "Falcon-1024",  nid, other_node_id, port_id)
               print("Signature valid:", is_valid2)
       else:
           if msg_type==1:
               is_valid = controller.pq_verify(message, signature, dig_Falcon1024_public_key, "Falcon-1024", nid, other_node_id, port_id)
               print("Signature valid:", is_valid)
           elif msg_type==2:
               is_valid2 = controller.pq_verify_node2(message, signature, dig_Falcon1024_public_key, "Falcon-1024",  nid, other_node_id, port_id)
               print("Signature valid:", is_valid2)
           
"""    	
    if generate_dig_ecc_key_pair:
    	controller.generate_ecc_key_pair(nid)
    	output = search_csv_item(csv_file_path, nid, 1)
    	print(f"output is {output}")
    if encrypt_ECDH:
        alice_symmetric_key = controller.compute_ecc_symmetric_key(controller.dig_ecc_alice_private_keys[nid], controller.dig_ecc_bob_public_keys[nid])
        ECDH_ciphertext = controller.encrypt_ecc(message, alice_symmetric_key)
        print("ECDH ciphertext {ECDH_ciphertext}")
    if decrypt_ECDH:
        bob_symmetric_key = controller.compute_ecc_symmetric_key(controller.dig_ecc_bob_private_keys[nid], controller.dig_ecc_alice_public_keys[nid])
        Decrypted_message = controller.decrypt_ecc(ECDH_ciphertext, bob_symmetric_key)
        print("Decrypted message is {Decrypted_message}")
    if generate_own_aes_key:
        controller.generate_own_aes_key()
    if sign_data:
        signature = controller.sign_data(message, nid)
        print(f"digital signature size is {len(signature)}")
        controller.set_dig_key_expiry(nid, dig_expir_time)
    if verify_signature:
        controller.verify_signature(message, signature, 0)
    if initiate_session1:
    	controller.set_session_hmac_keys_set1(nid)
    	controller.set_HMAC_key1_expiry(nid, ses1_expir_time)
    if initiate_session2:
    	controller.set_session_hmac_keys_set2(nid, other_node_id)
    	controller.set_HMAC_key2_expiry(nid, ses2_expir_time)
    
    if create_hmac_global:
        controller.create_hmac(message, 'global', nid)
    
    if create_hmac_set1:
        controller.create_hmac(message, 'set1', nid, nid)
    
    if create_hmac_set2:
        controller.create_hmac(message, 'set2', nid, other_node_id)
    
    if verify_key_expiry:
    	controller.is_dig_key_expired(nid)
    	controller.is_HMAC_key1_expired(nid)
    	controller.is_HMAC_key2_expired(nid)
   
if is_node:
	
	print("Node mode is enabled")
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
		con_enc_data = controller.encrypt_aes(message)
		print(f"size of message is {len(message)} and size of aes encrypted content is {len(con_enc_data)}")
	if decrypt_controller_data:
		con_dec_data = controller.decrypt_aes(con_enc_data)
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
	if encrypt_aes_node_pair:
		AES_encrypted = node[nid].encrypt_aes(message, nid, pid)
	if decrypt_aes_node_pair:
		decrypted_aes_data = node[nid].decrypt_aes(AES_encrypted, nid, pid)
		print(f"Decrypted AES data: {decrypted_aes_data}")

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
"""
end = time.time()
execution_time_us = (end - start) * 1_000_000  # convert seconds → microseconds
print(f"Execution time: {execution_time_us:.0f} µs")

