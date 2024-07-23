import os
import json
import binascii
import getpass
from bitcoin import *
import qrcode
import requests
from flask import Flask, request, jsonify
import bip32utils
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# Paths to store the keys
MASTER_KEY_FILE = 'master_key.enc'
PRIVATE_KEYS_FILE = 'private_keys.enc'
SALT_FILE = 'salt.bin'

# Generate a salt for KDF
def generate_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

# Derive a key from the user's password
def derive_key_from_password(password):
    salt = generate_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# Generate and save the master key on the first run
def generate_master_key(password):
    key = derive_key_from_password(password)
    if not os.path.exists(MASTER_KEY_FILE):
        master_private_key = random_key()
        master_public_key = privtopub(master_private_key)
        master_data = {
            'master_private_key': master_private_key,
            'master_public_key': master_public_key
        }
        encrypted_master_data = encrypt_data(json.dumps(master_data), key)
        with open(MASTER_KEY_FILE, 'wb') as f:
            f.write(encrypted_master_data)
        print("Master key generated and saved.")
    else:
        with open(MASTER_KEY_FILE, 'rb') as f:
            encrypted_master_data = f.read()
        master_data = json.loads(decrypt_data(encrypted_master_data, key))
    return master_data

# Derive a child private key from the master private key
def derive_child_key(master_private_key, index):
    bip32_master_key = bip32utils.BIP32Key.fromEntropy(binascii.unhexlify(master_private_key))
    child_key = bip32_master_key.ChildKey(index)
    return child_key.WalletImportFormat()

# Generate a new Bitcoin address
def generate_new_address(index, password):
    master_data = generate_master_key(password)
    child_private_key = derive_child_key(master_data['master_private_key'], index)
    child_public_key = privtopub(child_private_key)
    bitcoin_address = pubtoaddr(child_public_key)
    return bitcoin_address, child_private_key

# Save the private key to a file
def save_private_key(private_key, password):
    key = derive_key_from_password(password)
    encrypted_private_key = encrypt_data(private_key, key)
    with open(PRIVATE_KEYS_FILE, 'wb') as f:
        f.write(encrypted_private_key)

# Load the private key from a file
def load_private_key(password):
    key = derive_key_from_password(password)
    with open(PRIVATE_KEYS_FILE, 'rb') as f:
        encrypted_private_key = f.read()
    private_key = decrypt_data(encrypted_private_key, key)
    return private_key

# Generate a QR code for the Bitcoin address
def generate_qr_code(bitcoin_address):
    qr = qrcode.make(bitcoin_address)
    qr_filename = "bitcoin_address_qr.png"
    qr.save(qr_filename)
    return qr_filename

# Create a transaction
def create_transaction(private_key, to_address, amount, fee):
    # Get unspent outputs
    unspent_outputs = requests.get(f'https://blockchain.info/unspent?active={pubtoaddr(privtopub(private_key))}').json()
    inputs = unspent_outputs['unspent_outputs']
    
    # Create the transaction inputs
    tx_inputs = [{'output': f"{i['tx_hash_big_endian']}:{i['tx_output_n']}", 'value': i['value']} for i in inputs]

    # Create the transaction outputs
    tx_out = [{'address': to_address, 'value': amount}]

    # Calculate the change and add a change output
    total_in = sum(i['value'] for i in tx_inputs)
    change = total_in - amount - fee
    if change > 0:
        tx_out.append({'address': pubtoaddr(privtopub(private_key)), 'value': change})

    # Create the raw transaction
    raw_tx = mktx(tx_inputs, tx_out)
    
    # Sign the transaction
    signed_tx = sign(raw_tx, 0, private_key)

    return signed_tx

# Broadcast the transaction
def broadcast_transaction(signed_tx):
    url = 'https://blockchain.info/pushtx'
    response = requests.post(url, data={'tx': signed_tx})
    return response.text

# API Endpoints

@app.route('/generate_wallet', methods=['POST'])
def generate_wallet():
    password = getpass.getpass('Enter your password: ')
    index = int(request.json.get('index', 0))
    bitcoin_address, private_key = generate_new_address(index, password)
    save_private_key(private_key, password)
    qr_filename = generate_qr_code(bitcoin_address)
    return jsonify({
        'private_key': private_key,
        'bitcoin_address': bitcoin_address,
        'qr_code': qr_filename
    })

@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    password = getpass.getpass('Enter your password: ')
    data = request.json
    private_key = load_private_key(password)
    to_address = data['to_address']
    amount = data['amount']
    fee = data['fee']
    signed_tx = create_transaction(private_key, to_address, amount, fee)
    broadcast_response = broadcast_transaction(signed_tx)
    return jsonify({
        'signed_transaction': signed_tx,
        'broadcast_response': broadcast_response
    })

@app.route('/get_address', methods=['GET'])
def get_address():
    password = getpass.getpass('Enter your password: ')
    index = int(request.args.get('index', 0))
    bitcoin_address, _ = generate_new_address(index, password)
    return jsonify({
        'bitcoin_address': bitcoin_address
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
