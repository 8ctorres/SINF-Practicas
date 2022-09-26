from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import paho.mqtt.client
import sys

import logging

logging.basicConfig(
    level=logging.DEBUG,
    format="%(funcName)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Import public keys of all nodes in the network
import pubkeys

MQTT_SERVER = "3.250.118.218"
MQTT_USERNAME = "sinf"
MQTT_PASSWD = "HkxNtvLB3GC5GQRUWfsA"

# Utility function to encode user IDs to 5-byte elements
def encode_user_id(user_id_str):
    # Calculate user_id (5 bytes), adding padding if necessary
    # and convert it to bytes
    if len(user_id_str) > 5 or len(user_id_str) < 2:
        logging.error("USER ID must be between 2 and 5 ASCII characters")
        exit()
    try:
        user_id_binary = user_id_str.encode("ASCII")
    except UnicodeEncodeError:
        logging.error("USER ID must be ASCII characters only")
        exit()
    user_id = user_id_binary + b'\x00'*(5-len(user_id_binary))
    return user_id

# Utility function to convert bytes objects to reasonably printable objects
def bytes_print(b):
    return " ".join([hex(byte) if byte < 33 else chr(byte) for byte in b])
    

class OnionNode:
    def __init__(self, user_id_str, pubkey_str):
        # Encode user_id
        self.user_id = encode_user_id(user_id_str)

        # Load member's public key
        self.pubkey = load_ssh_public_key(
            pubkey_str.encode("ASCII"),
            backend=default_backend()
        )

class OnionSystem:
    def __init__(self, user_id_str, prkey_file="rsa_key", pubkey_file="rsa_key.pub", input_padding=None):
        logging.debug("Creating instance of OnionSystem with user_id " + user_id_str)
        # Load private key, if available
        if prkey_file is not None:
            with open(prkey_file, "rb") as key_file:
                self.prkey = load_ssh_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            logging.debug("Loaded private key")
        else:
            self.prkey=None

        # Load public key
        with open(pubkey_file, "rb") as key_file:
            self.pubkey = load_ssh_public_key(
                key_file.read(),
                backend=default_backend()
            )
        logging.debug("Loaded public key")

        # Encode user_id
        self.user_id = encode_user_id(user_id_str)
        logging.debug("Binary user_id is " + bytes_print(self.user_id))

        # Set OAEP padding for encryption and decryption
        self.padding = (padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) if input_padding is None else input_padding

        # Load all public keys into OnionNode objects
        # Create a network dictionary
        self.network = {}
        logging.debug("Loading network information")
        for (node_id, node_key) in pubkeys.pubkey_dictionary.items():
            self.network[node_id] = OnionNode(node_id, node_key)
        logging.info("Loaded " + str(len(self.network)) + " nodes into the network")

        # Instantiate MQTT Client and connect to the broker
        self.mqclient = paho.mqtt.client.Client()
        self.mqclient.username_pw_set(MQTT_USERNAME, MQTT_PASSWD)
        logging.debug("Created mqtt client")
        self.mqclient.connect(MQTT_SERVER, port=1883, keepalive=60)
        logging.info("Connected to MQTT Server at "+ MQTT_SERVER)


    def encrypt_message(self, pubkey, plaintext):
        # Generate AES key
        key = AESGCM.generate_key(128)
        #Encrypt the text
        ciphertext = AESGCM(key).encrypt(nonce=key, data=plaintext, associated_data=None)
        #Encrypt the AES key with RSA
        cipherkey = pubkey.encrypt(key, self.padding)
        # Prepend the encrypted key to the encrypted text
        return cipherkey+ciphertext

    def decrypt_message(self, prkey, cipherstring):
        # Obtain key length in bytes
        keylength = int(prkey.key_size/8)
        # First, use the private RSA key to obtain the AES key
        cipherkey = cipherstring[:keylength]
        AESkey = prkey.decrypt(cipherkey, self.padding)
        # Then, use the AES key to decrypt the rest of the packet
        ciphertext = cipherstring[keylength:]
        plaintext = AESGCM(AESkey).decrypt(nonce=AESkey, data=ciphertext, associated_data=None)

        # Return just the "plaintext" (which is possibly the next layer's ciphertext)
        return plaintext
