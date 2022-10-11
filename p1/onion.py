from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_ssh_private_key, load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import paho.mqtt.client
import sys

"""
    Information Security
    Lab 1
    Munics 2022/23
    Carlos Torres Paz (UDC)

    This Laboratory assignment aims to succesfully implement a messaging system based in the
    concepts of nested encryption and onion routing. This program will be able to send and receive
    encrypted messages, using an MQTT broker to exchange the encrypted messages with other
    systems.

    The code for this lab is organised in four Python classes:
        - OnionNode: A simple, bean-like object that stores information about a node's
            user_id and public RSA key
        - OnionSystem: This class contains the logic for the encryption and the decryption of
            messages using an AES-RSA hybrid encryption (explained below), as well as a constructor
            that imports both the private and public RSA keys, the user_id and creates an MQTT
            instance that connects to the central broker.
        - OnionRouter: This class extends OnionSystem and adds the capabilities to receive and
            forward messages. It implements the "receive_message" method, which is called when a
            message arrives and it forwars the message onto the next hop, if applicable
        - OnionClient: This class also extends OnionSystem and adds the capabilities to send
            messages into the network. It implements the "send_message" method, that given a
            plaintext message and a route through the network, it adds the necessary layers of
            encryption and sends the message on to the network.

    There are also a few additional components:
        - A logging system: The system sends logging messages through a logging system that the user
            can configure to the desired level of verbosity. This makes for an easier debugging
            and also for a less cluttered experience when the system is ready.
        - A couple of utility functions that are part of the main "onion" module. One of them is to
            convert a user_id from string to bytes and add padding if necessary. The other one is
            to convert a bytes object into a string form that can be printed to the terminal.
        - A dictionary containing user_ids and public keys of all the other nodes in the network
            (provided by our teacher)

    All of these are split into four python modules (files):
        - onion_router: Contains only the OnionRouter class, as well as a main() entrypoint to
            be runnable from a command line
        - onion_client: Contains only the OnionClient class, as well as a main() entrypoint to
            be runnable from a command line
        - onion.py: Contains the OnionNode and OnionSystem classes, the utility functions, the
            logging configuration and some global definitions (MQTT server ip, username and passwd)
        - pubkeys: Contains the dictionary with user ids and public keys for other nodes.

    
    Tested successfully with: Ignacio Borregán, Daniel Feito and David Fernández    
    
    More detailed documentation of how each component works is available below.
"""

# Use a basic logging system to output information to the terminal in a more configurable
# way than just using print() statements all over the place.
import logging

logging.basicConfig(
    level=logging.INFO, # <-- Change to INFO or WARN to reduce the amount of messages displayed
    format="%(funcName)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Import public keys of all nodes in the network
import pubkeys

# Global definitions
MQTT_SERVER = "3.250.118.218"
MQTT_USERNAME = "sinf"
MQTT_PASSWD = "HkxNtvLB3GC5GQRUWfsA"


def encode_user_id(user_id_str: str) -> bytes:
    """Converts the user_id from string to bytes and adds padding if necessary
    
    Parameters
    ----------
    user_id_str: str
        The user id

    Returns
    -------
    bytes
        A 5 byte long bytes object containing the user_id and the necessary padding
    """

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

def bytes_print(b: bytes) -> str:
    """Converts a bytes object to a pretty-printable string

    Takes a bytes object and for each byte, if it's a printable character, prints it as such
    and if it's not printable, prints the hexadecimal representation, all separated by a space
    between each two bytes.
    
    Parameters
    ----------
    b: bytes
        The bytes object to print

    Returns
    -------
    string
        A string containing the printable version of the input bytes    
    """

    return " ".join([hex(byte) if byte < 33 or byte > 128 else chr(byte) for byte in b])

class OnionNode:
    """A Bean-like object to store a user_id <-> public key association

    This class represents a Node on the network from an external point of view, without
    the private key and the mqtt client

    Attributes
    ----------
    user_id: bytes
        The user id of the node
    pubkey
        The public RSA key of the node

    Methods
    -------
    None
    """

    def __init__(self, user_id_str: str, pubkey_str: str):
        """
        Parameters
        ----------
        user_id_str: str
            The user id of the node
        pubkey_str: str
            The public key of the node, encoded in Base64 and starting with "ssh-rsa"
        """

        # Encode user_id to bytes
        self.user_id = encode_user_id(user_id_str)

        # Load node's public key
        self.pubkey = load_ssh_public_key(
            pubkey_str.encode("ASCII"),
            backend=default_backend()
        )

class OnionSystem:
    """A class used to represent a software that can interact with the onion network

    This class is a generalisation of any software that connects to and interacts with the
    onion network. It contains the logic for key management, the encryption and decryption
    algorithms, and manages the connection to the MQTT Broker.

    Attributes
    ----------
    user_id: bytes
        The user id of this node
    pubkey
        The public RSA key of the node
    prkey
        The private RSA key of the node
    padding
        An object that represents the type of padding used for RSA encryption and decryption
    network: dict(str, OnionNode)
        A dictionary containing the set of other OnionNodes on the network, indexed by their user_id
    mqclient
        An instance of an MQTT client, connected to the MQTT Broker

    Methods
    -------
    encrypt_message(pubkey, plaintext: bytes) -> bytes
        Takes a public key and a message and encrypts it
    decrypt_message(prkey, cipherstring: bytes) -> bytes
        Takes a private key and an encrypted message and decrypts it

    """

    def __init__(self, user_id_str: str, prkey_file: str="rsa_key", pubkey_file: str="rsa_key.pub", input_padding=None):
        """
        Parameters
        ----------
        user_id_str: str
            The user id of the node
        prkey_file: str
            The path to a file containing the private key of the node. By default it's a file called
            "rsa_key" in the working directory
        pubkey_file: str
            The path to a file containing the public key of the node. By default it's a file called
            "rsa_key.pub" in the working directory
        input_padding
            An object representing the type of padding used with RSA encryption. If ommited or None,
            it reverts to the default
        """

        logging.debug("Creating instance of OnionSystem with user_id " + user_id_str)
        # Load private key
        with open(prkey_file, "rb") as key_file:
            self.prkey = load_ssh_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        logging.debug("Loaded private key")

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
        self.padding = (
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None)) if input_padding is None else input_padding

        # Load all public keys into OnionNode objects
        # Create a network dictionary
        self.network = {}
        logging.debug("Loading network information")
        for (node_id, node_key) in pubkeys.pubkey_dictionary.items():
            self.network[node_id] = OnionNode(node_id, node_key)
        logging.info("Loaded " + str(len(self.network)) + " nodes into the network")

        # Instantiate MQTT Client
        self.mqclient = paho.mqtt.client.Client()
        # Set username and password
        self.mqclient.username_pw_set(MQTT_USERNAME, MQTT_PASSWD)
        logging.debug("Created mqtt client")
        # Connect to the broker
        self.mqclient.connect(MQTT_SERVER, port=1883, keepalive=60)
        logging.info("Connected to MQTT Server at "+ MQTT_SERVER)


    def encrypt_message(self, pubkey, plaintext: bytes) -> bytes:
        """Encrypts a message using a public RSA key

        This method implements hybrid encryption. It first generates a random AES 128 bit key,
        then encrypts the message using AESGCM with that key, and then encrypts the AES key
        with the public RSA key, and prepends this to the actual message.

        Parameters
        ----------
        pubkey
            The RSA public key
        plaintext: bytes
            The message to encrypt, in bytes

        Returns
        -------
        bytes
            The encrypted message
        """

        # Generate AES key
        key = AESGCM.generate_key(128)
        #Encrypt the text
        ciphertext = AESGCM(key).encrypt(nonce=key, data=plaintext, associated_data=None)
        #Encrypt the AES key with RSA
        cipherkey = pubkey.encrypt(key, self.padding)
        # Prepend the encrypted key to the encrypted text
        return cipherkey+ciphertext

    def decrypt_message(self, prkey, cipherstring: bytes) -> bytes:
        """Decrypts a message using a private RSA key

        This method works for messages encrypted using hybrid encryption. It expects the first
        part of the cipherstring to be an RSA-encrypted 128 bit key, and then uses that key to
        decrypt the rest of the message using AES GCM decryption.

        Parameters
        ----------
        prkey
            The RSA private key
        cipherstring: bytes
            The encrypted message

        Returns
        -------
        bytes
            The decrypted message
        """

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
