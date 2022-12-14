from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import paho.mqtt.client
import sys, time, os, signal

#MQTT_SERVER = "mastropiero.det.uvigo.es"
MQTT_SERVER = "3.250.118.218"
MQTT_USERNAME = "sinf"
MQTT_PASSWD = "HkxNtvLB3GC5GQRUWfsA"

INITIAL_ROOT_KEY = b'+\xf5f\x9f\xb4YH\x0ef\xa1\xcas*\xe9NY' #128 bits
HKDF_INFO_STRING = b'SINF_LAB4_CARLOSTORRES_ISMAVERDE'

HMAC_CHAIN_STRING = b'\x01'
HMAC_MSG_STRING = b'\x02'

TEXT_ENCODING = "UTF-8"
ELLIPTIC_CURVE = ec.SECP384R1()
KDF_KEY_LENGTH = 32 # 2x128 bits
DH_KEY_LENGTH = 48 # 384bits
NONCE_LENGTH = 12 # 96bits

# Use a basic logging system to output information to the terminal in a more configurable
# way than just using print() statements all over the place.
import logging

logging.basicConfig(
    level=logging.DEBUG, # <-- Change to INFO or WARN to reduce the amount of messages displayed
    format="%(funcName)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

"""
    Information Security
    Lab 4
    Munics 2022/23
    Carlos Torres Paz (UDC)
    Ismael Verde Costas (UDC)
"""

class KDFRatchet():
    def __init__(self, root_key: bytes):
        # Creamos una cadena KDF usando la root_key
        self.hkdf = HKDF(
            algorithm=SHA256(),
            length=KDF_KEY_LENGTH,
            salt=root_key,
            info=HKDF_INFO_STRING
        )
    
    def initialize(self, DH_key: bytes):
        # Inicializamos el ratchet simétrico con la clave compartida Diffie-Hellman,
        # extrayendo una nueva root key, que devolvemos y una nueva chain key para usar en adelante
        derived_key = self.hkdf.derive(DH_key)
        # Extraemos de la clave derivada, de 256 bits, los primeros 128 para la siguiente root key
        # y los siguientes 128 para la chain key
        self.current_chain_key = derived_key[(KDF_KEY_LENGTH//2):]
        return derived_key[:(KDF_KEY_LENGTH//2)] #Se devuelve la root key y el DHRatchet la guarda

    def next(self) -> bytes:
        # En cada llamada a next(), avanzamos un paso el ratchet
        # Instanciamos una cadena HMAC-SHA256 con la chain_key actual
        hmac_chain = HMAC(key=self.current_chain_key, algorithm=SHA256())
        # Nos guardamos una copia
        hmac_message = hmac_chain.copy()

        # Extraemos la siguiente chain_key y la guardamos
        hmac_chain.update(HMAC_CHAIN_STRING)
        self.current_chain_key = hmac_chain.finalize()

        # Extraemos la siguiente message_key y la devolvemos
        hmac_message.update(HMAC_MSG_STRING)
        return hmac_message.finalize()


class DHRatchet():
    def __init__(self, mqclient: paho.mqtt.client.Client, username: str, peer_name: str):
        # Guardamos el nombre de usuario y de compañero
        self.username = username
        self.peer_name = peer_name
        # Guardamos un puntero al cliente mqtt
        # Lo vamos a utilizar para el intercambio de claves inicial
        self.mqclient=mqclient

        # Guardamos la root key y la inicializamos al valor preestablecido
        self.root_key = INITIAL_ROOT_KEY
        
        # Generamos par de claves DH
        self.dh_sk = ec.generate_private_key(ELLIPTIC_CURVE)
        self.dh_pk = self.dh_sk.public_key()
        logging.debug("Generated DH keypair")
        # Creamos un atributo para guardar la clave pública del compañero
        self.peer_dh_pk = None
        # Creamos un flag para trackear si estamos en proceso de envío o de recepción
        self.is_first_sent = True

        # Nos ponemos a esperar para recibir la clave pública del compañero
        # Si recibimos una clave pública, la guardamos en el atributo self.peer_dh_pk
        def mqtt_on_message(client, userdata, message):
            msg = message.payload
            if len(msg)<25:
                return None
            (header, key) = (msg[:17], msg[17:])
            if header == b'DH_EXCHANGE_START':
                self.peer_dh_pk = serialization.load_der_public_key(key)
                return key

        logging.debug("Waiting for peer's pubkey in mqtt topic " + self.username + ".in")
        self.mqclient.on_message = mqtt_on_message
        self.mqclient.subscribe(topic=self.username+".in")
        # Loop_start inicia el bucle de eventos de MQTT en un nuevo hilo para que la ejecución
        # del programa continue
        self.mqclient.loop_start()

    def start(self):
        # Iniciamos el proceso de negociación
        # Mandamos por MQTT al topic de nuestro compañero la clave pública de DH (self.dh_pk)
        logging.debug("Start Diffie-Hellman key exchange")
        logging.debug("Sending public key via MQTT topic " + self.peer_name+".in")
        payload = b'DH_EXCHANGE_START'+self.dh_pk.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
        self.mqclient.publish(topic=self.peer_name+".in", payload=payload)

        # Esperamos a recibir la PK del compañero
        while (self.peer_dh_pk is None):
            time.sleep(0.1)
        # Una vez la tenemos, liberamos el control del cliente MQTT
        self.mqclient.loop_stop()

        # Una vez tenemos la PK del compañero, estamos listos tanto para enviar
        # como para recibir mensajes. Devolvemos el control al Messenger
        logging.info("Completed initial Diffie-Hellmann exchange")
        return
        
    def encrypt(self, plaintext_msg: str):
        # Si es el primer mensaje de este batch, tenemos que regenerar el Ratchet
        # Lo comprobamos con un flag de envío que guardamos como atributo de DHRatchet
        if (self.is_first_sent):
            self.is_first_sent = False
            # En el primer mensaje que enviamos, generamos un nuevo par de claves DH y mandamos
            # la pública al compañero junto con el mensaje
            self.dh_sk = ec.generate_private_key(ELLIPTIC_CURVE)
            self.dh_pk = self.dh_sk.public_key()

            # Realizamos el intercambio Diffie-Hellman usando la clave pública que teníamos de antes del compañero
            shared_key = self.dh_sk.exchange(ec.ECDH(), self.peer_dh_pk)

            # Creamos un nuevo ratchet interno y lo inicializamos con nuestra nueva clave compartida DH
            self.kdf = KDFRatchet(self.root_key)
            # En el proceso de inicialización, ya nos guardamos la nueva root_key para inicializar el siguiente ratchet
            self.root_key = self.kdf.initialize(shared_key)

        # Usamos el ratchet interno para cifrar nuestro mensaje
        nonce=os.urandom(96//8)
        msg = AESGCM(self.kdf.next()).encrypt(nonce=nonce, data=plaintext_msg, associated_data=None)

        # Vamos a enviar:
        # - Un flag de inicio (160 bits)
        # - Nuestra clave pública de Diffie-Hellman (384 bits)
        # - El nonce del cifrado AESGCM (96 bits)
        # - El mensaje cifrado (el resto)
        return b'DR_ENCRYPTED_MESSAGE' + self.dh_pk + nonce + msg

    def decrypt(self, input: bytes):
        # Si es el primer mensaje de este batch, tenemos que regenerar el Ratchet
        # Lo comprobamos viendo si la clave pública que tenemos del compañero es la misma o no

        flag_limit = len(b'DR_ENCRYPTED_MESSAGE') # 160 bits
        dh_pk_limit = flag_limit + DH_KEY_LENGTH
        nonce_limit = dh_pk_limit + NONCE_LENGTH

        # Comprobamos que la entrada tenga el tamaño adecuado. Si no, ignoramos el paquete
        if (len(msg) < nonce_limit+1):
            return None
        (flag, new_peer_dh_pk, nonce, encrypted_msg) = (
            input[:flag_limit],
            input[flag_limit:dh_pk_limit],
            input[dh_pk_limit:nonce_limit],
            input[nonce_limit:]
        )
        # Compobamos que la flag sea correcta. Si no, ignoramos el paquete
        if (flag != b'DR_ENCRYPTED_MESSAGE'):
            return None

        # Si este mensaje es el primero de esta cadena
        if (self.peer_dh_pk != new_peer_dh_pk):
            # Reseteamos el flag de envío ya que pasamos a modo recepción
            self.is_first_sent = True
            # Guardamos la nueva clave
            self.peer_dh_pk = new_peer_dh_pk
            # Hacemos el intercambio Diffie-Hellmann, obtenemos clave compartida
            shared_key = self.dh_sk.exchange(ec.ECDH(), self.peer_dh_pk)
            # Regeneramos ratchet interno y guardamos la siguiente root_key
            self.kdf = KDFRatchet(self.root_key)
            self.root_key = self.kdf.initialize(shared_key)

        # Usamos el ratchet interno para descifrar el mensaje
        msg = AESGCM(self.kdf.next()).decrypt(nonce=nonce, data=encrypted_msg, associated_data=None)
        return msg


class Messenger():
    def __init__(self, username: str, peer_name: str):
        # Guardamos nombre de usuario y del compañero
        self.username = username
        self.peer_name = peer_name
        # Instanciamos cliente MQTT
        self.mqclient = paho.mqtt.client.Client()
        # Ponemos username and password
        self.mqclient.username_pw_set(MQTT_USERNAME, MQTT_PASSWD)
        logging.debug("Created mqtt client")
        # Nos conectamos al servidor
        conn = self.mqclient.connect(MQTT_SERVER, port=1883, keepalive=60)
        logging.debug("conn is " + str(conn))
        if (conn == 0):
            logging.info("Connected to MQTT Server at "+ MQTT_SERVER)
        else:
            logging.error("Unable to connect to MQTT Server")
            exit(-1)

        # Instanciamos el DHRatchet y le pasamos un puntero al cliente MQTT
        # para que pueda usarlo para el proceso de intercambio de claves, y
        # le pasamos los username de ambas partes de la conversación
        self.ratchet = DHRatchet(self.mqclient, self.username, self.peer_name)
    
    def start(self):
        input("Press ENTER when both parties are ready to start")
        # Al pulsar ENTER, iniciamos el proceso de intercambio de DH
        self.ratchet.start()

        # Interceptamos el Ctrl+C para cerrar el programa correctamente
        def sigint_handler(signum, frame):
            print("Exiting...")
            logging.info("SIGINT Received. Disconnecting...")
            self.mqclient.disconnect()
            sys.exit(0)

        # Registramos el handler con la librería de signals
        signal.signal(signal.SIGINT, sigint_handler)

        #Handler para la recepción de mensajes
        def mqtt_recv_message(client,userdata,message):
            self.receive(message.payload)

        # Registramos handler MQTT e iniciamos bucle de eventos
        self.mqclient.on_message = mqtt_recv_message
        self.mqclient.loop_start()

        # Bucle principal de la aplicación
        while True:
            print()
            message = input(self.username + ": ")
            self.send(message)
    
    def send(self, plaintext):
        ciphertext = self.ratchet.encrypt(plaintext.encode(TEXT_ENCODING))
        #ciphertext=plaintext.encode(TEXT_ENCODING)
        self.mqclient.publish(topic=self.peer_name+".in", payload=ciphertext)
        #print(self.username + ": " + plaintext, end='\n')

    def receive(self, ciphertext):
        plaintext = self.ratchet.decrypt(ciphertext.decode(TEXT_ENCODING))
        #plaintext = ciphertext.decode(TEXT_ENCODING)
        print('\r' + self.peer_name + ": " + plaintext, end='\n')


if __name__ == "__main__":
    username = input("Input username: ")
    peer_name = input("Input peer's username: ")
    msg = Messenger(username, peer_name)
    msg.start()