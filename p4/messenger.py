from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import paho.mqtt.client
import sys, time, os

#MQTT_SERVER = "mastropiero.det.uvigo.es"
MQTT_SERVER = "3.250.118.218"
MQTT_USERNAME = "sinf"
MQTT_PASSWD = "HkxNtvLB3GC5GQRUWfsA"

ROOT_KEY = b'+\xf5f\x9f\xb4YH\x0ef\xa1\xcas*\xe9NY'

ELLIPTIC_CURVE = ec.SECP384R1()

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

class AESSystem():
    def AESencrypt(key, payload):
        pass
    def AESdecrypt(key, payload):
        pass

class KDFRatchet():
    def __init__(self, DH_key: bytes):
        # Creamos una cadena KDF usando la clave de Diffie-Hellman como salt
        # y la root key como primera clave
        self.hkdf = HKDF(
            algorithm=SHA512(),
            length=16,
            salt=ROOT_KEY,
            info=b'SINF_LAB4_CARLOSTORRES_ISMAVERDE'
        )
        self.current_key = self.hkdf.derive(DH_key)

    def next(self) -> bytes:
        # En cada llamada a next(), avanzamos un paso el ratchet
        # Sacamos una nueva clave, la devolvemos y nos la guardamos para el siguiente next()
        self.current_key = self.hkdf.derive(self.current_key)
        return self.current_key


class DHRatchet():
    def __init__(self):
        # Instanciamos cliente MQTT
        self.mqclient = paho.mqtt.client.Client()
        # Ponemos username and password
        self.mqclient.username_pw_set(MQTT_USERNAME, MQTT_PASSWD)
        logging.debug("Created mqtt client")
        # Nos conectamos al servidor
        conn = self.mqclient.connect(MQTT_SERVER, port=1883, keepalive=60)
        print("conn is", conn)
        if (conn == 0):
            logging.info("Connected to MQTT Server at "+ MQTT_SERVER)
        else:
            logging.error("Unable to connect to MQTT Server")
            exit(-1)
        
        # Generamos par de claves DH
        self.dh_sk = ec.generate_private_key(ELLIPTIC_CURVE)
        self.dh_pk = self.sk.public_key()
        # Creamos un atributo para guardar la clave pública del compañero
        self.peer_dh_pk = None
        # Creamos un flag para trackear si estamos en proceso de envío o de recepción
        self.is_first_sent = True

        # Nos ponemos a esperar para recibir la clave pública del compañero
        # Si recibimos una clave pública, la guardamos en el atributo self.peer_dh_pk
        def mqtt_on_message(client, userdata, message):
            if len(message)<25:
                return None
            (header, key) = (message[:24], message[24:])
            if header == b'DH_EXCHANGE_START.PUBKEY':
                self.peer_dh_pk = key
                return key

        self.mqclient.on_message = mqtt_on_message
        # Loop_start inicia el bucle de eventos de MQTT en un nuevo hilo para que la ejecución
        # del programa continue
        self.mqclient.loop_start()

    def start(self):
        # Iniciamos el proceso de negociación
        # Mandamos por MQTT al canal "self.peer".in la clave pública de DH (self.dh_pk)
        topic = self.peer + ".in"
        payload = b'DH_EXCHANGE_START.PUBKEY'+self.dh_pk
        self.mqclient.publish(topic=topic, payload=payload)

        # Esperamos a recibir la PK del compañero
        while (self.peer_dh_pk is None):
            time.sleep(0.1)
        # Una vez la tenemos, dejamos de escuchar
        self.mqclient.loop_stop()

        # Una vez tenemos la PK del compañero, estamos listos tanto para enviar como para recibir mensajes
        # Cambiamos el handler de mqtt para pasar a procesar mensajes entrantes
        def mqtt_on_message(client, userdata, message):
            return self.receive(message)

        # Reiniciamos el bucle de eventos con el nuevo handler
        self.mqclient.on_message = mqtt_on_message
        self.mqclient.loop_start()
    
    def send(self, plaintext_msg: str):
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

            # Creamos un nuevo ratchet interno con esta nueva clave compartida DH
            self.kdf = KDFRatchet(shared_key)

        # Usamos el ratchet interno para cifrar nuestro mensaje
        nonce=os.urandom(96//8) #TODO: saber los tamaños de claves, bloques... etc
        # Podemos meter como associated_data nuestra nueva clave pública de Diffie-Hellman
        msg = AESGCM(self.kdf.next()).encrypt(nonce=nonce, data=plaintext_msg.encode("UTF-8"), associated_data=self.dh_pk)

        # Mandamos las dos cosas
        return self.dh_pk + msg

    def receive(self, ciphertext_input: bytes):
        # Si es el primer mensaje de este batch, tenemos que regenerar el Ratchet
        # Lo comprobamos viendo si la clave pública que tenemos del compañero es la misma o no
        
        # Extraemos pk del compañero
        (ciphertext_msg, new_peer_dh_pk) = ciphertext_input #TODO: Definir esta estructura de datos

        if (self.peer_dh_pk != new_peer_dh_pk):
            # Reseteamos el flag de envío ya que pasamos a modo recepción
            self.is_first_sent = True
            # Guardamos la nueva clave
            self.peer_dh_pk = new_peer_dh_pk
            # Hacemos el intercambio Diffie-Hellmann, obtenemos clave compartida
            shared_key = self.dh_sk.exchange(ec.ECDH(), self.peer_dh_pk)
            # Regeneramos ratchet interno
            self.kdf = KDFRatchet(shared_key)

        # Usamos el ratchet interno para descifrar el mensaje
        nonce = b'esto lo tendre que haber sacado de algun sitio'
        # Sacamos la clave pública de Diffie-Hellman del compañero y la autenticamos también (y la guardamos)
        self.peer_dh_pk = b'de alguna forma lo sacaremos digo yo'
        msg = AESGCM(self.kdf.next()).decrypt(nonce=nonce, data=ciphertext_input, associated_data=self.peer_dh_pk)
        return msg


class Messenger():
    def __init__(self, username: str, peer_name: str):
        # Guardamos nombre de usuario y del compañero
        self.username = username
        self.peer_name = peer_name
        # Instanciamos el DHRatchet
        self.ratchet = DHRatchet()
    
    def start(self):
        # Nombres de usuario para los canales de MQTT
        self.username = input("Input username: ")
        self.peer = input("Input peer's username: ")

        input("Press ENTER when both parties are ready to start")
        # Al pulsar ENTER, iniciamos el proceso de intercambio de DH
        self.ratchet.start()
        self.ratchet.mqclient.on_message = self.receive()

        # TODO: Toda la parte de consola, los prompts, leer los mensajes, mostrar los mensajes recibidos...etc
        while True:
            message = input("Write a message (leave blank to exit chat): ")
            if message == '':
                break
            else:
                self.send(self, message)

            # TODO: Métodos encrypt y decrypt envían y reciben el mensaje correctamemte
    
    def send(self, plaintext):
        ciphertext = self.ratchet.encrypt(plaintext)
        print(plaintext)

        # TODO: Pendiente ver en donde se gestiona que el ciphertext se publique en el canal del destinatario
        return ciphertext

    def receive(self, ciphertext):
        plaintext = self.ratchet.decrypt(ciphertext)
        print("\r" + plaintext)




if __name__ == "__main__":
    msg = Messenger()
    #msg.start()