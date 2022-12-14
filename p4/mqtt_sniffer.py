import paho.mqtt.client
import sys, signal

#MQTT_SERVER = "mastropiero.det.uvigo.es"
MQTT_SERVER = "3.250.118.218"
MQTT_USERNAME = "sinf"
MQTT_PASSWD = "HkxNtvLB3GC5GQRUWfsA"

"""
    Information Security
    Lab 4
    Munics 2022/23
    Carlos Torres Paz (UDC)
    Ismael Verde Costas (UDC)
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

class Sniffer():
    def __init__(self):
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
    
    def start(self, topics):
        # Interceptamos el Ctrl+C para cerrar el programa correctamente
        def sigint_handler(signum, frame):
            print("Exiting...")
            logging.info("SIGINT Received. Disconnecting...")
            self.mqclient.disconnect()
            sys.exit(0)

        signal.signal(signal.SIGINT, sigint_handler)

        def mqtt_on_message(client, userdata, message):
            print(message.topic, "> ", message.payload)
            print()
        
        for t in topics:
            self.mqclient.subscribe(topic=t)
        
        self.mqclient.on_message = mqtt_on_message
        self.mqclient.loop_forever()


if __name__ == "__main__":
    topics_in = input("Enter topics to listen to: ")
    topics = topics_in.split(sep=' ')
    sniffer = Sniffer()
    sniffer.start(topics)