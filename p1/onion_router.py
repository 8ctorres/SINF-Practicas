# Import common module
import onion

import sys
import signal

# OnionRouter inherits from the OnionSystem class
# This class is in charge of receiving and relaying messages to other nodes
class OnionRouter(onion.OnionSystem):
    # Receive and process an incoming message
    def receive_message(self, message):
        onion.logging.info("Received incoming message")
        msg_dest = message[:5].strip(b'\x00')
        if msg_dest != self.user_id.strip(b'\x00'):
            #Message is not addressed to this node. Ignore it
            onion.logging.warn("Received message addressed to node: " + msg_dest + ". Ignoring...")
            return None
        #First, remove the user_id
        ciphertext = message[5:]
        #Now decrypt using the node's own private key
        message = self.decrypt_message(self.prkey, ciphertext)
        onion.logging.debug("Decrypted message with private key")
        #Extract next user_id
        msg_dest = message[:5].strip(b'\x00')
        onion.logging.debug("Next user_id is " + onion.bytes_print(message[:5]))

        # Next, check if we are the recipients of the message, by checking for "end" as next_hop
        if (msg_dest) == b'end':
            onion.logging.info("Message chain end")
            # Now, read the sender id, if available
            sender_id = message[5:10].strip(b'\x00')
            sender_str = "Anonymous sender" if sender_id == b'none' else sender_id.decode("ASCII")

            # Finally, decode the plain text message back into a string
            message_str = message[10:].decode("UTF-8")

            # Return the result as a tuple containing sender_id and plain text message, both as Strings.
            return (sender_str, message_str)
        else:
            onion.logging.info("Relaying message to next_node: " + onion.bytes_print(msg_dest))
            # Send the message to the next node via MQTT
            self.mqclient.publish(msg_dest.decode("ASCII"), message)
            return None

    def main(self):
        # Subscribe to the topic equal to our own user_id (as a string and without the zero-padding bytes)
        topic = self.user_id.strip(b'\x00').decode("ASCII")
        self.mqclient.subscribe(topic)
        onion.logging.info("Subscribed to MQTT topic " + topic)

        # Define a callback function for when a message is received
        def mqtt_on_message(client, userdata, message):
            onion.logging.debug("MQTT Callback on_message")
            # This helper function acts as an interface between the mqtt client
            # and the actual OnionRouter function for message handling
            
            # This function calls the OnionRouter.receive_message function
            # passing the MQTT message's payload as the only argument
            res = self.receive_message(message.payload)

            # When received a message that was adressed to this node
            if res is not None:
                # Extract sender id and actual payload
                (sender, payload) = res
                # Print the message to the console
                print("Received message from ", sender)
                print(payload)
                print('\n\n\n\n')

        # Set the helper function as the callback point for the MQTT Client
        self.mqclient.on_message = mqtt_on_message

        # Start the mqttclient event loop
        onion.logging.debug("Starting MQTT client event loop")
        self.mqclient.loop_forever()


if __name__ == "__main__":
    #Ctrl+C Handler to be able to shut down the program gracefully
    def sigint_handler(signum, frame):
        print()
        onion.logging.info("SIGINT Received. Disconnecting...")
        router.mqclient.disconnect()

    signal.signal(signal.SIGINT, sigint_handler)

    # Handle command line arguments
    if not len(sys.argv) == 2:
        print(
            "Usage: onion_router.py user_id"
        )
        exit()
    # Create an instance of the OnionRouter
    router = OnionRouter(sys.argv[1])
    onion.logging.debug("Created instance of OnionRouter")
    # Start the routing process by calling the main function
    onion.logging.info("Starting routing process")
    router.main()
    onion.logging.info("Stopping routing process and shutting down")

