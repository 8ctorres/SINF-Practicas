# Import common module
import onion

import sys
import signal

"""
    Information Security
    Lab 1
    Munics 2022/23
    Carlos Torres Paz (UDC)

    This module contains the OnionRouter class. More information about what this software is
    and how it works is available on the main module "onion"
"""

class OnionRouter(onion.OnionSystem):
    """This class implements an object that receives encrypted messages and forwards them as needed

    The OnionRouter class extends the OnionSystem class and adds the capability to receive,
    process and forward encrypted messages to the next hop, as needed.

    Methods
    -------
    receive_message(bytes) -> tuple[str,str] | None
        Receives, process and forwards encrypted messages
    main()
        Starts the routing process and keeps the loop working. It stops gracefully with a SIGINT.
    """
    
    def receive_message(self, message: bytes) -> tuple[str,str] | None:  
        """Receive, process and forward incoming messages

        This method is called when a message is received from the broker. It first checks that
        the message is addressed to this node (if it isn't, the method exits returning None).
        Then it decrypts it, removing one of the layers.

        If the next layer has the "end" flag, it means that this node is the intended recipient
        of the message. If this is the case, it checks for a sender identification (there can be
        one or a "none" flag, indicating an anonymous sender) and then returns a tuple of two
        strings, containing the sender identification and the message encoded back as a string.

        If the next layer does not have the "end" flag, it means the message has to be forwarded
        to the next node, so the method calls the mqtt client built it to do that and returns None.

        Parameters
        ----------
        message: bytes
            The received message

        Returns
        -------
        tuple[str,str]
            A tuple containing the sender id and the message, both as strings
        """

        onion.logging.info("Received incoming message")
        # Extract user_id of the recipient
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
            # We are the recipient of this message
            onion.logging.info("Message chain end")
            # Now, read the sender id, if available
            sender_id = message[5:10].strip(b'\x00')
            sender_str = "Anonymous sender" if sender_id == b'none' else sender_id.decode("ASCII")

            # Finally, decode the plain text message back into a string
            message_str = message[10:].decode("UTF-8")

            # Return the result as a tuple containing sender_id and plain text message, both as strings.
            return (sender_str, message_str)
        else:
            onion.logging.info("Relaying message to next_node: " + onion.bytes_print(msg_dest))
            # Send the message to the next node via MQTT
            self.mqclient.publish(msg_dest.decode("ASCII"), message)
            return None

    def main(self):
        """Starts and keeps alive the routing process

        This method keeps the OnionRouter listening for new messages to process. It listens for
        the SIGINT (Ctrl+C on bash) signal, and disconnects and stops gracefully if it receives one.

        It has no parameters and returns nothing
        """

        # SIGINT Handler to be able to shut down the program gracefully
        def sigint_handler(signum, frame):
            print()
            onion.logging.info("SIGINT Received. Disconnecting...")
            self.mqclient.disconnect()

        # Register the handler function with the signal library
        signal.signal(signal.SIGINT, sigint_handler)

        # Subscribe to the topic equal to our own user_id (as a string and without the zero-padding bytes)
        topic = self.user_id.strip(b'\x00').decode("ASCII")
        self.mqclient.subscribe(topic)
        onion.logging.info("Subscribed to MQTT topic " + topic)

        # Define a callback function for when a message is received
        def mqtt_on_message(client, userdata, message):
            onion.logging.debug("MQTT Callback on_message")
            # This helper function acts as an interface between the mqtt client
            # and the actual OnionRouter function for message handling, since
            # the receive_message function only expects one argument
            
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
