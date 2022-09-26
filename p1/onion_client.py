#Import common module
import onion

import sys


class OnionClient(onion.OnionSystem):
    def send_message(self, list_of_nodes, plaintext, anonymous=True):
        onion.logging.debug("Sending message to Onion Network")
        # First, reverse the list of nodes, because we encrypt from last to first (the last node in the list is the recipient)
        list_of_nodes.reverse()

        # Prepare the message. Convert to bytes and prepend sender's id (or null bytes if anonymous) and end of route marker
        message = b'end\x00\x00' + (b'none\x00' if anonymous else self.user_id) + plaintext.encode("UTF-8")
        onion.logging.debug("Prepared message: " + onion.bytes_print(message))

        # Start encoding message with every hop's public keys
        for node_id in list_of_nodes:
            #Encode the message and prepend the node's id
            node = self.network[node_id]
            message = node.user_id + self.encrypt_message(node.pubkey, message)
        # We now have the message with all the layers, and the first 5 bytes are the
        # user_id of the first node it's addressed to

        # Queue the message to send to the MQTT broker
        onion.logging.debug("MQTT Publish message")
        self.mqclient.publish(topic=message[:5].strip(b'\x00').decode("ASCII"), payload=message)
        # Start the MQTT client with a 10 second timeout
        onion.logging.debug("Start MQTT Client loop")
        self.mqclient.loop(timeout=10)
        # Disconnect from the MQTT broker
        onion.logging.debug("MQTT Disconnect")
        self.mqclient.disconnect()
        onion.logging.debug("MQTT Disconnected")

        # This function returns the encoded message in a bytes object
        return message

if __name__ == "__main__":
    # Handle command line arguments
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print(
            "Usage: onion_client.py user_id message_route(comma separated) message [-a (anonymous sender)]"
            )
        exit()
    
    send_anon = False
    if len(sys.argv) == 5:
        if (sys.argv[4] == "-a"):
            send_anon = True
        else:
            print("Unrecognised option ", sys.argv[4])
            exit()

    my_user_id = sys.argv[1]
    list_of_nodes = sys.argv[2].split(',')
    message = sys.argv[3]

    # Create an instance of the OnionClient
    client = OnionClient(my_user_id)
    onion.logging.debug("Created instance of OnionClient")
    # Call the send_message function
    onion.logging.debug("Sending message to Onion Network")
    sent = client.send_message(list_of_nodes, message, send_anon)

    print("Sent", len(sent), "bytes")
    print("Beginning with", sent[:20])