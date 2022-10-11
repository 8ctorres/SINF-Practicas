#Import common module
import onion

import sys

"""
    Information Security
    Lab 1
    Munics 2022/23
    Carlos Torres Paz (UDC)

    This module contains the OnionClient class. More information about what this software is
    and how it works is available on the main module "onion"
"""

class OnionClient(onion.OnionSystem):
    """This class implements an object that can send encrypted messages via the onion network

    The OnionClient class extends the OnionSystem class and adds the capability to send messages
    to a destination via a specific set of hops.

    Methods
    -------
    send_message(list_of_nodes: list[str], plaintext: bytes, anonymous: bool = True) -> bytes
        Encrypts a message and sends it to the network
    """

    def send_message(self, list_of_nodes: list[str], plaintext: str, anonymous: bool =True) -> bytes:
        """Encrypts a message and sends it to the network

        This method takes a plaintext message, and adds N hybrid encryption layers to it, one for
        each hop the message is going to traverse in the network.

        Parameters
        ---------
        list_of_nodes: list[str]
            The list of nodes the message will go through, from first to last (the last being
            the intended recipient of the message)
        plaintext: str
            The actual message to be sent
        anonymous: bool
            A boolean value indicating whether the message should be sent anonymously

        Returns
        -------
        bytes
            The actual payload that was sent to the network, being the message with all of the
            encryption layers on top of it.
        """

        onion.logging.debug("Sending message to Onion Network")
        # First, reverse the list of nodes, because we encrypt from last to first (the last node in the list is the recipient)
        list_of_nodes.reverse()

        # Prepare the message. Convert to bytes and prepend sender's id (or null bytes if anonymous) and end of route marker
        message = b'end\x00\x00' + (b'none\x00' if anonymous else self.user_id) + plaintext.encode("UTF-8")
        onion.logging.debug("Prepared message: " + onion.bytes_print(message))

        # Start encoding message with every hop's public keys
        for node_id in list_of_nodes:
            #Search the network dictionary for the corresponding OnionNode
            node = self.network[node_id]
            #Encode the message and prepend the node's id
            message = node.user_id + self.encrypt_message(node.pubkey, message)
        # We now have the message with all the layers, and the first 5 bytes are the
        # user_id of the first node it's addressed to
        first_hop = message[:5].strip(b'\x00').decode("ASCII")
        msg_send = message[5:]

        # Queue the message to send to the MQTT broker
        onion.logging.debug("MQTT Publish message")
        self.mqclient.publish(topic=first_hop, payload=msg_send)
        # Start the MQTT client with a 10 second timeout,
        # which should be more than enough to send the message
        onion.logging.debug("Start MQTT Client loop")
        self.mqclient.loop(timeout=10)
        # When the loop function returns, this means either the message was sent or the timeout was reached
        # Either way, we disconnect from the MQTT broker
        onion.logging.debug("MQTT Disconnect")
        self.mqclient.disconnect()
        onion.logging.debug("MQTT Disconnected")

        # This function returns the encoded message in a bytes object
        return msg_send

if __name__ == "__main__":
    # Handle command line arguments
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print(
            "Usage: onion_client.py user_id message_route(comma separated) message [-a (anonymous sender)]"
            )
        exit()
    
    # Look for the "-a" flag indicating that the message will be sent anonymously
    send_anon = False
    if len(sys.argv) == 5:
        if (sys.argv[4] == "-a"):
            send_anon = True
        else:
            print("Unrecognised option ", sys.argv[4])
            exit()

    # Parse all the other arguments
    my_user_id = sys.argv[1]
    list_of_nodes = sys.argv[2].split(',')
    message = sys.argv[3]

    # Create an instance of the OnionClient
    client = OnionClient(my_user_id)
    onion.logging.debug("Created instance of OnionClient")
    # Call the send_message function
    onion.logging.debug("Sending message to Onion Network")
    sent = client.send_message(list_of_nodes, message, send_anon)
    
    # When the send_message function returns, show the first bytes of what was sent, and exit
    print("Sent", len(sent), "bytes")
    print("Beginning with", sent[:20])