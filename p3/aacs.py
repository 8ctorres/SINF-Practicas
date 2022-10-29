import math
import os
from pydoc import plain
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

# Number of leaves in the tree
# The depth of the tree depends directly on this value
NUMBER_OF_LEAVES = 8
# Key size used for all cryptographic operations, in bits
KEY_SIZE = 128

class NoValidKeyException(Exception):
    pass

class Key():
    def __init__(self, id: int):
        self.id = id
        # Generate a random key of KEY_SIZE bits
        self.key = os.urandom(KEY_SIZE//8)

class Node():
    def __init__(self, id: int):
        self.id = id
        # Create this node's own key,
        # with the ID equal to that of the node itself
        self.keys: list[Key] = list()
        self.keys.append(Key(self.id))
    
    def add_key(self, key: Key):
        self.keys.append(key)
    
    def add_keys(self, keys: list[Key]):
        for k in keys:
            self.add_key(k)

    def get_parent_id(self) -> int:
        # The parent's id is your own id divided by 2 and rounded down
        # We use integer division so it's already rounded down.
        # If we run this on a root node, it returns zero, which is an invalid ID
        return self.id//2
    
    def get_sibling_id(self) -> int:
        # The sibling's id is the next if your id is even (this means you're the left sibling)
        # and the one before if your id is odd (this means you're the one on the rigth)
        return (self.id +1) if (self.id % 2 == 0) else (self.id - 1)

    def get_key(self) -> Key:
        # Returns the node's own key
        return self.keys[0]

class AACSBinaryTree():
    def get_node(self, id: int) -> Node:
        # This adjust for the fact that the first node (the root) has ID = 1
        return self.nodes[id-1]

    def __init__(self, n_leaves: int):
        self.n_leaves = n_leaves
        # First, calculate the depth needed for this tree
        # It has to be at least log2(n_leaves) deep (assuming
        # root is a depth 0)
        self.depth = math.ceil(math.log(n_leaves, 2))
        # Generate all the nodes, starting in 1 (root is node nº 1)
        self.nodes = list()
        for i in range(1, (2**(self.depth+1))):
            # Create a new Node
            # This operation generates the node's own key
            n = Node(i)
            if i == 1:
                # For the root node, nothing else is done
                pass
            else:
                # For any other nodes, we add to the current node
                # all the keys that the parent has
                n.add_keys(self.get_node(n.get_parent_id()).keys)

            # Add the node to the tree in current position
            self.nodes.append(n)
        
        # After generating the entire tree, each node has it's own key
        # in the first position of its list

    def get_leaves(self) -> list[Node]:
        # Return all leave nodes
        return self.nodes[(2**self.depth)-1:]

    def is_leaf(self, n: Node) -> bool:
        # Checks is a given node is a leaf of this tree
        # (assumes the node is actually part of the tree,
        # only checks based on ID)
        return n.id >= (2**self.depth)

class AACSSystem():
    def __init__(self):
        # Create the tree, with all its nodes and keys and all
        self.tree = AACSBinaryTree(NUMBER_OF_LEAVES)

    def AESencrypt(self, key: bytes, plaintext: bytes):
        # Generate random IV, 128 bits in size
        IV = os.urandom(128//8)

        # Instantiate an encryptor object
        encryptor = Cipher(
            algorithm=algorithms.AES128(key),
            mode=modes.CBC(IV),
            backend=default_backend()
        ).encryptor()

        # Encrypt the plaintext, prepend the IV and return that as a bytes object
        return IV + encryptor.update(plaintext) + encryptor.finalize()

    def AESdecrypt(self, key:bytes, ciphertext: bytes):
        # First, retrieve the Initialization Vector
        IV = ciphertext[:(128//8)]
        ciphertext = ciphertext[(128//8):]

        # Instantiate a decryptor object
        decryptor = Cipher(
            algorithm=algorithms.AES128(key),
            mode=modes.CBC(IV),
            backend=default_backend()
        ).decryptor()

        # Return the plaintext
        return decryptor.update(ciphertext) + decryptor.finalize()

    def find_cover(self, S_ids: list[int]) -> list[int]:
        # Basic situation -> If S is empty, the cover is just the root node:
        if len(S_ids) == 0:
            return [1]
        # If not, go on
        # This function receives a list of Node IDs. The first thing it does is map it onto a list
        # of the actual Node objects that correspond to those ids
        S = [self.tree.get_node(id) for id in S_ids]
        # Create two sets: one to store the cover and one to store the parents of the nodes in S
        cover = set()
        forbidden = set()
        # Now, for each node calculate its cover as if it was the own
        for node in S:
            # Run until we reach the root
            while node.id != 1:
                #Add the sibling's id to the cover set, and the node's own to the "forbidden" set
                forbidden.add(node.id)
                cover.add(node.get_sibling_id())
                #For the next iteration, do the same with the node's parent
                node = self.tree.get_node(node.get_parent_id())
        # After this we have a set which is the union of the individual covers of every node,
        # and we remove from it every node that's "forbidden", that is, every node that's in the
        # path from an excluded leaf to the root
        for node_id in forbidden:
            try:
                cover.remove(node_id)
            except KeyError:
                # If a forbidden is not a member of the cover, it's not a problem
                pass
        # Return the cover set as a list, and ordered from the root so it's more readable
        # This is a list of IDs, not of Node objects
        return sorted(cover)

    def AACSencrypt(self, plaintext: bytes, excluded_devices: list[int]) -> bytes:
        # First of all, we need to pad the plaintext so that the size is n exact number
        # of 128 bit blocks
        plaintext_length = len(plaintext)
        if len(plaintext) % (128//8) !=0:
            # Add zeros as needed
            plaintext = plaintext + b'\x00'*((128//8)-(len(plaintext) % (128//8)))

        # Now, generate a new key and encrypt the plaintext with it using AES128-CBC
        main_key = os.urandom(128//8)
        # Add a 128 bit block at the beginning indicating the size of the plaintext, so
        # later we know how much to trim out
        ciphertext = self.AESencrypt(main_key, (plaintext_length.to_bytes(128//8, sys.byteorder, signed=False))+plaintext)

        # Then calculate the cover set for the excluded_devices
        cover = self.find_cover(excluded_devices)

        # Then encrypt the original key once for each node in the cover
        cipherkeys = bytes()
        for node_id in cover:
            # Get the corresponding key
            nodekey = self.tree.get_node(node_id).get_key().key
            # We add a 128 bit marker at the beggining of the plaintext, so that on
            # decryption we can know if what we have is actually valid or not,
            # since the scheme we're using doesn't implement any message integrity
            # mechanisms
            cipherkeys = cipherkeys + self.AESencrypt(key=nodekey, plaintext=((b'is_valid_aacskey')+main_key))
            # length of each "cipherkey" is 384 bits
            # (128 IV + 256bits ciphertext, of which: 128 are marker and 128 actual encrypted key)

        # Now return as a bytes object the content that will be written to the output file
        # The main key encrypted with all the keys in the cover, then a marker to know when
        # there are no more nodekeys, and then the actual encrypted content
        return cipherkeys + (b'end_of_node_keys' + b'\x00'*32) + ciphertext
    
    def AACSdecrypt(self, ciphertext: bytes, viewing_node: Node) -> bytes:
        # First step is to decrypt the main key, using any of the keys this node has available
        main_key = None
        while main_key == None:
            # Extract the first 384 bits of ciphertext
            ckey = ciphertext[:384//8]
            if ckey == (b'end_of_node_keys' + b'\x00'*32):
                # If ckey is the end of keys marker, it means that we have search every node key
                break
            ciphertext = ciphertext[384//8:]
            # Try decrypting this cipherkey with every one of the node's available keys
            for nkey in viewing_node.keys:
                main_key = self.AESdecrypt(key=nkey.key, ciphertext=ckey)        
                # This returns a 256 bit string
                # If the key was correct, the first 128 bits of it are
                # exactly the string 'is_valid_aacskey'
                # If not, then they're random garbage
                if main_key[:(128//8)] == (b'is_valid_aacskey'):
                    # Success. Delete the marker and break out of the loop
                    main_key = main_key[(128//8):]
                else:
                    # Erase it and keep going
                    main_key = None

        # Once we're out of the While loop, it either means we found one or we ran out of keys
        if main_key == None:
            # If we didn't find one, raise an exception and exit.
            raise NoValidKeyException("Can't decrypt")
        else:
            # If we found one, the first step is to remove all the others that may be left over
            head = None
            while head != (b'end_of_node_keys' + b'\x00'*32):
                head = ciphertext[:(384//8)]
                ciphertext = ciphertext[(384//8):]
            # Once we've done that, we use the main_key we found to decrypt our (now clean) ciphertext
            plaintext_padded = self.AESdecrypt(key=main_key, ciphertext=ciphertext)
            # But this ciphertext still has a 128-bit block at the beginning to work out padding
            plaintext_length = int.from_bytes(plaintext_padded[:(128//8)], sys.byteorder, signed=False)
            plaintext_padded = plaintext_padded[(128//8):]
            # If it wasn't padded, the length will be an exact math
            if len(plaintext_padded) == plaintext_length:
                # We don't need to do anything
                return plaintext_padded
            else:
                # First, calculate the amout of padding
                padding_size = len(plaintext_padded) -plaintext_length
                # Remove that amount of bytes from the END of the plaintext
                # And then return that as the actual plaintext
                return plaintext_padded[:-padding_size]

if __name__ == "__main__":
    aacs = AACSSystem()

    # This software is used interactively, to allow for several different operations
    # with the same set of keys. Since the keys are all randomly generated on startup
    # it would be a problem if the program exited after each operation

    quit = False
    while not quit:
        print("Select an operation:")
        print(" 1 -> Encryption")
        print(" 2 -> Decryption")
        print(" q -> Quit")
        op = input(" > ")
        if op == "1":
            # Encyption of a file
            filename_in = input("Name of the input file? ")
            with open(filename_in, "rb") as file:
                file_in_contents = file.read()
            print("Read", len(file_in_contents), "bytes from file", filename_in, sep=" ")

            # Read excluded devices
            excluded_in = input("List of excluded devices (comma separated, can be empty): ")
            if len(excluded_in) == 0:
                excluded_devices= list()
            else:
                excluded_devices = [int(s) for s in excluded_in.split(',')]

            # Open new file for writing
            filename_out = input("Name of output file? ")
            file_out = open(filename_out, "wb")
            print("Opened file", filename_out, "for writing", sep=" ")

            encrypted_content = aacs.AACSencrypt(file_in_contents, excluded_devices)
            file_out.write(encrypted_content)
            file_out.flush()
            file_out.close()
            print("Wrote", len(encrypted_content), "bytes")
            print();print()

        elif op == "2":
            # Decryption of a file
            filename_in = input("Name of the input file? ")
            with open(filename_in, "rb") as file:
                file_in_contents = file.read()
            print("Read", len(file_in_contents), "bytes from file", filename_in, sep=" ")

            # Read viewing_node
            while True:
                viewing_node_id = int(input("Which node is used for this decryption? (Enter ID) "))
                viewing_node = aacs.tree.get_node(viewing_node_id)
                if not aacs.tree.is_leaf(viewing_node):
                    print("Node must be a leaf of the tree")
                else:
                    break

            # Open new file for writing
            filename_out = input("Name of output file? ")
            file_out = open(filename_out, "wb")
            print("Opened file", filename_out, "for writing", sep=" ")

            try:
                decrypted_content = aacs.AACSdecrypt(file_in_contents, viewing_node)
                file_out.write(decrypted_content)
                file_out.flush()
                file_out.close()
                print("Wrote", len(decrypted_content), "bytes")
            except NoValidKeyException:
                print("The selected node has no valid key to decrypt the file")
                print("Select a different node and try again")
                file_out.close()

            print();print()

        elif op == "q":
            quit = True
        else:
            pass
