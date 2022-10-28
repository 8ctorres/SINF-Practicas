import secrets
import randomgen.aes
import numpy as np

"""
    Information Security
    Lab 2
    Munics 2022/23
    Carlos Torres Paz (UDC)

    This Laboratory assingment aims to successfully implement a bit commitment
    scheme. This program shows two individuals, Alice and Bob interchanging a bit
    and using a bit commitment scheme to ensure consistency and security.

    The code for this lab is organised in three Python classes:
    - BitCommitmentParticipant: This class contains the common functions for
        the bit commitment protocol, like the G function and the commit function
    - Alice: This class represents Alice, the first participant
    - Bob: This class represents Bob, the second participant

    The __main__ function makes use of these classes and adds a few print statements
    to make it easier to follow through the process

    This project makes use of the secrets module from Python and the "randomgen" library
    for the generation of random numbers. It also uses NumPy for the handling of the 64 bit
    integers. Even tough the native Python "int" type does handle 64-bit integers, the
    bitwise XOR operation used in the commit function showed to be buggy and problematic depending
    on the size of the number. Using numpy solves this as it allows me to forcefully set the
    variable size to a 64-bit unsigned.

    More detailed documentation is available under each individual component
"""

class BitCommitmentParticipant:
    """A class used to represent a participant in the bit commitment process

    This class is used to model any of the two participants in a bit commitment process.

    Attributes
    ----------
    None

    Methods
    -------
    choose_random_string (size: int) -> np.uint64
        Generates a random number of "size" bits
    
    g (seed: np.uint64) -> np.uint64
        The cryptographically secure pseudo-random number generator
    
    commit(s: np.uint64, r: np.uint64, bit: bool) -> np.uint64
    """

    def choose_random_string(self, size: int) -> np.uint64:
        """Generate a random number

        This method generates a random integer using a cryptographically secure PRG (pseudo random generator)
        from the Python module "secrets" (source: https://docs.python.org/3/library/secrets.html#module-secrets).
        This module itself makes use of the "/dev/urandom device, relying on the Linux kernel's implementation of
        a CSPRNG.

        Arguments
        ---------
        size: int
            The size of the bitsring, in bits.

        Returns
        -------
        np.uint64
            The integer represented by the randomly generated bitstring of the desired size, as a Numpy object
        """
        return np.uint64(secrets.randbits(size))

    def g(self, seed: np.uint64) -> np.uint64:
        """The G(s) function, a secure PRG

        This is the chosen implementation of the secure PRG needed for the G function.
        It is based on the AES encryption protocol, and has an output size of 64 bits.
        Because the assignment states that the output space must be at least 3 times bigger
        than the Seed space, we'll be using 16 bits seeds.

        Arguments
        ---------
        seed: np.uint64
            The input to the PRG.
        
        Returns
        -------
        np.uint64
            The output of the PRG, a random number that is always the same for
            one given seed.
        """
        return np.uint64(randomgen.aes.AESCounter(seed=int(seed)).random_raw(1)[0])

    def commit(self, s: np.uint64, r: np.uint64, bit: bool) -> np.uint64:
        """The commitment function

        This is the implementation of the commitment function defined in the assigment.
        As stated above, uses NumPy types to avoid problems with the native XOR implementation.

        Arguments
        ---------
        s: np.uint64
            The random number chosen by Bob, used as the seed for G
        r: np.uint64
            The random number chosen by Alice
        bit: bool
            The bit to commit to

        Returns
        -------
        np.uint64:
            A 64 bit commitment string, contained in a NumPy object
        """
        commit = self.g(s)
        if bit:
            # If bit is 1 (true)
            commit = np.bitwise_xor(commit,r)
        return commit


class Alice(BitCommitmentParticipant):
    """A class used to represent the first participant

    This class represents Alice, the first of the two participants in the
    bit commitment process

    Attributes
    ----------
    r: np.uint64
        The random number generated in step 1
    c: np.uint64
        The commitment string received from Bob

    Methods
    -------
    choose_random_r() -> np.uint64
        Returns a random number and also stores it as self.r

    receive_commitment(c: np.uint64)
        Receives and stores a commitment string

    check_commitment(bit: bool, s: np.uint64) -> np.uint64
        Computes the commit function again to check the commitment was correct        
    """
    def choose_random_r(self) -> np.uint64:
        """Choose random number R
        
        First step: Alice chooses a random number R and sends it to Bob

        Arguments
        ---------
        None

        Returns
        -------
        np.uint64
            The random R
        """
        self.r = self.choose_random_string(size=64)
        return self.r

    def receive_commitment(self, commitment: np.uint64):
        """Receives the commitment string from Bob

        Arguments
        ---------
        commitment: np.uint64
            The commitment string generated by Bob
        
        Returns
        -------
        None
        """
        self.c = commitment

    def check_commitment(self, bit: bool, s: np.uint64) -> np.uint64:
        """Checks that the commit string is legitimate
        
        This function computes the commit string again after receiving b0 and s
        so that Alice can be sure that Bob didn't lie.

        Arguments
        ---------
        bit: bool
            The bit that Bob says he committed to
        s: np.uint64
            The seed number received from Bob

        Returns
        -------
        np.uint64
            The commitment string calculated by Alice, which should match the one received from Bob
        """
        return self.commit(s, self.r, bit)

class Bob(BitCommitmentParticipant):
    """A class used to represent the second participant
    
    This class represents Bob, the second of the two participants in the
    bit commitment process

    Attributes
    ----------
    bit: bool
        The bit chosen by Bob
    r: np.uint64
        The random number generated by Alice in step 1

    Methods
    -------
    get_Alice_R (r: np.uint64)
        Receives the random number R from Alice
    
    compute_commit() -> np.uint64
        Generates a random number s and computes the commitment function

    get_verification_data() -> tuple[bool, np.uint64]

    """
    def __init__(self, bit: bool):
        self.bit = bit

    def get_Alice_R(self, r: np.uint64) -> None:
        """Receives the random number R from Alice
    
        First step: Bob receives the random number that Alice just generated

        Arguments
        ---------
        r: np.uint64
            The R number computed by Alice

        Returns
        -------
        None
        """
        self.r = r
    
    def compute_commit(self) -> np.uint64:
        """Computes the commit string

        As specified in the assignment, the commit function calculates
        a commit string and outputs it, to be sent to the other party.

        Returns
        -------
        np.uint64
            The commitment string
        """
        # Bob generates the random number S
        self.s = self.choose_random_string(size=16)
        # Bob calculates the commit string
        return self.commit(self.s, self.r, self.bit)
    
    def get_verification_data(self):
        """Outputs the verification string

        Outputs the commited bit and the verification string S

        Returns
        -------
        tuple[bool, np.uint64]
        """
        return (self.bit, self.s)

if __name__ == "__main__":
    is_honest = True if input("Quieres que Bob sea honesto (y/n): ") == "y" else False
    bit = bool(int(input("¿Qué bit va a tener Bob? (0 or 1): ")))
    print()

    # Instanciamos a Alice y a Bob
    alice = Alice()
    bob = Bob(bit)

    # Empezamos el proceso de commitment
    # Alice genera su R y se lo pasa a Bob
    print("Alice escoge un numero R aleatorio")
    r = alice.choose_random_r()
    print("r =", r)
    bob.get_Alice_R(r)
    print()

    # Bob calcula el commitment string y se lo manda a Alice
    print("Bob calcula el commitment string c")
    c = bob.compute_commit()
    print("c =", c)
    alice.receive_commitment(c)
    print()

    guess = bool(int(input("Alice: Adivina cuál es el bit que escogió Bob: (0 o 1): ")))
    print()

    if (guess == bit) ^ (not is_honest):
        print("Bob dice: Correcto!")
    else:
        print("Bob dice: Incorrecto.")
    print()

    print("Alice comprueba el resultado")
    print()

    (bit, s) = bob.get_verification_data()
    # Invertimos el bit si Bob miente
    bit = bit if is_honest else not(bit)
    
    print("Bob dice que su bit es", "1" if bit else "0")
    print("El número S de Bob es", s)
    print()

    print("Alice calcula de nuevo el commit string")
    c2 = alice.check_commitment(bit, s)
    print("c2 =", c2)
    print()

    if (c == c2):
        print("Comprobación exitosa, Bob no mentía")
    else:
        print("Compobación no exitosa, Bob mentía")

