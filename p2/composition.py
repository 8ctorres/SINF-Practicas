import secrets
import randomgen.aes
import numpy as np
import sys

"""
    Information Security
    Lab 2b
    Munics 2022/23
    Carlos Torres Paz (UDC)

    This laboratory assignment aims to implement two different methods of PRG composition:
    parallel composition and Blum-Micali composition.
"""

def bytes_print(b: bytes):
    """Takes a bytes object and pretty prints it

    Takes a bytes object and for each byte, prints the hexadecimal representation,
    all separated by a space between each byte, in columns of 32 bytes.
    
    Parameters
    ----------
    b: bytes
        The bytes object to print

    Returns
    -------
    None
    """
    
    s = ""

    for i in range(len(b)):
        h = hex(b[i])[2:] 
        s = s + (h if len(h) == 2 else "0" + h) + " "
        if (i+1) % 32 == 0:
            s = s + "\n"

    print(s)

def g(seed: np.uint16) -> np.uint64:
    """The G(s) function, a secure PRG

    This is the chosen implementation of the secure PRG needed for the G function.
    It is based on the AES encryption protocol, and has an output size of 64 bits.
    For this lab, we'll be using 16 bit seeds.

    Arguments
    ---------
    seed: np.uint16
        The input to the PRG, 16 bits in size.
        
    Returns
    -------
    np.uint64
        The output of the PRG, a 64 bit random number that is always the same for
        one given seed.
    """
    return np.uint64(randomgen.aes.AESCounter(seed=int(seed)).random_raw(1)[0])

def parallel(seed: bytes):
    """Parallel composition of PRGs

    In the parallel composition, an arbitrarily long seed is taken, split up in blocks
    of the size the G function expects (16 bits for this case), and fed individually to
    the G function. Then all of the outputs are again concatenated.

    Arguments
    ---------
    seed: bytes
        An arbitrarily long bytes array, representing the input seed

    Returns
    -------
    bytes
        The output of the composed PRG, a bytes object, 4 times the size of the input   
    """

    # First, pad the input so that it's a multiple of 16 bits (2 bytes)
    if len(seed) % 2 != 0:
        #Just add one byte at the end
        seed = seed + b'\x00'
    
    output = bytes() # Create an empty bytes object
    for i in range (0, len(seed), 2):
        output = output + g(np.frombuffer(buffer=seed[i:i+2], dtype="u2")[0]).tobytes()

    return output

def blum_micali(seed: np.uint32, steps: int, g: np.uint32, p: np.uint32) -> bytes:
    """Blum-Micali composition of PRGs

    In the Blum-Micali algorithm, an input seed is taken and fed to the function, which returns an output
    bit and a seed for the next step. This is repeated up to N steps.

    Arguments
    ---------
    seed: np.uint32
        A 32 bits seed
    steps: int
        The number of iterations
    g: np.uint32
        The G value
    p: np.uint32
        The P value 
    
    Returns
    -------
    bytes
        The output of the composed PRG
    """
    
    # Create an empty string for the output
    output = ""
    x = seed
    # Pre-calculate the limit so the computation doesn't run every time
    # limit = (p-1)//2
    for _ in range(steps):
        # Run the function with the current seed to obtain the next seed
        # Xi+1 = g^Xi mod p
        x = np.mod(np.power(g, x), p)
        # Choose the output bit for this step
        o = "1" if np.less(x, (p-1)//2) else "0"
        # Append the bit to the output
        output = output + o
    
    # Convert the string of bits to bytes and return that
    return int(output, 2).to_bytes(steps//8, sys.byteorder)


if __name__ == "__main__":
    def main_parallel():
        seed_size = int(input("Choose a size for the seed, in bits: "))
        print("Generating seed...")
        seed: bytes = secrets.randbits(seed_size).to_bytes(seed_size//8, sys.byteorder)
        print("Seed =", bytes_print(seed))
        print()
        out: bytes = parallel(seed)
        print("Output of the composed PRG:")
        bytes_print(out)
    
    def main_blum_micali():
        seed_in = input("Choose a seed, leave empty for random: ")
        if len(seed_in) == 0:
            seed = secrets.randbits(32)
            print("Seed is", seed)
        else:
            seed = np.uint32(int(seed_in))
        
        steps = int(input("Choose the output size in bits: "))

        # p is a prime number, and g is a primitive root modulo p

        p = 3473997983
        g = 3473997981

        out = blum_micali(seed, steps, g, p)
        print("Output of the composed PRG:")
        bytes_print(out)


    print("PRG Composition")
    print("Choose type of composition")
    print("1 -> Parallel")
    print("2 -> Blum-Micali")
    type = int(input("Type? (1/2) "))
    if type == 1:
        main_parallel()
    elif type == 2:
        main_blum_micali()
    else:
        print("Invalid input type")
        exit(-1)
