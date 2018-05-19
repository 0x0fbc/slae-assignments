#!/usr/bin/env python3
"""
x86 Middle Squares Decoder Stub Sample
Usage: this_script.py [-e] <shellcode_to_encode>, if -e is set do not return full shellcode with decoder stub.
Author: @fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

from sys import argv
from secrets import SystemRandom


def nulls_in_hex(input_int):
    """Determine if there are nulls in a given dword sized int."""
    hex_input = "{0:#0{1}x}".format(input_int, 10)
    split_hex = map("".join, zip(*[iter(hex_input)]*2))
    hex_list = list(split_hex)
    for i in hex_list:
        if i == '00':
            return True
    return False

def nulls_in_bytearray(input_bytearray):
    for i in input_bytearray:
        if i == 0:
            return True
    return False

def generate_seed():
    """Generate and return an int that when converted to bytes contains no nulls."""
    seed = 0

    while nulls_in_hex(seed) is True:
        seed = SystemRandom().randrange(0x0000FFFF, 0xFFFFFFFF)  # generate a random seed
    if nulls_in_hex(seed) is False:  # Ensure that we're returning a seed without nulls
        return seed
    else:
        raise Exception("generate_seed() tried to return a seed with null bytes")


def array_hex_str_to_ints(list_of_hex_strings):
    """This function accepts a list of strings containing hex digits and
    converts each item into bytes.
    For example, [21, 41, 42, 43] is converted into [b'!', b'A', b'B', b'C']
    """

    for item in range(0, len(list_of_hex_strings)):
        list_of_hex_strings[item] = int(list_of_hex_strings[item], 16)

    return list_of_hex_strings


def expand_seed(seed, limit):
    """Expand seed into a list of ints that represents a pad of bytes to use for encoding."""
    pad = []

    for i in range(0, limit):

        seed = seed * seed
        hexseed = "{0:#0{1}x}".format(seed, 18)[-16:][4:12]  # get the middle eight bytes of the squared seed
        for j in range(0, len(hexseed), 2):
            pad.append(hexseed[j:j+2])
        seed = int(("0x" + hexseed), 16)

    processed_pad = array_hex_str_to_ints(pad)
    return processed_pad


def process_shellcode(shellcode_input):
    """Convert a string of hex values formatted as C-style hex escapes
    into an array of integers."""

    split_shellcode = shellcode_input.split("x")
    split_shellcode = split_shellcode[1::]  # Remove bogus empty string at start of array

    processed_shellcode = array_hex_str_to_ints(split_shellcode)

    return processed_shellcode


def encode_to_strings(seed, shellcode):
    """Encode provided shellcode and return human-readable strings for use with
    C-like languages or NASM.
    seed must be a dword (32 bit) sized int
    shellcode must be an array of char sized ints, preferably from process_shellcode"""

    pad = expand_seed(seed, ((len(shellcode) // 4) + 1))

    hex_escape_encoded = b''
    nasm_escaped_encoded = b''

    for i in range(0, len(shellcode)):
        encoded_byte = shellcode[i] ^ pad[i]

        hex_escape_encoded += b'\\x'
        hex_escape_encoded += bytes('%02x' % (encoded_byte & 0xff), 'iso-8859-1')

        nasm_escaped_encoded += b'0x'
        nasm_escaped_encoded += bytes('%02x,' % (encoded_byte & 0xff), 'iso-8859-1')

    return hex_escape_encoded, nasm_escaped_encoded


def encode_to_bytes(seed, shellcode):
    """Encode provided shellcode and return encoded bytes as a bytearray.
    seed must be a dword (32 bit) sized int
    shellcode must be an array of char sized ints, preferably from process_shellcode"""
    pad = expand_seed(seed, ((len(shellcode) // 4) + 1))

    encoded_shellcode = []

    for i in range(0, len(shellcode)):
        encoded = shellcode[i] ^ pad[i]

        encoded_shellcode.append(encoded)

    return bytes(encoded_shellcode)


def set_ecx(rounds_needed):
        return b"\xb1" + rounds_needed.to_bytes(1, byteorder='little')


def main():
    usage = """
    Usage: %s [-e] <shellcode_to_encode>
    -e
        If the -e flag is used, only encode the shellcode, do not insert it into a decoder stub.
    """
    if len(argv) < 2:
        print(usage)
        raise SystemExit
    elif len(argv) > 2 and argv[1] != '-e':
        print(usage)
        raise SystemExit
    elif len(argv) == 2 and argv[1] == '-e':
        print(usage)
        raise SystemExit

    if argv[1] == '-e':
        """If called with -e flag encode and return seed, various lengths
        the initial seed, and the encoded bytes in various formats."""
        shellcode = process_shellcode(argv[2])
        seed = generate_seed()
        hex_escaped_encoded, nasm_escaped_encoded = encode_to_strings(seed, shellcode)

        print('Real shellcode length in bytes: %d' % len(shellcode))
        print('Number of rounds to decode: %d' % ((len(shellcode) // 4) + 1))
        print('Starting seed: %s' % hex(seed))
        print('\nEncoded data hex escaped:')
        print(str(hex_escaped_encoded, 'utf-8'))
        print('\nEncoded data in 0x (nasm) format:')
        print(str(nasm_escaped_encoded, 'utf-8')[:-1])
    else:
        """If not called with -e encode shellcode, build a decoder, and return
        complete shellcode with completed decoder stub."""
        shellcode = process_shellcode(argv[1])
        if len(shellcode) > 1023:
            print('ERROR: Payload cannot be longer than 1024 bytes!')

        while True:
            seed = generate_seed()
            decoder = (
                       bytearray("\xeb\x23"         # <_start>: jmp <call_decoder>
                                 "\x31\xc9"         # <setup>: xor ecx, ecx
                                 "\x5e"             # pop esi
                                 "\x89\xf7",
                                 'iso-8859-1')        # mov edi, esi

                       + b"\xb8"                    # mov eax, <seed>
                       + seed.to_bytes(4, byteorder='little',
                                       signed=False)

                       + bytearray(set_ecx(((len(shellcode) // 4) + 1)))

                       + bytearray("\xf7\xe0"       # <decode_loop>: mul eax
                                   "\x66\x89\xd0"   # mov ax, dx
                                   "\xc1\xc8\x10"   # ror eax, 0x10
                                   "\x89\xc3"       # mov ebx, eax
                                   "\x0f\xcb"       # bswap ebx
                                   "\x33\x1f"       # xor ebx, [edi]
                                   "\x89\x1f"       # mov [edi], ebx
                                   "\x83\xc7\x04"   # add edi, 0x04
                                   "\xe2\xeb"       # loop <decode_loop>
                                   "\xff\xe6"       # jmp esi
                                   "\xe8\xd8\xff\xff\xff",  # call <setup>
                                   'iso-8859-1')
                     )

            shellcode_with_decoder = decoder + encode_to_bytes(seed, shellcode)

            return_string = b''

            if nulls_in_bytearray(shellcode_with_decoder) is True:
                continue

            for i in shellcode_with_decoder:
                return_string += b'\\x'
                return_string += b'%02x' % (i & 0xff)

            break

        print('Middle Squares Shellcode Encoder')
        print('Seed used: %s' % hex(seed))
        print('\nLength: %d\n' % len(shellcode_with_decoder))
        print(return_string.decode("utf-8"))


if __name__ == '__main__':
    main()
