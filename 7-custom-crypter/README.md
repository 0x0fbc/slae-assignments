
## Introduction

This script accepts a shellcode payload, encrypts it using libsodium's secret box (chacha20/poly1305) and generates a C source file that includes key, nonce, and ciphertext material is compiled and statically linked to glibc and libsodium. The resulting executable should run on most 32 bit linux systems.

## Requirements

This code depends on jinja2 and pynacl for python3.6.

To install, have python3 installed and run `pip3 install jinja2 pynacl`

The C host this generates and compiles depends on a 32 bit libsodium to build, you'll need to install libsodium-dev:i386 using your system's package manager. The resulting elf executable is statically linked to libsodium, you should *not* need it installed on your target to run the decrypter. Building was tested and works on Debian Testing and Ubuntu 17.10. To install the dependancies on a 32 bit debian based system run `sudo apt install libsodium-dev`. If you are on a 64 bit debian based system, you'll need to enable i386 multiarch with dpkg by running `dpkg --add-architecture i386` and then running `apt update && apt install gcc-multilib libsodium-dev:i386`.

`glibc` and `libsodium` are statically linked into the executable. The resulting files should work on a freshly installed system with no libsodium. It will not, however, work on a 64 bit Linux system. The location of the libsodium library and the target architecture need to be changed if your target system is 64 bit.

## Crypting

Usage: python3 libsodium_crypter.py <output_filename> <shellcode_to_crypt>

