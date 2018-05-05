//SLAE Shellcode Host
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x41\x41\x41SHELLCODE_HERE\x41\x41\x41";

int main(void) {
    printf("Shellcode length: %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())shellcode;

    ret();
}
