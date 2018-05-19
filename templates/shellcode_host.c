//SLAE Shellcode Host
#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"PASTE_SHELLCODE_HERE";

int main(void) {
    printf("Shellcode length: %d\n", strlen(shellcode));

    int (*ret)() = (int(*)())shellcode;

    ret();
}
