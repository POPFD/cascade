section .text

global __readcs
global __readcr3
global __writecr3

__readcs:
    mov ax, cs
    ret

__readcr3:
    mov rax, cr3
    ret

__writecr3:
    mov cr3, rcx
    ret