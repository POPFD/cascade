section .text

global __readcs
global __readcr3
global __writecr3
global __lidt
global __sidt

__readcs:
    mov ax, cs
    ret

__readcr3:
    mov rax, cr3
    ret

__writecr3:
    mov cr3, rcx
    ret

__lidt:
    lidt [rcx]
    ret

__sidt:
    sidt [rcx]
    ret