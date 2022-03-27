section .text

global __readcs
global __readcr0
global __readcr3
global __readcr4
global __readdr7
global __writecr3
global __lidt
global __sidt
global __lgdt
global __sgdt
global __lldt
global __sldt
global __str

__readcs:
    mov ax, cs
    ret

__readcr0:
    mov rax, cr0
    ret

__readcr3:
    mov rax, cr3
    ret

__readcr4:
    mov rax, cr4
    ret

__readdr7:
    mov rax, dr7
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

__lgdt:
    lgdt [rcx]
    ret

__sgdt:
    sgdt [rcx]
    ret

__lldt:
    lldt [rcx]
    ret

__sldt:
    sldt [rcx]
    ret

__str:
    str word [rcx]
    ret