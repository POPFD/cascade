section .text

global __readcs
global __readcr0
global __readcr3
global __readcr4
global __readdr7
global __writecr0
global __writecr3
global __writecr4
global __lidt
global __sidt
global __lgdt
global __sgdt
global __lldt
global __sldt
global __str
global __ltr
global __vmxon
global __vmclear
global __vmptrld
global __capture_context
global __restore_context

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

__writecr0:
    mov cr0, rcx
    ret

__writecr3:
    mov cr3, rcx
    ret

__writecr4:
    mov cr4, rcx
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

__ltr:
    ltr word [rcx]
    ret

__vmxon:
    vmxon [rcx]
    ret

__vmclear:
    vmclear [rcx]
    ret

__vmptrld:
    vmptrld [rcx]
    ret

__capture_context:
    pushfq
    mov [rcx + 78h], rax
    mov [rcx + 80h], rcx
    mov [rcx + 88h], rdx
    mov [rcx + 0B8h], r8
    mov [rcx + 0C0h], r9
    mov [rcx + 0C8h], r10
    mov [rcx + 0D0h], r11

    mov word [rcx + 38h], cs
    mov word [rcx + 3Ah], ds
    mov word [rcx + 3Ch], es
    mov word [rcx + 42h], ss
    mov word [rcx + 3Eh], fs
    mov word [rcx + 40h], gs

    mov [rcx + 90h], rbx
    mov [rcx + 0A0h], rbp
    mov [rcx + 0A8h], rsi
    mov [rcx + 0B0h], rdi
    mov [rcx + 0D8h], r12
    mov [rcx + 0E0h], r13
    mov [rcx + 0E8h], r14
    mov [rcx + 0F0h], r15

    lea rax, [rsp + 10h]
    mov [rcx + 98h], rax
    mov rax, [rsp + 8]
    mov [rcx + 0F8h], rax
    mov eax, [rsp]
    mov [rcx + 44h], eax

    add rsp, 8
    ret

__restore_context:
    mov ax, [rcx + 42h]
    mov [rsp + 20h], ax
    mov rax, [rcx + 98h]
    mov [rsp + 18h], rax
    mov eax, [rcx + 44h]
    mov [rsp + 10h], eax
    mov ax, [rcx + 38h]
    mov [rsp + 8], ax
    mov rax, [rcx + 0F8h]
    mov [rsp], rax

    mov rax, [rcx + 78h]
    mov rdx, [rcx + 88h]
    mov r8, [rcx + 0B8h]
    mov r9, [rcx + 0C0h]
    mov r10, [rcx + 0C8h]
    mov r11, [rcx + 0D0h]
    cli

    mov rbx, [rcx + 90h]
    mov rsi, [rcx + 0A8h]
    mov rdi, [rcx + 0B0h]
    mov rbp, [rcx + 0A0h]
    mov r12, [rcx + 0D8h]
    mov r13, [rcx + 0E0h]
    mov r14, [rcx + 0E8h]
    mov r15, [rcx + 0F0h]
    mov rcx, [rcx + 80h]

    iretq