section .text

global __readcs
global __readcr0
global __readcr2
global __readcr3
global __readcr4
global __readdr7
global __rdtsc
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
global __xsetbv
global __invd
global __invlpg
global __invept
global __vmxon
global __vmclear
global __vmptrld
global __vmwrite
global __vmread
global __vmlaunch
global __vmresume
global __capture_context
global __restore_context

__readcs:
    mov ax, cs
    ret

__readcr0:
    mov rax, cr0
    ret

__readcr2:
    mov rax, cr2
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

__rdtsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
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

__xsetbv:
    ; assume RCX already contains operand1
    ; move operand2 from RDX into EDX:EAX
    mov eax, edx
    shr rdx, 32
    xsetbv
    ret

__invd:
    invd
    ret

__invlpg:
    invlpg [rcx]
    ret

__invept:
    invept rcx, [rdx]
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

__vmwrite:
    vmwrite rcx, rdx
    ret

__vmread:
    vmread rax, rcx
    ret

__vmlaunch:
    vmlaunch
    ret

__vmresume:
    vmresume
    ; No need to RET as context RIP/RSP will change to VMCS_GUEST_R*P

__capture_context:
    ; Push RFLAGS onto the stack
    pushfq

    ; Low GP registers
    mov [rcx+078h], rax
    mov [rcx+080h], rcx
    mov [rcx+088h], rdx
    mov [rcx+0B8h], r8
    mov [rcx+0C0h], r9
    mov [rcx+0C8h], r10
    mov [rcx+0D0h], r11

    ; Low XMM Registers
    movaps [rcx+01A0h], xmm0
    movaps [rcx+01B0h], xmm1
    movaps [rcx+01C0h], xmm2
    movaps [rcx+01D0h], xmm3
    movaps [rcx+01E0h], xmm4
    movaps [rcx+01F0h], xmm5

    ; Segment selectors
    mov word [rcx+038h], cs
    mov word [rcx+03Ah], ds
    mov word [rcx+03Ch], es
    mov word [rcx+042h], ss
    mov word [rcx+03Eh], fs
    mov word [rcx+040h], gs

    ; High GP registers
    mov [rcx+090h], rbx
    mov [rcx+0A0h], rbp
    mov [rcx+0A8h], rsi
    mov [rcx+0B0h], rdi
    mov [rcx+0D8h], r12
    mov [rcx+0E0h], r13
    mov [rcx+0E8h], r14
    mov [rcx+0F0h], r15

    ; FPU Control Word
    fnstcw word [rcx+0100h]
    mov dword [rcx+0102h], 0

    ; High XMM Registers
    movaps [rcx+0200h], xmm6
    movaps [rcx+0210h], xmm7
    movaps [rcx+0220h], xmm8
    movaps [rcx+0230h], xmm9
    movaps [rcx+0240h], xmm10
    movaps [rcx+0250h], xmm11
    movaps [rcx+0260h], xmm12
    movaps [rcx+0270h], xmm13
    movaps [rcx+0280h], xmm14
    movaps [rcx+0290h], xmm15

    ; XMM control/status register
    stmxcsr dword [rcx+0118h]
    stmxcsr dword [rcx+034h]

    ; Fix context RSP values
    lea rax, [rsp+010h]
    mov [rcx+098h], rax
    mov rax, [rsp+08h]
    mov [rcx+0F8h], rax
    mov eax, [rsp]
    mov [rcx+044h], eax

    mov dword [rcx+030h], 10000Fh

    ; Return
    add rsp, 8
    ret

__restore_context:
    movaps  xmm0, [rcx+01A0h]   ;
    movaps  xmm1, [rcx+01B0h]   ;
    movaps  xmm2, [rcx+01C0h]   ;
    movaps  xmm3, [rcx+01D0h]   ;
    movaps  xmm4, [rcx+01E0h]   ;
    movaps  xmm5, [rcx+01F0h]   ;
    movaps  xmm6, [rcx+0200h]   ; Restore all XMM registers
    movaps  xmm7, [rcx+0210h]   ;
    movaps  xmm8, [rcx+0220h]   ;
    movaps  xmm9, [rcx+0230h]   ;
    movaps  xmm10, [rcx+0240h]  ;
    movaps  xmm11, [rcx+0250h]  ;
    movaps  xmm12, [rcx+0260h]  ;
    movaps  xmm13, [rcx+0270h]  ;
    movaps  xmm14, [rcx+0280h]  ;
    movaps  xmm15, [rcx+0290h]  ;
    ldmxcsr [rcx+034h]          ;

    mov     rax, [rcx+078h]     ;
    mov     rdx, [rcx+088h]     ;
    mov     r8,  [rcx+0B8h]     ; Restore volatile registers
    mov     r9,  [rcx+0C0h]     ;
    mov     r10, [rcx+0C8h]     ;
    mov     r11, [rcx+0D0h]     ;

    mov     rbx, [rcx+090h]     ;
    mov     rsi, [rcx+0A8h]     ;
    mov     rdi, [rcx+0B0h]     ;
    mov     rbp, [rcx+0A0h]     ; Restore non volatile regsiters
    mov     r12, [rcx+0D8h]     ;
    mov     r13, [rcx+0E0h]     ;
    mov     r14, [rcx+0E8h]     ;
    mov     r15, [rcx+0F0h]     ;

    cli                         ; Disable interrupts
    push    qword [rcx+044h]    ; Push RFLAGS on stack
    popfq                       ; Restore RFLAGS
    mov     rsp, [rcx+098h]     ; Restore old stack
    push    qword [rcx+0F8h]    ; Push RIP on old stack
    mov     rcx, [rcx+080h]     ; Restore RCX since we spilled it
    ret                         ; Restore RIP