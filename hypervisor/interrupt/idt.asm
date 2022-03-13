; Based upon Satoshi Tandasat's IDT handling stub/asm file.

section .text

extern idt_exception_handler

%macro pushaq 0
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro popaq 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
%endmacro

%macro isr_err_stub 1
isr_stub_%+%1:
    nop
    nop
    push %1
    call common_exception_handler
    iretq ; Using iretq as we are x64
%endmacro

%macro isr_no_err_stub 1
isr_stub_%+%1:
    push 0
    push %1
    call common_exception_handler
    iretq ; Using iretq as we are x64
%endmacro

isr_no_err_stub 0
isr_no_err_stub 1
isr_no_err_stub 2
isr_no_err_stub 3
isr_no_err_stub 4
isr_no_err_stub 5
isr_no_err_stub 6
isr_no_err_stub 7
isr_err_stub    8
isr_no_err_stub 9
isr_err_stub    10
isr_err_stub    11
isr_err_stub    12
isr_err_stub    13
isr_err_stub    14
isr_no_err_stub 15
isr_no_err_stub 16
isr_err_stub    17
isr_no_err_stub 18
isr_no_err_stub 19
isr_no_err_stub 20
isr_no_err_stub 21
isr_no_err_stub 22
isr_no_err_stub 23
isr_no_err_stub 24
isr_no_err_stub 25
isr_no_err_stub 26
isr_no_err_stub 27
isr_no_err_stub 28
isr_no_err_stub 29
isr_err_stub    30
isr_no_err_stub 31
%assign i 32
%rep 224
    isr_no_err_stub i
%assign i i+1
%endrep

global isr_stub_table
isr_stub_table:
%assign i 0 
%rep    256 
    dq isr_stub_%+i ; Using DQ as we are x64
%assign i i+1 
%endrep

common_exception_handler:
    pushaq
    mov rcx, rsp
    sub rsp, 20h
    call idt_exception_handler
    add rsp, 20h
    popaq
    add rsp, 10h
    iretq
    