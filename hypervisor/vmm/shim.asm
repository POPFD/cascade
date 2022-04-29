section .text

global shim_guest_to_host
global shim_host_to_guest

extern __capture_context
extern handler_guest_to_host

shim_guest_to_host:
    ; Save the RCX register and then load into RCX the value
    ; where we will want to store our stack offsetting by the
    ; push we just did to preserve RCX. This is then passed
    ; as a parameter to capture_context so that the guest
    ; context is stored within the host stack.
    push rcx
    lea rcx, [rsp + 08h]
    call __capture_context
    jmp handler_guest_to_host

shim_host_to_guest:
    ; This is just for debugging atm.
    int 3
h2g_loop:
    jmp h2g_loop
    ret