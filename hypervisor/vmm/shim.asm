section .text

global shim_guest_to_host
global shim_host_to_guest

extern __capture_context
extern handler_guest_to_host
extern vmm_hyperjack_handler

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
    ; We land here upon hyperjacking, where RSP is equal to what
    ; VMCS_GUEST_RSP was set to prior to the initial VMLAUNCH.
    ;
    ; We need to retrieve the vCPU context to call our vmm_hyperjack_handler.
    ; We can abuse the host_stack area, so that within setup_vmcs_guest
    ; when writing the VMCS_GUEST_RSP we also write the vcpu_ctx pointer
    ; onto the stack there ready for retrieval (but not popping it off).
    mov rdi, [rsp]
    jmp vmm_hyperjack_handler