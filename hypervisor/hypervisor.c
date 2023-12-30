#include "platform/standard.h"
#include "platform/serial.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "interrupt/idt.h"
#include "vmm/vmm.h"

void hypervisor_init(void)
{

//#define DEBUG_IDA
#ifdef DEBUG_IDA
    static volatile int wait_debug = 0;

    while (!wait_debug) {}
#endif

    /* Initialise all of the required modules and set up the parameters
     * required for the VMM to start. */
    struct vmm_init_params vmm_params = { 0 };

    serial_init();
    pmem_init();
    vmem_init(&vmm_params.guest_cr3, &vmm_params.host_cr3);
    idt_init(&vmm_params.guest_idtr, &vmm_params.host_idtr);
    vmm_init(&vmm_params);

    /* DEBUG: Try trigger a VMEXIT just to test. */
    uint64_t rax, rbx, rcx, rdx;
    asm volatile (
        "movl $0x40000000, %%eax;"
        "cpuid;"
        : "=a"(rax), "=b"(rbx), "=c"(rcx), "=d"(rdx)
    );
    debug_print("READ leaf=0x40000000 eax=0x%lX ebx=0x%lX ecx=0x%lX edx=0x%lX",
                rax, rbx, rcx, rdx);

    debug_print("Hypervisor initialised.");
}