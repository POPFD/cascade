#include "platform/standard.h"
#include "platform/serial.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "interrupt/idt.h"
#include "vmm/vmm.h"

static void trigger_cpuid(void)
{
    /* Running a CPUID should trigger an exit. */
    uint64_t ticks_before = __rdtsc();

    uint64_t rax, rbx, rcx, rdx;
    asm volatile (
        "movl $0x40000000, %%eax;"
        "cpuid;"
        : "=a"(rax), "=b"(rbx), "=c"(rcx), "=d"(rdx)
    );
    uint64_t ticks_delta = __rdtsc() - ticks_before;

    debug_print("Test CPUID leaf=0x40000000 eax=0x%lX ebx=0x%lX ecx=0x%lX edx=0x%lX ticks=%ld",
                rax, rbx, rcx, rdx, ticks_delta);
}

static void test_rdmsr(void)
{
    /* Reading MSRs may trigger a VM exit, if set in the bitmap. */
    uint64_t ticks_before = __rdtsc();
    uint64_t dummy_msr = rdmsr(IA32_TIME_STAMP_COUNTER);
    uint64_t ticks_delta = __rdtsc() - ticks_before;

    debug_print("Test RDMSR dummy_val=0x%lX ticks=%ld", dummy_msr, ticks_delta);
}

static void hypervisor_tests(void)
{
    trigger_cpuid();
    test_rdmsr();
}

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

    hypervisor_tests();

    debug_print("Hypervisor initialised.");
}