#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "platform/intrin.h"
#include "memory/vmem.h"
#include "vmm.h"
#include "vmm_reg.h"
#include "ia32_compact.h"

/* The main VMM that will initialise the hypervisor,
 * currently this is aimed at only targetting x86_64 platforms. */

#define DEBUG_VMM
#ifdef DEBUG_VMM
    #define VMM_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define VMM_PRINT(...)
#endif

/* At max, support up to 100 vCPUs. */
#define VCPU_MAX 100

/* Holds the global context for the VMM. */
struct vmm_ctx {
    struct vmm_init_params init;
    struct vcpu_ctx *vcpu[VCPU_MAX];
};

/* Holds the context specific to a singular vCPU. */
struct vcpu_ctx {
    struct control_registers guest_ctrl_regs;
};

static void probe_capabilities()
{
    VMM_PRINT(L"Checking CPU capabilities.\n");

    cpuid_eax_01 version_info;
    int rc = CPUID_LEAF_READ(CPUID_VERSION_INFO, version_info);
    die_on(!rc, L"Unable to query version information.");
    die_on(!version_info.ecx.virtual_machine_extensions, L"No virtual machine extensions.");

    cpuid_eax_80000001 extend_cpu;
    rc = CPUID_LEAF_READ(CPUID_EXTENDED_CPU_SIGNATURE, extend_cpu);
    die_on(!rc, L"Unable to read extended CPUID signature.");
    die_on(!extend_cpu.edx.pages_1gb_available, L"No 1GB pages support.");

    ia32_feature_control_register feature_control;
    feature_control.flags = rdmsr(IA32_FEATURE_CONTROL);
    die_on(!feature_control.lock_bit, L"Lock bit not set.");
    die_on(!feature_control.enable_vmx_outside_smx, L"VMX not enabled outside SMX.");

    ia32_vmx_ept_vpid_cap_register ept_vpid;
    ept_vpid.flags = rdmsr(IA32_VMX_EPT_VPID_CAP);
    die_on(!ept_vpid.page_walk_length_4, L"EPT PML4 not supported.");
    die_on(!ept_vpid.memory_type_write_back, L"EPT memory type WB not supported.");
    die_on(!ept_vpid.pdpte_1gb_pages, L"EPT 1GB pages not supported.");
    die_on(!ept_vpid.pde_2mb_pages, L"EPT 2MB pages not supported.");

    VMM_PRINT(L"CPU seems to provide all capabilities needed.\n");
}

static void capture_control_regs(struct control_registers *regs)
{
    regs->reg_cr0.flags = __readcr0();
    regs->reg_cr3.flags = __readcr3();
    regs->reg_cr4.flags = __readcr4();
    regs->debugctl.flags = rdmsr(IA32_DEBUGCTL);
    regs->gs_base = rdmsr(IA32_GS_BASE);
    regs->dr7 = __readdr7();

    VMM_PRINT(L"--- cr0 %lX cr3 %lX cr4 %lX debugctl %lX gs_base %lX dr7 %lX\n",
              regs->reg_cr0.flags, regs->reg_cr3.flags, regs->reg_cr4.flags,
              regs->debugctl.flags, regs->gs_base, regs->dr7);
}

static void __attribute__((ms_abi)) init_routine_per_vcpu(void *opaque)
{
    struct vmm_ctx *vmm = (struct vmm_ctx *)opaque;

    /* Ensure that the correct host IDT and CR3 are loaded for this vCPU.
     * This SHOULD be the case for vCPU 0 as they were originally set during
     * the initialisation of the modules, however for other vCPU's they
     * will be set to what they were before the hyperjack. */
    __writecr3(vmm->init.host_cr3.flags);
    __lidt(&vmm->init.host_idtr);

    size_t proc_idx;
    efi_plat_processor_index(&proc_idx);
    die_on(proc_idx >= VCPU_MAX, L"vCPU index greater than supported by VMM.");

    /* Create the vCPU context structure. */
    struct vcpu_ctx *vcpu = vmem_alloc(sizeof(struct vcpu_ctx), MEM_WRITE);
    die_on(!vcpu, L"Unable to allocate vCPU %ld context.", proc_idx);

    /* Set the global context so that it includes this vCPU's context pointer. */
    vmm->vcpu[proc_idx] = vcpu;

    VMM_PRINT(L"Initialising vCPU %ld vmm ctx 0x%lX vcpu ctx 0x%lX.\n", proc_idx, vmm, vcpu);

    /* Capturing control registers for the vCPU (as to what the guest should see). */
    capture_control_regs(&vcpu->guest_ctrl_regs);
}

void vmm_init(struct vmm_init_params *params)
{
    /* Make sure the CPU supports all of the features required. */
    probe_capabilities();

    /* Static allocation of the global vCPU context. This has to be
     * static rather than dynamically allocated as the other vCPUs
     * that are started will not have the host CR3 set, hence they
     * will not have access to our dynamically allocated memory. */
    static struct vmm_ctx vmm = { 0 };
    memcpy(&vmm.init, params, sizeof(*params));

    /* Run the initialisation routine on each LP. */
    efi_plat_run_all_processors(init_routine_per_vcpu, &vmm);
}