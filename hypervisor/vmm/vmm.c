#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "platform/intrin.h"
#include "memory/vmem.h"
#include "memory/mem.h"
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
    struct vcpu_context guest_context;
    struct gdt_config gdt_cfg;

    bool running_as_guest;
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

static void print_gdt(CHAR16 *prefix, segment_descriptor_register_64 *gdtr)
{
    VMM_PRINT(L"--- %s GDT base %lX limit %lX\n", prefix, gdtr->base_address, gdtr->limit);

    segment_descriptor_32 *gdt = (segment_descriptor_32 *)gdtr->base_address;
    int desc_max = (gdtr->limit + 1ull) / sizeof(segment_descriptor_32);
    for (int i = 0; i < desc_max; i++) {
        segment_descriptor_32 *curr_desc = (segment_descriptor_32 *)&gdt[i];

        VMM_PRINT(L"------ Descriptor %lX\n", (uintptr_t)curr_desc);
        VMM_PRINT(L"------ Flags %X\n", curr_desc->flags);
        VMM_PRINT(L"------ Present %X\n", curr_desc->present);
        VMM_PRINT(L"------ Type %X\n", curr_desc->type);
        VMM_PRINT(L"------ Segment limit %X\n",
                  (curr_desc->segment_limit_high << 16) | curr_desc->segment_limit_low);

        uintptr_t base_addr = (curr_desc->base_address_high << 24) |
                              (curr_desc->base_address_middle << 16) |
                              (curr_desc->base_address_low & UINT16_MAX);
        VMM_PRINT(L"------ Base address %lX\n\n", base_addr);
    }
}

static void configure_vcpu_gdt(struct gdt_config *gdt_cfg)
{
    /* Everything within the GDT is in linear/physical addresses
     * rather than virtual, therefore we need to retrieve CR3 so
     * that we can do some conversions from virt to phys. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();

    /* Read the original GDTR and store it so we can use it for the guest later. */
    __sgdt(&gdt_cfg->guest_gdtr);
    die_on(!gdt_cfg->guest_gdtr.base_address, L"No base address set for guest GDTR");
    die_on(!gdt_cfg->guest_gdtr.limit, L"No limit set for guest GDTR");

    /* For the host GDT we're going to copy the guest GDT and then append
     * a TSS to the GDT as this is required for VMX to be used, unfortunately
     * the UEFI environment doesn't set this up. */
    memcpy(gdt_cfg->host_gdt,
           (const void *)gdt_cfg->guest_gdtr.base_address,
           gdt_cfg->guest_gdtr.limit);

    /* Configure the GDTR we're going to use for the host. */
    uintptr_t host_gdt_phys = mem_va_to_pa(this_cr3, gdt_cfg->host_gdt);
    gdt_cfg->host_gdtr.base_address = host_gdt_phys;
    gdt_cfg->host_gdtr.limit = gdt_cfg->guest_gdtr.limit + sizeof(segment_descriptor_64);
    VMM_PRINT(L"Host GDTR base %lX limit %lX\n",
              gdt_cfg->host_gdtr.base_address,
              gdt_cfg->host_gdtr.limit);

    /* Append the TR to the end of the GDT. */
    gdt_cfg->host_tr.flags = 0;
    gdt_cfg->host_tr.index = (gdt_cfg->guest_gdtr.limit + 1ull) / sizeof(segment_descriptor_32);
    VMM_PRINT(L"Host TR index %d\n", gdt_cfg->host_tr.index);

    uintptr_t tss_pa = mem_va_to_pa(this_cr3, &gdt_cfg->host_tss);
    segment_descriptor_64 tss_desc = { 0 };
    tss_desc.segment_limit_low = sizeof(struct task_state_segment_64) - 1;
    tss_desc.base_address_low = tss_pa & UINT16_MAX;
    tss_desc.base_address_middle = (tss_pa >> 16) & UINT8_MAX;
    tss_desc.base_address_high = (tss_pa >> 24) & UINT8_MAX;
    tss_desc.base_address_upper = (tss_pa >> 32) & UINT32_MAX;
    tss_desc.type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    tss_desc.present = true;

    /* Now write the newly created TSS to our host GDT. */
    segment_descriptor_32 *gdt32 = (segment_descriptor_32 *)gdt_cfg->host_gdt;
    segment_descriptor_64 *tss_in_gdt = (segment_descriptor_64 *)&gdt32[gdt_cfg->host_tr.index];
    *tss_in_gdt = tss_desc;

    print_gdt(L"Host", &gdt_cfg->host_gdtr);

    /* Write the new GDTR and TR. */
    uintptr_t phys_gdtr = mem_va_to_pa(this_cr3, &gdt_cfg->host_gdtr);
    __lgdt((void*)phys_gdtr);
    __ltr(&gdt_cfg->host_tr);
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

    /* Configure the host GDT. */
    configure_vcpu_gdt(&vcpu->gdt_cfg);

    /* Capturing control registers & context for the vCPU,
     * as to what the guest should be restored to once hyperjacked. */
    capture_control_regs(&vcpu->guest_ctrl_regs);
    __capture_context(&vcpu->guest_context);

    /* First pass (before hypervised) this shall be false as we
     * haven't hyperjacked yet. Upon restoration of the context
     * from within the guest (which will lead us up to just after __capture_context)
     * we need to do nothing and effectively "complete" loading of the driver. */
    if (!vcpu->running_as_guest) {
        /* Enter VMX root mode. */

        /* Set up VMCS */

        /* Attempt VMLAUNCH. */

        /* If we have got to this point,
         * VMLAUNCH failed, therefore we get failure
         * reason and dump. */
    }
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