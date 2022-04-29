#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "platform/intrin.h"
#include "memory/vmem.h"
#include "memory/mem.h"
#include "vmm.h"
#include "ept.h"
#include "shim.h"
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

/* Mask used to ignore the ring level when specifying a selector. */
#define IGNORE_RPL_MASK (~3)

/* Defines the size of the host stack. */
#define HOST_STACK_SIZE 0x6000

/* Holds the global context for the VMM. */
struct vmm_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t msr_trap_bitmap[PAGE_SIZE];

    struct vmm_init_params init;
    struct vcpu_ctx *vcpu[VCPU_MAX];
    struct ept_ctx *ept;
};

/* Holds the context specific to a singular vCPU. */
struct vcpu_ctx {
    __attribute__ ((aligned (PAGE_SIZE))) vmxon host_vmxon;
    __attribute__ ((aligned (PAGE_SIZE))) vmcs guest_vmcs;
    __attribute__ ((aligned (PAGE_SIZE))) uint8_t host_stack[HOST_STACK_SIZE];

    struct control_registers guest_ctrl_regs;
    struct vcpu_context guest_context;
    struct gdt_config gdt_cfg;

    bool running_as_guest;
};

/* Holds information on a GDT entry. */
struct gdt_entry {
    size_t base;
    uint32_t limit;
    uint16_t sel;
    vmx_segment_access_rights access;
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
    __sldt(&gdt_cfg->guest_ldtr);
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

static void enter_root_mode(struct vcpu_ctx *vcpu)
{
    /* Set up root VMXON and the guest VMCS. */
    ia32_vmx_basic_register basic;
    basic.flags = rdmsr(IA32_VMX_BASIC);

    memset(&vcpu->host_vmxon, 0, sizeof(vcpu->host_vmxon));
    memset(&vcpu->guest_vmcs, 0, sizeof(vcpu->guest_vmcs));
    vcpu->host_vmxon.revision_id = basic.vmcs_revision_id;
    vcpu->guest_vmcs.revision_id = basic.vmcs_revision_id;

    /* Set the fixed requirements for the control registers for VMX. */
    vcpu->guest_ctrl_regs.reg_cr0.flags &= (uint32_t)rdmsr(IA32_VMX_CR0_FIXED1);
    vcpu->guest_ctrl_regs.reg_cr0.flags |= (uint32_t)rdmsr(IA32_VMX_CR0_FIXED0);

    vcpu->guest_ctrl_regs.reg_cr4.flags &= (uint32_t)rdmsr(IA32_VMX_CR4_FIXED1);
    vcpu->guest_ctrl_regs.reg_cr4.flags |= (uint32_t)rdmsr(IA32_VMX_CR4_FIXED0);

    /* Update host CR0/4 with new updated fields. */
    __writecr0(vcpu->guest_ctrl_regs.reg_cr0.flags);
    __writecr4(vcpu->guest_ctrl_regs.reg_cr4.flags);

    /* Calculate the physical addresses of vmxon and vmcs. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();
    void *phys_vmxon = (void *)mem_va_to_pa(this_cr3, &vcpu->host_vmxon);
    void *phys_vmcs = (void *)mem_va_to_pa(this_cr3, &vcpu->guest_vmcs);

    die_on(!__vmxon(&phys_vmxon), L"Unable to enter VMX root mode.");
    die_on(!__vmclear(&phys_vmcs), L"Unable to clear VMCS.");
    die_on(!__vmptrld(&phys_vmcs), L"Unable to load the VMCS.");
}

static uint64_t encode_msr(uint64_t ctrl, uint64_t desired)
{
    /*
     * VMX feature/capability MSRs encode the "must be 0" bits in the high word
     * of their value, and the "must be 1" bits in the low word of their value.
     * Adjust any requested capability/feature based on these requirements.
     */
    desired &= (uint32_t)(ctrl >> 32);
    desired |= (uint32_t)ctrl;
    return desired;
}

static void gather_gdt_entry(segment_descriptor_register_64 *gdtr, uint16_t sel,
                             struct gdt_entry *entry)
{
    /* If the selector is not valid (0) set unusable entry. */
    if (sel == 0) {
        entry->sel = 0;
        entry->limit = 0;
        entry->base = 0;
        entry->access.flags = 0;
        entry->access.unusable = true;
        return;
    }

    /* Calculate the descriptor pointer */
    segment_descriptor_64 *descriptor =
        (segment_descriptor_64 *)(gdtr->base_address + (sel & IGNORE_RPL_MASK));

    /* Fill in the entry information. */
    entry->sel = sel;
    entry->limit = (descriptor->segment_limit_high << 16) | descriptor->segment_limit_low;
    entry->base = ((size_t)descriptor->base_address_high << 24) |
                  ((size_t)descriptor->base_address_middle << 16) |
                  ((size_t)descriptor->base_address_low);

    if (descriptor->descriptor_type == 0) {
        entry->base |= (UINTN)descriptor->base_address_upper << 32;
    }

    /* Access rights are defines as the middle 16 bits of the descriptor flags section. */
    entry->access.flags = (descriptor->flags >> 8) & 0xFFFF;
    entry->access.unusable = !descriptor->present;
    entry->access.reserved_1 = 0;
}

static void setup_vmcs_host(struct vmm_ctx *vmm, struct vcpu_ctx *vcpu)
{
    /* Configure the host context, as we're hyperjacking we want
     * to clone the original context as much as possible for ease
     * of use. */
    struct vcpu_context *guest_ctx = &vcpu->guest_context;

    /* Write all of the selectors, ignoring the RPL for each field
     * as the host environment will always be ring-0. */
    __vmwrite(VMCS_HOST_CS_SEL, guest_ctx->seg_cs & IGNORE_RPL_MASK);
    __vmwrite(VMCS_HOST_SS_SEL, guest_ctx->seg_ss & IGNORE_RPL_MASK);
    __vmwrite(VMCS_HOST_DS_SEL, guest_ctx->seg_ds & IGNORE_RPL_MASK);
    __vmwrite(VMCS_HOST_ES_SEL, guest_ctx->seg_es & IGNORE_RPL_MASK);
    __vmwrite(VMCS_HOST_FS_SEL, guest_ctx->seg_fs & IGNORE_RPL_MASK);
    __vmwrite(VMCS_HOST_GS_SEL, guest_ctx->seg_gs & IGNORE_RPL_MASK);

    /* As in a UEFI environment TR is not set, therefore we use our own
     * generated one when we modified the GDT. */
    __vmwrite(VMCS_HOST_TR_SEL, vcpu->gdt_cfg.host_tr.flags & IGNORE_RPL_MASK);

    /* Now write all of the BASE registers that are used for the host. */
    __vmwrite(VMCS_HOST_GDTR_BASE, vcpu->gdt_cfg.host_gdtr.base_address);
    __vmwrite(VMCS_HOST_GS_BASE, vcpu->guest_ctrl_regs.gs_base);
    __vmwrite(VMCS_HOST_IDTR_BASE, vmm->init.host_idtr.base_address);


    /* Get the GDT information for FS & TR so we can write these for the host VMCS. */
    struct gdt_entry entry;
    gather_gdt_entry(&vcpu->gdt_cfg.host_gdtr, guest_ctx->seg_fs, &entry);
    __vmwrite(VMCS_HOST_FS_BASE, entry.base);

    gather_gdt_entry(&vcpu->gdt_cfg.host_gdtr, vcpu->gdt_cfg.host_tr.flags, &entry);
    __vmwrite(VMCS_HOST_TR_BASE, entry.base);

    /* SYSENTRY fields. */
    __vmwrite(VMCS_HOST_SYSENTER_ESP, rdmsr(IA32_SYSENTER_ESP));
    __vmwrite(VMCS_HOST_SYSENTER_EIP, rdmsr(IA32_SYSENTER_EIP));

    /* Control registers (using our own CR3 value for paging). */
    __vmwrite(VMCS_HOST_CR0, vcpu->guest_ctrl_regs.reg_cr0.flags);
    __vmwrite(VMCS_HOST_CR3, vmm->init.host_cr3.flags);
    __vmwrite(VMCS_HOST_CR4, vcpu->guest_ctrl_regs.reg_cr4.flags);

    /*
    * Load the hypervisor entrypoint and stack. We give ourselves a standard
    * size kernel stack (24KB) and bias for the context structure that the
    * hypervisor entrypoint will push on the stack, avoiding the need for RSP
    * modifying instructions in the entrypoint. Note that the CONTEXT pointer
    * and thus the stack itself, must be 16-byte aligned for ABI compatibility
    * with AMD64 -- specifically, XMM operations will fail otherwise, such as
    * the ones that __capture_context will perform.
    */
    __vmwrite(VMCS_HOST_RSP,
              (uintptr_t)&vcpu->host_stack[HOST_STACK_SIZE - sizeof(struct vcpu_context)]);
    __vmwrite(VMCS_HOST_RIP, (uintptr_t)shim_guest_to_host);
}

static void setup_vmcs_guest(struct vmm_ctx *vmm, struct vcpu_ctx *vcpu)
{
    /* 
     * Defines a generic structure so that we can iteratively write all segment
     * fields needed for the guest.
     */
    struct gdt_config {
        uint16_t sel;
        uint32_t vmcs_sel;
        uint32_t vmcs_lim;
        uint32_t vmcs_ar;
        uint32_t vmcs_base;
        segment_descriptor_register_64 *gdtr;
    };

    struct vcpu_context *guest_ctx = &vcpu->guest_context;

    const struct gdt_config vmcs_gdt_list[] = {
        {
            .sel = guest_ctx->seg_cs,
            .vmcs_sel = VMCS_GUEST_CS_SEL,
            .vmcs_lim = VMCS_GUEST_CS_LIMIT,
            .vmcs_ar = VMCS_GUEST_CS_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_CS_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = guest_ctx->seg_ss,
            .vmcs_sel = VMCS_GUEST_SS_SEL,
            .vmcs_lim = VMCS_GUEST_SS_LIMIT,
            .vmcs_ar = VMCS_GUEST_SS_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_SS_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = guest_ctx->seg_ds,
            .vmcs_sel = VMCS_GUEST_DS_SEL,
            .vmcs_lim = VMCS_GUEST_DS_LIMIT,
            .vmcs_ar = VMCS_GUEST_DS_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_DS_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = guest_ctx->seg_es,
            .vmcs_sel = VMCS_GUEST_ES_SEL,
            .vmcs_lim = VMCS_GUEST_ES_LIMIT,
            .vmcs_ar = VMCS_GUEST_ES_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_ES_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = guest_ctx->seg_fs,
            .vmcs_sel = VMCS_GUEST_FS_SEL,
            .vmcs_lim = VMCS_GUEST_FS_LIMIT,
            .vmcs_ar = VMCS_GUEST_FS_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_FS_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = guest_ctx->seg_gs,
            .vmcs_sel = VMCS_GUEST_GS_SEL,
            .vmcs_lim = VMCS_GUEST_GS_LIMIT,
            .vmcs_ar = VMCS_GUEST_GS_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_GS_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = vcpu->gdt_cfg.host_tr.flags,
            .vmcs_sel = VMCS_GUEST_TR_SEL,
            .vmcs_lim = VMCS_GUEST_TR_LIMIT,
            .vmcs_ar = VMCS_GUEST_TR_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_TR_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        },
        {
            .sel = vcpu->gdt_cfg.guest_ldtr.flags,
            .vmcs_sel = VMCS_GUEST_LDTR_SEL,
            .vmcs_lim = VMCS_GUEST_LDTR_LIMIT,
            .vmcs_ar = VMCS_GUEST_LDTR_ACCESS_RIGHTS,
            .vmcs_base = VMCS_GUEST_LDTR_BASE,
            .gdtr = &vcpu->gdt_cfg.host_gdtr,
        }
    };

    /*
     * For TR and LDTR we cannot use what the guest has, as to be able to
     * successfully VMENTER we need a TR and LDTR set (unfortunately)
     */

    /* For each selector, generate it's entry and then fill in relevant fields. */
    for (size_t i = 0; i < ARRAY_SIZE(vmcs_gdt_list); i++) {
        const struct gdt_config *curr_cfg = &vmcs_gdt_list[i];
        struct gdt_entry entry;

        gather_gdt_entry(curr_cfg->gdtr, curr_cfg->sel, &entry);

        if (curr_cfg->vmcs_sel)
            __vmwrite(curr_cfg->vmcs_sel, entry.sel);
        if (curr_cfg->vmcs_lim)
            __vmwrite(curr_cfg->vmcs_lim, entry.limit);
        if (curr_cfg->vmcs_ar)
            __vmwrite(curr_cfg->vmcs_ar, entry.access.flags);
        if (curr_cfg->vmcs_base)
            __vmwrite(curr_cfg->vmcs_base, entry.base);

        VMM_PRINT(L"VMX GDT Entry: %d\n"
                  L"--- VMCS SEL [0x%lX]: 0x%lX\n"
                  L"--- VMCS LIM [0x%lX]: 0x%lX\n"
                  L"--- VMCS AR [0x%lX]: 0x%lX\n"
                  L"--- VMCS BASE [0x%lX]: 0x%lX\n\n",
                  i, 
                  curr_cfg->vmcs_sel, entry.sel,
                  curr_cfg->vmcs_lim, entry.limit,
                  curr_cfg->vmcs_ar, entry.access.flags,
                  curr_cfg->vmcs_base, entry.base);
    }

    /* Now write the GDTR for the guest (due to TR & LDTR restrictions re-use guest). */
    __vmwrite(VMCS_GUEST_GDTR_BASE, vcpu->gdt_cfg.host_gdtr.base_address);
    __vmwrite(VMCS_GUEST_GDTR_LIMIT, vcpu->gdt_cfg.host_gdtr.limit);

    /* Now write IDTR, we can ACTUALLY use the guest IDT thank god... */
    __vmwrite(VMCS_GUEST_IDTR_BASE, vmm->init.guest_idtr.base_address);
    __vmwrite(VMCS_GUEST_IDTR_LIMIT, vmm->init.guest_idtr.limit);

    /* Control registers. */
    __vmwrite(VMCS_CTRL_CR0_READ_SHADOW, vcpu->guest_ctrl_regs.reg_cr0.flags);
    __vmwrite(VMCS_GUEST_CR0, vcpu->guest_ctrl_regs.reg_cr0.flags);

    /*
     * We have to use the page table created in our host environment for now
     * the guest will overwrite this when actually loading an OS though so we're golden.
     */
    __vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    __vmwrite(VMCS_GUEST_CR3, vcpu->guest_ctrl_regs.reg_cr3.flags);

    /* Set the guest/host mask and a shadow, this is used to hide
     * the fact that VMXE bit in CR4 is set.
     *
     * Setting a bit to 1 ensures that the bit is host owned,
     * meaning that the value will be read from the shadow register.
     *
     * Setting a bit to 0 ensures that the bit is guest owned,
     * meaning that the actual value will be read.
     */
    static const UINT64 POSITION_VMXE_BIT = (1 << 13);

    __vmwrite(VMCS_CTRL_CR4_MASK, POSITION_VMXE_BIT);
    //__vmwrite(VMCS_CTRL_CR4_READ_SHADOW, vcpu->guest_ctrl_regs.reg_cr4.flags & ~POSITION_VMXE_BIT);
    __vmwrite(VMCS_CTRL_CR4_READ_SHADOW, vcpu->guest_ctrl_regs.reg_cr4.flags);
    __vmwrite(VMCS_GUEST_CR4, vcpu->guest_ctrl_regs.reg_cr4.flags);

    /* Debug kernel registers. */
    __vmwrite(VMCS_GUEST_DEBUGCTL, vcpu->guest_ctrl_regs.debugctl.flags);
    __vmwrite(VMCS_GUEST_DR7, vcpu->guest_ctrl_regs.dr7);

    /* Extended feature enable registers. */
    __vmwrite(VMCS_GUEST_EFER, rdmsr(IA32_EFER));

    /*
    * Finally, load the guest stack, instruction pointer, and rflags, which
    * corresponds exactly to the location where __capture_context will return
    * to inside of init_routine_per_vcpu.
    */
    __vmwrite(VMCS_GUEST_RSP,
              (uintptr_t)&vcpu->host_stack[HOST_STACK_SIZE - sizeof(struct vcpu_context)]);
    __vmwrite(VMCS_GUEST_RIP, (uintptr_t)shim_host_to_guest);
    __vmwrite(VMCS_GUEST_RFLAGS, guest_ctx->e_flags);
}

static void setup_vmcs_generic(struct vmm_ctx *vmm)
{
    /* Set up the link pointer. */
    __vmwrite(VMCS_GUEST_VMCS_LINK_PTR, ~0ull);

    /* Set up the EPT fields. */
    __vmwrite(VMCS_CTRL_EPTP, ept_get_pointer(vmm->ept)->flags);
    __vmwrite(VMCS_CTRL_VPID, 1);

    /* Load the MSR bitmap with the bitmap which will be used to
     * indicate which MSR reads/writes to trap on.
     * 0 bits indicate trap, if set then auto route. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();
    __vmwrite(VMCS_CTRL_MSR_BITMAP, mem_va_to_pa(this_cr3, vmm->msr_trap_bitmap));

    /* We don't explicitly enable any pin-based options ourselves, but there may
     * be some required by the procesor, the encode the MSR to include these. */
    uint32_t encoded = encode_msr(rdmsr(IA32_VMX_TRUE_PINBASED_CTLS), 0);
    __vmwrite(VMCS_CTRL_PIN_EXEC, encoded);

    /*
     * Enable support for RDTSCP and XSAVES/XRESTORES in the guest. Windows 10
     * makes use of both of these instructions if the CPU supports it. By using
     * adjustMSR, these options will be ignored if this processor does
     * not actually support the instructions to begin with.
     *
     * Also enable EPT support, for additional performance and ability to trap
     * memory access efficiently.
     */
    ia32_vmx_procbased_ctls2_register proc_ctls2 = { 0 };
    proc_ctls2.enable_rdtscp = true;
    proc_ctls2.enable_invpcid = true;
    proc_ctls2.enable_xsaves = true;
    proc_ctls2.unrestricted_guest = true;
    proc_ctls2.enable_ept = true;
    proc_ctls2.enable_vpid = true;
    encoded = encode_msr(rdmsr(IA32_VMX_PROCBASED_CTLS2), proc_ctls2.flags);
    __vmwrite(VMCS_CTRL_PROC_EXEC2, encoded);

    /* In order for the proc_ctls2 & MSR bitmap to be used we need to explicitly
     * enable them. */
    ia32_vmx_procbased_ctls_register proc_ctls = { 0 };
    proc_ctls.use_msr_bitmaps = true;
    proc_ctls.activate_secondary_controls = true;
    encoded = encode_msr(rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS), proc_ctls.flags);
    __vmwrite(VMCS_CTRL_PROC_EXEC, encoded);

    /* Make sure to exit in x64 mode at all times. */
    ia32_vmx_exit_ctls_register exit_ctls = { 0 };
    exit_ctls.save_debug_controls = true;
    exit_ctls.save_ia32_efer = true;
    exit_ctls.host_address_space_size = true;
    encoded = encode_msr(rdmsr(IA32_VMX_TRUE_EXIT_CTLS), exit_ctls.flags);
    __vmwrite(VMCS_CTRL_EXIT, encoded);

    /* Make sure when we re-enter it's back in x64 mode too. */
    ia32_vmx_entry_ctls_register entry_ctls = { 0 };
    entry_ctls.load_debug_controls = true;
    entry_ctls.load_ia32_efer = true;
    entry_ctls.ia32e_mode_guest = true;
    encoded = encode_msr(rdmsr(IA32_VMX_TRUE_ENTRY_CTLS), entry_ctls.flags);
    __vmwrite(VMCS_CTRL_ENTRY, encoded);
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
        enter_root_mode(vcpu);

        /* Set up VMCS */
        setup_vmcs_generic(vmm);
        setup_vmcs_host(vmm, vcpu);
        setup_vmcs_guest(vmm, vcpu);

        /* Attempt VMLAUNCH. */
        VMM_PRINT(L"Attempting VMLAUNCH on vCPU %d\n", proc_idx);
        __vmlaunch();

        /* 
         * If we have got to this point, VMLAUNCH failed.
         * Get failure reason and dump info for debugging. */
        size_t fail_reason = 0;
        __vmread(VMCS_VM_INSTR_ERROR, &fail_reason);
        debug_print(L"Failed to launch VMX with reason: 0x%lX\n", fail_reason);
        while (1) {};
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

    vmm.ept = ept_init();

    /* Run the initialisation routine on each LP. */
    efi_plat_run_all_processors(init_routine_per_vcpu, &vmm);
}