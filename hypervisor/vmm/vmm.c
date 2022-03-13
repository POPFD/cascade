#include "platform/standard.h"
#include "platform/efi_plat.h"
#include "vmm.h"
#include "ia32_compact.h"

/* The main VMM that will initialise the hypervisor,
 * currently this is aimed at only targetting x86_64 platforms. */

#define DEBUG_VMM
#ifdef DEBUG_VMM
    #define VMM_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define VMM_PRINT(...)
#endif

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

static void init_routine_per_lp(void *opaque)
{
    size_t proc_idx;
    efi_plat_processor_index(&proc_idx);

    (void)opaque;

    VMM_PRINT(L"Running on LP %ld.\n", proc_idx);
}

void vmm_init(struct vmm_init_params *params)
{
    /* Make sure the CPU supports all of the features required. */
    probe_capabilities();

    /* Run the initialisation routine on each LP. */
    efi_plat_run_all_processors(init_routine_per_lp, params);
}