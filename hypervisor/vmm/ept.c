#define DEBUG_MODULE
#include <errno.h>
#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/vmem.h"
#include "memory/mem.h"
#include "ept.h"
#include "ia32_compact.h"

#define ENTRIES_PER_TABLE 512

struct mtrr_data {
    bool valid;
    uint8_t type;
    size_t phys_base_min;
    size_t phys_base_max;
};

struct ept_ctx {
    /* Describes 512 contiguous 512GiB memory regions. */
    __attribute__((aligned(PAGE_SIZE))) epml4e pml4[ENTRIES_PER_TABLE];
    /* Describes exactly 512 contiguous 1GiB memory regions with a singular PML4 region. */
    __attribute__((aligned(PAGE_SIZE))) ept_pdpte pml3[ENTRIES_PER_TABLE];
    /* For each 1GB PML3 entry, create 512 2MB regions.
     * We are using 2MB pages as the smallest paging size in the map so that we do not need
     * to allocate individual 4096 PML1 paging structures. */
    __attribute__((aligned(PAGE_SIZE))) ept_pde_2mb pml2[ENTRIES_PER_TABLE][ENTRIES_PER_TABLE];

    /* The EPT pointer for this context. */
    eptp ept_ptr;

    /* List of MTRR data, not all may be valid as each processor arch
     * can vary depending on the amount of MTRRs implemented. */
    struct mtrr_data mtrr[IA32_MTRR_COUNT];
};

struct ept_split_page {
    /* The PML1E/EPT_PTE table. */
    __attribute__((aligned(PAGE_SIZE))) ept_pte pml1[ENTRIES_PER_TABLE];

    /* A back reference to the PML2 entry which this was created for. */
    ept_pde_2mb *pml2e_ref;
};

static void gather_mtrr_list(struct ept_ctx *ctx)
{
    ia32_mtrrcap_register caps;
    ia32_mtrr_physbase_register base;
    ia32_mtrr_physmask_register mask;

    /* Query the capabilities to determine the number of registers. */
    caps.flags = rdmsr(IA32_MTRRCAP);
    for (size_t i = 0; i < caps.variable_range_registers_count; i++) {
        struct mtrr_data *mtrr = &ctx->mtrr[i];

        base.flags = rdmsr(IA32_MTRR_PHYSBASE0 + i * 2);
        mask.flags = rdmsr((IA32_MTRR_PHYSBASE0 + 1) + i * 2);

        /* Store the mtrr type and whether valid. */
        mtrr->type = base.type;
        mtrr->valid = (bool)mask.valid;

        /* If the mtrr is valid, calculate the min and maximum ranges. */
        if (mtrr->valid) {
            mtrr->phys_base_min = base.physical_addres_base * PAGE_SIZE;

            long long bit_idx = __builtin_ffsll(mask.physical_addres_mask * PAGE_SIZE);
            mtrr->phys_base_max = mtrr->phys_base_min + ((1ull << bit_idx) - 1);
        }

        DEBUG_PRINT("Valid %d type %d base_min %lX base_max %lX",
                  mtrr->valid, mtrr->type, mtrr->phys_base_min, mtrr->phys_base_max);
    }
}

static uint32_t adjust_memory_type(struct ept_ctx *ctx, uintptr_t addr, uint32_t type)
{
    /* Check to see if the specified address falls within
     * any of the MTRR ranges, if so we need to adjust the
     * effective memory type. */
    for (int i = 0; i < IA32_MTRR_COUNT; i++) {

        /* Not a valid entry, skip. */
        if (!ctx->mtrr[i].valid)
            continue;

        /* Check to see if boundary falls anywhere within range. */
        if (((addr + (MiB(2) - 1)) >= ctx->mtrr[i].phys_base_min) &&
            (addr <= ctx->mtrr[i].phys_base_max)) {
            
            return ctx->mtrr[i].type;
        }
    }

    /* If not in MTRR list, return desired. */
    return type;
}

static void ept_split_large_page(struct ept_ctx *ctx, uintptr_t phys_addr)
{
    /* Attempt to get the PML2E for the physical address specified. */
    ept_pde_2mb *target_pml2e = get_ept_pml2e(ctx, phys_addr);
    die_on(!target_pml2e, "Invalid PML2E for addr 0x%lX", phys_addr);
    
    /* If the large page bit isn't set, this means already split. */
    if (!target_pml2e->large_page)
        return;

    struct ept_split_page *new_split = vmem_alloc(sizeof(struct ept_split_page), MEM_WRITE);
    die_on(!new_split, "Unable to allocate memory for split page, phys_addr 0x%lX", phys_addr);

    /* Store the back reference to the PML2E */
    new_split->pml2e_ref = target_pml2e;

    /* Now create a stub/template PML1E with default params. */
    ept_pte temp_pte = {
        .read_access = true,
        .write_access = true,
        .execute_access = true,
        .memory_type = target_pml2e->memory_type,
        .ignore_pat = target_pml2e->ignore_pat,
        .suppress_ve = target_pml2e->suppress_ve
    };

    /* Calculate the physical address of the original PML2 entry.
     * and the page frame number, we will use this as base. */
    uintptr_t base_pml2e = target_pml2e->page_frame_number * MiB(2);
    uintptr_t base_pfn = base_pml2e / PAGE_SIZE;

    /* Now fill out all the new PML1E's for the table.
     * Use the template PTE for the general flags,
     * but we will also need to update the PFN.
     * As we have calculated the original PFN for the PML2E we can
     * we can just add one page for each entry. */
    for (int i = 0; i < ENTRIES_PER_TABLE; i++) {
        new_split->pml1[i] = temp_pte;
        new_split->pml1[i].page_frame_number = base_pfn + i;
    }

    /* Now create a new PML2E entry to replace the old one. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();

    uintptr_t phys_pml1e = mem_va_to_pa(this_cr3, &new_split->pml1[0]);

    ept_pde new_pde = {
        .read_access = true,
        .write_access = true,
        .execute_access = true,
        .page_frame_number = (phys_pml1e / PAGE_SIZE)
    };
    target_pml2e->flags = new_pde.flags;
}

struct ept_ctx *ept_init(void)
{
    /* Initialise SLAT/EPT for the guest.
     * As we are hyperjacking this will consist of a
     * 1:1 guest/host identity map to aid in conversion. */
    struct ept_ctx *ctx = vmem_alloc(sizeof(struct ept_ctx), MEM_WRITE);
    die_on(!ctx, "Unable to allocate context for EPT.");

    /* Gather the MTRR layout list so that this can be used in the future. */
    gather_mtrr_list(ctx);

    /* Configure the EPT pointer. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();

    uintptr_t phys_pml4 = mem_va_to_pa(this_cr3, ctx->pml4);
    ctx->ept_ptr.page_walk_length = 3;
    ctx->ept_ptr.memory_type = MEMORY_TYPE_WB;
    ctx->ept_ptr.page_frame_number = phys_pml4 / PAGE_SIZE;

    /* Fill out the first top level 512GiB entry.
     * We don't need to do the others as it's HIGHLY unlikely
     * that this will ever be ran on a 512GiB system. */
    uintptr_t phys_pml3 = mem_va_to_pa(this_cr3, ctx->pml3);
    ctx->pml4[0].read_access = true;
    ctx->pml4[0].write_access = true;
    ctx->pml4[0].execute_access = true;
    ctx->pml4[0].page_frame_number = phys_pml3 / PAGE_SIZE;

    /* Configure the lower level PML3 table,
     * each entry indicates 1GiB of physical memory,
     * therefore the first 512GiB is identity mapped. */
    for (int i = 0; i < ENTRIES_PER_TABLE; i++) {
        ctx->pml3[i].read_access = true;
        ctx->pml3[i].write_access = true;
        ctx->pml3[i].execute_access = true;

        uintptr_t phys_pml2 = mem_va_to_pa(this_cr3, &ctx->pml2[i][0]);
        ctx->pml3[i].page_frame_number = phys_pml2 / PAGE_SIZE;
    }

    /* Loop every 1 GiB of RAM (PML3). */
    for (int i = 0; i < ENTRIES_PER_TABLE; i++) {
        /* Loop every 2 MiB within that GiB. */
        for (int j = 0; j < ENTRIES_PER_TABLE; j++) {
            ctx->pml2[i][j].read_access = true;
            ctx->pml2[i][j].write_access = true;
            ctx->pml2[i][j].execute_access = true;
            ctx->pml2[i][j].large_page = true;
            ctx->pml2[i][j].page_frame_number = (i * ENTRIES_PER_TABLE) + j;

            uintptr_t phys_addr = ctx->pml2[i][j].page_frame_number * MiB(2);
            uint32_t mem_type = adjust_memory_type(ctx, phys_addr, MEMORY_TYPE_WB);
            ctx->pml2[i][j].memory_type = mem_type;
        }
    }

    return ctx;
}

eptp *ept_get_pointer(struct ept_ctx *ctx)
{
    return &ctx->ept_ptr;
}

ept_pde_2mb *get_ept_pml2e(struct ept_ctx *ctx, uintptr_t phys_addr)
{
    uint64_t pml4_idx = ADDRMASK_EPT_PML4_INDEX(phys_addr);
    die_on(pml4_idx, "Cannot support PML4E[%d] above 0 (512GiB)", pml4_idx);

    uint64_t pml3_idx = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    uint64_t pml2_idx = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    return &ctx->pml2[pml3_idx][pml2_idx];
}

ept_pte *ept_get_pml1e(struct ept_ctx *ctx, uintptr_t phys_addr)
{
    /* First get the PML2E.
     * If the current page is a large page (2MiB) then we
     * should proceed with splitting this PML2E into standard
     * pages. From there we can then return that value. */
    ept_pde_2mb *target_pml2e_2mb = get_ept_pml2e(ctx, phys_addr);
    die_on(!target_pml2e_2mb, "Invalid PML2E for addr 0x%lX", phys_addr);

    if (target_pml2e_2mb->large_page) {
        /* Split the page, and then ensure we invalidate and flush the
         * EPT cache. */
        ept_split_large_page(ctx, phys_addr);
        ept_invalidate_and_flush(ctx);
    }

    /* Now re-cast the PML2E/PDE as it should be split,
     * then we can just return the correct value. */
    ept_pde *target_pml2e = (ept_pde *)target_pml2e_2mb;

    ept_pte *pml1_table = (ept_pte *)((uintptr_t)target_pml2e->page_frame_number * PAGE_SIZE);
    return &pml1_table[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
}

void ept_invalidate_and_flush(struct ept_ctx *ctx)
{
    invept_descriptor desc = {
        .ept_pointer = ctx->ept_ptr.flags,
        .reserved = 0
    };
    __invept(invvpid_all_context, &desc);
}