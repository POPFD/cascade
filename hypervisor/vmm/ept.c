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
    bool is_fixed;
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
    size_t mtrr_count;
    uint8_t def_mem_type;
};

struct ept_split_page {
    /* The PML1E/EPT_PTE table. */
    __attribute__((aligned(PAGE_SIZE))) ept_pte pml1[ENTRIES_PER_TABLE];

    /* A back reference to the PML2 entry which this was created for. */
    ept_pde_2mb *pml2e_ref;
};

static void gather_fixed_mtrr(struct ept_ctx *ctx)
{
    struct fixed_mtrr_info {
        uint64_t msr_id;
        uintptr_t base_address;
        size_t managed_size;
    };

    typedef union {
        struct {
            uint8_t types[8];
        } u;
        uint64_t flags;
    } ia32_mtrr_fixed_range_msr;

    static const struct fixed_mtrr_info FIXED_INFO[] = {
        { IA32_MTRR_FIX64K_00000, 0x0, 0x10000, },
        { IA32_MTRR_FIX16K_80000, 0x80000, 0x4000, },
        { IA32_MTRR_FIX16K_A0000, 0xA0000, 0x4000, },
        { IA32_MTRR_FIX4K_C0000,  0xC0000, 0x1000, },
        { IA32_MTRR_FIX4K_C8000,  0xC8000, 0x1000, },
        { IA32_MTRR_FIX4K_D0000,  0xD0000, 0x1000, },
        { IA32_MTRR_FIX4K_D8000,  0xD8000, 0x1000, },
        { IA32_MTRR_FIX4K_E0000,  0xE0000, 0x1000, },
        { IA32_MTRR_FIX4K_E8000,  0xE8000, 0x1000, },
        { IA32_MTRR_FIX4K_F0000,  0xF0000, 0x1000, },
        { IA32_MTRR_FIX4K_F8000,  0xF8000, 0x1000, },
    };

    ia32_mtrrcap_register caps = { .flags = rdmsr(IA32_MTRRCAP) };
    ia32_mtrr_def_type_register def_type = { .flags = rdmsr(IA32_MTRR_DEF_TYPE) };

    /* Store the default memory type, for all regions not covered by a MTRR. */
    ctx->def_mem_type = def_type.default_memory_type;

    if (!caps.fixed_range_registers_supported || !def_type.fixed_range_mtrr_enable)
        return;

    struct mtrr_data *last_valid = NULL;

    for (size_t i = 0; i < ARRAY_SIZE(FIXED_INFO); i++) {
        const struct fixed_mtrr_info *curr_range = &FIXED_INFO[i];

        ia32_mtrr_fixed_range_msr fixed_range = {.flags = rdmsr(curr_range->msr_id) };

        for (size_t j = 0; j < ARRAY_SIZE(fixed_range.u.types); j++) {
            uint8_t mem_type = fixed_range.u.types[j];
            uint64_t range_begin = curr_range->base_address + (curr_range->managed_size * j);
            uint64_t range_end = range_begin + curr_range->managed_size;

            /*
             * Check to see if we can combine it with previous.
             * For this to be true, it must be of the same memory type
             * and also be contiguous.
             *
             * This will make it easier & quicker for when we do searching.
             */
            if (last_valid && (last_valid->type == mem_type) &&
                (last_valid->phys_base_max == range_begin)) {

                last_valid->phys_base_max += curr_range->managed_size;
                // DEBUG_PRINT("Extended last fixed entry to phys_based_min=0x%lX phys_base_max=0x%lX",
                //             last_valid->phys_base_min, last_valid->phys_base_max);
            } else {
                struct mtrr_data *new_entry = &ctx->mtrr[ctx->mtrr_count];
                new_entry->valid = true;
                new_entry->is_fixed = true;
                new_entry->phys_base_min = range_begin;
                new_entry->phys_base_max = range_end;
                new_entry->type = mem_type;

                // DEBUG_PRINT("Adding fixed entry phys_base_min=0x%lX phys_base_max=0x%lX type=0x%lX",
                //             new_entry->phys_base_min, new_entry->phys_base_max, new_entry->type);

                last_valid = new_entry;
                ctx->mtrr_count++;
            }
        }
    }
}

static void gather_variable_mtrr(struct ept_ctx *ctx)
{
    ia32_mtrrcap_register caps = { .flags = rdmsr(IA32_MTRRCAP) };
    ia32_mtrr_physbase_register base;
    ia32_mtrr_physmask_register mask;


    struct mtrr_data *last_valid = NULL;

    for (size_t i = 0; i < caps.variable_range_registers_count; i++) {
        base.flags = rdmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        mask.flags = rdmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        /* If the mtrr is valid, calculate the min and maximum ranges. */
        if (mask.valid) {

            /*
             * __builtin_ffsll returns 1 + the index of the least significate 1-bit of x.
             * https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
             */
            long long bit_idx = __builtin_ffsll(mask.physical_addres_mask) - 1;
            size_t size_in_pages = (1ull << bit_idx);

            uint8_t mem_type = base.type;
            uint64_t range_begin = base.physical_addres_base * PAGE_SIZE;
            uint64_t range_size = size_in_pages * PAGE_SIZE;
            uint64_t range_end = range_begin + range_size;

            if (last_valid && (last_valid->type == mem_type) &&
                (last_valid->phys_base_max == range_begin)) {

                last_valid->phys_base_max += range_size;
                // DEBUG_PRINT("Extended last variable entry to phys_base_min=0x%lX phys_base_max=0x%lX",
                //             last_valid->phys_base_min, last_valid->phys_base_max);
            } else {
                struct mtrr_data *new_entry = &ctx->mtrr[ctx->mtrr_count];
                new_entry->valid = true;
                new_entry->is_fixed = false;
                new_entry->phys_base_min = range_begin;
                new_entry->phys_base_max = range_end;
                new_entry->type = mem_type;

                // DEBUG_PRINT("Adding variable phys_base_min=0x%lX phys_base_max=0x%lX type=0x%lX",
                //             new_entry->phys_base_min, new_entry->phys_base_max, new_entry->type);

                last_valid = new_entry;
                ctx->mtrr_count++;
            }
        }
    }
}

static void gather_mtrr_list(struct ept_ctx *ctx)
{
    gather_fixed_mtrr(ctx);
    gather_variable_mtrr(ctx);

    /* Let's print our memory type information. */
    DEBUG_PRINT("Default memory type=%d", ctx->def_mem_type);
    for (size_t i = 0; i < IA32_MTRR_COUNT; i++) {
        const struct mtrr_data *curr_mtrr = &ctx->mtrr[i];

        if (curr_mtrr->valid)
            DEBUG_PRINT("Range begin=0x%016llX end=0x%016llX type=%d fixed=%d",
                        curr_mtrr->phys_base_min, curr_mtrr->phys_base_max,
                        curr_mtrr->type, curr_mtrr->is_fixed);
    }
}

static uint32_t calc_mem_type(struct ept_ctx *ctx, uintptr_t phys_begin, size_t phys_size)
{
    /*
     * Iterate all of the MTRRs we have defined, and check to see if they match any of
     * the range which we have specified, if so we then use that MTRR's value.
     */
    uint32_t mem_type = MEMORY_TYPE_INVALID;

    for (size_t i = 0; i < IA32_MTRR_COUNT; i++) {
        const struct mtrr_data *curr_mtrr = &ctx->mtrr[i];

        /* Filter out invalid/empty entries. */
        if (!curr_mtrr->valid)
            continue;

        /* If out of range, let's skip. */
        if ((phys_begin < curr_mtrr->phys_base_min) ||
            (phys_begin >= curr_mtrr->phys_base_max))
            continue;

        /* If the range of our phys region is larger than defined in the MTRR throw an error. */
        if ((phys_begin + phys_size - 1) >= curr_mtrr->phys_base_max)
            return mem_type;

        /* Fixed MTRRs take precedence over all others. */
        if (curr_mtrr->is_fixed)
            return curr_mtrr->type;

        /* Uncacheable takes next precedence. */
        if (curr_mtrr->type == MEMORY_TYPE_UC)
            return curr_mtrr->type;

        /* Writethrough always takes precedence over writeback memory. */
        if (((curr_mtrr->type == MEMORY_TYPE_WT) && (mem_type == MEMORY_TYPE_WB)) ||
            ((curr_mtrr->type == MEMORY_TYPE_WB) && (mem_type == MEMORY_TYPE_WT))) {
            mem_type = MEMORY_TYPE_WT;
        }

        /* Anything else, just set to last matched. */
        mem_type = curr_mtrr->type;
    }

    /* If we didn't find the value in the MTRR list then just use the default. */
    if (mem_type == MEMORY_TYPE_INVALID)
        mem_type = ctx->def_mem_type;

    return mem_type;
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
        .ignore_pat = target_pml2e->ignore_pat,
        .suppress_ve = target_pml2e->suppress_ve
    };

    die_on(temp_pte.memory_type == MEMORY_TYPE_INVALID,
           "Memory type for 0x%lX is invalid even with splitting.", phys_addr);

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
        size_t curr_pfn = base_pfn + i;
        uintptr_t curr_phys = curr_pfn * PAGE_SIZE;

        new_split->pml1[i] = temp_pte;
        new_split->pml1[i].memory_type = calc_mem_type(ctx, curr_phys, PAGE_SIZE);
        new_split->pml1[i].page_frame_number = curr_pfn;
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

            /* Calculate the memory type for this entry. */
            uint32_t mem_type = calc_mem_type(ctx, phys_addr, MiB(2));

            /*
             * If the memory type is invalid (too large but semi in a 2MiB page)
             * Then let's split the it into smaller PML1E entries and then re-calc
             * the memory type individually.
             */
            if (mem_type != MEMORY_TYPE_INVALID) {
                ctx->pml2[i][j].memory_type = mem_type;
            } else {
                DEBUG_PRINT("Memory type for 0x%lX is invalid, splitting.", phys_addr);
                ept_split_large_page(ctx, phys_addr);
            }
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