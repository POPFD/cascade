#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/vmem.h"
#include "memory/mem.h"
#include "ept.h"

//#define DEBUG_EPT
#ifdef DEBUG_EPT
    #define EPT_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define EPT_PRINT(...)
#endif

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

        EPT_PRINT("Valid %d type %d base_min %lX base_max %lX",
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