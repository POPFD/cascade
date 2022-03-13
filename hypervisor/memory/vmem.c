#include "platform/standard.h"
#include "platform/intrin.h"
#include "memory/pmem.h"
#include "memory/vmem.h"

/* Standalone virtual memory manager.
 * This module created the page tables required to implement virtual memory
 * which will be used the by HOST/ROOT of the hypervisor.
 * When booted from an EFI environment normally memory is identity mapped
 * with a 1:1 of physical to virtual memory. We are going to do the same
 * for here.
 * 
 * However, physical memory (allocated via the pmem module) can be allocated
 * for use (so contiguous pages can exist) into virtual memory.
 * The first 512GB of vmem will be identity mapped, and then the second 512GB (PML4 idx 1)
 * address starting at 0x8000000000 of virtual space will be used for memory allocated
 * within here.
 * 
 * This allows for an easy seperation and determination of identity mapped vs allocated
 * memory.
 */
//#define DEBUG_VMEM
#ifdef DEBUG_VMEM
    #define VMEM_PRINT(...) debug_print(__VA_ARGS__)
#else
    #define VMEM_PRINT(...)
#endif

#define ENTRIES_PER_TABLE 512

#define ADDRMASK_PML4_INDEX(addr)   (((size_t)addr & 0xFF8000000000ULL) >> 39)
#define ADDRMASK_PDPTE_INDEX(addr)  (((size_t)addr & 0x7FC0000000ULL) >> 30)
#define ADDRMASK_PDE_INDEX(addr)    (((size_t)addr & 0x3FE00000ULL) >> 21)
#define ADDRMASK_PTE_INDEX(addr)    (((size_t)addr & 0x1FF000ULL) >> 12)
#define ADDRMASK_PTE_OFFSET(addr)   ((size_t)addr & 0xFFFULL)

#define DYN_VMEM_START GiB(512)

struct vmem_ctx {
    /* Describes the 512 contiguous 512GB memory regions. */
    __attribute__ ((aligned (PAGE_SIZE))) pml4e_64 pml4[ENTRIES_PER_TABLE];

    /* Describes the first 512 1GB memory regions within PML4[0] used for identity mapping.
     * These will be set as large pages.
     * So that we don't need to go to lower granularity (2MB or 4k). */
    __attribute__ ((aligned (PAGE_SIZE))) pdpte_1gb_64 identity_pdpt[ENTRIES_PER_TABLE];

    /*
     * pml4e_64
     * --- pdpte_64
     * ------ pde_64
     * ---------pte_64
     */

    uintptr_t next_free_addr;
};

static struct vmem_ctx *m_ctx = NULL;

static void init_identity_table(struct vmem_ctx *ctx)
{
    /* Set out the first PML4E to indicate this is present
     * and this is what we'll be using for identity mapping. */
    ctx->pml4[0].present = true;
    ctx->pml4[0].write = true;
    ctx->pml4[0].page_frame_number = ((uintptr_t)ctx->identity_pdpt) / PAGE_SIZE;

    for (size_t i = 0; i < 512; i++) {
        ctx->identity_pdpt[i].present = true;
        ctx->identity_pdpt[i].write = true;
        ctx->identity_pdpt[i].execute_disable = false;
        ctx->identity_pdpt[i].large_page = true;
        ctx->identity_pdpt[i].page_frame_number = i;
    }
}

static void create_table_entries(uintptr_t addr, bool write, bool exec)
{
    VMEM_PRINT(L"Creating page tables for address %lX write %d exec %d\n", addr, write, exec);

    size_t pml4_idx = ADDRMASK_PML4_INDEX(addr);
    size_t pdpte_idx = ADDRMASK_PDPTE_INDEX(addr);
    size_t pde_idx = ADDRMASK_PDE_INDEX(addr);
    size_t pte_idx = ADDRMASK_PTE_INDEX(addr);
    VMEM_PRINT(L"PML4[%d] PDPTE[%d] PDE[%d] PTE[%d]\n", pml4_idx, pdpte_idx, pde_idx, pte_idx);

    pml4e_64 *pml4e = &m_ctx->pml4[pml4_idx];

    if (!pml4e->present) {
        pml4e->write = true;
        pml4e->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pml4e->page_frame_number, L"Could not allocate PML4E for addr %lX\n", addr);
        pml4e->present = true;
    }
    VMEM_PRINT(L"--- PDPT base PFN[ADDR] %lX[%lX]\n",
                pml4e->page_frame_number,
                pml4e->page_frame_number * PAGE_SIZE);

    pdpte_64 *pdpt = (pdpte_64 *)((uintptr_t)pml4e->page_frame_number * PAGE_SIZE);
    pdpte_64 *pdpte = &pdpt[pdpte_idx];

    if (!pdpte->present) {
        pdpte->write = true;
        pdpte->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pdpte->page_frame_number, L"Could not allocate PDPTE for addr %lX\n", addr);
        pdpte->present = true;
    }
    VMEM_PRINT(L"--- PD base PFN[ADDR] %lX[%lX]\n",
                pdpte->page_frame_number,
                pdpte->page_frame_number * PAGE_SIZE);

    pde_64 *pd = (pde_64 *)((uintptr_t)pdpte->page_frame_number * PAGE_SIZE);
    pde_64 *pde = &pd[pde_idx];

    if (!pde->present) {
        pde->write = true;
        pde->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pde->page_frame_number, L"Could not allocate PDE for addr %lX\n", addr);
        pde->present = true;
    }
    VMEM_PRINT(L"--- PT base PFN[ADDR] %lX[%lX]\n",
                pde->page_frame_number,
                pde->page_frame_number * PAGE_SIZE);

    pte_64 *pt = (pte_64 *)((uintptr_t)pde->page_frame_number * PAGE_SIZE);
    pte_64 *pte = &pt[pte_idx];

    die_on(pte->present, L"PTE is already present for addr %lX\n", addr);
    pte->write = write;
    pte->execute_disable = !exec;
    pte->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
    die_on(!pte->page_frame_number, L"Could not allocate PTE for addr %lX\n", addr);
    pte->present = true;
    VMEM_PRINT(L"--- Allocated pmem PFN[ADDR] %lX[%lX]\n",
                pte->page_frame_number,
                pte->page_frame_number * PAGE_SIZE);
}

void vmem_init(cr3 *original_cr3, cr3 *new_cr3)
{
    /* Store the original CR3 value before initialising the virtual-memory manager. */
    original_cr3->flags = __readcr3();
    VMEM_PRINT(L"Storing original CR3 %lX\n", original_cr3->flags);

    /*
     * Allocated a page for the vmem context.
     * Unfortunately as we are the virtual memory manager we cannot
     * allocate virtual memory to do this (for obvious reasons)
     * so we will allocate via pmem (it will be identity mapped either way)
     */
    m_ctx = (struct vmem_ctx *)pmem_alloc_contiguous(sizeof(struct vmem_ctx));
    die_on(!m_ctx, L"Unable to allocate contact for virtual memory manager.\n");

    /* Clear main root PML4. */
    memset(m_ctx->pml4, 0, sizeof(m_ctx->pml4));

    /* Initialise the page table with identity mapping for the environment. */
    init_identity_table(m_ctx);

    /* Set the next free address in the dynamic allocator. */
    m_ctx->next_free_addr = DYN_VMEM_START;

    /* Write the new CR3 value so that the memory manager is used. */
    new_cr3->page_level_cache_disable = original_cr3->page_level_cache_disable;
    new_cr3->page_level_write_through = original_cr3->page_level_write_through;
    new_cr3->address_of_page_directory = ((uintptr_t)m_ctx->pml4) / PAGE_SIZE;
    __writecr3(new_cr3->flags);
    VMEM_PRINT(L"New CR3 value loaded %lX\n", new_cr3->flags);
}

void *vmem_alloc(size_t size, unsigned int flags)
{
    /* 
     * For each of the pages for the address specified from our next
     * free start address create a table entry.
     */

    /* Align size to next largest page. */
    size = (size & PAGE_MASK) ? ((size + PAGE_SIZE) & ~PAGE_MASK) : size;
    VMEM_PRINT(L"Attempting allocation of size: %ld\n", size);

    /* Determine info from flags. */
    bool write = (flags & MEM_WRITE) != 0;
    bool exec = (flags & MEM_EXECUTE) != 0;

    uintptr_t start_addr = m_ctx->next_free_addr;
    uintptr_t end_addr = start_addr + size;

    for (uintptr_t curr_addr = start_addr;
         curr_addr < end_addr;
         curr_addr += PAGE_SIZE) {
        
        /* Allocate the pages tables for the address needed. */
        create_table_entries(curr_addr, write, exec);
    }

    m_ctx->next_free_addr = end_addr;
    die_on(m_ctx->next_free_addr < DYN_VMEM_START,
           L"The virtual memory manager's next_free_addr has iterated back into the" \
           L"identity mapped area, we should probably create an algorithm to reuse" \
           L"freed memory ranges.");

    return (void *)start_addr;
}

void vmem_free(void *addr, size_t size)
{
    /* TODO: Unfortunately need to pass size here, unless
     * we keep a VAD style map logging all of our allocations
     * (I'd rather kill myself than add more complexity to this
     * considering this is not the main goal of the project). */
    die_on(true, L"vmem_free not implemented as of yet.");
    (void)addr;
    (void)size;
}