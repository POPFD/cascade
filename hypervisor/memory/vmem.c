//#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/spinlock.h"
#include "platform/intrin.h"
#include "memory/pmem.h"
#include "memory/vmem.h"
#include "memory/mem.h"

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

#define ENTRIES_PER_TABLE 512
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
    spinlock_t sync;
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
    DEBUG_PRINT("Creating page tables for address %lX write %d exec %d", addr, write, exec);

    size_t pml4_idx = ADDRMASK_PML4_INDEX(addr);
    size_t pdpte_idx = ADDRMASK_PDPTE_INDEX(addr);
    size_t pde_idx = ADDRMASK_PDE_INDEX(addr);
    size_t pte_idx = ADDRMASK_PTE_INDEX(addr);
    DEBUG_PRINT("PML4[%d] PDPTE[%d] PDE[%d] PTE[%d]", pml4_idx, pdpte_idx, pde_idx, pte_idx);

    pml4e_64 *pml4e = &m_ctx->pml4[pml4_idx];
    DEBUG_PRINT("--- PML4E PFN[ADDR] %lX[%lX]", (uintptr_t)pml4e / PAGE_SIZE, pml4e);

    if (!pml4e->present) {
        pml4e->write = true;
        pml4e->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pml4e->page_frame_number, "Could not allocate PML4E for addr %lX", addr);
        pml4e->present = true;
    }

    pdpte_64 *pdpt = (pdpte_64 *)((uintptr_t)pml4e->page_frame_number * PAGE_SIZE);
    pdpte_64 *pdpte = &pdpt[pdpte_idx];
    DEBUG_PRINT("--- PDPTE PFN[ADDR] %lX[%lX]", (uintptr_t)pdpte / PAGE_SIZE, pdpte);

    if (!pdpte->present) {
        pdpte->write = true;
        pdpte->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pdpte->page_frame_number, "Could not allocate PDPTE for addr %lX", addr);
        pdpte->present = true;
    }

    pde_64 *pd = (pde_64 *)((uintptr_t)pdpte->page_frame_number * PAGE_SIZE);
    pde_64 *pde = &pd[pde_idx];
    DEBUG_PRINT("--- PDE PFN[ADDR] %lX[%lX]", (uintptr_t)pde / PAGE_SIZE, pde);

    if (!pde->present) {
        pde->write = true;
        pde->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
        die_on(!pde->page_frame_number, "Could not allocate PDE for addr %lX", addr);
        pde->present = true;
    }

    pte_64 *pt = (pte_64 *)((uintptr_t)pde->page_frame_number * PAGE_SIZE);
    pte_64 *pte = &pt[pte_idx];
    DEBUG_PRINT("--- PTE PFN[ADDR] %lX[%lX]", (uintptr_t)pte / PAGE_SIZE, pte);

    die_on(pte->present, "PTE is already present for addr %lX", addr);
    pte->write = write;
    pte->execute_disable = !exec;
    pte->page_frame_number = pmem_alloc_page() / PAGE_SIZE;
    die_on(!pte->page_frame_number, "Could not allocate PTE for addr %lX", addr);
    pte->present = true;
    DEBUG_PRINT("--- Allocated page memory PFN[ADDR] %lX[%lX]",
               pte->page_frame_number, pte->page_frame_number * PAGE_SIZE);

    /* Invalidate the TLB for address. */
    __invlpg(&addr);

#ifdef DEBUG_MODULE
    /* Some debug code that ensures that the created PA matches if we
     * traverse the VA back to PA. */
    cr3 tmp_cr3;
    tmp_cr3.flags = __readcr3();
    uintptr_t actual_pa = pte->page_frame_number * PAGE_SIZE;
    uintptr_t calc_pa = mem_va_to_pa(tmp_cr3, (void *)addr);
    die_on(actual_pa != calc_pa,
           "Physical addr %lX does not match calculated physical addr %lX",
           actual_pa, calc_pa);
#endif
}

static void modify_entry_perms(uintptr_t addr, bool write, bool exec)
{
    DEBUG_PRINT("Modifying page table entries for address %lX write %d exec %d", addr, write, exec);

    size_t pml4_idx = ADDRMASK_PML4_INDEX(addr);
    size_t pdpte_idx = ADDRMASK_PDPTE_INDEX(addr);
    size_t pde_idx = ADDRMASK_PDE_INDEX(addr);
    size_t pte_idx = ADDRMASK_PTE_INDEX(addr);
    DEBUG_PRINT("PML4[%d] PDPTE[%d] PDE[%d] PTE[%d]", pml4_idx, pdpte_idx, pde_idx, pte_idx);

    pml4e_64 *pml4e = &m_ctx->pml4[pml4_idx];
    die_on(!pml4e->present, "PML4E for addr %lX not present", addr);

    pdpte_64 *pdpt = (pdpte_64 *)((uintptr_t)pml4e->page_frame_number * PAGE_SIZE);
    pdpte_64 *pdpte = &pdpt[pdpte_idx];
    die_on(!pdpte->present, "PDPTE for addr %lX not present", addr);

    pde_64 *pd = (pde_64 *)((uintptr_t)pdpte->page_frame_number * PAGE_SIZE);
    pde_64 *pde = &pd[pde_idx];

    die_on(!pde->present, "PDE for addr %lX not present", addr);

    pte_64 *pt = (pte_64 *)((uintptr_t)pde->page_frame_number * PAGE_SIZE);
    pte_64 *pte = &pt[pte_idx];
    die_on(!pte->present, "PTE for addr %lX not present", addr);
    pte->write = write;
    pte->execute_disable = !exec;

    /* Invalidate the TLB for address. */
    __invlpg(&addr);
}

void vmem_init(cr3 *original_cr3, cr3 *new_cr3)
{
    /* Store the original CR3 value before initialising the virtual-memory manager. */
    original_cr3->flags = __readcr3();
    DEBUG_PRINT("Storing original CR3 %lX", original_cr3->flags);

    /*
     * Allocated a page for the vmem context.
     * Unfortunately as we are the virtual memory manager we cannot
     * allocate virtual memory to do this (for obvious reasons)
     * so we will allocate via pmem (it will be identity mapped either way)
     */
    m_ctx = (struct vmem_ctx *)pmem_alloc_contiguous(sizeof(struct vmem_ctx));
    die_on(!m_ctx, "Unable to allocate contact for virtual memory manager.");

    /* Clear main root PML4. */
    memset(m_ctx->pml4, 0, sizeof(m_ctx->pml4));

    /* Initialise the page table with identity mapping for the environment. */
    init_identity_table(m_ctx);

    /* Set the next free address in the dynamic allocator. */
    m_ctx->next_free_addr = DYN_VMEM_START;

    spin_init(&m_ctx->sync);

    /* Write the new CR3 value so that the memory manager is used. */
    new_cr3->page_level_cache_disable = original_cr3->page_level_cache_disable;
    new_cr3->page_level_write_through = original_cr3->page_level_write_through;
    new_cr3->address_of_page_directory = ((uintptr_t)m_ctx->pml4) / PAGE_SIZE;
    __writecr3(new_cr3->flags);
    DEBUG_PRINT("New CR3 value loaded %lX", new_cr3->flags);
}

void *vmem_alloc(size_t size, unsigned int flags)
{
    /* 
     * For each of the pages for the address specified from our next
     * free start address create a table entry.
     */
    spin_lock(&m_ctx->sync);

    DEBUG_PRINT("Unaligned size: %ld", size);
    /* Align size to next largest page. */
    size = (size & PAGE_MASK) ? ((size + PAGE_SIZE) & ~PAGE_MASK) : size;
    DEBUG_PRINT("Attempting allocation of size: %ld", size);

    /* Determine info from flags. */
    bool write = (flags & MEM_WRITE) != 0;
    bool exec = (flags & MEM_EXECUTE) != 0;

    uintptr_t start_addr = m_ctx->next_free_addr;
    uintptr_t end_addr = start_addr + size;
    DEBUG_PRINT("Start addr 0x%lX end addr 0x%lX diff 0x%lX", start_addr, end_addr, end_addr - start_addr);

    for (uintptr_t curr_addr = start_addr;
         curr_addr < end_addr;
         curr_addr += PAGE_SIZE) {
        
        /* Allocate the pages tables for the address needed. */
        create_table_entries(curr_addr, write, exec);
    }

    m_ctx->next_free_addr = end_addr;
    die_on(m_ctx->next_free_addr < DYN_VMEM_START,
           "The virtual memory manager's next_free_addr has iterated back into the" \
           "identity mapped area, we should probably create an algorithm to reuse" \
           "freed memory ranges.");

    spin_unlock(&m_ctx->sync);

    return (void *)start_addr;
}

void vmem_change_perms(void *addr, size_t size, unsigned int flags)
{
    spin_lock(&m_ctx->sync);

    /* Determine info from flags. */
    bool write = (flags & MEM_WRITE) != 0;
    bool exec = (flags & MEM_EXECUTE) != 0;

    uintptr_t start_addr = (uintptr_t)addr;
    uintptr_t end_addr = start_addr + size;

    /* Iterate each page and change permissions. */
    for (uintptr_t curr_addr = start_addr;
         curr_addr < end_addr;
         curr_addr += PAGE_SIZE) {

        modify_entry_perms(curr_addr, write, exec);
    }

    spin_unlock(&m_ctx->sync);
}

void vmem_free(void *addr, size_t size)
{
    /* TODO: Unfortunately need to pass size here, unless
     * we keep a VAD style map logging all of our allocations
     * (I'd rather kill myself than add more complexity to this
     * considering this is not the main goal of the project). */
    die_on(true, "vmem_free not implemented as of yet.");
    (void)addr;
    (void)size;
}