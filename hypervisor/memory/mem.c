#include "mem.h"

static void copy_physical_page(enum copy_dir dir, uintptr_t addr, void *buffer, size_t size)
{
    if (dir == COPY_READ) {
        memcpy(buffer, (const void *)addr, size);
    } else {
        memcpy((void *)addr, buffer, size);
    }
}

static pt_entry_64 *get_pte_from_va(cr3 table, void *va, int *level)
{
    size_t pml4_idx = ADDRMASK_PML4_INDEX(va);
    size_t pdpte_idx = ADDRMASK_PDPTE_INDEX(va);
    size_t pde_idx = ADDRMASK_PDE_INDEX(va);
    size_t pte_idx = ADDRMASK_PTE_INDEX(va);

    pml4e_64 *pml4 = (pml4e_64 *)((uintptr_t)table.address_of_page_directory * PAGE_SIZE);
    pml4e_64 *pml4e = &pml4[pml4_idx];
    if (!pml4e->present) {
        *level = 4;
        return (pt_entry_64 *)pml4e;
    }

    pdpte_64 *pdpt = (pdpte_64 *)((uintptr_t)pml4e->page_frame_number * PAGE_SIZE);
    pdpte_64 *pdpte = &pdpt[pdpte_idx];
    if (!pdpte->present || pdpte->large_page) {
        *level = 3;
        return (pt_entry_64 *)pdpte;
    }

    pde_64 *pd = (pde_64 *)((uintptr_t)pdpte->page_frame_number * PAGE_SIZE);
    pde_64 *pde = &pd[pde_idx];
    if (!pde->present || pde->large_page) {
        *level = 2;
        return (pt_entry_64 *)pde;
    }

    pte_64 *pt = (pte_64 *)((uintptr_t)pde->page_frame_number * PAGE_SIZE);
    pte_64 *pte = &pt[pte_idx];
    *level = 1;
    return (pt_entry_64 *)pte;
}

uintptr_t mem_va_to_pa(cr3 table, void *va)
{
    int level;
    pt_entry_64 *entry = get_pte_from_va(table, va, &level);
    if (!entry->present) {
        return 0;
    }

    switch (level) {
    case 4:
        die_on(true, "Invalid level of 4 retrieved for va %lX", va);
        break;
    case 3:
    {
        pdpte_1gb_64 pdpte;
        pdpte.flags = entry->flags;
        return (pdpte.page_frame_number * GiB(1)) + ADDRMASK_PDPTE_OFFSET(va);
    }
    case 2:
    {
        pde_2mb_64 pde;
        pde.flags = entry->flags;
        return (pde.page_frame_number * MiB(2)) + ADDRMASK_PDE_OFFSET(va);
    }
    case 1:
    {
        pte_64 pte;
        pte.flags = entry->flags;
        return (pte.page_frame_number * PAGE_SIZE) + ADDRMASK_PTE_OFFSET(va);
    }
    default:
        die_on(true, "Invalid pte level %d for va %lX", level, va);
        break;
    }
}

bool mem_copy_virt_tofrom_host(enum copy_dir dir, cr3 table,
                             uintptr_t addr, void *buffer, size_t size)
{
    die_on(!table.flags, "Invalid CR3 value");
    die_on(!addr, "Invalid virtual address");
    die_on(!buffer, "Invalid host buffer");
    die_on(!size, "Invalid size");

    bool result = true;

    /*
     * As buffer referenced in the virtual address may not have a contiguous
     * physical address for each page, we need to retrieve and copy pages individually.
     */
    while (size) {
        /* Calculate how many bytes need to be copied for this page. */
        size_t page_offset = ADDRMASK_PTE_OFFSET(addr);
        size_t copy_this_page = PAGE_SIZE - page_offset;
        size_t bytes_to_copy = (copy_this_page < size) ? copy_this_page : size;

        /* Get this physical address of this page. */
        uintptr_t phys_addr = mem_va_to_pa(table, (void *)addr);
        if (!phys_addr) {
            result = false;
            break;
        }

        /* Do the operation for copying the page. */
        copy_physical_page(dir, phys_addr, buffer, bytes_to_copy);

        /* Update counters for next page. */
        addr += bytes_to_copy;
        buffer = (void *)((uintptr_t)buffer + bytes_to_copy);
        size -= bytes_to_copy;
    }

    return result;
}

bool mem_copy_virt_to_virt(cr3 src_cr3, void *src, cr3 dest_cr3, void *dest, size_t size)
{
    die_on(!src_cr3.flags, "Invalid source CR3 value");
    die_on(!src, "Invalid source value");
    die_on(!dest_cr3.flags, "Invalid dest CR3 value");
    die_on(!dest, "Invalid destination value");
    die_on(!size, "Invalid size specified");

    bool result = true;

    /* Re-read our guest -> host copy, pretty much identical. */
    uintptr_t virt_src = (uintptr_t)src;
    uintptr_t virt_dest = (uintptr_t)dest;
    while (size) {
        /* Calculate how many bytes we can do from first page. */
        size_t src_page_offset = ADDRMASK_PTE_OFFSET(virt_src);
        size_t src_page_bytes = PAGE_SIZE - src_page_offset;

        size_t dest_page_offset = ADDRMASK_PTE_OFFSET(virt_dest);
        size_t dest_page_bytes = PAGE_SIZE - dest_page_offset;

        /* Make sure we are not overlapping a copy from dest or source.
         * Also make sure we're not copying more than what is available left to copy. */
        size_t copy_bytes = (src_page_bytes < dest_page_bytes) ? src_page_bytes : dest_page_bytes;
        copy_bytes = (copy_bytes < size) ? copy_bytes : size;

        /* Get the physical addresses for src & dest.
         * Since we map all physical memory into VMROOT, just copy like normal. */
        uint8_t *phys_src = (uint8_t *)mem_va_to_pa(src_cr3, (void *)virt_src);
        uint8_t *phys_dest = (uint8_t *)mem_va_to_pa(dest_cr3, (void *)virt_dest);
        if (!phys_src || !phys_dest) {
            result = false;
            break;
        }

        memcpy(&phys_dest[dest_page_offset], &phys_src[src_page_offset], copy_bytes);
        virt_src += copy_bytes;
        virt_dest += copy_bytes;
        size -= copy_bytes;
    }

    return result;
}
