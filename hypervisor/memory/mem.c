#include "mem.h"

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
        die_on(true, L"Invalid level of 4 retrieved for va %lX\n", va);
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
        die_on(true, L"Invalid pte level %d for va %lX\n", level, va);
        break;
    }
}