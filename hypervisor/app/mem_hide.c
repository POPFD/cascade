#define DEBUG_MODULE
#include "mem_hide.h"
#include "memory/mem.h"
#include "vmm/ept.h"

/*
 * The memory hider module effectively hides ALL of the EFI RT
 * driver from the hyperjacked guest operating system. This will
 * prevent the guest from being able to probe the hypervisor.
 *
 * As we currently store our memory allocation buffers and such
 * within the image size as well there may be situations where we
 * need to make these visible to the guest, as such in the FUTURE
 * we will add in code to allow setting a flag for visible to guest
 * or not for each page.
 */

/*
 * We utilize EPT/SLAT to override what the guest can see, effectively
 * making any EFI RT driver page (from the guests perspective) point to
 * this DUMMY_PAGE.
 */
__attribute__ ((aligned (PAGE_SIZE)))
    static const uint8_t DUMMY_PAGE[PAGE_SIZE] = { 0 };

void mem_hide_init(struct vmm_ctx *vmm)
{
    DEBUG_PRINT("Memory hiding initialization base: 0x%lX size: 0x%lX",
                vmm->init.image_base, vmm->init.image_size);

    /* Get the physical address of the dummy page. */
    cr3 this_cr3;
    this_cr3.flags = __readcr3();
    uintptr_t phys_dummy = mem_va_to_pa(this_cr3, (void *)DUMMY_PAGE);

    /* Now iterage ALL pages of the image.
     * Setting each of the EPT PTE's to point to the dummy page. */
    uintptr_t start_page = vmm->init.image_base;
    uintptr_t end_page = start_page + vmm->init.image_size;

    for (uintptr_t curr_page = start_page;
         curr_page < end_page;
         curr_page += PAGE_SIZE) {

        /* This ISN'T explicitly needed as we can assume the memory
         * is actually below our "dynamically allocated" region, however
         * better safe than sorry. */
        uintptr_t phys_page = mem_va_to_pa(this_cr3, (void *)curr_page);

        ept_pte *curr_pte = ept_get_pml1e(vmm->ept, phys_page);

        curr_pte->page_frame_number = phys_dummy / PAGE_SIZE;

        /* While we're here lets actually trap on RWX in guest mode for access. */
        curr_pte->read_access = false;
        curr_pte->write_access = false;
        curr_pte->execute_access = false;
    }
    ept_invalidate_and_flush(vmm->ept);
}