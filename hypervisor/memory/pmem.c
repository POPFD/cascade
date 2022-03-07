#include "platform/standard.h"
#include "pmem.h"

/*
 * Standalone physical memory manager.
 * This module can be used for allocating pages of physical memory within
 * the host system. The lowest granularity supported is the size of a 4K page
 * due to page table restrictions (x86_64) as this is used with things such as
 * EPT where 4k pages are needed this is no problem (and no need to create a
 * heap allocator then).
 * 
 * The MM does not use 0xE820 or the EFI equivalent as the goal of this system
 * is a bit different. Instead we use a reserved PMEM range that is effectively
 * a uint8_t array within the .data? section of the application. The reasoning
 * behind this is that in the future when we look at implementing EPT and potentially
 * hiding the EFI driver from the guest OS running on the system all allocated/used
 * memory is actually within actual image so we don't have to traverse or keep
 * a record of memory allocated elsewhere.
 */

/* Defines the size of physical memory that can be used. */
#define PMEM_SIZE MiB(20)
#define PMEM_PAGE_COUNT (PMEM_SIZE / PAGE_SIZE)

#define PAGE_COUNT(byte_count) ((byte_count + PAGE_SIZE - 1) / PAGE_SIZE)
#define SET_N_BITS(n) ((1 << n) - 1)

/*
 * This *SHOULD* reside in the .bss section
 * not affecting actual PE size, however will be allocated at load
 * time of the image. 
 */
static uint8_t __attribute__ ((aligned (PAGE_SIZE))) pmem_region[PMEM_SIZE] = { 0 };

/*
 * A bitmap will be used for storing which pages are used/free
 * Each bit represents a page. We will also store the index of
 * the last page allocated, this is to speed up allocation
 * when contiguous pages need to be allocated (however this
 * will not help for when we overflow or memory is freed).
 * 
 * TODO: Make this better.....
 */
static size_t pmem_bitmap[PMEM_PAGE_COUNT / NUMBER_BITS_TYPE(size_t)];
static size_t pmem_last_chunk_idx;

void pmem_init(void)
{
    /* Lets ensure everything is cleared/zero'd. */
    pmem_last_chunk_idx = 0;
    memset(pmem_bitmap, 0, sizeof(pmem_bitmap));
    memset(pmem_region, 0, sizeof(pmem_region));
}

uintptr_t pmem_alloc_page(void)
{
    /* Start from the last allocated page index
     * and check each bit in the bitmap to find where
     * we can next allocate at. */
    size_t curr_idx = pmem_last_chunk_idx;
    do {
        /* Check each bit in the index to find the next free space */
        for (size_t bit_index = 0; bit_index < NUMBER_BITS_TYPE(pmem_bitmap[0]); bit_index++) {

            /* If that bit is not set, this means we can use this one. */
            if (((pmem_bitmap[curr_idx] >> bit_index) & 1) == 0) {

                /* Set the bit to indicate that page is now in use. */
                pmem_bitmap[curr_idx] |= 1ull << bit_index;

                /* Update the last index stored to help speed up future allocations. */
                pmem_last_chunk_idx = curr_idx;

                /* Calculate & return the allocated page's address. */
                size_t offset = (curr_idx * NUMBER_BITS_TYPE(pmem_bitmap[0])) + bit_index;
                offset *= PAGE_SIZE;

                uint8_t *result = &pmem_region[offset];
                memset(result, 0, PAGE_SIZE);
                return (uintptr_t)result;
            }
        }

        curr_idx++;
        curr_idx %= ARRAY_SIZE(pmem_bitmap);
    } while (curr_idx != pmem_last_chunk_idx);

    return 0;
}

uintptr_t pmem_alloc_contiguous(size_t bytes)
{
    die_on(!bytes, L"Invalid parameter unable to allocate 0 bytes.");
    die_on(bytes > (NUMBER_BITS_TYPE(pmem_bitmap[0]) * PAGE_SIZE),
           L"Current pmem allocator cannot allocate enough pages to fit %d bytes",
           bytes);

    const size_t number_pages = PAGE_COUNT(bytes);
    const size_t contiguous_bits = SET_N_BITS(number_pages);

    size_t chunk_idx = pmem_last_chunk_idx;

    /* Iterate the whole bitmap array and try find some contiguous bits
     * of space we can use. */
    do {
        size_t chunk_mask = pmem_bitmap[chunk_idx];

        for (size_t bit_index = 0; bit_index < NUMBER_BITS_TYPE(pmem_bitmap[0]); bit_index++) {
        
            /* Check if the current mask against number of bits to set is clear. */
            if ((chunk_mask & contiguous_bits) == 0) {
                
                /* Set the bits in the bitmask to indicate these are now in use. */
                pmem_bitmap[chunk_idx] |= (contiguous_bits << bit_index);

                /* Store the last chunk in the bitmap we used. */
                pmem_last_chunk_idx = chunk_idx;

                /* Calculate the physical address of the buffer. */
                size_t offset_chunk = (NUMBER_BITS_TYPE(pmem_bitmap[0]) * chunk_idx) * PAGE_SIZE;
                size_t offset_bit = bit_index * PAGE_SIZE;

                uint8_t *result = &pmem_region[offset_chunk + offset_bit];
                memset(result, 0, bytes);
                return (uintptr_t)result;
            } else {
                chunk_mask >>= 1ull;
            }
        }

    } while (chunk_idx != pmem_last_chunk_idx);

    return 0;
}

void pmem_free_page(uintptr_t page)
{
    /* Assert that the memory to free is within our allocator range.
     * and that it is page aligned. */
    assert(page >= (uintptr_t)pmem_region);
    assert(page < (uintptr_t)pmem_region + sizeof(pmem_region));
    assert(!(page & (PAGE_SIZE - 1)));

    /* Calculate the page index in the bitmap. */
    size_t offset = page - (uintptr_t)&pmem_region[0];
    size_t full_bit_index = offset / PAGE_SIZE;

    size_t array_index = full_bit_index / NUMBER_BITS_TYPE(pmem_bitmap[0]);
    size_t bit_offset = full_bit_index % NUMBER_BITS_TYPE(pmem_bitmap[0]);

    /* Assert that the array index is within our pmem bitmap region. */
    assert(array_index < ARRAY_SIZE(pmem_bitmap));

    /* Assert that the bit is already set. */
    assert(pmem_bitmap[array_index] & (1ull << bit_offset));

    /* Clear the bit. */
    pmem_bitmap[array_index] &= ~(1ull << bit_offset);
}