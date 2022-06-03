//#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/spinlock.h"
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
static size_t pmem_last_bit_idx;

static spinlock_t lock;
static size_t total_allocated = 0;

static inline bool find_contiguous_unset(size_t count,
                                         size_t *found_chunk_idx,
                                         size_t *found_bit_idx)
{
    size_t chunk_idx = pmem_last_chunk_idx;
    size_t bit_idx = pmem_last_bit_idx;

    do {

        size_t curr_count = 0;
        while (1) {

            /* Check to see if current bit is unsed. */
            if (!((pmem_bitmap[chunk_idx] >> bit_idx) & 1))
                curr_count++;
            else
                curr_count = 0;

            /* If we have found N contiguous bits return value. */
            if (curr_count == count) {
                *found_chunk_idx = chunk_idx;
                *found_bit_idx = bit_idx;
                return true;
            }

            /* Increment the chunk and bit indexes. */
            bit_idx = (bit_idx + 1) % NUMBER_BITS_TYPE(pmem_bitmap[0]);
            if (!bit_idx)
                chunk_idx = (chunk_idx + 1) % ARRAY_SIZE(pmem_bitmap);

            /*
             * If chunk index has iterated to beginning of bitmap
             * we must reset current count as overflow cannot count
             * as contiguous.
             */
            if (!chunk_idx && !bit_idx)
                curr_count = 0;
        }
    } while ((chunk_idx != pmem_last_chunk_idx) && (bit_idx != pmem_last_bit_idx));

    return false;
}

static inline void set_contiguous_bits(size_t chunk_idx, size_t bit_idx, size_t count, bool val)
{
    for (size_t i = 0; i < count; i++) {
        die_on(((pmem_bitmap[chunk_idx] >> bit_idx) & 1) == val,
               "Bit already set, chunk %d bit %d",
               chunk_idx, bit_idx);

        if (val)
            pmem_bitmap[chunk_idx] |= 1ull << bit_idx;
        else
            pmem_bitmap[chunk_idx] &= 1ull << bit_idx;

        bit_idx = (bit_idx + 1) % NUMBER_BITS_TYPE(pmem_bitmap[0]);
        if (!bit_idx)
            chunk_idx = (chunk_idx + 1) % ARRAY_SIZE(pmem_bitmap);
    }
}

void pmem_init(void)
{
    /* Lets ensure everything is cleared/zero'd. */
    pmem_last_chunk_idx = 0;
    pmem_last_bit_idx = 0;
    memset(pmem_bitmap, 0, sizeof(pmem_bitmap));
    memset(pmem_region, 0, sizeof(pmem_region));

    spin_init(&lock);
}

uintptr_t pmem_alloc_page(void)
{
    spin_lock(&lock);

    /* Search for 1 contiguous page in the bitmap that is unset. */
    size_t chunk_idx;
    size_t bit_idx;
    if (find_contiguous_unset(1, &chunk_idx, &bit_idx)) {
        DEBUG_PRINT("Found chunk %d bit %d", chunk_idx, bit_idx);

        /* Indicate that bit & page is now in use. */
        set_contiguous_bits(chunk_idx, bit_idx, 1, true);

        /* Update the last index stored to help speed up future allocations. */
        pmem_last_chunk_idx = chunk_idx;
        pmem_last_bit_idx = bit_idx;

        /* Calculate & return the allocated page's address. */
        size_t offset = (chunk_idx * NUMBER_BITS_TYPE(pmem_bitmap[0])) + bit_idx;
        offset *= PAGE_SIZE;

        uint8_t *result = &pmem_region[offset];
        memset(result, 0, PAGE_SIZE);
        spin_unlock(&lock);
        return (uintptr_t)result;
    }

    spin_unlock(&lock);
    return 0;
}

uintptr_t pmem_alloc_contiguous(size_t bytes)
{
    die_on(!bytes, "Invalid parameter unable to allocate 0 bytes.");
    die_on(bytes > (NUMBER_BITS_TYPE(pmem_bitmap[0]) * PAGE_SIZE),
           "Current pmem allocator cannot allocate enough pages to fit %d bytes",
           bytes);

    const size_t number_pages = PAGE_COUNT(bytes);

    spin_lock(&lock);

    size_t chunk_idx;
    size_t bit_idx;
    if (find_contiguous_unset(number_pages, &chunk_idx, &bit_idx)) {
        DEBUG_PRINT("Found chunk %d bit %d", chunk_idx, bit_idx);

        /* Indicate the following bits are used. */
        set_contiguous_bits(chunk_idx, bit_idx, number_pages, true);

        /* Update the last index stored to help speed up future allocations. */
        pmem_last_chunk_idx = chunk_idx;
        pmem_last_bit_idx = bit_idx;

        /* Calculate the physical address of the buffer. */
        size_t offset_chunk = (NUMBER_BITS_TYPE(pmem_bitmap[0]) * chunk_idx) * PAGE_SIZE;
        size_t offset_bit = bit_idx * PAGE_SIZE;

        uint8_t *result = &pmem_region[offset_chunk + offset_bit];
        memset(result, 0, bytes);
        spin_unlock(&lock);
        total_allocated += PAGE_COUNT(bytes) * PAGE_SIZE;
        return (uintptr_t)result;
    }

    spin_unlock(&lock);
    return 0;
}

void pmem_free_page(uintptr_t page)
{
    /* Assert that the memory to free is within our allocator range.
     * and that it is page aligned. */
    assert(page >= (uintptr_t)pmem_region);
    assert(page < (uintptr_t)pmem_region + sizeof(pmem_region));
    assert(!(page & (PAGE_SIZE - 1)));

    spin_lock(&lock);

    /* Calculate the page index in the bitmap. */
    size_t offset = page - (uintptr_t)&pmem_region[0];
    size_t full_bit_index = offset / PAGE_SIZE;

    size_t chunk_idx = full_bit_index / NUMBER_BITS_TYPE(pmem_bitmap[0]);
    size_t bit_idx = full_bit_index % NUMBER_BITS_TYPE(pmem_bitmap[0]);

    set_contiguous_bits(chunk_idx, bit_idx, 1, false);
    spin_unlock(&lock);
}