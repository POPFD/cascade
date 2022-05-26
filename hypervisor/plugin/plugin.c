#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/nt.h"
#include "memory/mem.h"
#include "memory/vmem.h"
#include "cascade_if.h"
#include "plugin.h"

static bool check_image(uint8_t *guest_raw,
                        struct image_dos_header *idh,
                        struct image_nt_headers64 *inh)
{
    /* Read the DOS header and check validity. */
    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)guest_raw,
                                 idh, sizeof(*idh))) {
        DEBUG_PRINT("Unable to read IDH.");
        return false;
    }

    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("Invalid IDH signature.");
        return false;
    }

    /* Read the INH and check validity. */
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)&guest_raw[idh->e_lfanew],
                                 inh, sizeof(*inh))) {
        DEBUG_PRINT("Unable to read INH.");
        return false;
    }

    if (inh->optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        DEBUG_PRINT("Image does not seem to be X64.");
        return false;
    }

    DEBUG_PRINT("Image headers validated\n" \
                "--- idh.e_magic: 0x%lX\n" \
                "--- idh.e_lfanew: 0x%lX\n" \
                "--- inh.opt.magic: 0x%lX\n" \
                "--- inh.opt.size_of_hdrs: 0x%lX\n" \
                "--- inh.opt.size_of_image: 0x%lX\n",
                idh->e_magic,
                idh->e_lfanew,
                inh->optional_header.magic,
                inh->optional_header.size_of_headers,
                inh->optional_header.size_of_image);

    return true;
}

static void relocate_image(uint8_t *new_image)
{
    /* We assume IDH and INH are valid already by this point. */
    struct image_dos_header *idh = (struct image_dos_header *)new_image;
    struct image_nt_headers64 *inh = (struct image_nt_headers64 *)&new_image[idh->e_lfanew];

    /*
     * Calculate the delta between the new image and what the original image base
     * was before it was loaded into the hypervisor.
     */
    const size_t delta = (uintptr_t)new_image - inh->optional_header.image_base;

    /* Get the pointer to the relocation data directory. */
    struct image_data_directory *idd =
        &inh->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (!idd->virtual_address || !idd->size) {
        DEBUG_PRINT("No relocation directory in plugin.");
        return;
    }

    struct image_base_relocation *curr_base_reloc =
        (struct image_base_relocation *)&new_image[idd->virtual_address];
    struct image_base_relocation *end_base_reloc =
        (struct image_base_relocation *)&new_image[idd->virtual_address + idd->size];

    /* Now iterate all the relocation bases until we reach the end block. */
    while (curr_base_reloc->size_of_block && curr_base_reloc < end_base_reloc) {
        /*
         * image_base_relocation is an incomplete type, there is an array of X bytes
         * calculated via the size_of_block. These are the relocation items.
         */
        uint8_t *block_start = &new_image[curr_base_reloc->virtual_address];
        uint16_t *item_start =
            (uint16_t *)((uintptr_t)curr_base_reloc + sizeof(struct image_base_relocation));

        size_t item_count =
            (curr_base_reloc->size_of_block / sizeof(struct image_base_relocation)) / sizeof(uint16_t);

        for (size_t i = 0; i < item_count; i++) {
            const uint16_t type = item_start[i] >> 12;
            const uint16_t offset = item_start[i] & 0xFFF;

            /* Only able to relocate DIR64 type. */
            if (type != IMAGE_REL_BASED_DIR64) {
                DEBUG_PRINT("Cannot relocate item of type: 0x%X item_start 0x%lX.",
                            type, &item_start[i]);
                continue;
            }

            /* Relocate/rebase the 64 bit address. */
            uint64_t *reloc_addr = (uint64_t *)&block_start[offset];
            uint64_t orig_value = *reloc_addr;
            *reloc_addr += delta;
            DEBUG_PRINT("Relocated address 0x%lX with original value 0x%lX to 0x%lX.",
                        reloc_addr, orig_value, *reloc_addr);
        }

        /* Go to the new relocation block. */
        curr_base_reloc =
            (struct image_base_relocation *)((uintptr_t)curr_base_reloc + curr_base_reloc->size_of_block);
    }

    /* Set the new image base. */
    inh->optional_header.image_base = (uint64_t)new_image;
}

static bool load_image(struct vmm_ctx *vmm,
                      void *guest_raw,
                      struct image_dos_header *orig_idh,
                      struct image_nt_headers64 *orig_inh,
                      plugin_load_t *load_callback)
{
    (void)vmm;
    (void)orig_idh;
    (void)load_callback;

    /* 
     * Allocate enough memory within the host for the whole image.
     * Setting specific RO, WR, RX pages is not too important here
     * as if there's a bug in the plugin you'll crash the hypervisor.
     */
    size_t image_size = orig_inh->optional_header.size_of_image;
    uint8_t *new_image = (uint8_t *)vmem_alloc(image_size, MEM_WRITE | MEM_EXECUTE);
    if (!new_image) {
        DEBUG_PRINT("Unable to allocate memory for plugin image.");
        return false;
    }

    /* Copy over the image from the plugin straight to the newly allocated host memory. */
    cr3 guest_cr3 = { 0 };
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)guest_raw,
                                 new_image, image_size)) {
        DEBUG_PRINT("Unable to copy plugin image to host.");
        return false;
    }

    /* Perform the relocations on the file as image base has changed. */
    relocate_image(new_image);

    /*
     * No need to perform import resolution, as the plugin is a DLL
     * and obviously it CANNOT import anything user or kernel mode
     * into the hypervisor.
     */

    /* TODO: Locate export for the load_callback. */

    return false;
}

int plugin_load(struct vmm_ctx *vmm, void *guest_raw)
{
    /* Check validity of the parameters. */
    if (!guest_raw) {
        DEBUG_PRINT("Invalid plugin parameters.");
        return -1;
    }

    /* Verify plugin integrity. */
    struct image_dos_header idh = { 0 };
    struct image_nt_headers64 inh = { 0 };
    if (!check_image(guest_raw, &idh, &inh)) {
        DEBUG_PRINT("Plugin does not meet integrity.");
        return -1;
    }

    /*
     * As the plugin has been loaded into guest memory and DLL_ATTACH called
     * we now need to load it into the host memory and perform relocations.
     */
    plugin_load_t load_callback;
    if (!load_image(vmm, guest_raw, &idh, &inh, &load_callback)) {
        DEBUG_PRINT("Unable to load plugin image.");
        return -1;
    }

    /* TODO: Register plugin to main VMM plugin list. */

    /* TODO: Call export for plugin host init (call load_callback). */

    return 0;
}