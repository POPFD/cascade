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

static bool load_image(struct vmm_ctx *vmm,
                      void *guest_raw,
                      struct image_dos_header *orig_idh,
                      struct image_nt_headers64 *orig_inh,
                      plugin_load_t *load_callback)
{
    (void)vmm;
    (void)guest_raw;
    (void)orig_idh;
    (void)orig_inh;
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