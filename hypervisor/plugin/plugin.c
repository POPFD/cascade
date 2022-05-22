#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/nt.h"
#include "memory/mem.h"
#include "plugin.h"

static bool check_image(uint8_t *guest_raw, size_t plugin_size)
{
    /* Verify that the image is larger than DOS headers. */
    if (plugin_size <= sizeof(struct image_dos_header)) {
        DEBUG_PRINT("Plugin size smaller than dos headers.\n");
        return false;
    }

    /* Read the DOS header and check validity. */
    cr3 guest_cr3;
    guest_cr3.flags = __vmread(VMCS_GUEST_CR3);
    struct image_dos_header idh = { 0 };
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)guest_raw,
                                 &idh, sizeof(idh))) {
        DEBUG_PRINT("Unable to read IDH\n.");
        return false;
    }

    if (idh.e_magic != IMAGE_DOS_SIGNATURE) {
        DEBUG_PRINT("Invalid IDH signature.\n");
        return false;
    }

    /* Read the INH and check validity. */
    struct image_nt_headers64 inh = { 0 };
    if (!mem_copy_virtual_memory(COPY_READ, guest_cr3, (uintptr_t)&guest_raw[idh.e_lfanew],
                                 &inh, sizeof(inh))) {
        DEBUG_PRINT("Unable to read INH\n.");
        return false;
    }

    if (inh.optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        DEBUG_PRINT("Image does not seem to be X64\n.");
        return false;
    }

    /* Verify that the plugin isn't just headers. */
    if (plugin_size <= inh.optional_header.size_of_headers) {
        DEBUG_PRINT("Image just seems to be headers.\n");
        return false;
    }

    DEBUG_PRINT("Image headers validated\n" \
                "--- plugin size: 0x%lX\n" \
                "--- idh.e_magic: 0x%lX\n" \
                "--- idh.e_lfanew: 0x%lX\n" \
                "--- inh.opt.magic: 0x%lX\n" \
                "--- inh.opt.size_of_hdrs: 0x%lX\n\n",
                plugin_size,
                idh.e_magic,
                idh.e_lfanew,
                inh.optional_header.magic,
                inh.optional_header.size_of_headers);

    return true;
}

int plugin_load(struct vmm_ctx *vmm, void *guest_raw, size_t plugin_size)
{
    /* Check validity of the parameters. */
    if (!guest_raw || !plugin_size) {
        DEBUG_PRINT("Invalid plugin parameters, raw 0x%lX size 0x%lX\n");
        return -1;
    }

    (void)vmm;

    /* Verify plugin integrity. */
    if (!check_image(guest_raw, plugin_size)) {
        DEBUG_PRINT("Plugin does not meet integrity.\n");
    }

    return 0;
}