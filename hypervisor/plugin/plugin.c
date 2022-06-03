#define DEBUG_MODULE
#include "platform/standard.h"
#include "platform/nt.h"
#include "memory/mem.h"
#include "memory/vmem.h"
#include "plugin.h"
#include "plugin-shim.h"

struct plugin_info {
    struct plugin_info *next, *prev;
    uintptr_t base_address;
    plugin_load_t load_callback;
};

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
            (curr_base_reloc->size_of_block - sizeof(struct image_base_relocation)) / sizeof(uint16_t);

        for (size_t i = 0; i < item_count; i++) {
            const uint16_t type = item_start[i] >> 12;
            const uint16_t offset = item_start[i] & 0xFFF;

            /* Only able to relocate DIR64 type. */
            if (type != IMAGE_REL_BASED_DIR64) {
                /* We can skip absolutes no matter what, no point logging. */
                if (type != IMAGE_REL_BASED_ABSOLUTE)
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

static bool is_str_same(const char *name1, const char *name2)
{
    /*
     * We could simply use memcmp with strlen, however
     * we do not have these linked so I just reinvent the
     * wheel.
     */
	bool result = true;
	size_t count = 0;

	while ((name1[count] != '\0') && (name2[count] != '\0'))
	{
		if (name1[count] != name2[count])
		{
			result = false;
			break;
		}

		count++;
	}

	return result;
}

static void *get_export_by_name(uint8_t *image, const char *export_name)
{
    /* We assume IDH and INH are valid already by this point. */
    struct image_dos_header *idh = (struct image_dos_header *)image;
    struct image_nt_headers64 *inh = (struct image_nt_headers64 *)&image[idh->e_lfanew];

    /* Get the virtual address of the image export directory. */
    uintptr_t ied_va = inh->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    if (!ied_va) {
        DEBUG_PRINT("Image 0x%lX has no export directory.", image);
        return NULL;
    }

    struct image_export_directory *ied = (struct image_export_directory *)&image[ied_va];
    uint32_t *address_ptr = (uint32_t *)&image[ied->address_of_functions];
    uint32_t *name_ptr = (uint32_t *)&image[ied->address_of_names];
    uint16_t *ordinal_ptr = (uint16_t *)&image[ied->address_of_name_ordinals];

    /* Iterate through all of the named exports and check to see if any match. */
    for (uint32_t i = 0; i < ied->number_of_names; i++) {
        const char *name = (const char *)&image[name_ptr[i]];

        if (is_str_same(export_name, name))
            return (void *)&image[address_ptr[ordinal_ptr[i]]];
    }

    DEBUG_PRINT("Image 0x%lX does not contain export %s", image, export_name);
    return NULL;
}

static bool load_image(void *guest_raw,
                       struct image_nt_headers64 *orig_inh,
                       uintptr_t *image_base,
                       plugin_load_t *load_callback)
{
    /* 
     * Allocate enough memory within the host for the whole image.
     * Setting specific RO, WR, RX pages is not too important here
     * as if there's a bug in the plugin you'll crash the hypervisor.
     */
    size_t image_size = orig_inh->optional_header.size_of_image;
    uint8_t *new_image = (uint8_t *)vmem_alloc(image_size, MEM_WRITE | MEM_EXECUTE);
    DEBUG_PRINT("Allocated memory at address 0x%lX for plugin.", new_image);
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

    /* Locate the export from the image which we call once plugin is loaded into HV. */
    plugin_load_t cbk = (plugin_load_t)get_export_by_name(new_image, PLUGIN_LOAD_EXPORT_NAME);
    if (cbk) {
        DEBUG_PRINT("Found load callback at 0x%lX", cbk);
        *image_base = (uintptr_t)new_image;
        *load_callback = cbk;
        return true;
    }

    return false;
}

static void register_plugin(struct vmm_ctx *vmm, uintptr_t base, plugin_load_t load)
{
    /* Ensure only the current vCPU is manipulating the plugin list. */
    spin_lock(&vmm->lock);

    /* Allocate a new plugin information structure. */
    struct plugin_info *new_info = vmem_alloc(sizeof(struct plugin_info), MEM_WRITE);
    die_on(!new_info, "Unable to allocate memory for new plugin info structure.");

    /* Fill out the structure. */
    new_info->base_address = base;
    new_info->load_callback = load;

    /* Now manipulated the doubly linked list. */
    if (vmm->plugin_list) {
        /* First one to be added so we just set the VMM struct and also
         * set prev/next accordingly. */
        vmm->plugin_list = new_info;
        vmm->plugin_list->prev = new_info;
        vmm->plugin_list->next = NULL;
    } else {
        /* Get the most recent plugin by utilising back pointer from first item. */
        struct plugin_info *last_info = vmm->plugin_list->prev;

        vmm->plugin_list->prev = new_info;
        last_info->next = new_info;
    }

    DEBUG_PRINT("Registered: base 0x%lX load 0x%lX.", base, load);
    spin_unlock(&vmm->lock);
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
    uintptr_t image_base;
    plugin_load_t load_callback;
    if (!load_image(guest_raw, &inh, &image_base, &load_callback)) {
        DEBUG_PRINT("Unable to load plugin image.");
        return -1;
    }

    /* Register the plugin with the VMM. */
    register_plugin(vmm, image_base, load_callback);

    /* Call export for plugin host init. */
    load_callback(vmm, &PLUGIN_INTERFACE);

    return 0;
}