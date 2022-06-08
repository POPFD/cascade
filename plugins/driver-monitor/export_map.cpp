#include <iostream>
#include <winternl.h>
#include "nt_defs.h"
#include "export_map.hpp"

export_map::export_map()
    : m_modules(get_modules())
{
}

std::vector<export_map::module_record> export_map::get_modules()
{
    /* This is an undocumented function and as such could change in future. */
    static constexpr auto SYSTEM_MODULE_INFORMATION = 11;

    std::vector<export_map::module_record> modules;

    /*
     * Keep calling NtQuerySystemInformation untill we've got a list of modules.
     * The first time, deliberately call with no buffer and invalid size, so
     * that the second call we will know how much to allocate for.
     */
    ULONG info_length = 0;
    NTSTATUS status = NtQuerySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>(SYSTEM_MODULE_INFORMATION), nullptr, 0, &info_length);

    std::vector<uint8_t> mod_buff_raw;
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        mod_buff_raw.resize(info_length);
        status = NtQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS>(SYSTEM_MODULE_INFORMATION),
            &mod_buff_raw[0], info_length, &info_length);
    }

    if (!NT_SUCCESS(status)) {
        std::cout << "Unable to retrieve system module buffer status = 0x" <<
            std::hex << status << "\n";
        return modules;
    }

    auto proc_mods = reinterpret_cast<rtl_process_modules *>(&mod_buff_raw[0]);
    for (auto i = 0ul; i < proc_mods->number_of_modules; i++) {
        auto mod = &proc_mods->modules[i];

        const auto mod_name = &mod->full_path_name[mod->offset_to_file_name];

        std::cout << "Found module: " << std::string(mod_name) <<
            " image_base: 0x" << std::hex << mod->image_base <<
            " image_size: 0x" << std::hex << mod->image_size << "\n";

        module_record new_rec(std::string(mod_name), mod->image_base);
        new_rec.exports = get_exports(mod->image_base);

        modules.push_back(new_rec);
    }

    return modules;
}

std::vector<export_map::export_record> export_map::get_exports(uintptr_t base)
{
    std::vector<export_map::export_record> exports;

    (void)base;
    return exports;
}