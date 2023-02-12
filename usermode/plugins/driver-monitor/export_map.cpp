#include <iostream>
#include <fstream>
#include <regex>
#include <winternl.h>
#include "nt_defs.h"
#include "error.hpp"
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

    user_die_on(!NT_SUCCESS(status),
                "Unable to retrieve system module buffer status 0x%lX\n", status);

    auto proc_mods = reinterpret_cast<rtl_process_modules *>(&mod_buff_raw[0]);
    for (auto i = 0ul; i < proc_mods->number_of_modules; i++) {
        auto mod = &proc_mods->modules[i];

        const auto mod_name = mod->full_path_name;

        std::cout << "Found module: " << std::string(mod_name) <<
            " image_base: 0x" << std::hex << mod->image_base <<
            " image_size: 0x" << std::hex << mod->image_size << "\n";

        modules.push_back(parse_module(mod_name, mod->image_base));
    }

    return modules;
}

export_map::module_record export_map::parse_module(std::string full_path, uintptr_t base)
{
    auto file_name = full_path.substr(full_path.find_last_of("/\\") + 1);
    module_record result(file_name, base);

    /*
     * Get a mapped in local memory equivalent of the raw file
     * in the state it'd look like if loaded in kernel memory.
     * No need to re-verify headers as this is done during image map.
     */
    auto mapped = map_image(full_path);
    if (!mapped.size()) {
        /* If unable to map file just return what we had filled in so far. */
        return result;
    }

    auto idh = reinterpret_cast<PIMAGE_DOS_HEADER>(&mapped[0]);
    auto inh = reinterpret_cast<PIMAGE_NT_HEADERS64>(&mapped[idh->e_lfanew]);

    /* Parse the export data dir if present. */
    auto export_base = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto export_size = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (!export_base || !export_size) {
        std::cout << "No exports\n";
        return result;
    }

    /* If we are here this means it has exports, so lets parse each one. */
    auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(&mapped[export_base]);
    auto name_off_table = reinterpret_cast<uint32_t *>(&mapped[export_dir->AddressOfNames]);
    auto ordinal_table = reinterpret_cast<uint16_t *>(&mapped[export_dir->AddressOfNameOrdinals]);
    auto func_off_table = reinterpret_cast<uint32_t *>(&mapped[export_dir->AddressOfFunctions]);

    for (auto i = 0u; i < export_dir->NumberOfNames; i++) {
        auto func_name = std::string(reinterpret_cast<char *>(&mapped[name_off_table[i]]));

        auto ordinal = ordinal_table[i];
        auto func_rva = func_off_table[ordinal];

        #ifdef PRINT_EXPORTS
            std::cout << "--- " << func_name << " 0x" << std::hex << func_rva << "\n";
        #endif

        result.exports.push_back(export_record(func_name, func_rva));
    }

    return result;
}

std::vector<uint8_t> export_map::map_image(std::string path)
{
    std::vector<uint8_t> mapped;

    /*
     * Attempt to open the file.
     * First convert the path from a NT kernel patch into something
     * valid for standard ifstream in usermode.
     * This is a VERY DIRTY HACK we cannot assume C: is always root volume.
     */
    path = std::regex_replace(path, std::regex("\\\\SystemRoot"), "C:\\Windows");
    std::ifstream stream(path, std::ios::in | std::ios::binary);
    if (!stream.is_open()) {
        std::cout << "Unable to open file " << path << "\n";
        return mapped;
    }

    /* Get the file as raw bytes. */
    std::vector<uint8_t> raw_file((std::istreambuf_iterator<char>(stream)),
                                   std::istreambuf_iterator<char>());

    /* Now validate the headers. */
    auto idh = reinterpret_cast<PIMAGE_DOS_HEADER>(&raw_file[0]);
    user_die_on(idh->e_magic != IMAGE_DOS_SIGNATURE, "Invalid DOS header");

    auto inh = reinterpret_cast<PIMAGE_NT_HEADERS64>(&raw_file[idh->e_lfanew]);
    user_die_on(inh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC,
                "Invalid NT header value 0x%X", inh->OptionalHeader.Magic);

    /* Allocate resultant image. */
    mapped.resize(inh->OptionalHeader.SizeOfImage);

    /* Copy the headers. */
    memcpy(&mapped[0], &raw_file[0], inh->OptionalHeader.SizeOfHeaders);

    /* Now map in the sections. */
    auto section_list = IMAGE_FIRST_SECTION(inh);

    for (auto i = 0; i < inh->FileHeader.NumberOfSections; i++) {
        auto curr_section = &section_list[i];

        /* Skip if section contains no raw data. */
        if (!curr_section->PointerToRawData || !curr_section->SizeOfRawData)
            continue;

        /* Copy from the raw file to mapped memory. */
        memcpy(&mapped[curr_section->VirtualAddress],
               &raw_file[curr_section->PointerToRawData],
               curr_section->SizeOfRawData);
    }

    /*
     * No need to do relocations as we are just doing this
     * so we have something that we can parse.
     */
    return mapped;
}