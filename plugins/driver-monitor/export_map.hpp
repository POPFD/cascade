/*
 * Module that parses all kernel modules and stores their exports.
 */
#pragma once
#include <string>
#include <vector>
#include <stdint.h>

class export_map {

    struct export_record {
        std::string name;
        uintptr_t relative_address;

        export_record(std::string nm, uintptr_t rva)
        {
            name = nm;
            relative_address = rva;
        }
    };

    struct module_record {
        std::string name;
        uintptr_t base_addr;
        std::vector<export_record> exports;

        module_record(std::string nm, uintptr_t base)
        {
            name = nm;
            base_addr = base;
        }
    };

    const std::vector<module_record> m_modules;

    /* Enumerates all kernel modules querying their
     * base addresses and stores each within a list. */
    std::vector<module_record> get_modules();

    /* Enumerates all the exports of a single module. */
    module_record parse_module(std::string path, uintptr_t base);

    /* Map an PE/SYS file into memory as if it would look if in kernel. */
    std::vector<uint8_t> map_image(std::string path);

public:
    export_map();
};
