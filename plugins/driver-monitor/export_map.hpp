/*
 * Module that parses all kernel modules and stores their exports.
 */
#pragma once
#include <string>
#include <vector>

class export_map {

    struct export_record {
        std::string name;
        uintptr_t address;
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
    std::vector<export_record> get_exports(uintptr_t base);

public:
    export_map();
};
