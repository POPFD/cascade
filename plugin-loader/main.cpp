#include <iostream>
#include "hypervisor.hpp"

int main()
{
    hypervisor hv;

    if (!hv.check_presence()) {
        std::cout << "Cascade not present!\n";
    } else {
        std::cout << "Cascade present!\n";

        if (!hv.load_plugin("plugin-loader.exe")) {
            std::cout << "Unable to load plugin.\n";
        } else {
            std::cout << "Plugin loaded.\n";
        }
    }

    system("pause");
    return 0;
}