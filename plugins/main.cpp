#include <iostream>
#include "hypervisor.hpp"

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cout << "Invalid number of arguments, please plugin path.\n";
        return -EINVAL;
    }

    hypervisor hv;
    if (!hv.check_presence()) {
        std::cout << "Cascade not present!\n";
    } else {
        std::cout << "Cascade present!\n";

        if (!hv.load_plugin(argv[1])) {
            std::cout << "Unable to load plugin.\n";
        } else {
            std::cout << "Plugin loaded.\n";
        }
    }

    system("pause");
    return 0;
}