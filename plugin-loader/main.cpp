#include <iostream>
#include "hypervisor.hpp"

int main()
{
    hypervisor hv;

    if (hv.check_presence())
        std::cout << "Cascade present!\n";
    else
        std::cout << "Cascade not present!\n";

    system("pause");
    return 0;
}