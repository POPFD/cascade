#!/bin/bash

# To exit do Ctrl-A X
./uefi-run/target/debug/uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/bin/qemu-system-x86_64 build/hypervisor.efi -- -nographic -enable-kvm -cpu host -smp 2