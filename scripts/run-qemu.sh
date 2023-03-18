#!/bin/bash

# To exit do Ctrl-A X
./submodules/uefi-run/target/debug/uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/bin/qemu-system-x86_64 build/uefi.efi -- -nographic -enable-kvm -cpu host -smp 1