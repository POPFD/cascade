#!/bin/bash

# To exit do Ctrl-A X
./uefi-run/target/debug/uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/bin/qemu-system-x86_64 build/hypervisor.efi -- \
    -display gtk -enable-kvm -serial stdio -cpu host -smp 1 -drive file=/vm/win10-uefi-dev.qcow2,media=disk,if=ide,cache=off,index=1 -m 4G