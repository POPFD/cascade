#!/bin/bash

TARGET_IMG=/vm/hvci-win10-uefi-dev.qcow2
TARGET_IMG_SNAP=$TARGET_IMG.snap

# Create a snapshot of the win10 image we want to use.
rm -f $TARGET_IMG_SNAP
qemu-img create -f qcow2 -F qcow2 -b $TARGET_IMG $TARGET_IMG_SNAP

# To exit do Ctrl-A X
./submodules/uefi-run/target/debug/uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/local/bin/qemu-system-x86_64 build/hypervisor.efi -- \
    -display gtk -enable-kvm -serial stdio -cpu host -smp 4 -m 8G \
    -drive file=$TARGET_IMG_SNAP,media=disk,if=ide,cache=off,index=1 \
    -drive file=fat:rw:./build/