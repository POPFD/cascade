#!/bin/bash

TARGET_UEFI_IMAGE=$1
TARGET_IMG=/vm/hvci-win10-uefi-dev.qcow2
TARGET_IMG_SNAP=$TARGET_IMG.snap

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Create a snapshot of the win10 image we want to use.
rm -f $TARGET_IMG_SNAP
qemu-img create -f qcow2 -F qcow2 -b $TARGET_IMG $TARGET_IMG_SNAP

# To exit do Ctrl-A X
$SCRIPT_DIR/../submodules/uefi-run/target/debug/uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/local/bin/qemu-system-x86_64 $TARGET_UEFI_IMAGE -- \
    -display gtk -enable-kvm -serial stdio -cpu host -smp 1 -m 8G \
    -drive file=$TARGET_IMG_SNAP,media=disk,if=ide,cache=off,index=1 \
    -drive file=fat:rw:./build/