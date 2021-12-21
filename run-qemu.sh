#!/bin/bash

uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/bin/qemu-system-x86_64 build/hypervisor.efi