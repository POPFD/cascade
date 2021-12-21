# cascade
## A thin introspection hypervisor framework that allows for low level resource manipulation.

This framework runs a thin hypervisor in the form of an EFI application on top of the existing hardware. 
This passes through all system resources & devices and acts as if it's not there.
Once loaded, the operating system load can take place as usual.

A VMCALL interface is provided by the hypervisor which allows for introspection related activities.

### Installation, Compilation & Testing (Ubuntu)
1. Ensure the following dependencies are installed on your system

    ```sudo apt-get install qemu qemu-utils ovmf gnu-efi binutils-mingw-w64 gcc-mingw-w64 xorriso mtools cargo```
    ```cargo install uefi-run```

2. To compile run a simple make command
   
   ```make```

3. To run the build quickly in a QEMU instance use the EFI run tool (or use ```./run-qemu.sh```)

   ```uefi-run -b /usr/share/OVMF/OVMF_CODE.fd -q /usr/bin/qemu-system-x86_64 build/hypervisor.efi```
