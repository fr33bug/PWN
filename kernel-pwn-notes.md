# Enviroment setup

## 1.build kernel
Normally used comnands:
```
gzq#make mrproper
gzq#make defconfig
edit .config to config items
gzq#make olddefconfig
gzq#time make -j32

```
Then you will get the bzImage in arch/XXX/boot/gzImage

## 2.Install QEMU
Simply run the following command(s):
```
gzq$sudo apt install qemu
```
## 3.Make rootfs image
https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912

## 4.Generate vmlinux
To reverse engineering and debug kernel, we need the ELF file of kernel.We can use the vmlinux-to-elf project.

See: https://github.com/marin-m/vmlinux-to-elf

## 5.Start debugging with QEMU+gdb
Start QEMU VM with a command like this:
```
qemu-system-x86_64 -kernel /usr/src/linux-4.6.2/arch/x86/boot/bzImage -initrd ../initramfs.img -smp 2 -S -s
Parameters:
-S : Hang up gdbserver and let gdb client remote connect it.
-s : Use the default port 1234 for debugging.
```
And in a another terminal, run the following  command(s):
```
gdb /usr/src/linux-4.6.2/vmlinux
target remote:1234
b start_kernel (set breakpoint)
c (continue)
```
Sometimes b command may not work, then use hb command to setup a breakpoint.

# Regions that are not affected by FG_KASL
- The functions from _text base to __x86_retpoline_r15, which is _text+0x400dc6 are unaffected
- KPTI trampoline swapgs_restore_regs_and_return_to_usermode() is unaffected.
- The kernel symbol table ksymtab, starts at _text+0xf85198 is unaffected