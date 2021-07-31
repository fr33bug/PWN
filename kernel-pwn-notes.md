# 0x01 Enviroment setup & Tools

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

Usage: vmlinux-to-elf path-to-vmlinuz path-to-output

Note that it will take very long time to finish this process.

Aslo we can use extract-image.sh to extract vmlinux directly from vmlinuz. It is much faster than vmlinux-to-elf.

See: https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/extract-image.sh

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
Sometimes the **b** command may not work, then please use **hb** command to setup a breakpoint.

## 6.CPIO related
To compress a file
```
find . | cpio -o --format=newc | gzip -9 > ../initramfs.cpio.gz
```
TO decompress a file
```
gunzip initramfs.cpio.gz  #we get initramfs.cpio
cpio -idmv < initramfs.cpio
```

## 7.ropper
ropper is faster than ROPgadget, we can use ropper go get gadgets to build rop chain.

## 8. Get root privilege
When debugging, we need root priviledge. Please modify rcS or other script files that call setxxid, change id to 0000 to get root priviledge.

## 9. Add symbols of LKM
When debugging with GDB, we can load symbols of a LKM by running:
```
add-symbol-file xx.ko text-addr
```
And the text-addr can be obtained by reading /sys/modules/xxx/section/.text. Remember this operation needs root privilege.

# Registers
CR3 - Control page tables

CR4 - 20th bit/SMEP, 21st bit/SMAP
## Other tips
### Regions that are not affected by FG_KASL
- The functions from _text base to __x86_retpoline_r15, which is _text+0x400dc6 are unaffected
- KPTI trampoline swapgs_restore_regs_and_return_to_usermode() is unaffected.
- The kernel symbol table ksymtab, starts at _text+0xf85198 is unaffected

### Use objdump to find specific instruction
objdump -j .text -d vmlinux | grep iretq | head -1

# 0x02 Exploitation tricks
- **ret2usr**

If SMEP is not enabled, we can hijack the return address to userspace shellcode.  

Should call **swapgs**  and restore userspace registers, including IP,CS,RFLAGS,RSP,SS, and then call **iretq**

- **by pass SMEP**

In kernel mode, we can overwrite the 20th bit of CR4 register to bypass SMEP. We can rop to native_write_cr4(value) to achieve this goal.

**Caution!!!**: This method is no longer available, because CR4 is pinned so we can't modify it any more. We can use kernel rop to avoid executing code in userspace.

- **Parameters**

on X86_64 platform, first six parameters are passed by registers, others are fetched from the stack. 

for f(a, b, c, d, e, f, g, h):
a->rdi, b->rsi, c->rdx, d->rcx, e->r8, f->r9, h->8(%rsp), g->(%rsp)

- **Stack pivot**

Stack pivot involves hijacking the return address to some gadgets that modify the RSP to pointer to an area that is controlled by us so that we can deploy ROP chains there.

- **Kernel image base address**

Is the "_text" symbol in /proc/kallsyms presents the kernel image base address?

```
/sbin # cat /proc/kallsyms | grep "_text" | head -n 10
ffffffffb3800000 T _text
ffffffffb380a080 T __noinstr_text_start
ffffffffb380de9f T __noinstr_text_end
ffffffffb3816ab8 T __sched_text_start
ffffffffb381b4c0 T __cpuidle_text_start
ffffffffb381b4c0 T __sched_text_end
ffffffffb381bb2d T __cpuidle_text_end
ffffffffb381bb30 T __lock_text_start
ffffffffb381bf3a T __lock_text_end
ffffffffb381bf40 T __kprobes_text_end
```
- Gadgets that can be used

**Arbitrary Address Read**

imagebase + 0x4d11 : pop rax; ret

imagebase + 0x4aae : mov eax, dword ptr[rax + 0x10]; pop rbp; ret

**Arbitrary Address Write**

imagebase + 0x4d11 : pop rax; ret;
imagebase + 0x3190 : pop rbx ; pop r12 ; pop rbp ; ret;
imagebase + 0x306d : mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;

**Pass Parameter**

imagebase + 0x38a0 : pop rdi; pop rbp; ret
