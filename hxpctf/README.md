#### 漏洞
hackme.ko是一个简单的内核驱动，在其read()和write()函数中，针对栈上变量的读/写存在越界。
开启了SMEP, SMAP,FG_KASLR，KPTI等保护。

#### 利用
可通过越界读，leak内核地址信息和栈cookie，并计算其他gadget的地址信息，通过越界写进行ROP.

通过覆写modprobe_path达到代码执行的目的。

绕过KPTI有两种方法，使用第二种：

- 使用信号处理函数，signal(SIGSEGV, foo)
- 使用KPTI Trampoline
从内核态返回用户态时，需要设置CR3寄存器已恢复用户态页表，调用swapgs交换内核和用户态的GS寄存器，然后执行iretq指令将之前压栈的IP/CS/eflags/sp/ss等寄存器弹出，恢复用户态调用时的寄存器上下文。

#### 攻击payload布局
```

  |-------------------|
  |                   |
  | padding(16 uls)   |
  |                   |
  |-------------------|
  |    Canary         |
  |-------------------
  |     \x00          |		rbx
  |-------------------|		
  |     \x00          |		r12
  |-------------------|
  |     \x00          |		rbp
  |-------------------|
  |   ROP Gadget1     |		return address = pop rax;ret
  |-------------------|
  |  0x782f706d742f   | 	/tmp/x to replace modprobe_path
  |-------------------|
  |   ROP Gadget2     |		pop rbx ; pop r12 ; pop rbp ; ret;
  |-------------------|
  |modeprobe_path addr|
  |-------------------|
  |     \x00          |
  |-------------------|
  |     \x00          |
  |-------------------|
  |   ROP Gadget3     |		mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;
  |-------------------|
  |     \x00          |
  |-------------------|
  |     \x00          |
  |-------------------|
  | kpti trampoline   |
  |-------------------|
  |     \x00          |
  |-------------------|
  |     \x00          |
  |-------------------| 
  |      foo          |		iretq stack layout should be:IP|CS|RFLAGS|RSP|SS
  |-------------------|
  |       CS          |
  |-------------------|
  |       RFLAGS      |
  |-------------------|
  |       RSP         |
  |-------------------|
  |       SS          |
  |-------------------|
```
#### use commit_creds(prepare_kernel_cred(0)) to getshell

Hacking points:
1. Leak address information from kernel and calculate address of commit_creds() and prepare_kernel_cred()
Stack canary - payload[16]
Kernel image base - payload[38] & 0xFFFFFFFFFFFF0000 //How to determine kernel image base?
Because FG_KASLR is enabled, we need to get address of commit_creds() and prepare_kernel_cred() from  __ksymtab_commit_creds and __ksymtab_prepare_kernel_cred, so we need a arbitrary address read gadget.

3. 

#### Some writeups of this challenge

https://zhangyidong.top/2021/02/10/kernel_pwn(fg_kaslr)/

https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/
