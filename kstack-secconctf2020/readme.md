This is seccon ctf 2020 kstack challenge.

A simple stack is implemented in kernel space, user can push/pop elements by ioctl(). There is no lock protection when doing such operations, so we can trigger race conditon issues.

However, the time windows for competition is so short that it is very hard to exploit the vunerability in a triditional way. So we need to use userfaultfd a find a reliable way to race.

Through this challenge, we can practice a universal heap spray techniq called "userfaultfd + setxattr".

As said by many researchers, the following conditions should hold for a universal heap spray:

1.Ojbect size is controlled by user. No restrictions even for very small objects.(like 8 byte object)
2.object's content is controlled by user. No unctrolled header at the beginning of the object.
3.The target object should stay in the kernel during the exploitation stage.

Exploitation steps:

1. Normal userfaultfd operations. We can refer to the manpage to setup userfaultfd. In this challenge, we setup a monitor range of 4 pages. (4*PAGESIZE)

2. the leak the kernel base address


