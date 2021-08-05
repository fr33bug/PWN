This is seccon ctf 2020 kstack challenge.

A simple stack is implemented in kernel space, user can push/pop elements by ioctl(). There is no lock protection when doing such operations, so we can trigger race conditon issues.

However, the time windows for competition is so short that it is very hard to exploit the vunerability in a triditional way. So we need to use userfaultfd a find a reliable way to race.

Through this challenge, we can practice a universal heap spray techniq called "userfaultfd + setxattr".

As said by many researchers, the following conditions should hold for a universal heap spray:

```
1.Ojbect size is controlled by user. No restrictions even for very small objects.(like 8 byte object)

2.object's content is controlled by user. No unctrolled header at the beginning of the object.

3.The target object should stay in the kernel during the exploitation stage.
```

**Exploitation steps:**

1. Normal userfaultfd operations. We can refer to the manpage to setup userfaultfd. In this challenge, we setup a monitor range of 4 pages. (4*PAGESIZE)

2. the leak the kernel base address

The Element struct in this challenge is 32 bytes, so we can use struct shm_file_data struct for this stage to leak kernel address.

First, we do shmat()/shmdt() so that the kernel allocate and free a shm_file_data struct. So next time when we try to allocate a 32 bytes object from kmalloc-32, the freed shm_file_data will be allocated, containning the `ns` pointer which is a kernel space address. 

By doing this, we can calculate the kernel base address and modprobe_path address.

Second, we push the first 8 bytes of the first page into an element. So the former shm_file_data chunk will be allocaed and when calling `copy_from_user()`, userfault will be triggered and the main thread will be hang up and userfault handler be handled.

In the userfault handler, we do a POP operation, so the newly-allocated Element which contails former shm_file_data's `ns` pointer will be read. Thus we get a kernelspace pointer address.

3. modify modeprobe_path to execute malicious program.

By triggering userfault, we can pop an element twice, so result in a double free. As we know, double free vuln can be exploited to write arbitrary address.
