## **0x01 About the vulnerability**

This challenge is about kernel UAF vulnerability.

Buffer will be allocated when opening a device, and be released when closing it. Because the buffer is global, if you open the device two times continuously,  and close one fd, you can still visit the global buffer by the other fd, so an UAF vulnerability exists.

Also in the ioctl method, we can change the size of the buffer, and reallocate it. So we can manipulate a specified-size buffer slub allocation.

## **0x02 How to exploit**

To exploit this vulnerability, we set the buffer size to sizeof(struct cred), then close a fd to free it. After that, we fork() a new process, during this process, a struct cred will be allocated. Because of cache, the memory block we just free is used as the cred struct.

Because we can still write the memory block through the other FD, we can change uid, gid in the cred, so we can become root now.

In kernel version 4.4.72, struct cred is as follow:
```
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
};
···

It's size is 0xA8, so we set the buffer size to 0xA8 by ioctl(), and the exploit the UAF vulnerability to get root privilege.
