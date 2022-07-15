#include "ft_traceroute.h"
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>

suseconds_t		get_time(void)
{
	struct timeval	time;

	if (gettimeofday(&time, NULL) == -1)
	{
		perror("ft_traceroute: gettimeofday");
		free_and_exit_failure();
	}
	return (time.tv_sec * 1000000 + time.tv_usec);
}
