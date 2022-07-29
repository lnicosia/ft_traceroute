#include "libft.h"
#include "ft_traceroute.h"
#include <stdio.h>

int	main(int ac, char **av)
{
	if (ac < 2)
	{
		print_usage(STDERR_FILENO);
		return 0;
	}
	return ft_traceroute(ac, av);
}
