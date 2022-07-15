#include "libft.h"
#include "ft_traceroute.h"
#include <stdio.h>

int	main(int ac, char **av)
{
	if (ac < 2)
	{
		print_usage_stderr();
		return (2);
	}
	return ft_traceroute(ac, av);
}
