#include "libft.h"
#include "options.h"
#include "ft_traceroute.h"

int	ft_traceroute(int ac, char **av)
{
	t_global_data	env;

	ft_bzero(&env, sizeof(env));
	int	ret = parse_traceroute_options(ac, av, &env);
	if (ret != 0)
	{
		//	Valid exiting option (help, version)
		if (ret == 1)
			return 0;
		return ret;
	}
	return 0;
}
