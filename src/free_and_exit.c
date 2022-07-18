#include "ft_traceroute.h"
#include "libft.h"
#include <stdlib.h>

void	free_all(t_global_data *env)
{
	if (env->canonname)
		ft_strdel(&env->canonname);
}

void	free_and_exit_success(t_global_data *env)
{
	free_all(env);
	exit(EXIT_SUCCESS);
}

void	free_and_exit_failure(t_global_data *env)
{
	free_all(env);
	exit(EXIT_FAILURE);
}
