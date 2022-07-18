#include "ft_traceroute.h"
#include "libft.h"
#include <stdlib.h>

void	free_all(t_env *env)
{
	if (env->canonname)
		ft_strdel(&env->canonname);
}

void	free_and_exit_success(t_env *env)
{
	free_all(env);
	exit(EXIT_SUCCESS);
}

void	free_and_exit_failure(t_env *env)
{
	free_all(env);
	exit(EXIT_FAILURE);
}
