#include "ft_traceroute.h"
#include "libft.h"
#include <stdlib.h>

void	free_all(t_env *env)
{
	if (env->canonname)
		ft_strdel(&env->canonname);
	if (env->out_ibuffer.payload)
		ft_memdel((void**)&env->out_ibuffer.payload);
	if (env->out_ubuffer.payload)
		ft_memdel((void**)&env->out_ubuffer.payload);
	if (env->icmp_socket)
		close(env->icmp_socket > 0);
	if (env->udp_socket > 0)
		close(env->udp_socket);
	if (env->probes)
		ft_memdel((void**)&env->probes);
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
