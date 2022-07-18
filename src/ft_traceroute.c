#include "libft.h"
#include "options.h"
#include "ft_traceroute.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

static void	init_env(t_env *env)
{
	ft_bzero(env, sizeof(*env));
	env->start_ttl = 1;
}

static int	init_socket(t_env *env)
{
	int	sckt;

	sckt = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sckt == -1)
	{
		perror("ft_traceroute: socket");
	}
	if (setsockopt(sckt, SOL_IP, IP_TTL,
		&env->start_ttl, sizeof(env->start_ttl)))
	{
		perror("ft_tracerroute");
		close(sckt);
	}
	return sckt;
}

int	ft_traceroute(int ac, char **av)
{
	t_env	env;

	init_env(&env);
	int	ret = parse_traceroute_options(ac, av, &env);
	if (ret != 0)
	{
		//	Valid exiting option (help, version)
		if (ret == 1)
			return 0;
		return ret;
	}
	if (getuid() != 0)
	{
		fprintf(stderr, "Must be root to run the program\n");
		return 2;
	}
	env.socket = init_socket(&env);
	if (env.socket == -1)
		free_and_exit_failure(&env);
	if (send_probes(&env))
		free_and_exit_failure(&env);
	free_and_exit_failure(&env);
	return 0;
}
