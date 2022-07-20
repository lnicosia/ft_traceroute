#include "libft.h"
#include "options.h"
#include "ft_traceroute.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

static void	init_env(t_env *env)
{
	ft_bzero(env, sizeof(*env));
	env->total_packet_size = 60;
	env->payload_size = env->total_packet_size - sizeof(struct icmphdr);
	env->sequence = 0;
	env->ttl = 1;
	env->port = 33434;
	env->max_hops = 30;
	env->probes_per_hop = 3;
	//	Max timeout
	env->max.tv_sec = 1;
	env->max.tv_usec = 0;
	//	Here timeout
	env->here.tv_sec = 3;
	env->here.tv_usec = 0;
	//	Near timeout
	env->near.tv_sec = 10;
	env->near.tv_usec = 0;
	env->opt |= OPT_MODE_UDP;
}

static void	init_sockets(t_env *env)
{

	env->icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	env->udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (env->icmp_socket == -1 || env->udp_socket == -1)
	{
		perror("ft_traceroute: socket");
		free_and_exit_failure(env);
	}
	if (setsockopt(env->icmp_socket, SOL_SOCKET, SO_RCVTIMEO,
		&env->max, sizeof(env->max)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
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
	init_sockets(&env);
	if (env.opt & OPT_MODE_ICMP)
		send_icmp_probes(&env);
	else if (env.opt & OPT_MODE_UDP)
		send_probes(&env);
	free_and_exit_failure(&env);
	return 0;
}
