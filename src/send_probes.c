#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

static void	send_current_probes(char *out_buff, t_env *env)
{
	if (setsockopt(env->udp_socket, SOL_IP, IP_TTL,
			&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	if (env->opt & OPT_VERBOSE)
	{
		printf("Sending ttl=%ld port=%d\n", env->ttl, env->port);
	}
	env->ttl++;
	env->ip.sin_port = htons(env->port++);
	ft_bzero(out_buff, env->total_packet_size);
	if (sendto(env->udp_socket, out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->ip, sizeof(env->ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
}

int		send_probes(t_env *env)
{
	char	*out_buff;
	char	in_buff[BUFF_SIZE];

	out_buff = (char*)malloc(env->total_packet_size);
	if (out_buff == NULL)
		free_and_exit_failure(env);
	ft_bzero(in_buff, BUFF_SIZE);
	printf("traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->ip_str, env->max_hops, env->total_packet_size);
	while (env->i < env->max_hops && env->dest_reached == 0)
	{
		send_current_probes(out_buff, env);
		receive_messages(in_buff, env);
		env->i++;
	}
	/*size_t	total_probes = env->max_hops * env->probes_per_hop;
	while (env->i < total_probes
		&& env->dest_reached == 0)
	{
		size_t query = 0;
		while (query < env->squeries && env->i < total_probes
			&& env->dest_reached == 0)
		{
			size_t probe = 0;
			while (probe < env->probes_per_hop && env->i < total_probes
				&& env->dest_reached == 0)
			{
				send_current_probes(out_buff, env);
				receive_messages(in_buff, env);
				env->i++;
				query++;
				probe++;
				printf("Sent probes = %ld\n", env->i);
			}
		}
	}*/
	return 0;
}
