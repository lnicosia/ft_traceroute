#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

static void	send_current_probes(char *out_buff, t_env *env)
{
	if (env->opt & OPT_VERBOSE)
	{
		printf("Sending ttl=%ld port=%d\n", env->ttl, env->port);
	}
	env->dest_ip.sin_port = htons(env->port++);
	ft_bzero(out_buff, env->total_packet_size);
	env->probes[env->curr_query].send_time = get_time();
	if (sendto(env->udp_socket, out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
}

int		send_probes(t_env *env)
{
	char	*out_buff;

	out_buff = (char*)malloc(env->total_packet_size);
	if (out_buff == NULL)
		free_and_exit_failure(env);
	printf("traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->dest_ip_str, env->max_hops, env->total_packet_size);
	/*size_t	total_probes = env->max_hops * env->probes_per_hop;
	while (env->i < total_probes
		&& env->dest_reached == 0)
	{
		env->curr_query = 0;
		ft_bzero(env->probes, env->squeries * sizeof(t_probe));
		while (env->curr_query < env->squeries && env->i < total_probes)
		{
			send_current_probes(out_buff, env);
			receive_messages(&env->probes[env->curr_query], env);
			env->i++;
			env->curr_query++;
			env->curr_probe++;
			if (env->curr_probe >= env->probes_per_hop)
			{
				env->curr_probe = 0;
				env->curr_hop++;
				env->ttl++;
				if (setsockopt(env->udp_socket, SOL_IP, IP_TTL,
						&env->ttl, sizeof(env->ttl)))
				{
					perror("ft_traceroute: setsockopt");
					free_and_exit_failure(env);
				}
			}
		}
	}*/
	while (1)
	{
		if (env->dest_reached == 0)
			break;
		if (env->outgoing_packets < env->squeries)
		{
			send_current_probes(out_buff, env);
		}
	}
	return 0;
}
