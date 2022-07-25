#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

size_t	first_available_probe(t_env *env)
{
	size_t	i;
	for (i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].used == 0)
			return i;
	}
	return i;
}

static void	send_current_probes(t_env *env)
{
	size_t	curr_query = first_available_probe(env);
	if (curr_query >= env->squeries * 2)
		return ;
	if (env->opt & OPT_VERBOSE)
	{
		printf("Sending ttl=%hhd port=%d\n", env->ttl, env->port);
	}
	env->dest_ip.sin_port = htons(env->port++);
	ft_bzero(env->out_buff, env->total_packet_size);
	env->probes[curr_query].send_time = get_time();
	env->probes[curr_query].ttl = env->ttl;
	env->probes[curr_query].used = 1;
	ft_strcpy(env->out_buff, "Bonjour");
	env->udp_sockets[curr_query] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setsockopt(env->udp_sockets[curr_query], SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	if (sendto(env->udp_sockets[curr_query], env->out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	env->outgoing_packets++;
	env->curr_probe++;
	if (env->curr_probe >= env->probes_per_hop)
	{
		env->curr_probe = 0;
		env->ttl++;
	}
}

int		send_probes(t_env *env)
{
	env->out_buff = (char*)malloc(env->total_packet_size);
	if (env->out_buff == NULL)
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
		if (env->dest_reached == 1)
			break;
		if (env->last_ttl == 0 && env->outgoing_packets < env->squeries)
		{
			send_current_probes(env);
		}
		else
		{
			receive_messages(&env->probes[0], env);
		}
	}
	flush_received_packets(env);
	return 0;
}
