#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

static void	send_current_probes(t_env *env)
{
	size_t	curr_query = first_available_probe(env);
	if (curr_query >= env->squeries * 2)
	{
		//printf("max\n");
		return ;
	}
	//dprintf(STDOUT_FILENO, "Sending on socket %ld\n", curr_query);
	if (env->opt & OPT_VERBOSE)
		dprintf(STDOUT_FILENO, "Sending ttl=%hhd port=%d\n", env->ttl, env->port);
	ft_bzero(env->out_buff, env->total_packet_size);
	env->probes[curr_query].ttl = env->ttl;
	env->probes[curr_query].used = 1;
	env->used_probes++;
	env->probes[curr_query].probe = env->curr_probe;
	env->probes[curr_query].checksum = ((struct udphdr*)env->out_buff)->uh_sum;
	env->probes[curr_query].port = htons(env->port);
	env->dest_ip.sin_port = htons(env->port++);
	env->udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setsockopt(env->udp_socket, SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	if (sendto(env->udp_socket, env->out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	env->probes[curr_query].send_time = get_time();
	close(env->udp_socket);
	env->outgoing_packets++;
	env->total_sent++;
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
	dprintf(STDOUT_FILENO, "traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->dest_ip_str, env->max_hops, env->total_packet_size);
	while (1)
	{
		if (env->dest_reached == 1)
			break;
		if (env->outgoing_packets < env->squeries
			&& env->total_sent < env->max_packets
			&& env->used_probes < env->squeries
			&& !are_last_ttl_probes_all_sent(env))
		{
			//dprintf(STDOUT_FILENO, "Sending\n");
			send_current_probes(env);
		}
		else// if (env->total_received < env->max_packets)
		{
			//dprintf(STDOUT_FILENO, "Receiving\n");
			//dprintf(STDOUT_FILENO, "%ld used probes\n", env->used_probes);
			/*dprintf(STDOUT_FILENO, "%ld outgoing packets\n", env->outgoing_packets);
			dprintf(STDOUT_FILENO, "%ld used probes\n", env->used_probes);
			dprintf(STDOUT_FILENO, "%ld/%ld sent\n",
				env->total_sent, env->max_packets);
			dprintf(STDOUT_FILENO, "%d\n", are_last_ttl_probes_all_sent(env));*/
			receive_messages(&env->probes[0], env);
		}
	}
	//dprintf(STDOUT_FILENO, "End of loop\n");
	if (env->last_ttl == 0)
		flush_received_packets(env->ttl, env);
	else
		flush_received_packets(env->last_ttl, env);
	return 0;
}
