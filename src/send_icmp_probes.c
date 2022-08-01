#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

void	fill_icmp_header(struct icmphdr* icmphdr, t_env *env)
{
	ft_bzero(env->out_buff, env->total_packet_size);
	icmphdr->type = ICMP_ECHO;
	icmphdr->code = 0;
	icmphdr->un.echo.id = env->id;
	ft_strcpy(env->out_buff + ICMP_HEADER_SIZE, "Bonjour oui");
	icmphdr->un.echo.sequence = htons((uint16_t)env->total_sent);
	icmphdr->checksum = checksum(icmphdr,
		(int)(env->total_packet_size - IP_HEADER_SIZE));
}

static void	send_current_probes(t_env *env)
{
	//dprintf(STDOUT_FILENO, "Sending on socket %ld\n", env->total_sent);
	if (env->opt & OPT_VERBOSE)
		dprintf(STDOUT_FILENO, "Sending ttl=%hhd sequence=%ld\n",
			env->ttl, env->total_sent);
	fill_icmp_header((struct icmphdr*)env->out_buff, env);
	if (env->opt & OPT_VERBOSE)
		print_icmp_header((struct icmphdr*)env->out_buff);
	env->probes[env->total_sent].ttl = env->ttl;
	env->probes[env->total_sent].sequence = htons((uint16_t)env->total_sent);
	env->probes[env->total_sent].probe = env->curr_probe;
	env->probes[env->total_sent].checksum = ((struct udphdr*)env->out_buff)->uh_sum;
	env->probes[env->total_sent].port = htons(env->port);
	//env->dest_ip.sin_port = htons(env->port++);
	//env->icmp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setsockopt(env->icmp_socket, SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	if (sendto(env->icmp_socket, env->out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	env->probes[env->total_sent].send_time = get_time();
	//close(env->udp_socket);
	env->outgoing_packets++;
	env->total_sent++;
	env->curr_probe++;
	if (env->curr_probe >= env->probes_per_hop)
	{
		env->curr_probe = 0;
		env->ttl++;
	}
}

int		send_icmp_probes(t_env *env)
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
			receive_messages(env);
		}
	}
	//dprintf(STDOUT_FILENO, "End of loop\n");
	if (env->last_ttl == 0)
		flush_received_packets(env->ttl, env);
	else
		flush_received_packets(env->last_ttl, env);
	return 0;
}
