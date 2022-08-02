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
	icmphdr->un.echo.sequence = htons(env->port);
	icmphdr->checksum = checksum(icmphdr,
		(int)(env->total_packet_size - IP_HEADER_SIZE));
}

static void	send_current_probes(t_env *env)
{
	if (env->opt & OPT_VERBOSE)
		dprintf(STDOUT_FILENO, "Sending ttl=%hhd sequence=%d\n",
			env->ttl, env->port);
	fill_icmp_header((struct icmphdr*)env->out_buff, env);
	if (env->opt & OPT_VERBOSE)
		print_icmp_header((struct icmphdr*)env->out_buff);
	env->probes[env->total_sent].ttl = env->ttl;
	env->probes[env->total_sent].sequence = htons(env->port++);
	env->probes[env->total_sent].probe = env->curr_probe;
	env->probes[env->total_sent].checksum = ((struct udphdr*)env->out_buff)->uh_sum;
	env->probes[env->total_sent].port = htons(env->port);
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
			send_current_probes(env);
		}
		else
			receive_messages(env);
	}
	if (env->last_ttl == 0)
		flush_received_packets(env->ttl, env);
	else
		flush_received_packets(env->last_ttl, env);
	return 0;
}
