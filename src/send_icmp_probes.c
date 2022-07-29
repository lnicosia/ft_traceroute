#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

/** Set out packet data for every probe
*/

static void	set_out_packet_data(t_icmp_packet* out_packet, t_env *env)
{
	ft_bzero(&out_packet->header, sizeof(struct icmphdr));
	ft_bzero(out_packet->payload, env->payload_size);
	out_packet->header.type = ICMP_ECHO;
	out_packet->header.code = 0;
	out_packet->header.un.echo.id = (uint16_t)get_time();
	if (env->payload_size > 0)
	{
		size_t i;
		for (i = 0; i < env->payload_size - 1; i++)
		{
			out_packet->payload[i] = (char)(i + '0');
		}
		out_packet->payload[i] = '\0';
	}
	//	Update sequence (= received packets count) and checksum
	out_packet->header.un.echo.sequence = ++env->sequence;
	out_packet->header.checksum = checksum(out_packet,
		(int)env->total_packet_size);
}

/*
**	Send probes
*/

static void	send_current_probes(t_env *env)
{
	if (setsockopt(env->icmp_socket, SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	env->ttl++;
	set_out_packet_data(&env->out_ibuffer, env);
	if (env->opt & OPT_VERBOSE)
	{
		dprintf(STDOUT_FILENO, "Sending:\n");
		print_icmp_header(&env->out_ibuffer.header);
	}
	if (sendto(env->icmp_socket, &env->out_ibuffer, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
}

int		send_icmp_probes(t_env *env)
{
	char	in_buff[BUFF_SIZE];

	env->out_ibuffer.payload = (char*)malloc(env->payload_size);
	if (env->out_ibuffer.payload == NULL)
		free_and_exit_failure(env);
	ft_bzero(in_buff, sizeof(in_buff));
	dprintf(STDOUT_FILENO, "traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->dest_ip_str, env->max_hops, env->total_packet_size);
	/*while (env->i < env->max_hops && env->dest_reached == 0)
	{
		send_current_probes(env);
		receive_messages(in_buff, env);
		env->i++;
	}*/
	size_t	curr_hop = 0;
	while (curr_hop < env->max_hops && env->dest_reached == 0)
	{
		dprintf(STDOUT_FILENO, "Hop %ld\n", curr_hop);
		if (setsockopt(env->udp_socket, SOL_IP, IP_TTL,
				&env->ttl, sizeof(env->ttl)))
		{
			perror("ft_traceroute: setsockopt");
			free_and_exit_failure(env);
		}
		ft_bzero(env->probes, sizeof(t_probe) * env->probes_per_hop);
		size_t	curr_probe = 0;
		while (curr_probe < env->probes_per_hop)
		{
			send_current_probes(env);
			receive_messages(&env->probes[curr_probe], env);
			dprintf(STDOUT_FILENO, "Probe %ld/%ld\n", curr_probe, env->probes_per_hop);
			curr_probe++;
		}
		env->ttl++;
		curr_hop++;
	}
	return 0;
}
