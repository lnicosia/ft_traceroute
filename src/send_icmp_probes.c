#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"
#include <netdb.h>

#define BUFF_SIZE 1024

/** Set out packet data for every probe
*/

void	set_out_packet_data(t_icmp_packet* out_packet, t_env *env)
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
		(int)env->icmp_packet_size);
}

/*
**	Analyze a received packet
*/

void	analyze_packet(char *in_buff, struct sockaddr_in *addr, t_env *env)
{
	struct ip *ip = (struct ip*)in_buff;
	struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);

	if (env->opt & OPT_VERBOSE)
	{
		printf("Received:\n");
		print_ip4_header(ip);
		print_icmp_header(icmphdr);
	}
	else if (icmphdr->type == ICMP_TIME_EXCEEDED
		|| icmphdr->type == ICMP_ECHOREPLY)
	{
		printf("%2ld  ", env->i);
		if (env->opt & OPT_NUMERIC)
			printf("%s", inet_ntoa(ip->ip_src));
		else
		{
			char	host[512];

			ft_bzero(host, sizeof(host));
			if (getnameinfo((struct sockaddr*)addr,
				sizeof(*addr), host, sizeof(host), NULL, 0, 0))
				printf("%s ", inet_ntoa(addr->sin_addr));
			else
				printf("%s ", host);
			printf("(%s)", inet_ntoa(ip->ip_src));
		}
		for (size_t i = 0; i < env->probes_per_hop; i++)
			printf("  %.3f ms", 0.0);
		printf("\n");
		if (icmphdr->type == ICMP_ECHOREPLY)
			env->dest_reached = 1;
	}
}

/*
**	Receive message
*/

void	receive_messages(char *in_buff, t_env *env)
{
	struct sockaddr_in	ret_addr;
	ssize_t				recv_bytes;
	socklen_t			len;

	len = sizeof(ret_addr);
	ft_bzero(in_buff, BUFF_SIZE);
	recv_bytes = recvfrom(env->socket, in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&ret_addr, &len);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
	}
	else
	{
		analyze_packet(in_buff, &ret_addr, env);
	}
}

/*
**	Send probes
*/

void	send_current_probes(t_env *env)
{
	if (setsockopt(env->socket, SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		close(env->socket);
	}
	env->ttl++;
	set_out_packet_data(&env->out_buffer, env);
	if (env->opt & OPT_VERBOSE)
	{
		printf("Sending:\n");
		print_icmp_header(&env->out_buffer.header);
	}
	if (sendto(env->socket, &env->out_buffer, env->icmp_packet_size,
		0, (struct sockaddr*)&env->ip, sizeof(env->ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
}

int		send_icmp_probes(t_env *env)
{
	char			in_buff[BUFF_SIZE];

	env->out_buffer.payload = (char*)malloc(env->payload_size);
	if (env->out_buffer.payload == NULL)
		free_and_exit_failure(env);
	ft_bzero(in_buff, sizeof(in_buff));
	printf("traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->ip_str, env->max_hops, env->icmp_packet_size);
	while (env->i < env->max_hops && env->dest_reached == 0)
	{
		send_current_probes(env);
		receive_messages(in_buff, env);
		env->i++;
	}
	return 0;
}
