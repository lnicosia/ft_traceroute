#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

void	print_probes(uint8_t ttl, t_env *env)
{
	struct sockaddr_in	first_ip;
	int					first = 0;
	t_probe				*probe;

	for (size_t i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].ttl == ttl)
		{
			//printf("ttl = %hhu\n", ttl);
			probe = &env->probes[i];
			//printf("probe received = %d\n", probe->received);
			if (probe->received == 1)
			{
				if (first == 0)
				{
					first_ip = probe->recv_addr;
					first = 1;
					print_ip(&probe->recv_addr, env->opt);
				}
				else if (probe->recv_addr.sin_addr.s_addr != first_ip.sin_addr.s_addr)
				{
					printf(" ");
					print_ip(&probe->recv_addr, env->opt);
				}
				printf("  %.3f ms",
					(double)(probe->recv_time - probe->send_time) / 1000.0);
			}
			else
				printf(" *");
			ft_bzero(probe, sizeof(*probe));
		}
	}
	if (env->dest_reached == 0)
	{
		env->last_printed_ttl = (uint8_t)(ttl - 1);
		//printf("\nlast printed updated to %hhu\n", ttl - 1);
	}
}

void	update_probes(ssize_t recv_bytes, struct sockaddr_in recv_addr,
	uint8_t ttl, t_env *env)
{
	uint8_t	received = 0;
	uint8_t	found = 0;

	//	Find the sent probe
	size_t	i;
	for (i = 0; i < env->squeries * 2; i++)
	{
		if ((ttl == 255 && env->probes[i].ttl == 1)
			|| ttl == env->probes[i].ttl - 1)
		{
			if (found == 0 && env->probes[i].received == 0)
			{
				env->probes[i].received = 1;
				env->probes[i].recv_bytes = recv_bytes;
				env->probes[i].recv_addr = recv_addr;
				env->probes[i].recv_time = get_time();
				received++;
				found = 1;
			}
			else if (env->probes[i].received == 1)
				received++;
		}
	}
	for (i = 0; i < env->squeries * 2; i++)
	{
		//printf("probe %ld ttl = %d, received = %d used = %d\n",
		//	i, env->probes[i].ttl - 1, env->probes[i].received, env->probes[i].used);
	}
	//printf("received %d ttl %d\n", received, ttl);
	//	We received all the sent probes for this ttl
	if (received == env->probes_per_hop)
	{
		if (ttl == env->last_ttl)
		{
			printf("\n%ld probes received for dest IP (ttl %hhu), dest reached\n",
				env->probes_per_hop, env->last_ttl);
			env->dest_reached = 1;
		}
		printf("%2ld  ", env->curr_hop++ + 1);
		printf("(%hhu) ", ttl);
		if (ttl == 255)
			print_probes(1, env);
		else
			print_probes((uint8_t)(ttl + 1), env);
		printf("\n");
	}
}

void	flush_received_packets(t_env *env)
{
	//printf("last printed ttl = %d\n", env->last_printed_ttl);
	for (uint8_t i = ++env->last_printed_ttl; i <= env->last_ttl; i++)
	{
		printf("%2ld  ", env->curr_hop++ + 1);
		printf("(%hhu) ", i);
		print_probes((uint8_t)(i + 1), env);
		printf("\n");
	}
}

/*
**	Receive message
*/

void	receive_messages(t_probe *probe, t_env *env)
{
	socklen_t			len;
	ssize_t				recv_bytes;
	char				in_buff[BUFF_SIZE];
	struct sockaddr_in	recv_addr;

	(void)probe;
	ft_bzero(&recv_addr, sizeof(recv_addr));
	len = sizeof(recv_addr);
	ft_bzero(in_buff, BUFF_SIZE);
	recv_bytes = recvfrom(env->icmp_socket, in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&recv_addr, &len);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
		else
		{
			//if (env->curr_probe > 0)
			//	printf(" ");
			//printf("*");
		}
		env->outgoing_packets--;
		//if (env->last_ttl != 0)

	}
	else
	{
		struct ip *ip = (struct ip*)in_buff;
		struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
		if (icmphdr->type != ICMP_TIME_EXCEEDED
			&& icmphdr->type != ICMP_ECHOREPLY
			&& icmphdr->type != ICMP_DEST_UNREACH)
			return ;
		env->outgoing_packets--;
		if (env->last_ttl > 0 && ip->ip_ttl > env->last_ttl)
			return ;
		if (env->opt & OPT_VERBOSE)
		{
			printf("Received:\n");
			print_ip4_header(ip);
			print_icmp_header(icmphdr);
		}
		printf("port = %d\n", ntohs(recv_addr.sin_port));
		//printf("ttl = %d\n", ip->ip_ttl);
		update_probes(recv_bytes, recv_addr, ip->ip_ttl, env);
		if (env->dest_ip.sin_addr.s_addr == ip->ip_src.s_addr
			&& env->last_ttl == 0
			&& ((env->opt & OPT_MODE_ICMP && icmphdr->type == ICMP_ECHOREPLY)
			|| (env->opt & OPT_MODE_UDP && icmphdr->type == ICMP_DEST_UNREACH
				&& icmphdr->code == ICMP_PORT_UNREACH)))
		{
			//printf("Reached at ttl = %hhu\n", ip->ip_ttl);
			env->last_ttl = ip->ip_ttl;
			env->dest_reached = 1;
			//printf("Last printed ttl = %hhu\n", env->last_printed_ttl);
		}
	}
}
