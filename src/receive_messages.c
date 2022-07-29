#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

void	print_probes(uint8_t ttl, t_env *env)
{
	size_t				last_printed = 0;
	struct sockaddr_in	gateway_ip;
	t_probe				*probe;
	//	Maximum 10 probes per hop
	t_probe				*probes[10] = { NULL };

	for (size_t i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].ttl == ttl)
			probes[env->probes[i].probe] = &env->probes[i];
	}
	for (size_t i = 0; i < env->probes_per_hop; i++)
	{
		if (probes[i] == NULL)
			continue;
		//dprintf(STDOUT_FILENO, "ttl = %hhu\n", ttl);
		probe = probes[i];
		//dprintf(STDOUT_FILENO, "probe received = %d\n", probe->received);
		if (i == 0)
			dprintf(STDOUT_FILENO, "%2d  ", ttl);
		else
			dprintf(STDOUT_FILENO, " ");
		if (probe->received == 1
			&& probe->recv_time - probe->send_time < timeval_to_usec(env->max))
		{
			if (i == 0)
			{
				gateway_ip = probe->recv_addr;
				print_ip(&probe->recv_addr, env->opt);
			}
			else if (probe->recv_addr.sin_addr.s_addr != gateway_ip.sin_addr.s_addr)
				print_ip(&probe->recv_addr, env->opt);
			dprintf(STDOUT_FILENO, " %.3f ms",
				(double)(probe->recv_time - probe->send_time) / 1000.0);
		}
		else
			dprintf(STDOUT_FILENO, "*");
		ft_bzero(probe, sizeof(*probe));
		env->used_probes--;
		last_printed = i;
	}
	if (last_printed == env->probes_per_hop - 1)
	{
		dprintf(STDOUT_FILENO, "\n");
		if (env->dest_reached == 0)
			env->last_printed_ttl = ttl;
	}
}

void	print_next_received_probes(t_env *env)
{
	uint8_t	end;
	
	if (env->last_ttl == 0)
		end = env->ttl;
	else
		end = env->last_ttl;
	if (env->last_printed_ttl + 1 >= end)
		return ;
	for (uint8_t i = (uint8_t)(env->last_printed_ttl + 1); i < end; i++)
	{
		size_t	received = 0;
		for (size_t j = 0; j < env->squeries * 2; j++)
		{
			if (env->probes[j].ttl == i && env->probes[j].received == 1)
				received++;
		}
		if (received == env->probes_per_hop)
			print_probes(i, env);
		else
			return;
	}
}

void	update_probes(char *in_buff, ssize_t recv_bytes, 
	struct sockaddr_in recv_addr, uint64_t recv_time, t_env *env)
{
	uint8_t	received = 0;
	t_probe			*probe;

	struct ip *ip = (struct ip*)in_buff;
	struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
	struct udphdr *udphdr = (struct udphdr*)(in_buff + IP_HEADER_SIZE + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
	probe = NULL;
	if (env->opt & OPT_VERBOSE)
	{
		dprintf(STDOUT_FILENO, "\e[36mError message:\n");
		print_udp_header(udphdr);
	}
	//	Find the sent probe
	size_t	i;
	for (i = 0; i < env->squeries * 2; i++)
	{
		//if (udphdr->uh_sum == env->probes[i].checksum)
		if (udphdr->uh_dport == env->probes[i].port)
		{
			//dprintf(STDOUT_FILENO,
			//	"Received response from probe %ld of ttl %d and port %d\n",
			//	env->probes[i].probe, env->probes[i].ttl, ntohs(udphdr->uh_dport));
			env->probes[i].received = 1;
			env->probes[i].recv_bytes = recv_bytes;
			env->probes[i].recv_addr = recv_addr;
			env->probes[i].recv_time = recv_time;
			probe = &env->probes[i];
			if (env->last_ttl != 0 && probe->ttl > env->last_ttl)
				return ;
		}
	}
	if (probe == NULL)
		return ;
	env->outgoing_packets--;
	env->total_received++;
	if (env->total_received >= env->max_packets)
	{
		//dprintf(STDOUT_FILENO, "Received enough packets\n");
		env->dest_reached = 1;
	}
	for (i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].ttl == probe->ttl && env->probes[i].received)
			received++;
		//dprintf(STDOUT_FILENO, "probe %ld ttl = %d, received = %d used = %d\n",
		//	i, env->probes[i].ttl - 1, env->probes[i].received, env->probes[i].used);
	}
	//dprintf(STDOUT_FILENO, "received %d probes of hop %d\n", received, probe->hop);
	//	We received all the sent probes for this ttl
	if (received == env->probes_per_hop)
	{
		if (probe->ttl == env->last_ttl)
		{
			//dprintf(STDOUT_FILENO, "\n%ld probes received for dest IP (ttl %hhu), dest reached\n",
			//	env->probes_per_hop, env->last_ttl);
			//env->dest_reached = 1;
		}
		if (probe->ttl == env->last_printed_ttl + 1)
		{
			print_probes(probe->ttl, env);
			//	Print next probes if they are already received
			print_next_received_probes(env);
		}
	}
	if (env->dest_ip.sin_addr.s_addr == ip->ip_src.s_addr
		&& env->last_ttl == 0
		&& ((env->opt & OPT_MODE_ICMP && icmphdr->type == ICMP_ECHOREPLY)
		|| (env->opt & OPT_MODE_UDP && icmphdr->type == ICMP_DEST_UNREACH
			&& icmphdr->code == ICMP_PORT_UNREACH)))
	{
		//dprintf(STDOUT_FILENO, "Reached at ttl = %hhu\n", probe->ttl);
		env->last_ttl = probe->ttl;
		env->max_packets = env->probes_per_hop * env->last_ttl;
		//env->dest_reached = 1;
		//dprintf(STDOUT_FILENO, "Last printed ttl = %hhu\n", env->last_printed_ttl);
	}
}

void	flush_received_packets(uint8_t last_ttl, t_env *env)
{
	//dprintf(STDOUT_FILENO, "last printed ttl = %d\n", env->last_printed_ttl);
	if (env->last_printed_ttl + 1 >= last_ttl)
		return ;
	for (uint8_t i = ++env->last_printed_ttl; i <= last_ttl; i++)
	{
		print_probes(i, env);
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
	uint64_t			recv_time;

	(void)probe;
	ft_bzero(&recv_addr, sizeof(recv_addr));
	len = sizeof(recv_addr);
	ft_bzero(in_buff, BUFF_SIZE);
	recv_bytes = recvfrom(env->icmp_socket, in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&recv_addr, &len);
	recv_time = get_time();
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
		env->total_received += env->outgoing_packets;
		env->outgoing_packets = 0;
		if (env->total_received >= env->max_packets)
		{
			//dprintf(STDOUT_FILENO, "Received or not all packets\n");
			env->dest_reached = 1;
		}
		if (env->last_ttl != 0)
		{
			//dprintf(STDOUT_FILENO, "Dest reached and not received\n");
			env->dest_reached = 1;
		}
		else
			flush_received_packets(env->ttl, env);
	}
	else
	{
		struct ip *ip = (struct ip*)in_buff;
		struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
		//struct udphdr	*udphdr =
		//	(struct udphdr*)((void*)icmphdr + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
		//	Only accept ICMP 
		if (icmphdr->type != ICMP_TIME_EXCEEDED
			&& icmphdr->type != ICMP_ECHOREPLY
			&& icmphdr->type != ICMP_DEST_UNREACH)
			return ;
		//dprintf(STDOUT_FILENO, "ttl = %d\n", ip->ip_ttl);
		update_probes(in_buff, recv_bytes, recv_addr, recv_time, env);
		if (env->opt & OPT_VERBOSE)
		{
			dprintf(STDOUT_FILENO, "Received:\n");
			print_ip4_header(ip);
			print_icmp_header(icmphdr);
		}
	}
}
