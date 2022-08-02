#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

void	print_probes(uint8_t ttl, t_env *env)
{
	size_t				last_printed = 0;
	size_t				printed = 0;
	int					final_print = 0;
	struct sockaddr_in	gateway_ip;
	t_probe				*probe = NULL;
	//	Maximum 10 probes per hop
	t_probe				*probes[10] = { NULL };

	size_t i = env->last_printed_ttl * env->probes_per_hop;
	for ( ; i < env->total_sent; i++)
	{
		if (env->probes[i].ttl == ttl && env->probes[i].printed == 0)
			probes[env->probes[i].probe] = &env->probes[i];
	}
	for (i = 0; i < env->probes_per_hop; i++)
	{
		if (probes[i] == NULL)
			continue;
		probe = probes[i];
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
				if (env->probes_per_hop == 1)
					dprintf(STDOUT_FILENO, " ");
			}
			else if (probe->recv_addr.sin_addr.s_addr != gateway_ip.sin_addr.s_addr)
				print_ip(&probe->recv_addr, env->opt);
			if (probe->recv_addr.sin_addr.s_addr == env->dest_ip.sin_addr.s_addr)
				final_print = 1;
			dprintf(STDOUT_FILENO, " %.3f ms",
				(double)(probe->recv_time - probe->send_time) / 1000.0);
		}
		else
			dprintf(STDOUT_FILENO, "*");
		env->hops_to_print[probe->ttl] = 0;
		last_printed = i;
		printed++;
		probe->printed = 1;
	}
	if (last_printed == env->probes_per_hop - 1 && printed > 0)
	{
		dprintf(STDOUT_FILENO, "\n");
		if (env->dest_reached == 0)
			env->last_printed_ttl = ttl;
		//	With small nqueries values, we may reach the destination multiple
		//	times and receive probes with higher ttl before the minimum one
		if (final_print == 1)
			free_and_exit_success(env);
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
		if (env->hops_to_print[i] == 1)
		{
			print_probes(i, env);
			env->nb_hops_to_print--;
		}
		else
			return ;
	}
}

t_probe	*find_icmp_probe(struct icmphdr* icmphdr, t_env *env)
{
	t_probe	*res = NULL;
	size_t	i = env->last_printed_ttl * env->probes_per_hop;
	for ( ; i < env->total_sent; i++)
	{
			if (icmphdr->un.echo.id == env->id
			&& icmphdr->un.echo.sequence == env->probes[i].sequence)
		{
			res = &env->probes[i];
			if (env->last_ttl != 0 && env->probes[i].ttl > env->last_ttl)
				return NULL;
			return res;
		}
	}
	return res;
}

t_probe	*find_udp_probe(struct udphdr *udphdr, t_env *env)
{
	t_probe	*res = NULL;
	size_t	i = env->last_printed_ttl * env->probes_per_hop;
	for ( ; i < env->total_sent; i++)
	{
		if (udphdr->uh_dport == env->probes[i].port)
		{
			res = &env->probes[i];
			if (env->last_ttl != 0 && env->probes[i].ttl > env->last_ttl)
				return NULL;
		}
	}
	return res;
}

void	update_probes(char *in_buff, ssize_t recv_bytes, 
	struct sockaddr_in recv_addr, uint64_t recv_time, t_env *env)
{
	uint8_t	received = 0;
	t_probe			*probe;

	struct ip *ip = (struct ip*)in_buff;
	struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
	struct udphdr *udphdr = (struct udphdr*)
		(in_buff + IP_HEADER_SIZE + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
	struct icmphdr *error_icmphdr = (struct icmphdr*)
		(in_buff + IP_HEADER_SIZE + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
	probe = NULL;
	if (env->opt & OPT_VERBOSE)
	{
		dprintf(STDOUT_FILENO, "\e[36mError message:\n");
		if (env->opt & OPT_MODE_UDP)
			print_udp_header(udphdr);
		else if (env->opt & OPT_MODE_ICMP)
			print_icmp_header(error_icmphdr);
	}
	//	Find the sent probe
	if (env->opt & OPT_MODE_UDP)
		probe = find_udp_probe(udphdr, env);
	else if (env->opt & OPT_MODE_ICMP)
	{
		if (icmphdr->type == ICMP_ECHOREPLY)
			probe = find_icmp_probe(icmphdr, env);
		else
			probe = find_icmp_probe(error_icmphdr, env);
	}
	if (probe == NULL)
		return ;
	probe->received = 1;
	probe->recv_bytes = recv_bytes;
	probe->recv_addr = recv_addr;
	probe->recv_time = recv_time;
	env->outgoing_packets--;
	env->total_received++;
	if (env->sendwait.tv_sec != 0 || env->sendwait.tv_usec != 0)
		print_probes(probe->ttl, env);
	if (env->total_received >= env->max_packets)
	{
		env->dest_reached = 1;
	}
	for (size_t i = 0; i < env->total_sent; i++)
	{
		if (env->probes[i].ttl == probe->ttl && env->probes[i].received)
			received++;
	}
	//	We received all the sent probes for this ttl
	if (received == env->probes_per_hop)
	{
		if (probe->ttl == env->last_printed_ttl + 1)
		{
			print_probes(probe->ttl, env);
			//	Print next probes if they are already received
			if (env->nb_hops_to_print > 0)
				print_next_received_probes(env);
		}
		else
		{
			env->nb_hops_to_print++;
			env->hops_to_print[probe->ttl] = 1;
		}
	}
	if (env->dest_ip.sin_addr.s_addr == ip->ip_src.s_addr
		&& env->last_ttl == 0
		&& ((env->opt & OPT_MODE_ICMP && icmphdr->type == ICMP_ECHOREPLY)
		|| (env->opt & OPT_MODE_UDP && icmphdr->type == ICMP_DEST_UNREACH
			&& icmphdr->code == ICMP_PORT_UNREACH)))
	{
		env->last_ttl = probe->ttl;
		env->max_packets = env->probes_per_hop * env->last_ttl;
	}
}

void	flush_received_packets(uint8_t last_ttl, t_env *env)
{
	if (env->last_printed_ttl + 1 > last_ttl)
		return ;
	for (uint8_t i = (uint8_t)(env->last_printed_ttl + 1); i <= last_ttl; i++)
	{
		print_probes(i, env);
	}
}

/*
**	Receive message
*/

void	receive_messages(t_env *env)
{
	socklen_t			len;
	ssize_t				recv_bytes;
	char				in_buff[BUFF_SIZE];
	struct sockaddr_in	recv_addr;
	uint64_t			recv_time;

	ft_bzero(&recv_addr, sizeof(recv_addr));
	len = sizeof(recv_addr);
	ft_bzero(in_buff, BUFF_SIZE);
	recv_bytes = recvfrom(env->icmp_socket, in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&recv_addr, &len);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
		env->total_received += env->outgoing_packets;
		env->outgoing_packets = 0;
		if (env->total_received >= env->max_packets)
		{
			env->dest_reached = 1;
		}
		if (env->last_ttl != 0)
		{
			env->dest_reached = 1;
		}
		else
			flush_received_packets(env->ttl, env);
	}
	else
	{
		recv_time = get_time();
		struct ip *ip = (struct ip*)in_buff;
		struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
		//	Only accept ICMP 
		if (icmphdr->type != ICMP_TIME_EXCEEDED
			&& icmphdr->type != ICMP_ECHOREPLY
			&& icmphdr->type != ICMP_DEST_UNREACH)
			return ;
		if (env->opt & OPT_VERBOSE)
		{
			dprintf(STDOUT_FILENO, "Received:\n");
			print_ip4_header(ip);
			print_icmp_header(icmphdr);
		}
		update_probes(in_buff, recv_bytes, recv_addr, recv_time, env);
	}
}
