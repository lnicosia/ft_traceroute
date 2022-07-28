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

void fill_ip_header(struct iphdr* ip, t_env *env)
{
	ip->version = 4;
	ip->ihl = IP_HEADER_SIZE / 4;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)env->total_packet_size);
	ip->id = htons(0);
	ip->frag_off = htons(0);
	ip->ttl = env->ttl;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->saddr = INADDR_ANY;
	ip->daddr = env->dest_ip.sin_addr.s_addr;
}

uint16_t	udp_checksum(struct ip* ip, struct udphdr *udphdr, int len)
{
	t_pseudo_header	header;

	header.src = ip->ip_src.s_addr;
	header.dst = ip->ip_dst.s_addr;
	header.zeros = 0;
	header.port = ip->ip_p;
	header.len = udphdr->uh_ulen;
	header.udphdr = *udphdr;
	return checksum(&header, len);
}

void fill_udp_header(struct ip* ip, struct udphdr* udphdr, t_env *env)
{
	udphdr->uh_sport = htons(4242);
	udphdr->uh_dport = htons(env->port);
	udphdr->uh_ulen = htons((uint16_t)(env->total_packet_size - IP_HEADER_SIZE));
	ft_strcpy((char*)env->out_buff + IP_HEADER_SIZE + UDP_HEADER_SIZE,
		"Bonjour oui");
	udphdr->uh_sum = udp_checksum(ip, udphdr,
		(int)(env->total_packet_size - IP_HEADER_SIZE));
}

void	fill_icmp_header(struct icmphdr* icmphdr, t_env *env)
{
	icmphdr->type = ICMP_ECHO;
	icmphdr->code = 0;
	icmphdr->un.echo.id = htons((uint16_t)getpid());;
	ft_strcpy(env->out_buff + IP_HEADER_SIZE + sizeof(struct icmphdr),
		"Bonjour oui");
	icmphdr->un.echo.sequence = htons(env->ttl);
	icmphdr->checksum = checksum(icmphdr,
		(int)(env->total_packet_size - IP_HEADER_SIZE));
}

static void	send_current_probes(t_env *env)
{
	size_t	curr_query = first_available_probe(env);
	if (curr_query >= env->squeries * 2)
		return ;
	//printf("Sending on socket %ld\n", curr_query);
	if (env->opt & OPT_VERBOSE)
		printf("Sending ttl=%hhd port=%d\n", env->ttl, env->port);
	ft_bzero(env->out_buff, env->total_packet_size);
	//fill_ip_header((struct iphdr*)env->out_buff, env);
	//fill_udp_header((struct ip*)env->out_buff,
	//	(struct udphdr*)(env->out_buff), env);
	//fill_icmp_header((struct icmphdr*)(env->out_buff + IP_HEADER_SIZE), env);
	if (env->opt & OPT_VERBOSE)
	{
		//print_ip4_header((struct ip*)env->out_buff);
		print_udp_header((struct udphdr*)(env->out_buff));
		//print_icmp_header((struct icmphdr*)(env->out_buff + IP_HEADER_SIZE));
	}
	env->probes[curr_query].ttl = env->ttl;
	env->probes[curr_query].used = 1;
	env->probes[curr_query].probe = env->curr_probe;
	env->probes[curr_query].checksum = ((struct udphdr*)env->out_buff)->uh_sum;
	env->probes[curr_query].port = htons(env->port);
	env->dest_ip.sin_port = htons(env->port++);
	//ft_strcpy(env->out_buff, "Bonjour");
	env->udp_sockets[curr_query] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (setsockopt(env->udp_sockets[curr_query], SOL_IP, IP_TTL,
		&env->ttl, sizeof(env->ttl)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}
	/*char yes = 1;
	if (setsockopt(env->udp_sockets[curr_query], IPPROTO_IP, IP_HDRINCL,
		&yes, sizeof(yes)))
	{
		perror("ft_traceroute: setsockopt");
		free_and_exit_failure(env);
	}*/
	if (sendto(env->udp_sockets[curr_query], env->out_buff, env->total_packet_size,
		0, (struct sockaddr*)&env->dest_ip, sizeof(env->dest_ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	gettimeofday(&env->probes[curr_query].send_time, NULL);
	close(env->udp_sockets[curr_query]);
	env->outgoing_packets++;
	env->curr_probe++;
	if (env->curr_probe >= env->probes_per_hop)
	{
		env->curr_probe = 0;
		env->ttl++;
	}
}

int		are_last_ttl_probes_all_sent(t_env *env)
{
	if (env->last_ttl == 0)
		return 0;
	if (env->all_last_probes_sent)
		return 1;

	uint8_t	nb_last_ttl_probes = 0;

	for (size_t i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].ttl == env->last_ttl)
			nb_last_ttl_probes++;
	}
	//printf("Sent %d probes of ttl %d\n", nb_last_ttl_probes, env->last_ttl);
	if (nb_last_ttl_probes == env->probes_per_hop)
	{
		printf("All last probes sent\n");
		env->all_last_probes_sent = 1;
		for (size_t i = 0; i < env->squeries * 2; i++)
		{
			if (env->probes[i].ttl == env->last_ttl
				&& env->probes[i].received == 1)
			{
				double sec_timeout = 
					env->here * (double)(env->probes[i].recv_time.tv_sec
					- env->probes[i].send_time.tv_sec);
				double usec_timeout = 
					env->here * (double)(env->probes[i].recv_time.tv_usec
					- env->probes[i].send_time.tv_usec);
				struct timeval timeout =
				{
					(time_t)sec_timeout,
					(suseconds_t)usec_timeout
				};
				printf("End timeout = %ld sec %ld usec (%ld ms)\n",
				timeout.tv_sec, timeout.tv_usec, timeout.tv_usec / 1000);
				if (setsockopt(env->icmp_socket, SOL_SOCKET, SO_RCVTIMEO,
					&timeout, sizeof(timeout)))
					perror("ft_traceroute: setsockopt for last probe");
				break;
			}
		}
		return 1;
	}
	return 0;
}

int		send_probes(t_env *env)
{
	env->out_buff = (char*)malloc(env->total_packet_size);
	if (env->out_buff == NULL)
		free_and_exit_failure(env);
	printf("traceroute to %s (%s), %lu hops max, %lu byte packets\n",
		env->host, env->dest_ip_str, env->max_hops, env->total_packet_size);
	while (1)
	{
		if (env->dest_reached == 1)
			break;
		if (env->outgoing_packets < env->squeries
			&& env->total_sent < env->probes_per_hop * env->max_hops
			&& !are_last_ttl_probes_all_sent(env))
		{
			send_current_probes(env);
			env->total_sent++;
		}
		else
		{
			//printf("Receiving (%ld outgoing packets)\n", env->outgoing_packets);
			receive_messages(&env->probes[0], env);
		}
	}
	printf("Dest reached\n");
	flush_received_packets(env->last_ttl, env);
	return 0;
}
