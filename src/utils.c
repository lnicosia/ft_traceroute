#include "ft_traceroute.h"
#include "libft.h"

size_t	first_available_probe(t_env *env)
{
	size_t	i;
	for (i = 0; i < env->max_packets; i++)
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

/*
**	No need to keep sending probes if we reached the dest
**	and that all probes were sent for it
*/

int		are_last_ttl_probes_all_sent(t_env *env)
{
	if (env->last_ttl == 0)
		return 0;
	if (env->ttl > env->last_ttl)
	{
		//dprintf(STDOUT_FILENO, "Dest reached and ttl > env->last_ttl\n");
		return 1;
	}
	if (env->all_last_probes_sent)
		return 1;

	uint8_t	nb_last_ttl_probes = 0;

	for (size_t i = 0; i < env->squeries * 2; i++)
	{
		if (env->probes[i].ttl == env->last_ttl)
			nb_last_ttl_probes++;
	}
	//dprintf(STDOUT_FILENO, "Sent %d probes of ttl %d\n", nb_last_ttl_probes, env->last_ttl);
	if (nb_last_ttl_probes == env->probes_per_hop)
	{
		//dprintf(STDOUT_FILENO, "All last probes sent\n");
		env->all_last_probes_sent = 1;
		for (size_t i = 0; i < env->squeries * 2; i++)
		{
			if (env->probes[i].ttl == env->last_ttl
				&& env->probes[i].received == 1)
			{
				///dprintf(STDOUT_FILENO, "Send time is %ld seconds\n", env->probes[i].send_time);
				//dprintf(STDOUT_FILENO, "Recv time is %ld seconds\n", env->probes[i].recv_time);
				uint64_t diff = env->probes[i].recv_time - env->probes[i].send_time;
				double sec_timeout = 
					env->here * ((double)diff / 1000000);
				//dprintf(STDOUT_FILENO, "Time is %lf seconds\n", sec_timeout);
				double fraction = sec_timeout - (double)((uint64_t)sec_timeout);
				//dprintf(STDOUT_FILENO, "Fractionnal is %lf seconds\n", fraction);
				//dprintf(STDOUT_FILENO, "usec is %lf seconds\n", fraction * 1000000);
				struct timeval timeout =
				{
					(time_t)(sec_timeout),
					(suseconds_t)(fraction * 1000000)
				};
				dprintf(STDOUT_FILENO, "End timeout = %ld sec %ld usec (%ld ms)\n",
				timeout.tv_sec, timeout.tv_usec, timeout.tv_usec / 1000);
				//	If setsockopt fails we don't care
				//setsockopt(env->icmp_socket, SOL_SOCKET, SO_RCVTIMEO,
				//	&timeout, sizeof(timeout));
				break;
			}
		}
		return 1;
	}
	return 0;
}
