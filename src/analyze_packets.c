#include "ft_traceroute.h"
#include "options.h"
#include "libft.h"
#include <netdb.h>

/*
**	Print IP
*/

void	print_ip(struct sockaddr_in *addr, unsigned long long opt)
{
	if (opt & OPT_NUMERIC)
		printf("%s", inet_ntoa(addr->sin_addr));
	else
	{
		char	host[512];
			ft_bzero(host, sizeof(host));
		if (getnameinfo((struct sockaddr*)addr,
			sizeof(struct sockaddr), host, sizeof(host), NULL, 0, 0))
			printf("%s ", inet_ntoa(addr->sin_addr));
		else
			printf("%s ", host);
		printf("(%s)", inet_ntoa(addr->sin_addr));
	}
}

/*
**	Analyze a received packet
*/

void	analyze_probe(t_probe *probe, t_env *env)
{
	struct ip *ip = (struct ip*)probe->in_buff;
	struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);

	if (icmphdr->type == ICMP_TIME_EXCEEDED
		|| icmphdr->type == ICMP_ECHOREPLY
		|| icmphdr->type == ICMP_DEST_UNREACH)
	{
		if (ip->ip_src.s_addr != env->current_gateway.sin_addr.s_addr)
		{
			printf(" ");
			print_ip(&probe->recv_addr, env->opt);
		}
		printf("  %.3f ms",
			(double)(probe->recv_time - probe->send_time) / 1000.0);
		//	Destination reached, which means:
		//		- ICMP_ECHOREPLY for ICMP mode
		//		- ICMP_DEST_UNREACH for UDP mode
		if ((env->opt & OPT_MODE_ICMP && icmphdr->type == ICMP_ECHOREPLY)
			|| (env->opt & OPT_MODE_UDP && icmphdr->type == ICMP_DEST_UNREACH
				&& icmphdr->code == ICMP_PORT_UNREACH))
			env->dest_reached = 1;
	}
}

/*
**	Analyze a received packet
*/

void	analyze_packets(t_env *env)
{
	//	Not sure about this
	env->current_gateway = env->probes[0].recv_addr;
	print_ip(&env->probes[0].recv_addr, env->opt);
	for (size_t i = 0; i < env->probes_per_hop; i++)
	{
		if (env->probes[i].recv_bytes == -1)
			printf("* ");
		else
			analyze_probe(&env->probes[i], env);
	}
	printf("\n");
}
