#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"
#include <netdb.h>

/*
**	Analyze a received packet
*/

static void	analyze_packet(char *in_buff, struct sockaddr_in *addr, t_env *env)
{
	struct ip *ip = (struct ip*)in_buff;
	struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);

	if (env->opt & OPT_VERBOSE)
	{
		printf("Received:\n");
		print_ip4_header(ip);
		print_icmp_header(icmphdr);
	}
	if (icmphdr->type == ICMP_TIME_EXCEEDED
		|| icmphdr->type == ICMP_ECHOREPLY
		|| icmphdr->type == ICMP_DEST_UNREACH)
	{
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
		//	Destination reached:	*ICMP_ECHOREPLY for ICMP mode
		//							*ICMP_DEST_UNREACH for UDP mode
		if ((env->opt & OPT_MODE_ICMP && icmphdr->type == ICMP_ECHOREPLY)
			|| (env->opt & OPT_MODE_UDP && icmphdr->type == ICMP_DEST_UNREACH
				&& icmphdr->code == ICMP_PORT_UNREACH))
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
	recv_bytes = recvfrom(env->icmp_socket, in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&ret_addr, &len);
	printf("%2ld  ", env->i + 1);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
		else
		{
			printf("* * *\n");
		}
	}
	else
	{
		analyze_packet(in_buff, &ret_addr, env);
	}
}
