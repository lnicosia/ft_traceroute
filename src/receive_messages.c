#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

/*
**	Receive message
*/

void	receive_messages(t_probe *probe, t_env *env)
{
	socklen_t			len;

	len = sizeof(probe->recv_addr);
	ft_bzero(probe->in_buff, BUFF_SIZE);
	probe->recv_bytes = recvfrom(env->icmp_socket, probe->in_buff, BUFF_SIZE, 0,
		(struct sockaddr*)&probe->recv_addr, &len);
	probe->recv_time = get_time();
	if (env->curr_probe == 0)
		printf("%2ld  ", env->curr_hop + 1);
	if (probe->recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
		else
		{
			if (env->curr_probe > 0)
				printf(" ");
			printf("*");
		}
	}
	else
	{
		if (env->opt & OPT_VERBOSE)
		{
			struct ip *ip = (struct ip*)probe->in_buff;
			struct icmphdr *icmphdr = (struct icmphdr*)(ip + 1);
			printf("Received:\n");
			print_ip4_header(ip);
			print_icmp_header(icmphdr);
		}
		if (env->curr_probe == 0)
		{
			print_ip(&probe->recv_addr, env->opt);
			env->current_gateway = probe->recv_addr;
		}
		analyze_probe(probe, env);
	}
	if (env->curr_probe == env->probes_per_hop - 1)
		printf("\n");
}
