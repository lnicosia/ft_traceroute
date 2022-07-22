#include "libft.h"
#include "ft_traceroute.h"
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <stdio.h>

int		resolve_hostname(char *hostname, t_env *env)
{
	int		ret;

	struct addrinfo *ai;
	struct addrinfo hints;
	ft_bzero(&hints, sizeof(hints));
	ai = NULL;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = AI_CANONNAME;
	if ((ret = getaddrinfo(hostname, NULL, &hints, &ai)))
	{
		fprintf(stderr, "%s: %s\n",
			hostname, gai_strerror(ret));
		return -1;
	}
	if (!(env->canonname = ft_strdup(ai->ai_canonname)))
	{
		perror("ft_traceroute: ft_strdup");
		free_and_exit_failure(env);
	}
	struct addrinfo *tmp = ai;
	while (tmp)
	{
		if (tmp->ai_family == AF_INET)
		{
			struct sockaddr_in *ip4 = (struct sockaddr_in*)tmp->ai_addr;
			ft_memcpy(&env->dest_ip, ip4, sizeof(*ip4));
			env->dest_ip_str = inet_ntoa(ip4->sin_addr);
			break;
		}
		tmp = tmp->ai_next;
	}
	freeaddrinfo(ai);
	//	Test on localhost
	//env->ip.sin_addr.s_addr = inet_addr("127.0.0.1");
	return 0;
}
