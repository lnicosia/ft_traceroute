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
