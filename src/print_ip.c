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
	{
		char	host[128];
			ft_bzero(host, sizeof(host));
		if (getnameinfo((struct sockaddr*)addr,
			sizeof(struct sockaddr), host, sizeof(host), NULL, 0, 0))
			dprintf(STDOUT_FILENO, "%s ", inet_ntoa(addr->sin_addr));
		else
			dprintf(STDOUT_FILENO, "%s ", host);
		dprintf(STDOUT_FILENO, "(%s)", inet_ntoa(addr->sin_addr));
	}
	else
		dprintf(STDOUT_FILENO, "%s", inet_ntoa(addr->sin_addr));
}
