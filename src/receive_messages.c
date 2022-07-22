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
	if (probe->recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
	}
}
