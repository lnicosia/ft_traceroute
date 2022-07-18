#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

int		send_probes(t_env *env)
{
	char			out_buff[1024];
	char			in_buff[1024];
	socklen_t		len;
	ssize_t			recv_bytes;

	ft_bzero(out_buff, sizeof(out_buff));
	ft_bzero(in_buff, sizeof(in_buff));
	ft_strcpy(out_buff, "Bonjour");
	if (sendto(env->socket, out_buff, sizeof(out_buff), 0,
		(struct sockaddr*)&env->ip, sizeof(env->ip)) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	len = sizeof(env->ip);
	recv_bytes = recvfrom(env->socket, in_buff, sizeof(in_buff), 0,
		(struct sockaddr*)&env->ip, &len);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recv_bytes");
	}
	else if (recv_bytes == 0)
	{
		printf("Received 0 bytes\n");
	}
	else
	{
		printf("Received!\n");
	}
	return 0;
}
