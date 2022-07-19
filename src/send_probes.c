#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

#define BUFF_SIZE 56

/** Set out packet data for every probe
*/

void	set_out_packet_data(t_icmp_packet* out_packet)
{
	ft_bzero(out_packet, sizeof(struct icmphdr) + BUFF_SIZE);
	out_packet->header.type = ICMP_ECHO;
	out_packet->header.code = 0;
	out_packet->header.un.echo.id = 4242;
	if (BUFF_SIZE > 0)
	{
		size_t i;
		for (i = 0; i < BUFF_SIZE - 1; i++)
		{
			out_packet->payload[i] = (char)(i + '0');
		}
		out_packet->payload[i] = '\0';
	}
	//	Update sequence (= received packets count) and checksum
	out_packet->header.un.echo.sequence = 1;
	out_packet->header.checksum = checksum(out_packet,
		sizeof(struct icmphdr) + BUFF_SIZE);
}

int		send_probes(t_env *env)
{
	t_icmp_packet	out_buff;
	char			in_buff[BUFF_SIZE];
	socklen_t		len;
	ssize_t			recv_bytes;

	set_out_packet_data(&out_buff);
	ft_bzero(in_buff, sizeof(in_buff));
	len = sizeof(env->ip);
	if (env->opt & OPT_VERBOSE)
		print_icmp_header(&out_buff.header);
	if (sendto(env->socket, &out_buff, BUFF_SIZE + sizeof(struct icmphdr), 0,
		(struct sockaddr*)&env->ip, len) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	printf("Host = '%s' ip = '%s'\n", inet_ntoa(env->ip.sin_addr), env->ip_str);
	struct msghdr	msghdr;
	struct iovec	iov;
	iov.iov_base = in_buff;
	iov.iov_len = sizeof(in_buff);
	ft_bzero(&msghdr, sizeof(msghdr));
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	recv_bytes = recvmsg(env->socket, &msghdr, 0);
	//recv_bytes = recvfrom(env->socket, in_buff, sizeof(in_buff), 0,
	//	(struct sockaddr*)&env->ip, &len);
	if (recv_bytes == -1)
	{
		if (env->opt & OPT_VERBOSE)
			perror("ft_traceroute: recvfrom");
	}
	else if (recv_bytes == 0)
	{
		printf("Received 0 bytes\n");
	}
	else
	{
		if (env->opt & OPT_VERBOSE)
		{
			print_ip4_header((struct ip*)in_buff);
			print_icmp_header((struct icmphdr*)((void*)in_buff
			+ sizeof(struct iphdr)));
		}
		printf("Received!\n");
	}
	return 0;
}
