#include "ft_traceroute.h"
#include "libft.h"
#include "options.h"

#define BUFF_SIZE 56

/** Set out packet data for every probe
*/

void	set_out_packet_data(t_icmp_packet* out_packet, t_env *env)
{
	ft_bzero(&out_packet->header, sizeof(struct icmphdr));
	ft_bzero(out_packet->payload, env->payload_size);
	out_packet->header.type = ICMP_ECHO;
	out_packet->header.code = 0;
	out_packet->header.un.echo.id = 4242;
	if (env->payload_size > 0)
	{
		size_t i;
		for (i = 0; i < env->payload_size - 1; i++)
		{
			out_packet->payload[i] = (char)(i + '0');
		}
		out_packet->payload[i] = '\0';
	}
	//	Update sequence (= received packets count) and checksum
	out_packet->header.un.echo.sequence = 1;
	out_packet->header.checksum = checksum(out_packet,
		(int)env->icmp_packet_size);
}

int		send_probes(t_env *env)
{
	char			in_buff[BUFF_SIZE];
	socklen_t		len;
	ssize_t			recv_bytes;

	env->out_buffer.payload = (char*)malloc(env->payload_size);
	if (env->out_buffer.payload == NULL)
		free_and_exit_failure(env);
	set_out_packet_data(&env->out_buffer, env);
	ft_bzero(in_buff, sizeof(in_buff));
	len = sizeof(env->ip);
	if (env->opt & OPT_VERBOSE)
		print_icmp_header(&env->out_buffer.header);
	if (sendto(env->socket, &env->out_buffer, env->icmp_packet_size,
		0, (struct sockaddr*)&env->ip, len) <= 0)
	{
		perror("ft_traceroute: sendto");
		free_and_exit_failure(env);
	}
	env->ip.sin_port = htons(33434);
	recv_bytes = recvfrom(env->socket, in_buff, sizeof(in_buff), 0,
		(struct sockaddr*)&env->ip, &len);
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
	}
	return 0;
}
