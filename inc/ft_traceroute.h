#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define UDP_HEADER_SIZE	sizeof(struct udphdr)

typedef struct			s_udp_packet
{
	struct udphdr		header;
	char				*payload;
}						t_udp_packet;

typedef struct			s_icmp_packet
{
	struct icmphdr		header;
	char				*payload;
}						t_icmp_packet;

typedef struct			s_env
{
	t_icmp_packet		out_buffer;
	struct sockaddr_in	ip;
	unsigned long long	opt;
	char				*host;
	char				*canonname;
	char				*ip_str;
	size_t				hops;
	size_t				ttl;
	size_t				port;
	size_t				nb_probes;
	size_t				max_hops;
	size_t				payload_size;
	size_t				icmp_packet_size;
	struct timeval		max;
	struct timeval		here;
	struct timeval		near;
	int					packetlen;
	int					socket;
	uint16_t			sequence;
	char				padding[6];
}						t_env;

int						ft_traceroute(int ac, char **av);
int						resolve_hostname(char *hostname, t_env *env);
void					free_and_exit_failure(t_env *env);
void					free_and_exit_success(t_env *env);
void					print_usage(FILE *o);
int						send_probes(t_env *env);

#endif
