#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define UDP_HEADER_SIZE	sizeof(struct udphdr)
#define BUFF_SIZE 1024

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
	t_icmp_packet		out_ibuffer;
	t_icmp_packet		out_ubuffer;
	struct sockaddr_in	ip;
	unsigned long long	opt;
	char				*host;
	char				*canonname;
	char				*ip_str;
	size_t				hops;
	size_t				ttl;
	size_t				probes_per_hop;
	size_t				max_hops;
	size_t				payload_size;
	size_t				total_packet_size;
	size_t				i;
	size_t				squeries;
	struct timeval		max;
	struct timeval		here;
	struct timeval		near;
	int					packetlen;
	int					udp_socket;
	int					icmp_socket;
	int					dest_reached;
	uint16_t			sequence;
	uint16_t			port;
	char				padding[4];
}						t_env;

int						ft_traceroute(int ac, char **av);
int						resolve_hostname(char *hostname, t_env *env);
void					free_and_exit_failure(t_env *env);
void					free_and_exit_success(t_env *env);
void					print_usage(FILE *o);
int						send_probes(t_env *env);
int						send_icmp_probes(t_env *env);
void					receive_messages(char *in_buff, t_env *env);

#endif
