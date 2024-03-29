#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define UDP_HEADER_SIZE		sizeof(struct udphdr)
#define ICMP_HEADER_SIZE	sizeof(struct icmphdr)
#define IP_HEADER_SIZE		sizeof(struct iphdr)
#define BUFF_SIZE			256
#define MAX_SQUERIES		100
#define MAX_HOPS			255

typedef struct			s_pseudo_header
{
	uint32_t			src;
	uint32_t			dst;
	uint8_t				zeros;
	uint8_t				port;
	uint16_t			len;
	struct udphdr		udphdr;
}						t_pseudo_header;

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

typedef struct			s_probe
{
	uint64_t			send_time;
	uint64_t			recv_time;
	struct sockaddr_in	recv_addr;
	ssize_t				recv_bytes;
	size_t				probe;
	char				in_buff[BUFF_SIZE];
	uint16_t			checksum;
	uint16_t			port;
	uint16_t			sequence;
	uint8_t				ttl;
	uint8_t				received;
	uint8_t				printed;
	char				padding[7];
}						t_probe;

typedef struct			s_env
{
	//	Output buffer for icmp packet
	t_icmp_packet		out_ibuffer;
	//	Input buffer for icmp packet
	t_icmp_packet		out_ubuffer;
	//	Received probes. Saved in case we don't receive them
	//	in the sending order
	t_probe				*probes;
	//	Destination IP. Whereto send the probes
	struct sockaddr_in	dest_ip;
	//	The first gateway to get received for each ttl
	struct sockaddr_in	current_gateway;
	unsigned long long	opt;
	char				*host;
	char				*canonname;
	char				*dest_ip_str;
	char				*out_buff;
	size_t				outgoing_packets;
	size_t				i;
	size_t				hops;
	size_t				probes_per_hop;
	size_t				max_hops;
	size_t				payload_size;
	size_t				total_packet_size;
	size_t				curr_hop;
	size_t				curr_query;
	size_t				curr_probe;
	size_t				recv_hop;
	size_t				recv_query;
	size_t				recv_probe;
	size_t				squeries;
	size_t				total_sent;
	size_t				total_received;
	size_t				max_packets;
	size_t				nb_hops_to_print;
	struct timeval		max;
	struct timeval		sendwait;
	double				here;
	double				near;
	uint8_t				*hops_to_print;
	int					*udp_sockets;
	int					packetlen;
	int					all_last_probes_sent;
	int					udp_socket;
	int					icmp_socket;
	int					dest_reached;
	uint16_t			sequence;
	uint16_t			id;
	uint16_t			port;
	uint16_t			sport;
	uint8_t				ttl;
	uint8_t				last_ttl;
	uint8_t				last_printed_ttl;
	char				padding[1];
}						t_env;

int						ft_traceroute(int ac, char **av);
int						resolve_hostname(char *hostname, t_env *env);
void					free_and_exit_failure(t_env *env);
void					free_and_exit_success(t_env *env);
void					print_usage(int fd);
int						send_probes(t_env *env);
int						send_icmp_probes(t_env *env);
void					receive_messages(t_env *env);
void					analyze_packets(t_env *env);
void					analyze_probe(t_probe *probe, t_env *env);
void					print_ip(struct sockaddr_in *addr, unsigned long long opt);
void					flush_received_packets(uint8_t last_ttl, t_env *env);
size_t					first_available_probe(t_env *env);
int						are_last_ttl_probes_all_sent(t_env *env);

#endif
