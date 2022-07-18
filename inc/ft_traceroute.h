#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/time.h>

typedef struct			s_env
{
	struct sockaddr_in	ip;
	unsigned long long	opt;
	char				*host;
	char				*canonname;
	char				*ip_str;
	size_t				hops;
	size_t				start_ttl;
	size_t				port;
	size_t				nb_probes;
	struct timeval		max;
	struct timeval		here;
	struct timeval		near;
	int					packetlen;
	int					socket;
	//char				padding[4];
}						t_env;

int						ft_traceroute(int ac, char **av);
int						resolve_hostname(char *hostname, t_env *env);
void					free_and_exit_failure(t_env *env);
void					free_and_exit_success(t_env *env);
void					print_usage(FILE *o);
int						send_probes(t_env *env);

#endif
