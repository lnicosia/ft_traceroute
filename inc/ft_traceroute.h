#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <arpa/inet.h>
#include <stdio.h>

typedef struct			s_global_data
{
	struct sockaddr_in	ip;
	unsigned long long	opt;
	char				*host;
	char				*canonname;
	char				ip_str[INET_ADDRSTRLEN];
	int					packetlen;
	char				padding[4];
}						t_global_data;

int						ft_traceroute(int ac, char **av);
int						resolve_hostname(char *hostname, t_global_data *env);
void					free_and_exit_failure(t_global_data *env);
void					free_and_exit_success(t_global_data *env);
void					print_usage(FILE *o);

#endif
