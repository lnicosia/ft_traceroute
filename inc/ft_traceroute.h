#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

typedef struct			s_global_data
{
	unsigned long long	opt;
}						t_global_data;

int						ft_traceroute(int ac, char **av);

#endif
