#ifndef OPTIONS_H
# define OPTIONS_H

# include "ft_traceroute.h"

# define OPT_VERBOSE			(1UL << 0)
# define OPT_NUMERIC			(1UL << 1)
# define OPT_MODE_UDP			(1UL << 2)
# define OPT_MODE_ICMP			(1UL << 3)

# define FATAL_ERROR 2
# define PRINT_VERSION 3

int	parse_traceroute_options(int ac, char **av, t_env *env);

#endif
