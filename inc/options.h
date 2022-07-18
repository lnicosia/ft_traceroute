#ifndef OPTIONS_H
# define OPTIONS_H

# include "ft_traceroute.h"

# define OPT_VERBOSE			(1UL << 0)

# define FATAL_ERROR 2
# define PRINT_VERSION 3

int	parse_traceroute_options(int ac, char **av, t_global_data *env);

#endif
