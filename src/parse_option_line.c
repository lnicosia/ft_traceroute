#include "options.h"
#include "libft.h"
#include <stdio.h>

static void	print_version(void)
{
	fprintf(stderr, "lnicosia's ft_traceroute version 1.0\n");
	fprintf(stderr, "This program is free software; you may redistribute it\n");
	fprintf(stderr, "This program has absolutely no warranty\n");
}

static void	print_usage(FILE *o)
{
	fprintf(o, "Usage:\n  traceroute [ -hvV ] host [ packetlen ]\n");
}

/*
**	Parse all the options
*/

int	parse_traceroute_options(int ac, char **av, t_global_data *env)
{
	int	opt, option_index = 0, count = 1;
	char		*optarg = NULL;
	const char	*optstring = "-hvV";
	static struct option long_options[] =
	{
		{"help",	0,			0, 'h'},
		{"verbose",	0,			0, 'v'},
		{"version",	0,			0, 'V'},
		{0,			0,			0,	0 }
	};

	while ((opt = ft_getopt_silent(ac, av, optstring, &optarg,
		long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case 'v':
				env->opt |= OPT_VERBOSE;
				break;
			case 'V':
				print_version();
				return 1;
			case 'h':
				print_usage(stdout);
				return 1;
			case '?':
				fprintf(stderr, "Bad option `%s' (argc %d)\n", 
					av[count], count);
				return FATAL_ERROR;
			default:
				break;
		}
		count++;
	}
	for (int i = 1; i < ac; i++)
	{
		if (!is_arg_an_opt(av, i, optstring, long_options))
		{
		}
	}
	return 0;
}
