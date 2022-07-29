#include "options.h"
#include "libft.h"
#include "ft_traceroute.h"
#include <stdio.h>
#include <math.h>

static void	print_version(void)
{
	dprintf(STDERR_FILENO, "lnicosia's ft_traceroute version 1.0\n");
	dprintf(STDERR_FILENO, "This program is free software; you may redistribute it\n");
	dprintf(STDERR_FILENO, "This program has absolutely no warranty\n");
}

void		print_usage(int fd)
{
	dprintf(fd, "Usage:\n  traceroute [ -hvV ] host [ packetlen ]\n");
}

static int	is_valid_packetlen(char *av)
{
	int	first_digit = 0;
	for (size_t i = 0; av[i]; i++)
	{
		if (av[i] == ' ' || av[i] == '\n' || av[i] == '\t' || av[i] == '\r'
				|| av[i] == '\v' || av[i] == 'f')
		{
			if (first_digit == 1)
				return 0;
		}
		else if (ft_isdigit(av[i]))
			first_digit = 1;
		else
			return 0;
	}
	return 1;
}

/*
**	Parse all the options
*/

int	parse_traceroute_options(int ac, char **av, t_env *env)
{
	int	opt, option_index = 0, count = 1;
	char		*optarg = NULL;
	const char	*optstring = "-hvVnIw:m:q:";
	static struct option long_options[] =
	{
		{"help",	0,			0, 'h'},
		{"verbose",	0,			0, 'v'},
		{"version",	0,			0, 'V'},
		{"max_hops",0,			0, 'm'},
		{"queries", 0,			0, 'q'},
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
			case 'n':
				env->opt |= OPT_NUMERIC;
				break;
			case 'I':
				env->opt |= OPT_MODE_ICMP;
				break;
			case 'w':
			{
				double timeout = ft_atof(optarg);
				if (timeout < 0)
				{
					dprintf(STDERR_FILENO, "bad wait specifications `-%f' used\n",
						timeout);
					free_and_exit_failure(env);
				}
				double integral;
				double fractional = modf(timeout, &integral);
				env->max.tv_sec = (time_t)integral;
				env->max.tv_usec = (suseconds_t)(fractional * 1000000);
				if (timeout < 10e-7)
					env->max.tv_usec = 1;
				break;
			}
			case 'm':
			{
				env->max_hops = (size_t)ft_atoll(optarg);
				env->max_packets = env->probes_per_hop * env->max_hops;
				if (env->max_hops > 255)
				{
					dprintf(STDERR_FILENO, "max hops cannot be more than 255\n");
					free_and_exit_failure(env);
				}
				if (env->max_hops == 0)
				{
					dprintf(STDERR_FILENO, "first hop out of range\n");
					free_and_exit_failure(env);
				}
				break;
			}
			case 'q':
			{
				env->probes_per_hop = (size_t)ft_atoll(optarg);
				env->max_packets = env->probes_per_hop * env->max_hops;
				if (env->probes_per_hop == 0 || env->probes_per_hop > 10)
				{
					dprintf(STDERR_FILENO, "no more than 10 probes per hop\n");
					free_and_exit_failure(env);
				}
				break;
			}
			case 'V':
				print_version();
				return 1;
			case 'h':
				print_usage(STDOUT_FILENO);
				return 1;
			case '?':
			{
				dprintf(STDERR_FILENO, "Bad option `%s' (argc %d)\n", 
					av[count], count);
				free_and_exit_failure(env);
				break;
			}
			default:
			{
				dprintf(STDERR_FILENO, "Bad option `%s' (argc %d)\n", 
					av[count], count);
				free_and_exit_failure(env);
				break;
			}
		}
		count++;
	}
	for (int i = 1; i < ac; i++)
	{
		if (!is_arg_an_opt(av, i, optstring, long_options))
		{
			if (env->host == NULL)
			{
				env->host = av[i];
				if (resolve_hostname(av[i], env))
				{
					dprintf(STDERR_FILENO, "Cannot handle \"host\" cmdline arg " \
						"`%s' on position 1 (argc %d)\n", av[i], i);
					free_and_exit_failure(env);
				}
			}
			else
			{
				if (!is_valid_packetlen(av[i]))
				{
					dprintf(STDERR_FILENO, "Cannot handle \"packetlen\" cmdline arg " \
						"`%s' on position 2 (argc %d)\n", av[i], i);
					free_and_exit_failure(env);
				}
				env->total_packet_size = (size_t)ft_atoll(av[i]);
				if (env->total_packet_size > 65000)
				{
					dprintf(STDERR_FILENO, "too big packetlen %ld specified\n",
						env->total_packet_size);
					free_and_exit_failure(env);
				}
			}
		}
	}
	return 0;
}
