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
	dprintf(fd, "Usage:\n  ft_traceroute [ -hInvV ] [-m max_ttl ] [ -N squeries ] " \
		"[ -p port ] [ -w MAX ] [ -q nqueries ] [ -z sendwait ] host [ packetlen ]\n");
	dprintf(fd, "Options:\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-I", "  --icmp", "Use ICMP ECHO for tracerouting\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-m max_ttl", "  --max-hops=max_ttl", "\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "Set the max number of hops (max TTL to be\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "reached). Default is 30\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-N squeries", "  --sim-queries=squeries", "\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "Set the number of probes to be tried\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "simultaneously (default is 16)\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-n", "", "Resolve IP addresses to their domain names\n");
	dprintf(fd, "%s%2s%-21s%s", "  ", "-p port", "  --port=port", "Set the destination port to use. It is either\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "initial udp port value for \"default\" method\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "(incremented by each probe, default is 33434), or\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "initial seq for \"icmp\" (incremented as well,\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "default from 1)\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-w MAX", "  --wait=MAX", "\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "Wait for a probe no more than MAX (default 5.0) seconds\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "", "(float point values allowed too)\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-q nqueries", "  --queries=nqueries", "\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "Set the number of probes per each hop. Default is\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "3\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-z sendwait", "  --sendwait=sendwait", "\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "Minimal time interval between probes (default 0).\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "If the value is more than 10, then it specifies a\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "number in milliseconds, else it is a number of\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "", "  ", "seconds (float point values allowed too)\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-v", "  --verbose", "Verbose mode. Print send and received packets headers\n");
	dprintf(fd, "%s%2s%-26s%s", "  ", "-V", "  --version", "Print version info and exit\n");

	dprintf(fd, "%s%2s%-26s%s", "  ", "-h", "  --help", "Read this help and exit\n");
	dprintf(fd, "\nArguments:\n");
	dprintf(fd, "+    host          The host to traceroute to\n");
	dprintf(fd, "     packetlen     The full packets length (default is the length of an IP\n");
	dprintf(fd, "                   header plus 40). Can be ignored or increased to a minimal\n");
	dprintf(fd, "                   allowed value\n");
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
	const char	*optstring = "-hvVnIw:m:q:N:p:z:";
	static struct option long_options[] =
	{
		{"help",		0,					0, 'h'},
		{"verbose",		0,					0, 'v'},
		{"version",		0,					0, 'V'},
		{"max_hops",	required_argument,	0, 'm'},
		{"queries",		required_argument,	0, 'q'},
		{"sim-queries", required_argument,	0, 'N'},
		{"wait",		required_argument,	0, 'w'},
		{"port",		required_argument,	0, 'p'},
		{"sendwait",	required_argument,	0, 'z'},
		{0,				0,					0,	0 }
	};

	while ((opt = ft_getopt_long(ac, av, optstring, &optarg,
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
			{
				env->opt &= ~OPT_MODE_UDP;
				env->opt |= OPT_MODE_ICMP;
				env->port = 0;
				break;
			}
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
			case 'z':
			{
				double sendwait = ft_atof(optarg);
				if (sendwait < 0)
				{
					dprintf(STDERR_FILENO, "bad sendtime `-%f' specified\n",
						sendwait);
					free_and_exit_failure(env);
				}
				if (sendwait >= 10)
				{
					env->sendwait.tv_sec = 0;
					env->sendwait.tv_usec = (suseconds_t)sendwait * 1000;
				}
				else
				{
					double integral;
					double fractional = modf(sendwait, &integral);
					env->sendwait.tv_sec = (time_t)integral;
					env->sendwait.tv_usec = (suseconds_t)(fractional * 1000000);
				}
				if (sendwait < 10e-7)
					env->sendwait.tv_usec = 1;
				env->squeries = 1;
				env->max = env->sendwait;
				break;
			}
			case 'p':
			{
				double port = ft_atof(optarg);
				env->port = (uint16_t)port;
				break;
			}
			case 'N':
			{
				env->squeries = (size_t)ft_atoll(optarg);
				if (env->squeries == 0)
					env->squeries = 1;
				if (env->squeries > MAX_SQUERIES)
					env->squeries = MAX_SQUERIES;
				break;
			}
			case 'm':
			{
				env->max_hops = (size_t)ft_atoll(optarg);
				env->max_packets = env->probes_per_hop * env->max_hops;
				if (env->max_hops > MAX_HOPS)
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
				free_and_exit_failure(env);
				break;
			}
			default:
			{
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
