/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Shared library add-on to iptables to add IP set mangling target. */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include <xtables.h>
#include <linux/netfilter/xt_set.h>
#include "libxt_set.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* Revision 0 */

static void
set_target_snat_help_v0(void)
{
	printf("SNATMAP target options:\n"
	       " --nat-set name flags\n"
	       "		where flags are the comma separated list of\n"
	       "		'src' and 'dst' specifications.\n");
}

static void
set_target_dnat_help_v0(void)
{
	printf("DNATMAP target options:\n"
	       " --nat-set name flags\n"
	       "		where flags are the comma separated list of\n"
	       "		'src' and 'dst' specifications.\n");
}

static const struct option set_target_opts_v0[] = {
	{.name = "nat-set", .has_arg = true, .val = '1'},
	XT_GETOPT_TABLEEND,
};

static void
set_target_check_v0(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			   "You must specify either `--nat-set'");
}

static void
set_target_init_v0(struct xt_entry_target *target)
{
	struct xt_set_info_target_v0 *info =
		(struct xt_set_info_target_v0 *) target->data;

	info->add_set.index =
	info->del_set.index = IPSET_INVALID_ID;

}

static void
parse_target_v0(char **argv, int invert, unsigned int *flags,
		struct xt_set_info_v0 *info, const char *what)
{
	if (info->u.flags[0])
		xtables_error(PARAMETER_PROBLEM,
			      "--%s can be specified only once", what);

	if (!argv[optind]
	    || argv[optind][0] == '-' || argv[optind][0] == '!')
		xtables_error(PARAMETER_PROBLEM,
			      "--%s requires two args.", what);

	if (strlen(optarg) > IPSET_MAXNAMELEN - 1)
		xtables_error(PARAMETER_PROBLEM,
			      "setname `%s' too long, max %d characters.",
			      optarg, IPSET_MAXNAMELEN - 1);

        if(test_set_byname(optarg,(struct xt_set_info *)info))
                try_auto_load(optarg);

	get_set_byname(optarg, (struct xt_set_info *)info);
	parse_dirs_v0(argv[optind], info);
	optind++;

	*flags = 1;
}

static int
set_target_snat_parse_v0(int c, char **argv, int invert, unsigned int *flags,
		    const void *entry, struct xt_entry_target **target)
{
	struct xt_set_info_target_v0 *myinfo =
		(struct xt_set_info_target_v0 *) (*target)->data;

	switch (c) {
	case '1':		/* --snat-set <set> <flags> */
		parse_target_v0(argv, invert, flags,
				&myinfo->add_set, "nat-set");
		break;
	}
	return 1;
}

static int
set_target_dnat_parse_v0(int c, char **argv, int invert, unsigned int *flags,
		    const void *entry, struct xt_entry_target **target)
{
	struct xt_set_info_target_v0 *myinfo =
		(struct xt_set_info_target_v0 *) (*target)->data;

	switch (c) {
	case '1':		/* --snat-set <set> <flags> */
		parse_target_v0(argv, invert, flags,
				&myinfo->del_set, "nat-set");
		break;
	}
	return 1;
}

static void
print_target_v0(const char *prefix, const struct xt_set_info_v0 *info)
{
	int i;
	char setname[IPSET_MAXNAMELEN];

	if (info->index == IPSET_INVALID_ID)
		return;
	get_set_byid(setname, info->index);
	printf(" %s %s", prefix, setname);
	for (i = 0; i < IPSET_DIM_MAX; i++) {
		if (!info->u.flags[i])
			break;
		printf("%s%s",
		       i == 0 ? " " : ",",
		       info->u.flags[i] & IPSET_SRC ? "src" : "dst");
	}
}

static void
set_target_snat_print_v0(const void *ip, const struct xt_entry_target *target,
		    int numeric)
{
	const struct xt_set_info_target_v0 *info = (const void *)target->data;

	print_target_v0("nat-set", &info->add_set);
}

static void
set_target_dnat_print_v0(const void *ip, const struct xt_entry_target *target,
		    int numeric)
{
	const struct xt_set_info_target_v0 *info = (const void *)target->data;

	print_target_v0("nat-set", &info->del_set);
}

static void
set_target_snat_save_v0(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_set_info_target_v0 *info = (const void *)target->data;

	print_target_v0("--nat-set", &info->add_set);
}

static void
set_target_dnat_save_v0(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_set_info_target_v0 *info = (const void *)target->data;

	print_target_v0("--nat-set", &info->del_set);
}

static struct xtables_target set_tg_reg[] = {
	{
		.name		= "SNATMAP",
		.revision	= 0,
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.size		= XT_ALIGN(sizeof(struct xt_set_info_target_v0)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_set_info_target_v0)),
		.help		= set_target_snat_help_v0,
		.init		= set_target_init_v0,
		.parse		= set_target_snat_parse_v0,
		.final_check	= set_target_check_v0,
		.print		= set_target_snat_print_v0,
		.save		= set_target_snat_save_v0,
		.extra_opts	= set_target_opts_v0,
	},
	{
		.name		= "DNATMAP",
		.revision	= 0,
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_IPV4,
		.size		= XT_ALIGN(sizeof(struct xt_set_info_target_v0)),
		.userspacesize	= XT_ALIGN(sizeof(struct xt_set_info_target_v0)),
		.help		= set_target_dnat_help_v0,
		.init		= set_target_init_v0,
		.parse		= set_target_dnat_parse_v0,
		.final_check	= set_target_check_v0,
		.print		= set_target_dnat_print_v0,
		.save		= set_target_dnat_save_v0,
		.extra_opts	= set_target_opts_v0,
	},
};

void _init(void)
{
	xtables_register_targets(set_tg_reg, ARRAY_SIZE(set_tg_reg));
}
