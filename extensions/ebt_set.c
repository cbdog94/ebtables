/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

/* Shared library add-on to iptables to add IP set matching. */
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>

#include "../include/ebtables_u.h"
#include <linux/netfilter/xt_set.h>
#include <linux/netfilter_bridge/ebt_set.h>

static const char type2str[][4] = {
	[TYPE_SRC] = "src",
	[TYPE_DST] = "dst"};

static void
set_check_v0(const struct ebt_u_entry *entry,
			 const struct ebt_entry_match *match, const char *name,
			 unsigned int hookmask, unsigned int time)
{
}

static void
print_match(const char *prefix, const struct xt_set_info *info)
{
	int i;
	char setname[IPSET_MAXNAMELEN];

	get_set_byid(setname, info->index);
	printf("--%s%s %s",
		   prefix,
		   (info->flags & IPSET_INV_MATCH) ? " !" : "",
		   setname);
}

/* Revision 3 */
static void
set_help_v3(enum type type)
{
	printf("set match options:\n"
		   " [!] --match-set-%s name [--return-nomatch]\n"
		   "   [! --update-counters] [! --update-subcounters]\n"
		   "   [[!] --packets-eq value | --packets-lt value | --packets-gt value\n"
		   "   [[!] --bytes-eq value | --bytes-lt value | --bytes-gt value\n"
		   "		 'name' is the set name from to match.\n",
		   type2str[type]);
}

static void
set_help_v3_src()
{
	set_help_v3(TYPE_SRC);
}

static void
set_help_v3_dst()
{
	set_help_v3(TYPE_DST);
}

static const struct option set_opts_v3_src[] = {
	{.name = "match-set-src", .has_arg = true, .val = '1'},
	{.name = "set-src", .has_arg = true, .val = '2'},
	{.name = "return-nomatch", .has_arg = false, .val = '3'},
	{.name = "update-counters", .has_arg = false, .val = '4'},
	{.name = "packets-eq", .has_arg = true, .val = '5'},
	{.name = "packets-lt", .has_arg = true, .val = '6'},
	{.name = "packets-gt", .has_arg = true, .val = '7'},
	{.name = "bytes-eq", .has_arg = true, .val = '8'},
	{.name = "bytes-lt", .has_arg = true, .val = '9'},
	{.name = "bytes-gt", .has_arg = true, .val = '0'},
	{.name = "update-subcounters", .has_arg = false, .val = 'a'},
	{0}};

static const struct option set_opts_v3_dst[] = {
	{.name = "match-set-dst", .has_arg = true, .val = '1'},
	{.name = "set-dst", .has_arg = true, .val = '2'},
	{.name = "return-nomatch", .has_arg = false, .val = '3'},
	{.name = "update-counters", .has_arg = false, .val = '4'},
	{.name = "packets-eq", .has_arg = true, .val = '5'},
	{.name = "packets-lt", .has_arg = true, .val = '6'},
	{.name = "packets-gt", .has_arg = true, .val = '7'},
	{.name = "bytes-eq", .has_arg = true, .val = '8'},
	{.name = "bytes-lt", .has_arg = true, .val = '9'},
	{.name = "bytes-gt", .has_arg = true, .val = '0'},
	{.name = "update-subcounters", .has_arg = false, .val = 'a'},
	{0}};

static uint64_t
parse_counter(const char *opt)
{
	char *buffer;
	__u64 count = strtoull(opt, &buffer, 10);
	if (*buffer != '\0')
		ebt_print_error2("Packet counter '%s' invalid", optarg);
	return (uint64_t)count;
}

/* Revision 4 */

static int
set_parse_v4(int c, char **argv, int argc, const struct ebt_u_entry *entry,
			 unsigned int *flags, struct ebt_entry_match **match, enum type type)
{
	struct xt_set_info_match_v4 *info =
		(struct xt_set_info_match_v4 *)(*match)->data;

	switch (c)
	{
	case 'a':
		if (ebt_check_inverse2(optarg))
			info->flags |= IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE;
		break;
	case '0':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --bytes-[eq|lt|gt]"
				" is allowed\n");
		if (ebt_check_inverse2(optarg))
			ebt_print_error2(
				"--bytes-gt option cannot be inverted\n");
		info->bytes.op = IPSET_COUNTER_GT;
		info->bytes.value = parse_counter(optarg);
		break;
	case '9':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --bytes-[eq|lt|gt]"
				" is allowed\n");
		if (ebt_check_inverse2(optarg))
			ebt_print_error2(
				"--bytes-lt option cannot be inverted\n");
		info->bytes.op = IPSET_COUNTER_LT;
		info->bytes.value = parse_counter(optarg);
		break;
	case '8':
		if (info->bytes.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --bytes-[eq|lt|gt]"
				" is allowed\n");
		info->bytes.op = ebt_check_inverse2(optarg) ? IPSET_COUNTER_NE : IPSET_COUNTER_EQ;
		info->bytes.value = parse_counter(optarg);
		break;
	case '7':
		if (info->packets.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --packets-[eq|lt|gt]"
				" is allowed\n");
		if (ebt_check_inverse2(optarg))
			ebt_print_error2(
				"--packets-gt option cannot be inverted\n");
		info->packets.op = IPSET_COUNTER_GT;
		info->packets.value = parse_counter(optarg);
		break;
	case '6':
		if (info->packets.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --packets-[eq|lt|gt]"
				" is allowed\n");
		if (ebt_check_inverse2(optarg))
			ebt_print_error2(
				"--packets-lt option cannot be inverted\n");
		info->packets.op = IPSET_COUNTER_LT;
		info->packets.value = parse_counter(optarg);
		break;
	case '5':
		if (info->packets.op != IPSET_COUNTER_NONE)
			ebt_print_error2(
				"only one of the --packets-[eq|lt|gt]"
				" is allowed\n");
		info->packets.op = ebt_check_inverse2(optarg) ? IPSET_COUNTER_NE : IPSET_COUNTER_EQ;
		info->packets.value = parse_counter(optarg);
		break;
	case '4':
		if (ebt_check_inverse2(optarg))
			info->flags |= IPSET_FLAG_SKIP_COUNTER_UPDATE;
		break;
	case '3':
		if (ebt_check_inverse2(optarg))
			ebt_print_error2(
				"--return-nomatch flag cannot be inverted\n");
		info->flags |= IPSET_FLAG_RETURN_NOMATCH;
		break;
	case '2':
		fprintf(stderr,
				"--set-%s option deprecated, please use --match-set-%s\n", type2str[type]),
			type2str[type];
		/* fall through */
	case '1': /* --match-set <set> <flag>[,<flag> */
		if (info->match_set.dim)
			ebt_print_error2(
				"--match-set-%s can be specified only once", type2str[type]);
		if (ebt_check_inverse2(optarg))
			info->match_set.flags |= IPSET_INV_MATCH;
		if (strlen(optarg) > IPSET_MAXNAMELEN - 1)
			ebt_print_error2(
				"setname `%s' too long, max %d characters.",
				optarg, IPSET_MAXNAMELEN - 1);

		get_set_byname(optarg, &info->match_set);
		if (type == TYPE_SRC)
		{
			info->match_set.flags |= IPSET_DIM_ONE_SRC;
		}
		info->match_set.dim = 1;

		*flags = 1;
		break;
	default:
		return 0;
	}

	return 1;
}

static int
set_parse_v4_src(int c, char **argv, int argc, const struct ebt_u_entry *entry,
				 unsigned int *flags, struct ebt_entry_match **match)
{
	return set_parse_v4(c, argv, argc, entry, flags, match, TYPE_SRC);
}

static int
set_parse_v4_dst(int c, char **argv, int argc, const struct ebt_u_entry *entry,
				 unsigned int *flags, struct ebt_entry_match **match)
{
	return set_parse_v4(c, argv, argc, entry, flags, match, TYPE_DST);
}

static void
set_printv4_counter(const struct ip_set_counter_match *c, const char *name,
					const char *sep)
{
	switch (c->op)
	{
	case IPSET_COUNTER_EQ:
		printf(" %s%s-eq %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_NE:
		printf(" ! %s%s-eq %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_LT:
		printf(" %s%s-lt %llu", sep, name, c->value);
		break;
	case IPSET_COUNTER_GT:
		printf(" %s%s-gt %llu", sep, name, c->value);
		break;
	}
}

static void
set_print_v4_matchinfo(const struct xt_set_info_match_v4 *info,
					   const char *opt, const char *sep)
{
	print_match(opt, &info->match_set);
	if (info->flags & IPSET_FLAG_RETURN_NOMATCH)
		printf(" %sreturn-nomatch", sep);
	if ((info->flags & IPSET_FLAG_SKIP_COUNTER_UPDATE))
		printf(" ! %supdate-counters", sep);
	if ((info->flags & IPSET_FLAG_SKIP_SUBCOUNTER_UPDATE))
		printf(" ! %supdate-subcounters", sep);
	set_printv4_counter(&info->packets, "packets", sep);
	set_printv4_counter(&info->bytes, "bytes", sep);
	printf(" ");
}

/* Prints out the matchinfo. */
static void
set_print_v4_src(const struct ebt_u_entry *entry,
				 const struct ebt_entry_match *match)
{
	const struct xt_set_info_match_v4 *info = (const void *)match->data;
	set_print_v4_matchinfo(info, "match-set-src", "");
}

static void
set_print_v4_dst(const struct ebt_u_entry *entry,
				 const struct ebt_entry_match *match)
{
	const struct xt_set_info_match_v4 *info = (const void *)match->data;
	set_print_v4_matchinfo(info, "match-set-dst", "");
}

static void init(struct ebt_entry_match *match)
{
}

static int compare(const struct ebt_entry_match *m1,
				   const struct ebt_entry_match *m2)
{
	const struct xt_set_info_match_v4 *info1 =
		(const struct xt_set_info_match_v4 *)m1->data;
	const struct xt_set_info_match_v4 *info2 =
		(const struct xt_set_info_match_v4 *)m2->data;

	if (info1->flags != info2->flags)
		return 0;
	if (info1->match_set.index != info2->match_set.index)
		return 0;
	if (info1->match_set.dim != info2->match_set.dim)
		return 0;
	if (info1->match_set.flags != info2->match_set.flags)
		return 0;
	if (info1->packets.value != info2->packets.value)
		return 0;
	if (info1->packets.op != info2->packets.op)
		return 0;
	if (info1->bytes.value != info2->bytes.value)
		return 0;
	if (info1->bytes.op != info2->bytes.op)
		return 0;

	return 1;
}

static struct ebt_u_match set_match_src =
	{
		.name = "set-src",
		.revision = 4,
		.size = sizeof(struct xt_set_info_match_v4),
		.help = set_help_v3_src,
		.init = init,
		.parse = set_parse_v4_src,
		.final_check = set_check_v0,
		.print = set_print_v4_src,
		.compare = compare,
		.extra_ops = set_opts_v3_src,
};

static struct ebt_u_match set_match_dst =
	{
		.name = "set-dst",
		.revision = 4,
		.size = sizeof(struct xt_set_info_match_v4),
		.help = set_help_v3_dst,
		.init = init,
		.parse = set_parse_v4_dst,
		.final_check = set_check_v0,
		.print = set_print_v4_dst,
		.compare = compare,
		.extra_ops = set_opts_v3_dst,
};

static void _INIT(void)
{
	ebt_register_match(&set_match_src);
	ebt_register_match(&set_match_dst);
}
