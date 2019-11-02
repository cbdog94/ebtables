/* Shared library add-on to ebtables to add comment support.
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "../include/ebtables_u.h"
#include <linux/netfilter/xt_comment.h>

#define COMMENT '0'
#define OPT_COMMENT (1 << 0)

static const struct option comment_opts[] = {
	{.name = "comment", .has_arg = 1, .val = COMMENT},
	{0}};

static void comment_help(void)
{
	printf(
		"comment match options:\n"
		"--comment COMMENT             Attach a comment to a rule\n");
}

static void
comment_print(const struct ebt_u_entry *entry,
			  const struct ebt_entry_match *match)
{
	const struct xt_comment_info *commentinfo = (const void *)match->data;
	printf("--comment %s ", commentinfo->comment);
}

static void init(struct ebt_entry_match *match)
{
}

static int comment_compare(const struct ebt_entry_match *m1,
						   const struct ebt_entry_match *m2)
{
	const struct xt_comment_info *info1 =
		(const struct xt_comment_info *)m1->data;
	const struct xt_comment_info *info2 =
		(const struct xt_comment_info *)m2->data;

	return strcmp(info1->comment, info2->comment) == 0 ? 1 : 0;
}

static void
final_check(const struct ebt_u_entry *entry,
			const struct ebt_entry_match *match, const char *name,
			unsigned int hookmask, unsigned int time)
{
}

static int
comment_parse(int c, char **argv, int argc, const struct ebt_u_entry *entry,
			  unsigned int *flags, struct ebt_entry_match **match)
{
	struct xt_comment_info *info =
		(struct xt_comment_info *)(*match)->data;

	switch (c)
	{
	case COMMENT:
		ebt_check_option2(flags, OPT_COMMENT);
		if (ebt_check_inverse2(optarg))
			ebt_print_error2("Unexpected `!' after --comment");
		if (snprintf(info->comment, sizeof(info->comment), "%s", optarg) >=
			sizeof(info->comment))
			ebt_print_error2("\"%s\" is truncated", info->comment);
		break;
	default:
		return 0;
	}

	return 1;
}

static struct ebt_u_match comment_match =
	{
		.name = "comment",
		.revision = 0,
		.size = sizeof(struct xt_comment_info),
		.help = comment_help,
		.init = init,
		.parse = comment_parse,
		.final_check = final_check,
		.print = comment_print,
		.compare = comment_compare,
		.extra_ops = comment_opts,
};

static void _INIT(void)
{
	ebt_register_match(&comment_match);
}