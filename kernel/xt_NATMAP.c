// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 */

/* Kernel module which implements the set match and NATMAP target
 * for netfilter/iptables.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_nat.h>
#include <net/ip.h>
#include <net/tcp.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <uapi/linux/netfilter/xt_set.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vitaliy Lavrov <vel21ripn@gmail.com>");
MODULE_DESCRIPTION("Xtables: IP set target module");
MODULE_ALIAS("xt_NATMAP");
MODULE_ALIAS("ipt_NATMAP");
MODULE_ALIAS("ipt_SNATMAP");
MODULE_ALIAS("ipt_DNATMAP");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
MODULE_IMPORT_NS(NET_IPSET);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
#error Kernel too old. Require >= 4.4
#endif


#ifdef HAVE_CHECKENTRY_BOOL
#define CHECK_OK	1
#define CHECK_FAIL(err)	0
#define	CONST		const
#define FTYPE		bool
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35) */
#define CHECK_OK	0
#define CHECK_FAIL(err)	(err)
#define	CONST
#define	FTYPE		int
#endif

#define XT_PAR_NET(par)	((par)->net)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#define NF_CT_NETNS_GET(par) nf_ct_netns_get(XT_PAR_NET(par), par->family)
#define NF_CT_NETNS_PUT(par) nf_ct_netns_put(XT_PAR_NET(par), par->family)
#else
#define NF_CT_NETNS_GET(par)
#define NF_CT_NETNS_PUT(par)

static inline int xt_family(const struct xt_action_param *par) {
	return par->family;
}
#endif

#define ADT_OPT(n, f)	\
struct ip_set_adt_opt n = {				\
	.family	= f,					\
	.dim = 0,					\
	.flags = 0,					\
	.cmdflags = 0,					\
	.ext.timeout = UINT_MAX,			\
}

#ifdef HAVE_XT_TARGET_PARAM
#undef xt_action_param
#define xt_action_param	xt_target_param
#define CAST_TO_MATCH	(const struct xt_match_param *)
#else
#define	CAST_TO_MATCH
#endif

static void
compat_flags(struct xt_set_info_v0 *info)
{
        u_int8_t i;

        /* Fill out compatibility data according to enum ip_set_kopt */
        info->u.compat.dim = IPSET_DIM_ZERO;
        if (info->u.flags[0] & IPSET_MATCH_INV)
                info->u.compat.flags |= IPSET_INV_MATCH;
        for (i = 0; i < IPSET_DIM_MAX - 1 && info->u.flags[i]; i++) {
                info->u.compat.dim++;
                if (info->u.flags[i] & IPSET_SRC)
                        info->u.compat.flags |= (1 << info->u.compat.dim);
        }
}

/* Revision 0 interface: backward compatible with netfilter/iptables */

static unsigned int
set_target_v0(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_set_info_target_v0 *info = par->targinfo;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
        struct nf_nat_range2 range;
#else
        struct nf_nat_range range;
#endif
	uint32_t nat_ip,nat_port;

	int index,nat_mode,ret;
        enum ip_conntrack_info ctinfo;
        struct nf_conn *ct;

	ADT_OPT(opt, xt_family(par));

	index = info->add_set.index;
	if (index != IPSET_INVALID_ID) {
		nat_mode = NF_NAT_MANIP_SRC;
		opt.dim = info->add_set.u.compat.dim;
		opt.flags = info->add_set.u.compat.flags;
	} else {
		index = info->del_set.index;
		if (index == IPSET_INVALID_ID) return XT_CONTINUE;
		nat_mode = NF_NAT_MANIP_DST;
		opt.dim = info->del_set.u.compat.dim;
		opt.flags = info->del_set.u.compat.flags;
	}

	if (!ip_set_test(index, skb, CAST_TO_MATCH par, &opt)) return XT_CONTINUE;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
	nat_ip = opt.ext.skbmark;
	nat_port = opt.ext.skbmarkmask & 0xffff;
#else
	nat_ip = opt.ext.skbinfo.skbmark;
	nat_port = opt.ext.skbinfo.skbmarkmask & 0xffff;
#endif
        memset((char *)&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS;
        range.min_addr.ip = range.max_addr.ip = htonl(nat_ip);
        range.min_proto.tcp.port = range.max_proto.tcp.port = htons(nat_port);
	if(nat_port) range.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
        ct = nf_ct_get(skb, &ctinfo);

        ret = nf_nat_setup_info(ct, &range, nat_mode);
	/*
	printk("%s:%d:  %s ip %pI4 port %d ret %s\n",__func__,__LINE__,
			nat_mode == NF_NAT_MANIP_SRC ? "SNAT":"DNAT",
			(void *)&range.min_addr.ip, range.min_proto.tcp.port,
			ret == NF_ACCEPT ? "ACCEPT":"DROP");
			*/
	return ret;
}

static FTYPE
set_target_v0_checkentry(const struct xt_tgchk_param *par, struct xt_set_info_v0 *info_set)
{
	ip_set_id_t index;

	if (info_set->index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(XT_PAR_NET(par),
						info_set->index);
		if (index == IPSET_INVALID_ID) {
			pr_warn("Cannot find nat_set index %u as target\n",
				info_set->index);
			return CHECK_FAIL(-ENOENT);
		}
	}

	if (info_set->u.flags[IPSET_DIM_MAX - 1] != 0 ) {
		pr_warn("Protocol error: SET target dimension is over the limit!\n");
		if (info_set->index != IPSET_INVALID_ID)
			ip_set_nfnl_put(XT_PAR_NET(par), info_set->index);
		return CHECK_FAIL(-ERANGE);
	}

	/* Fill out compatibility data */
	compat_flags(info_set);
        NF_CT_NETNS_GET(par);
	return CHECK_OK;
}

static FTYPE
set_target_snat_v0_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_set_info_target_v0 *info = par->targinfo;
	return set_target_v0_checkentry(par,&info->add_set);
}

static FTYPE
set_target_dnat_v0_checkentry(const struct xt_tgchk_param *par)
{
	struct xt_set_info_target_v0 *info = par->targinfo;
	return set_target_v0_checkentry(par,&info->del_set);
}

static void
set_target_v0_destroy(const struct xt_tgdtor_param *par)
{
	const struct xt_set_info_target_v0 *info = par->targinfo;

	if (info->add_set.index != IPSET_INVALID_ID) {
		ip_set_nfnl_put(XT_PAR_NET(par), info->add_set.index);
        	NF_CT_NETNS_PUT(par);
	}
	if (info->del_set.index != IPSET_INVALID_ID) {
		ip_set_nfnl_put(XT_PAR_NET(par), info->del_set.index);
        	NF_CT_NETNS_PUT(par);
	}
}

static struct xt_target set_targets[] __read_mostly = {
	{
		.name		= "SNATMAP",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= set_target_v0,
		.targetsize	= sizeof(struct xt_set_info_target_v0),
		.table		= "nat",
		.hooks		= (1 << NF_INET_POST_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.checkentry	= set_target_snat_v0_checkentry,
		.destroy	= set_target_v0_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "DNATMAP",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= set_target_v0,
		.targetsize	= sizeof(struct xt_set_info_target_v0),
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_OUT),
		.checkentry	= set_target_dnat_v0_checkentry,
		.destroy	= set_target_v0_destroy,
		.me		= THIS_MODULE
	},
};

static int __init xt_natmap_init(void)
{
	int ret = xt_register_targets(set_targets,
					  ARRAY_SIZE(set_targets));
	return ret;
}

static void __exit xt_natmap_fini(void)
{
	xt_unregister_targets(set_targets, ARRAY_SIZE(set_targets));
}

module_init(xt_natmap_init);
module_exit(xt_natmap_fini);
