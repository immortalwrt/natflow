/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Tue, 22 Jun 2021 22:50:41 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include "natflow_common.h"
#include "natflow_urllogger.h"

struct urlinfo {
	struct list_head list;
	__be32 sip;
	__be32 dip;
	__be16 sport;
	__be16 dport;
	unsigned int timestamp;
	unsigned char mac[ETH_ALEN];
#define URLINFO_HTTPS 0x0001
	unsigned short flags;
	unsigned int data_len;
	unsigned char data[0];
};

static unsigned char *tls_sni_search(unsigned char *data, int *data_len)
{
	unsigned char *p = data;
	int p_len = *data_len;
	unsigned int i = 0;
	unsigned short len;

	if (p[i + 0] != 0x16) {//Content Type NOT HandShake
		return NULL;
	}
	i += 1 + 2;
	if (i >= p_len) return NULL;
	len = ntohs(get_byte2(p + i + 0)); //content_len
	i += 2;
	if (i >= p_len) return NULL;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	if (p[i + 0] != 0x01) { //HanShake Type NOT Client Hello
		return NULL;
	}
	i += 1;
	if (i >= p_len) return NULL;
	len = (p[i + 0] << 8) + ntohs(get_byte2(p + i + 0 + 1)); //hanshake_len
	i += 1 + 2;
	if (i >= p_len) return NULL;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	i += 2 + 32;
	if (i >= p_len) return NULL; //tls_v, random
	i += 1 + p[i + 0];
	if (i >= p_len) return NULL; //session id
	i += 2 + ntohs(get_byte2(p + i + 0));
	if (i >= p_len) return NULL; //Cipher Suites
	i += 1 + p[i + 0];
	if (i >= p_len) return NULL; //Compression Methods

	len = ntohs(get_byte2(p + i + 0)); //ext_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	while (i < p_len) {
		if (get_byte2(p + i + 0) != __constant_htons(0)) {
			i += 2 + 2 + ntohs(get_byte2(p + i + 0 + 2));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 2)); //sn_len
		i = i + 2 + 2;
		if (i + len > p_len) return NULL;

		p = p + i;
		p_len = len;
		i = 0;
		break;
	}
	if (i >= p_len) return NULL;

	len = ntohs(get_byte2(p + i + 0)); //snl_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	while (i < p_len) {
		if (p[i + 0] != 0) {
			i += 1 + 2 + ntohs(get_byte2(p + i + 0 + 1));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 1 + 2;
		if (i + len > p_len) return NULL;

		*data_len = len;
		return (p + i);
	}

	return NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_urllogger_hook_v1(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_urllogger_hook_v1(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_urllogger_hook_v1(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_urllogger_hook_v1(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *out = state->out;
#endif
#endif
	int dir = 0;
	enum ip_conntrack_info ctinfo;
	int data_len;
	unsigned char *data;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;

	if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct)
		return NF_ACCEPT;

	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	if ((ct->status & IPS_NATFLOW_URLLOGGER_HANDLED))
		return NF_ACCEPT;

	if (!(IPS_NATFLOW_FF_STOP & ct->status)) set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

	if (skb_try_make_writable(skb, skb->len)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
	data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
	if (data_len > 0) {
		unsigned char *host = NULL;
		int host_len = data_len;
		/* check one packet only */
		set_bit(IPS_NATFLOW_URLLOGGER_HANDLED_BIT, &ct->status);
		clear_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);

		/* try to get HTTPS/TLS SNI HOST */
		host = tls_sni_search(data, &host_len);
		if (host) {
			struct urlinfo *url = kmalloc(sizeof(struct urlinfo) + host_len + 1, GFP_ATOMIC);
			if (!url)
				return NF_ACCEPT;
			memcpy(url->data, host, host_len);
			url->data[host_len] = 0;
			url->data_len = host_len;
			url->sip = iph->saddr;
			url->dip = iph->daddr;
			url->sport = TCPH(l4)->source;
			url->dport = TCPH(l4)->dest;
			url->timestamp = jiffies / HZ;
			url->flags = URLINFO_HTTPS;
			memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

			printk("%pI4:%u->%pI4:%u, url=%s, https, t=%u\n", &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->data, url->timestamp);
		} else {
			;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops urllogger_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_urllogger_hook_v1,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER - 10,
	},
};

int natflow_urllogger_init(void)
{
	int ret = 0;

	ret = nf_register_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
	return ret;
}

void natflow_urllogger_exit(void)
{
	nf_unregister_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
}
