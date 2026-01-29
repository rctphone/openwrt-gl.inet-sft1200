/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Siflower SF19A28 HNAT Driver Header
 *
 * Based on original Siflower SDK code from BPI-WiFi5-Siflower project
 * Adapted for kernel 6.x flow offload API
 *
 * Copyright (C) Siflower Communications
 * Copyright (C) 2024-2026 OpenWrt contributors
 */

#ifndef _SF_HNAT_H_
#define _SF_HNAT_H_

#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/rhashtable.h>
#include <linux/types.h>
#include <net/flow_offload.h>
#include <net/netfilter/nf_flow_table.h>

#include "sf_hnat_reg.h"

#define SF_HNAT_MAX_FLOWS		SF_NAPT_TABLE_MAX
#define SF_HNAT_SUBNET_MAX		8
#define SF_HNAT_WIFI_NDEV_MAX		16

/*
 * Flow entry state
 */
enum sf_hnat_flow_state {
	SF_FLOW_STATE_INVALID = 0,
	SF_FLOW_STATE_UNBIND,
	SF_FLOW_STATE_BIND,
	SF_FLOW_STATE_FIN,
};

/*
 * Protocol types
 */
enum sf_hnat_proto {
	SF_PROTO_TCP = 0,
	SF_PROTO_UDP = 1,
};

/*
 * VLAN information for a flow
 */
struct sf_hnat_vlan_info {
	u16 id;
	u16 proto;
};

/*
 * Flow data extracted from flow_cls_offload
 * This replaces the old flow_offload_hw_path approach
 */
struct sf_flow_data {
	/* L2 info */
	struct ethhdr eth;
	struct sf_hnat_vlan_info vlan[2];
	u8 vlan_num;
	u16 pppoe_sid;
	bool pppoe;

	/* L3 info */
	union {
		struct {
			__be32 src_addr;
			__be32 dst_addr;
		} v4;
		struct {
			struct in6_addr src_addr;
			struct in6_addr dst_addr;
		} v6;
	};

	/* L4 info */
	__be16 src_port;
	__be16 dst_port;
	u8 l4proto;
};

/*
 * NAPT hash key - describes a unique flow
 * This structure is used to program the HNAT hardware tables
 */
struct sf_hashkey {
	/* Flow identification (5-tuple) */
	__be32 sip;		/* Source IP (private) */
	__be32 dip;		/* Destination IP (public) */
	__be16 sport;		/* Source port (private) */
	__be16 dport;		/* Destination port (public) */
	__be32 router_pub_ip;	/* Router's public IP for SNAT */

	/* L2 information */
	u8 src_mac[ETH_ALEN];
	u16 src_vlan;
	u16 dest_vlan;
	u8 dest_mac[ETH_ALEN];
	u8 router_src_mac[ETH_ALEN];	/* WAN MAC */
	u8 router_dest_mac[ETH_ALEN];	/* LAN MAC */
	__be16 router_port;		/* Translated port */
	u8 proto;			/* TCP=0, UDP=1 */
	u16 ppp_sid;			/* PPPoE session ID */

	/* Internal state */
	u8 valid;
	u8 cur_pppoe_en;
	u8 src_vlan_index;
	u8 dest_vlan_index;
	u8 rt_pub_net_index;
	u8 dest_dip_index;
	u8 src_dip_index;
	u8 ppphd_index;
	u8 dnat_to_host;
	u8 is_dip_rt_ip_same_subnet;
	u8 lan_subnet_index;
	u8 wan_subnet_index;

	/* Link to flow offload entry (for deletion) */
	unsigned long cookie;
} __packed;

/*
 * Flow table entry tracked by driver
 */
struct sf_hnat_flow_entry {
	struct rhash_head node;		/* rhashtable linkage */
	unsigned long cookie;		/* Unique flow identifier */
	struct sf_hashkey key;		/* Hardware key */
	u32 napt_index;			/* Index in NAPT table */
	u64 packets;			/* Packet counter */
	u64 bytes;			/* Byte counter */
	unsigned long last_used;	/* For aging */
};

/*
 * Subnet configuration
 */
struct sf_hnat_subnet {
	__be32 ipaddr;
	u8 prefix_len;
	u8 valid;
	char ifname[IFNAMSIZ];
};

/*
 * Main HNAT private data structure
 */
struct sf_hnat_priv {
	struct device *dev;
	void __iomem *base;		/* HNAT register base */
	struct net_device *ndev;	/* Associated network device */

	/* Flow table */
	struct rhashtable flow_table;
	struct sf_hashkey napt_keys[SF_NAPT_TABLE_MAX];
	struct sf_napt_crc_info napt_crc[SF_NAPT_TABLE_MAX];

	/* Secondary tables */
	struct sf_dip_entry dip_entries[SF_DIP_TABLE_MAX];
	struct sf_dip_crc_info dip_crc[SF_DIP_TABLE_MAX];
	struct sf_dmac_entry dmac_entries[SF_DMAC_TABLE_MAX];
	struct sf_rmac_entry rmac_entries[SF_ROUTER_MAC_TABLE_MAX];
	struct sf_ppphd_entry ppphd_entries[SF_PPPHD_TABLE_MAX];
	struct sf_rt_pub_net_entry rt_pub_net_entries[SF_RT_PUB_NET_TABLE_MAX];
	struct sf_vlan_entry vlan_entries[SF_VLAN_TABLE_MAX];

	/* Current table usage counts */
	u16 curr_napt_num;
	u16 curr_napt_tcp_num;
	u16 curr_napt_udp_num;
	u16 curr_dip_num;
	u8 curr_dmac_num;
	u8 curr_rmac_num;
	u8 curr_ppphd_num;
	u8 curr_rt_pub_net_num;
	u8 curr_vlan_id_num;

	/* Configuration */
	u32 hnat_mode;			/* NAT mode (symmetric, full cone, etc.) */
	bool use_big_endian;		/* Table write endianness */
	bool vlan_replace;		/* VLAN replacement mode */
	bool snat_arp_force_dip;	/* Force DIP for SNAT ARP */
	bool pppoe_padding_dis;		/* Disable PPPoE padding */

	/* Subnet configuration */
	struct sf_hnat_subnet lan_subnet[SF_HNAT_SUBNET_MAX];
	struct sf_hnat_subnet wan_subnet[SF_HNAT_SUBNET_MAX];

	/* WiFi device tracking */
	struct net_device *wifi_ndev[SF_HNAT_WIFI_NDEV_MAX];
	u16 wifi_base;

	/* Timing */
	unsigned long last_age_time;
	unsigned long last_flush_time;

	/* Locks */
	spinlock_t table_lock;		/* Table access lock */
	spinlock_t csr_lock;		/* CSR access lock */
	struct mutex flow_mutex;	/* Flow table mutex */

	/* Statistics */
	u32 add_fail_count;
	u32 update_flow_count;
	u32 crc_clean_flow_count;

	/* Debug */
	struct dentry *debugfs;
};

/*
 * Function prototypes
 */

/* Core HNAT operations */
int sf_hnat_init(struct sf_hnat_priv *priv);
void sf_hnat_deinit(struct sf_hnat_priv *priv);
int sf_hnat_enable(struct sf_hnat_priv *priv);
void sf_hnat_disable(struct sf_hnat_priv *priv);

/* Flow offload operations (TC flower integration) */
int sf_hnat_setup_tc_block(struct net_device *dev,
			   struct flow_block_offload *f);
int sf_hnat_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			      void *cb_priv);

/* Flow entry management */
int sf_hnat_flow_add(struct sf_hnat_priv *priv,
		     struct flow_cls_offload *cls);
int sf_hnat_flow_del(struct sf_hnat_priv *priv,
		     struct flow_cls_offload *cls);
int sf_hnat_flow_stats(struct sf_hnat_priv *priv,
		       struct flow_cls_offload *cls);

/* Low-level table operations */
int sf_hnat_table_write(struct sf_hnat_priv *priv, int table_no,
			int depth, const u32 *data);
int sf_hnat_table_read(struct sf_hnat_priv *priv, int table_no,
		       int depth, u32 *data);

/* Subnet management */
int sf_hnat_add_lan_subnet(struct sf_hnat_priv *priv, u8 index,
			   __be32 ip, u8 prefix_len, const char *ifname);
int sf_hnat_add_wan_subnet(struct sf_hnat_priv *priv, u8 index,
			   __be32 ip, u8 prefix_len, const char *ifname);
int sf_hnat_del_lan_subnet(struct sf_hnat_priv *priv, u8 index);
int sf_hnat_del_wan_subnet(struct sf_hnat_priv *priv, u8 index);

/* Debug/statistics */
void sf_hnat_read_counters(struct sf_hnat_priv *priv);
void sf_hnat_dump_flow(struct sf_hnat_priv *priv, u32 index);

/*
 * Inline helpers
 */

static inline u32 sf_hnat_readl(struct sf_hnat_priv *priv, u32 offset)
{
	return readl(priv->base + offset);
}

static inline void sf_hnat_writel(struct sf_hnat_priv *priv, u32 val, u32 offset)
{
	writel(val, priv->base + offset);
}

static inline bool sf_hnat_is_ipv4(const struct sf_flow_data *data)
{
	return data->v4.src_addr != 0;
}

static inline bool sf_hnat_is_tcp(const struct sf_flow_data *data)
{
	return data->l4proto == IPPROTO_TCP;
}

/*
 * Global instance (for integration with stmmac driver)
 */
extern struct sf_hnat_priv *g_sf_hnat;

#endif /* _SF_HNAT_H_ */
