// SPDX-License-Identifier: GPL-2.0-only
/*
 * Siflower SF19A28 HNAT Driver
 *
 * Hardware NAT acceleration for Siflower SF19A28 SoC
 * The HNAT engine sits between the MAC and DMA in the GMAC block
 * and can accelerate NAT/NAPT flows in hardware.
 *
 * Based on original Siflower SDK code from BPI-WiFi5-Siflower project
 * Adapted for kernel 6.x flow offload API
 *
 * Copyright (C) Siflower Communications
 * Copyright (C) 2024-2026 OpenWrt contributors
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/crc16.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/flow_offload.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/pkt_cls.h>
#include <net/dsa.h>

#include "sf_hnat.h"

#define DRV_NAME	"sf-hnat"
#define DRV_VERSION	"2.0.0"

/* Global instance pointer for stmmac integration */
struct sf_hnat_priv *g_sf_hnat;
EXPORT_SYMBOL(g_sf_hnat);

/* rhashtable parameters for flow tracking */
static const struct rhashtable_params sf_flow_table_params = {
	.head_offset = offsetof(struct sf_hnat_flow_entry, node),
	.key_offset = offsetof(struct sf_hnat_flow_entry, cookie),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};

/* Number of value registers for each table type */
static const u8 table_value_reg_num[32] = {
	0, 1, 0, 0, 1, 0, 4, 1,
	1, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 2, 1, 0,
	1, 0, 0, 0, 0, 0, 0, 0
};

/* Number of entries for each table type */
static const u16 table_entry_num[32] = {
	512,  256,   32,  512,  256,   32, 1024,   32,
	 16,    0,    0,    0,    0,    0,    0,    0,
	256,   64,  512,   16,  128,    8,    8,  128,
	128,    0,    0,    0,    0,    0,    0,    0
};

/* Last value register mask for each table type */
static const u32 table_last_value_mask[32] = {
	0x003fffff, 0x00000fff, 0x003fffff, 0x003fffff,
	0x00000fff, 0x003fffff, 0x00000001, 0x00000000,
	0x00000fff, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x000000ff, 0x000000ff, 0x00003fff, 0x00000000,
	0x0007ffff, 0x00000000, 0x0000ffff, 0x00000fff,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000
};

/*
 * Low-level table access functions
 */

static int sf_hnat_wait_table_ready(struct sf_hnat_priv *priv)
{
	int timeout = 1000;
	u32 val;

	while (timeout--) {
		val = sf_hnat_readl(priv, SF_HNAT_TB_STATUS);
		if (!(val & SF_HNAT_TB_STATUS_BUSY))
			return 0;
		udelay(1);
	}

	dev_err(priv->dev, "HNAT table access timeout\n");
	return -ETIMEDOUT;
}

int sf_hnat_table_write(struct sf_hnat_priv *priv, int table_no,
			int depth, const u32 *data)
{
	unsigned long flags;
	int i, ret;

	if (table_no >= 32 || depth >= table_entry_num[table_no])
		return -EINVAL;

	spin_lock_irqsave(&priv->table_lock, flags);

	ret = sf_hnat_wait_table_ready(priv);
	if (ret)
		goto out;

	/* Write data registers */
	for (i = 0; i < table_value_reg_num[table_no]; i++)
		sf_hnat_writel(priv, data[i], SF_HNAT_TB_WRDATA0 + i * 4);

	/* Write last register with mask if applicable */
	if (table_last_value_mask[table_no])
		sf_hnat_writel(priv, data[i] & table_last_value_mask[table_no],
			       SF_HNAT_TB_WRDATA0 + i * 4);

	/* Set table address: table_no << 16 | depth */
	sf_hnat_writel(priv, (table_no << SF_HNAT_TB_ADDR_NO_SHIFT) | depth,
		       SF_HNAT_TB_ADDRESS);

	/* Trigger write operation */
	sf_hnat_writel(priv, SF_HNAT_TB_OP_WRITE, SF_HNAT_TB_OP_CODE);

	ret = sf_hnat_wait_table_ready(priv);

out:
	spin_unlock_irqrestore(&priv->table_lock, flags);
	return ret;
}

int sf_hnat_table_read(struct sf_hnat_priv *priv, int table_no,
		       int depth, u32 *data)
{
	unsigned long flags;
	int i, ret;

	if (table_no >= 32 || depth >= table_entry_num[table_no])
		return -EINVAL;

	spin_lock_irqsave(&priv->table_lock, flags);

	ret = sf_hnat_wait_table_ready(priv);
	if (ret)
		goto out;

	/* Set table address */
	sf_hnat_writel(priv, (table_no << SF_HNAT_TB_ADDR_NO_SHIFT) | depth,
		       SF_HNAT_TB_ADDRESS);

	/* Trigger read operation */
	sf_hnat_writel(priv, SF_HNAT_TB_OP_READ, SF_HNAT_TB_OP_CODE);

	ret = sf_hnat_wait_table_ready(priv);
	if (ret)
		goto out;

	/* Read data registers */
	for (i = 0; i <= table_value_reg_num[table_no]; i++)
		data[i] = sf_hnat_readl(priv, SF_HNAT_TB_RDDATA0 + i * 4);

out:
	spin_unlock_irqrestore(&priv->table_lock, flags);
	return ret;
}

/*
 * CRC calculation for hash table indexing
 * Uses CRC-16 with polynomial 0x8005
 */
static u16 sf_hnat_calc_crc(const void *data, int len)
{
	return crc16(0, data, len);
}

/*
 * Flow data extraction from TC flower
 */

static int sf_hnat_parse_flow(struct flow_cls_offload *cls,
			      struct sf_flow_data *data)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_match_ipv4_addrs match_ipv4;
	struct flow_match_ports match_ports;
	struct flow_match_basic match_basic;
	struct flow_match_eth_addrs match_eth;
	struct flow_match_vlan match_vlan;

	memset(data, 0, sizeof(*data));

	/* Basic match (L3 proto, L4 proto) */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		flow_rule_match_basic(rule, &match_basic);

		/* Only support IPv4 for now */
		if (match_basic.key->n_proto != htons(ETH_P_IP))
			return -EOPNOTSUPP;

		/* Only support TCP and UDP */
		if (match_basic.key->ip_proto != IPPROTO_TCP &&
		    match_basic.key->ip_proto != IPPROTO_UDP)
			return -EOPNOTSUPP;

		data->l4proto = match_basic.key->ip_proto;
	} else {
		return -EINVAL;
	}

	/* Ethernet addresses */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		flow_rule_match_eth_addrs(rule, &match_eth);
		ether_addr_copy(data->eth.h_source, match_eth.key->src);
		ether_addr_copy(data->eth.h_dest, match_eth.key->dst);
	}

	/* IPv4 addresses */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		flow_rule_match_ipv4_addrs(rule, &match_ipv4);
		data->v4.src_addr = match_ipv4.key->src;
		data->v4.dst_addr = match_ipv4.key->dst;
	} else {
		return -EINVAL;
	}

	/* L4 ports */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		flow_rule_match_ports(rule, &match_ports);
		data->src_port = match_ports.key->src;
		data->dst_port = match_ports.key->dst;
	} else {
		return -EINVAL;
	}

	/* VLAN (optional) */
	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		flow_rule_match_vlan(rule, &match_vlan);
		data->vlan[0].id = match_vlan.key->vlan_id;
		data->vlan[0].proto = match_vlan.key->vlan_tpid;
		data->vlan_num = 1;
	}

	return 0;
}

static int sf_hnat_parse_actions(struct flow_cls_offload *cls,
				 struct sf_flow_data *data)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_action_entry *act;
	int i;

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				/* MAC address rewrite */
				if (act->mangle.offset <= 4) {
					memcpy(data->eth.h_dest + act->mangle.offset,
					       &act->mangle.val,
					       act->mangle.mask ? 2 : 4);
				} else if (act->mangle.offset <= 10) {
					memcpy(data->eth.h_source + act->mangle.offset - 6,
					       &act->mangle.val,
					       act->mangle.mask ? 2 : 4);
				}
				break;

			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				/* IP address rewrite */
				if (act->mangle.offset == offsetof(struct iphdr, saddr))
					memcpy(&data->v4.src_addr, &act->mangle.val, 4);
				else if (act->mangle.offset == offsetof(struct iphdr, daddr))
					memcpy(&data->v4.dst_addr, &act->mangle.val, 4);
				break;

			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
				/* Port rewrite */
				if (act->mangle.offset == 0) {
					u32 val = be32_to_cpu((__force __be32)act->mangle.val);
					if (act->mangle.mask == 0x0000ffff)
						data->dst_port = cpu_to_be16(val);
					else
						data->src_port = cpu_to_be16(val >> 16);
				} else if (act->mangle.offset == 2) {
					data->dst_port = (__force __be16)act->mangle.val;
				}
				break;
			default:
				return -EOPNOTSUPP;
			}
			break;

		case FLOW_ACTION_REDIRECT:
		case FLOW_ACTION_MIRRED:
			/* Output device - we handle this via the ingress/egress path */
			break;

		case FLOW_ACTION_VLAN_PUSH:
			if (data->vlan_num >= 2)
				return -EOPNOTSUPP;
			data->vlan[data->vlan_num].id = act->vlan.vid;
			data->vlan[data->vlan_num].proto = act->vlan.proto;
			data->vlan_num++;
			break;

		case FLOW_ACTION_VLAN_POP:
			if (data->vlan_num > 0)
				data->vlan_num--;
			break;

		case FLOW_ACTION_PPPOE_PUSH:
			data->pppoe = true;
			data->pppoe_sid = act->pppoe.sid;
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

/*
 * Flow entry management
 */

static int sf_hnat_alloc_napt_index(struct sf_hnat_priv *priv,
				    struct sf_hashkey *key)
{
	u16 crc_keys[3];
	u8 hash_data[12];
	int i, index;

	/* Build hash key from 5-tuple */
	memcpy(hash_data, &key->sip, 4);
	memcpy(hash_data + 4, &key->dip, 4);
	memcpy(hash_data + 8, &key->sport, 2);
	memcpy(hash_data + 10, &key->dport, 2);

	/* Calculate CRC for each hash table */
	crc_keys[0] = sf_hnat_calc_crc(hash_data, 12) & 0x1ff;  /* 9 bits */
	crc_keys[1] = sf_hnat_calc_crc(hash_data, 8) & 0xff;    /* 8 bits */
	crc_keys[2] = sf_hnat_calc_crc(hash_data + 4, 8) & 0x1f; /* 5 bits */

	/* Try to find a free slot in the hash tables */
	for (i = 0; i < 3; i++) {
		index = crc_keys[i];
		/* Check if slot is free in NAPT table */
		if (!priv->napt_keys[index].valid)
			return index;
	}

	/* All hash slots full, try linear probing */
	for (index = 0; index < SF_NAPT_TABLE_MAX; index++) {
		if (!priv->napt_keys[index].valid)
			return index;
	}

	return -ENOSPC;
}

static int sf_hnat_build_key(struct sf_hnat_priv *priv,
			     const struct sf_flow_data *data,
			     struct sf_hashkey *key)
{
	memset(key, 0, sizeof(*key));

	key->sip = data->v4.src_addr;
	key->dip = data->v4.dst_addr;
	key->sport = data->src_port;
	key->dport = data->dst_port;
	key->proto = (data->l4proto == IPPROTO_TCP) ? 0 : 1;

	ether_addr_copy(key->src_mac, data->eth.h_source);
	ether_addr_copy(key->dest_mac, data->eth.h_dest);

	if (data->vlan_num > 0)
		key->src_vlan = data->vlan[0].id;
	if (data->vlan_num > 1)
		key->dest_vlan = data->vlan[1].id;

	if (data->pppoe) {
		key->ppp_sid = data->pppoe_sid;
		key->cur_pppoe_en = 1;
	}

	key->valid = 1;

	return 0;
}

static int sf_hnat_program_entry(struct sf_hnat_priv *priv,
				 struct sf_hashkey *key, u32 index)
{
	u32 data[5];
	int ret;

	/* Build NAPT table entry data */
	data[0] = key->sip;
	data[1] = key->dip;
	data[2] = (key->sport << 16) | key->dport;
	data[3] = (key->router_port << 16) | key->proto;
	data[4] = key->valid;

	/* Write to NAPT table */
	ret = sf_hnat_table_write(priv, SF_NAPT_TABLE, index, data);
	if (ret)
		return ret;

	/* Mark entry valid */
	data[0] = 1;
	return sf_hnat_table_write(priv, SF_NAPT_VLD_TABLE, index, data);
}

int sf_hnat_flow_add(struct sf_hnat_priv *priv,
		     struct flow_cls_offload *cls)
{
	struct sf_hnat_flow_entry *entry;
	struct sf_flow_data data;
	struct sf_hashkey key;
	int ret, index;

	/* Parse the flow rule */
	ret = sf_hnat_parse_flow(cls, &data);
	if (ret)
		return ret;

	ret = sf_hnat_parse_actions(cls, &data);
	if (ret)
		return ret;

	/* Build hardware key */
	ret = sf_hnat_build_key(priv, &data, &key);
	if (ret)
		return ret;

	mutex_lock(&priv->flow_mutex);

	/* Allocate NAPT table index */
	index = sf_hnat_alloc_napt_index(priv, &key);
	if (index < 0) {
		ret = index;
		goto out;
	}

	/* Allocate flow entry */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		ret = -ENOMEM;
		goto out;
	}

	entry->cookie = cls->cookie;
	entry->napt_index = index;
	memcpy(&entry->key, &key, sizeof(key));
	entry->key.cookie = cls->cookie;
	entry->last_used = jiffies;

	/* Program hardware */
	ret = sf_hnat_program_entry(priv, &key, index);
	if (ret) {
		kfree(entry);
		goto out;
	}

	/* Save key in local cache */
	memcpy(&priv->napt_keys[index], &key, sizeof(key));

	/* Add to flow table */
	ret = rhashtable_insert_fast(&priv->flow_table, &entry->node,
				     sf_flow_table_params);
	if (ret) {
		kfree(entry);
		priv->napt_keys[index].valid = 0;
		goto out;
	}

	priv->curr_napt_num++;
	if (data.l4proto == IPPROTO_TCP)
		priv->curr_napt_tcp_num++;
	else
		priv->curr_napt_udp_num++;

	dev_dbg(priv->dev, "Added flow %lx at index %d\n", cls->cookie, index);

out:
	mutex_unlock(&priv->flow_mutex);
	return ret;
}

int sf_hnat_flow_del(struct sf_hnat_priv *priv,
		     struct flow_cls_offload *cls)
{
	struct sf_hnat_flow_entry *entry;
	u32 data[5] = {0};
	int ret = 0;

	mutex_lock(&priv->flow_mutex);

	entry = rhashtable_lookup_fast(&priv->flow_table, &cls->cookie,
				       sf_flow_table_params);
	if (!entry) {
		ret = -ENOENT;
		goto out;
	}

	/* Clear hardware entry */
	sf_hnat_table_write(priv, SF_NAPT_VLD_TABLE, entry->napt_index, data);
	sf_hnat_table_write(priv, SF_NAPT_TABLE, entry->napt_index, data);

	/* Clear local cache */
	priv->napt_keys[entry->napt_index].valid = 0;

	/* Update counters */
	priv->curr_napt_num--;
	if (entry->key.proto == 0)
		priv->curr_napt_tcp_num--;
	else
		priv->curr_napt_udp_num--;

	/* Remove from flow table */
	rhashtable_remove_fast(&priv->flow_table, &entry->node,
			       sf_flow_table_params);

	dev_dbg(priv->dev, "Deleted flow %lx from index %d\n",
		cls->cookie, entry->napt_index);

	kfree(entry);

out:
	mutex_unlock(&priv->flow_mutex);
	return ret;
}

int sf_hnat_flow_stats(struct sf_hnat_priv *priv,
		       struct flow_cls_offload *cls)
{
	struct sf_hnat_flow_entry *entry;
	u32 data[8];
	int ret;

	mutex_lock(&priv->flow_mutex);

	entry = rhashtable_lookup_fast(&priv->flow_table, &cls->cookie,
				       sf_flow_table_params);
	if (!entry) {
		mutex_unlock(&priv->flow_mutex);
		return -ENOENT;
	}

	/* Read statistics from hardware */
	ret = sf_hnat_table_read(priv, SF_STATISTICS_TABLE, entry->napt_index, data);
	if (ret == 0) {
		u64 packets = ((u64)data[1] << 32) | data[0];
		u64 bytes = ((u64)data[3] << 32) | data[2];

		/* Report delta since last read */
		flow_stats_update(&cls->stats,
				  bytes - entry->bytes,
				  packets - entry->packets,
				  0,
				  entry->last_used,
				  FLOW_ACTION_HW_STATS_DELAYED);

		entry->packets = packets;
		entry->bytes = bytes;
		entry->last_used = jiffies;
	}

	mutex_unlock(&priv->flow_mutex);
	return ret;
}

/*
 * TC flower block callback
 */

int sf_hnat_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			      void *cb_priv)
{
	struct net_device *dev = cb_priv;
	struct sf_hnat_priv *priv = g_sf_hnat;
	struct flow_cls_offload *cls = type_data;

	if (!priv)
		return -ENODEV;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (cls->command) {
	case FLOW_CLS_REPLACE:
		return sf_hnat_flow_add(priv, cls);
	case FLOW_CLS_DESTROY:
		return sf_hnat_flow_del(priv, cls);
	case FLOW_CLS_STATS:
		return sf_hnat_flow_stats(priv, cls);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(sf_hnat_setup_tc_block_cb);

int sf_hnat_setup_tc_block(struct net_device *dev,
			   struct flow_block_offload *f)
{
	static LIST_HEAD(block_cb_list);
	struct flow_block_cb *block_cb;
	flow_setup_cb_t *cb = sf_hnat_setup_tc_block_cb;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	f->driver_block_list = &block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		block_cb = flow_block_cb_lookup(f->block, cb, dev);
		if (block_cb) {
			flow_block_cb_incref(block_cb);
			return 0;
		}

		block_cb = flow_block_cb_alloc(cb, dev, dev, NULL);
		if (IS_ERR(block_cb))
			return PTR_ERR(block_cb);

		flow_block_cb_incref(block_cb);
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &block_cb_list);
		return 0;

	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block, cb, dev);
		if (!block_cb)
			return -ENOENT;

		if (!flow_block_cb_decref(block_cb)) {
			flow_block_cb_remove(block_cb, f);
			list_del(&block_cb->driver_list);
		}
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(sf_hnat_setup_tc_block);

/*
 * Hardware initialization
 */

static void sf_hnat_hw_init(struct sf_hnat_priv *priv)
{
	u32 val;

	/* Configure table access */
	val = SF_HNAT_TB_CONFIG_ENTB;  /* Enable all tables */
	if (priv->use_big_endian)
		val |= SF_HNAT_TB_CONFIG_BIG_ENDIAN;
	sf_hnat_writel(priv, val, SF_HNAT_TB_CONFIG);

	/* Set NAT mode */
	sf_hnat_writel(priv, priv->hnat_mode, SF_HNAT_REG0_CSR);

	dev_info(priv->dev, "HNAT hardware initialized, mode=0x%x\n",
		 priv->hnat_mode);
}

int sf_hnat_init(struct sf_hnat_priv *priv)
{
	int ret;

	/* Initialize flow table */
	ret = rhashtable_init(&priv->flow_table, &sf_flow_table_params);
	if (ret)
		return ret;

	/* Initialize hardware */
	sf_hnat_hw_init(priv);

	dev_info(priv->dev, "HNAT initialized with %d max flows\n",
		 SF_NAPT_TABLE_MAX);

	return 0;
}
EXPORT_SYMBOL(sf_hnat_init);

void sf_hnat_deinit(struct sf_hnat_priv *priv)
{
	/* Flush all flows */
	rhashtable_destroy(&priv->flow_table);

	dev_info(priv->dev, "HNAT deinitialized\n");
}
EXPORT_SYMBOL(sf_hnat_deinit);

int sf_hnat_enable(struct sf_hnat_priv *priv)
{
	/* Enable HNAT in the CSR */
	u32 val = sf_hnat_readl(priv, SF_HNAT_REG0_CSR);
	val |= BIT(0);  /* Enable bit */
	sf_hnat_writel(priv, val, SF_HNAT_REG0_CSR);

	dev_info(priv->dev, "HNAT enabled\n");
	return 0;
}
EXPORT_SYMBOL(sf_hnat_enable);

void sf_hnat_disable(struct sf_hnat_priv *priv)
{
	u32 val = sf_hnat_readl(priv, SF_HNAT_REG0_CSR);
	val &= ~BIT(0);
	sf_hnat_writel(priv, val, SF_HNAT_REG0_CSR);

	dev_info(priv->dev, "HNAT disabled\n");
}
EXPORT_SYMBOL(sf_hnat_disable);

/*
 * Debug/statistics functions
 */

void sf_hnat_read_counters(struct sf_hnat_priv *priv)
{
	dev_info(priv->dev, "HNAT Statistics:\n");
	dev_info(priv->dev, "  RX enter SOF: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_RX_ENTER_SOF_CNT_L));
	dev_info(priv->dev, "  RX to host: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_RX_2HOST_SOF_CNT_L));
	dev_info(priv->dev, "  RX2TX: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_RX2TX_DATA_CNT));
	dev_info(priv->dev, "  TX nohits: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_TX_NOHITS_CNT));
	dev_info(priv->dev, "  RX INAT: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_RX_INAT_CNT));
	dev_info(priv->dev, "  TX ENAT: %u\n",
		 sf_hnat_readl(priv, SF_HNAT_TX_ENAT_CNT));
}
EXPORT_SYMBOL(sf_hnat_read_counters);

/*
 * Get HNAT base address from stmmac driver
 */
extern void __iomem *sf19a2890_get_hnat_base(void) __attribute__((weak));

/*
 * Module initialization
 *
 * The HNAT registers are part of the GMAC address space.
 * We get the base address from the stmmac glue driver.
 */
static struct sf_hnat_priv *sf_hnat_priv_alloc(void)
{
	struct sf_hnat_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	/* Initialize locks */
	spin_lock_init(&priv->table_lock);
	spin_lock_init(&priv->csr_lock);
	mutex_init(&priv->flow_mutex);

	/* Default configuration */
	priv->hnat_mode = SF_HNAT_MODE_SYMMETRIC;
	priv->use_big_endian = true;
	priv->wifi_base = 4000;

	return priv;
}

static int __init sf_hnat_module_init(void)
{
	struct sf_hnat_priv *priv;
	void __iomem *base;
	int ret;

	/* Check if stmmac driver exported the HNAT base */
	if (!sf19a2890_get_hnat_base) {
		pr_info("sf-hnat: stmmac driver not loaded or doesn't export HNAT base\n");
		return -ENODEV;
	}

	base = sf19a2890_get_hnat_base();
	if (!base) {
		pr_info("sf-hnat: HNAT base not available yet\n");
		return -EPROBE_DEFER;
	}

	priv = sf_hnat_priv_alloc();
	if (!priv)
		return -ENOMEM;

	priv->base = base;

	ret = sf_hnat_init(priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	g_sf_hnat = priv;

	pr_info("Siflower HNAT driver v%s loaded, base=%p\n", DRV_VERSION, base);

	return 0;
}

static void __exit sf_hnat_module_exit(void)
{
	struct sf_hnat_priv *priv = g_sf_hnat;

	if (!priv)
		return;

	g_sf_hnat = NULL;

	sf_hnat_deinit(priv);
	kfree(priv);

	pr_info("Siflower HNAT driver unloaded\n");
}

module_init(sf_hnat_module_init);
module_exit(sf_hnat_module_exit);

MODULE_DESCRIPTION("Siflower SF19A28 HNAT Driver");
MODULE_AUTHOR("OpenWrt contributors");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
