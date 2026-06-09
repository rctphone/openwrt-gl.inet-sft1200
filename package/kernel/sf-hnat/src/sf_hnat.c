// SPDX-License-Identifier: GPL-2.0-only
/*
 * Siflower SF19A28 HNAT Driver
 *
 * Hardware NAT acceleration for Siflower SF19A28 SoC
 * The HNAT engine sits between the MAC and DMA in the GMAC block
 * and can accelerate NAT/NAPT flows in hardware.
 *
 * Based on original Siflower SDK code from BPI-WiFi5-Siflower project
 * (openwrt-18.06/package/kernel/sf_hnat). Table programming logic is a
 * faithful port of the SDK; the datapath integration is rewritten for
 * the kernel 6.x nf_flow_table offload API:
 *
 *  - flows arrive as paired FLOW_CLS_REPLACE rules (one per direction)
 *    via an indirect flow block (flow_indr_dev_register); both halves
 *    are correlated by their post-NAT tuple and programmed as a single
 *    symmetric NAPT entry
 *  - port identification uses dsa_tag_8021q VIDs (the switch runs the
 *    tag_mxl_gsw1xx_8021q DSA tagger), replacing the vendor eth0.X
 *    VLAN-subinterface scheme
 *  - router LAN/WAN subnets are learned from inetaddr notifiers,
 *    replacing the vendor devinet.c kernel patch
 *
 * Not ported from the SDK: WiFi forwarding (skb->cb hacks in dev.c and
 * the pseudo-VLAN wifi_base scheme) — impossible without core kernel
 * patches and vendor WiFi driver hooks. WiFi flows are served by the
 * software flowtable fastpath instead.
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
#include <linux/seq_file.h>
#include <linux/inetdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dsa/8021q.h>
#include <net/dsa.h>
#include <net/flow_offload.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/pkt_cls.h>

#include "sf_hnat.h"

#define DRV_NAME	"sf-hnat"
#define DRV_VERSION	"2.1.0"

/* Global instance pointer for stmmac integration */
struct sf_hnat_priv *g_sf_hnat;
EXPORT_SYMBOL(g_sf_hnat);

/* Interface classification for the inetaddr notifier */
static char *lan_ifnames = "br-lan";
module_param(lan_ifnames, charp, 0444);
MODULE_PARM_DESC(lan_ifnames, "comma separated LAN interface names");

static char *wan_ifnames = "wan,pppoe-wan";
module_param(wan_ifnames, charp, 0444);
MODULE_PARM_DESC(wan_ifnames, "comma separated WAN interface names");

/* Pending (half-assembled) flow pairs are dropped after this */
#define SF_HNAT_PENDING_TIMEOUT	(5 * HZ)

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

/* Hash table secondary-bank index offsets (SDK constants) */
#define SF_NAPT_HASH2_INDEX_OFFSET	2
#define SF_NAPT_HASH3_INDEX_OFFSET	6
#define SF_DIP_HASH2_INDEX_OFFSET	4

/* "no VLAN" index sentinel used by the hardware */
#define SF_VLAN_INDEX_NONE		0x7f

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

static void sf_hnat_table_clean(struct sf_hnat_priv *priv)
{
	u32 data[7] = {0};
	int table_no, depth;

	for (table_no = 0; table_no < 32; table_no++) {
		for (depth = 0; depth < table_entry_num[table_no]; depth++)
			sf_hnat_table_write(priv, table_no, depth, data);
	}
}

/*
 * CRC helpers (faithful port of the SDK bit layout)
 */

/* vlan index is 7 bit; rcc shifts for the ARP/DIP hash key */
static void sf_hnat_rcc_dip(u8 *data)
{
	int i;

	for (i = 3; i >= 0; i--) {
		data[i + 1] &= 0x7f;
		data[i + 1] |= (data[i] & 0x1) << 7;
		data[i] >>= 1;
	}
}

static u16 sf_hnat_crc16(const u8 *buf, u8 len, u16 *crc_key)
{
	u16 crc_value = 0;
	u16 crc2_value = 0;
	const u8 *p = buf;
	u8 n = len;
	int i;

	while (n > 0) {
		crc_value ^= *p++ << 8;
		for (i = 0; i < 8; i++) {
			if (crc_value & 0x8000)
				crc_value = (crc_value << 1) ^ 0x1021;
			else
				crc_value <<= 1;
		}
		n--;
	}

	p = buf;
	n = len;
	while (n > 0) {
		crc2_value ^= *p++ << 8;
		for (i = 0; i < 8; i++) {
			if (crc2_value & 0x8000)
				crc2_value = (crc2_value << 1) ^ 0x8005;
			else
				crc2_value <<= 1;
		}
		n--;
	}

	crc_key[0] = (crc_value & 0xff80) >> 7;
	crc_key[1] = crc_value & 0xff;
	crc_key[2] = (crc2_value & 0x1f0) >> 4;
	return crc_value;
}

static int sf_napt_key_crc_get(struct sf_hnat_priv *priv,
			       struct sf_hashkey *key,
			       u16 *crc_key, bool is_inat)
{
	u8 crc_data[13] = {0};

	/* SYMMETRIC mode layout; other SDK modes intentionally dropped */
	crc_data[0] = key->proto;
	if (!is_inat) {
		memcpy(crc_data + 1, &key->sport, 2);
		memcpy(crc_data + 3, &key->sip, 4);
		memcpy(crc_data + 7, &key->dport, 2);
		memcpy(crc_data + 9, &key->dip, 4);
	} else {
		memcpy(crc_data + 1, &key->dport, 2);
		memcpy(crc_data + 3, &key->dip, 4);
		memcpy(crc_data + 7, &key->router_port, 2);
		memcpy(crc_data + 9, &key->router_pub_ip, 4);
	}

	return sf_hnat_crc16(crc_data, 13, crc_key);
}

/*
 * Valid-bit tables (bitmap, 32 entries per word)
 */

static void sf_hnat_napt_vld_cfg(struct sf_hnat_priv *priv, u16 napt_index,
				 bool enable)
{
	u32 data[7] = {0};
	int depth = napt_index / 32;

	sf_hnat_table_read(priv, SF_NAPT_VLD_TABLE, depth, data);
	if (enable)
		data[0] |= BIT(napt_index % 32);
	else
		data[0] &= ~BIT(napt_index % 32);
	sf_hnat_table_write(priv, SF_NAPT_VLD_TABLE, depth, data);
}

static void sf_hnat_dip_vld_cfg(struct sf_hnat_priv *priv, u16 dip_index,
				bool enable)
{
	u32 data[7] = {0};
	int depth = dip_index / 32;

	sf_hnat_table_read(priv, SF_DIP_VLD_TABLE, depth, data);
	if (enable)
		data[0] |= BIT(dip_index % 32);
	else
		data[0] &= ~BIT(dip_index % 32);
	sf_hnat_table_write(priv, SF_DIP_VLD_TABLE, depth, data);
}

/*
 * Router MAC table (our own interface MACs, 8 entries)
 */

static void sf_hnat_del_router_mac(struct sf_hnat_priv *priv, u8 rmac_index)
{
	u32 data[7] = {0};
	struct sf_rmac_entry *e = &priv->rmac_entries[rmac_index];

	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0) {
		e->valid = 0;
		priv->curr_rmac_num--;
		sf_hnat_table_write(priv, SF_ROUTER_MAC_TABLE, rmac_index, data);
	}
}

static int sf_hnat_search_router_mac(struct sf_hnat_priv *priv,
				     const u8 *mac, bool is_add)
{
	u8 i;

	for (i = 0; i < SF_ROUTER_MAC_TABLE_MAX; i++) {
		struct sf_rmac_entry *e = &priv->rmac_entries[i];

		if (!e->valid)
			continue;
		if (ether_addr_equal(e->rmac, mac)) {
			if (is_add)
				e->ref_count++;
			else
				sf_hnat_del_router_mac(priv, i);
			return i;
		}
	}
	return -1;
}

static int sf_hnat_add_router_mac(struct sf_hnat_priv *priv, const u8 *mac)
{
	u32 data[7] = {0};
	struct sf_rmac_entry *e;
	int ret;
	u8 i;

	ret = sf_hnat_search_router_mac(priv, mac, true);
	if (ret >= 0)
		return ret;

	for (i = 0; i < SF_ROUTER_MAC_TABLE_MAX; i++) {
		if (!priv->rmac_entries[i].valid)
			break;
	}
	if (i == SF_ROUTER_MAC_TABLE_MAX) {
		dev_err(priv->dev, "router mac table full\n");
		return -1;
	}

	e = &priv->rmac_entries[i];
	memcpy(e->rmac, mac, ETH_ALEN);

	/* bits 0..47: MAC */
	memcpy(&data[0], e->rmac, 4);
	memcpy(&data[1], e->rmac + 4, 2);
	sf_hnat_table_write(priv, SF_ROUTER_MAC_TABLE, i, data);

	e->valid = 1;
	e->ref_count = 1;
	priv->curr_rmac_num++;
	return i;
}

/*
 * DMAC table (next-hop/peer MACs, 128 entries, references router MAC)
 */

static void sf_hnat_dmac_write(struct sf_hnat_priv *priv, u8 dmac_index)
{
	struct sf_dmac_entry *e = &priv->dmac_entries[dmac_index];
	u32 data[7] = {0};
	u16 hi;

	/* bits 0..47: DA, bits 48..50: router mac index */
	memcpy(&data[0], e->dmac, 4);
	memcpy(&hi, e->dmac + 4, 2);
	data[1] = hi | (e->router_mac_index << 16);
	sf_hnat_table_write(priv, SF_DMAC_TABLE, dmac_index, data);
}

static void sf_hnat_del_dmac(struct sf_hnat_priv *priv, u8 dmac_index)
{
	struct sf_dmac_entry *e = &priv->dmac_entries[dmac_index];
	u32 data[7] = {0};

	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0) {
		sf_hnat_del_router_mac(priv, e->router_mac_index);
		sf_hnat_table_write(priv, SF_DMAC_TABLE, dmac_index, data);
		e->valid = 0;
		priv->curr_dmac_num--;
	}
}

static int sf_hnat_search_dmac(struct sf_hnat_priv *priv, const u8 *mac,
			       bool is_add, const u8 *router_mac)
{
	u8 i;

	for (i = 0; i < SF_DMAC_TABLE_MAX; i++) {
		struct sf_dmac_entry *e = &priv->dmac_entries[i];

		if (!e->valid)
			continue;
		if (!ether_addr_equal(e->dmac, mac))
			continue;
		if (!ether_addr_equal(priv->rmac_entries[e->router_mac_index].rmac,
				      router_mac))
			continue;

		if (is_add)
			e->ref_count++;
		else
			sf_hnat_del_dmac(priv, i);
		return i;
	}
	return -1;
}

static int sf_hnat_add_dmac(struct sf_hnat_priv *priv, const u8 *mac,
			    const u8 *router_mac)
{
	struct sf_dmac_entry *e;
	int rmac_index;
	int ret;
	u8 i;

	ret = sf_hnat_search_dmac(priv, mac, true, router_mac);
	if (ret >= 0)
		return ret;

	for (i = 0; i < SF_DMAC_TABLE_MAX; i++) {
		if (!priv->dmac_entries[i].valid)
			break;
	}
	if (i == SF_DMAC_TABLE_MAX) {
		dev_err(priv->dev, "dmac table full\n");
		return -1;
	}

	e = &priv->dmac_entries[i];
	memcpy(e->dmac, mac, ETH_ALEN);

	rmac_index = sf_hnat_add_router_mac(priv, router_mac);
	if (rmac_index < 0)
		return -1;
	e->router_mac_index = rmac_index;

	sf_hnat_dmac_write(priv, i);
	e->valid = 1;
	e->ref_count = 1;
	priv->curr_dmac_num++;
	return i;
}

/*
 * VLAN ID table (dsa_tag_8021q VIDs of switch ports, 128 entries)
 */

static void sf_hnat_del_vlan(struct sf_hnat_priv *priv, u8 vlan_index)
{
	struct sf_vlan_entry *e;
	u32 data[7] = {0};

	if (vlan_index == SF_VLAN_INDEX_NONE)
		return;

	e = &priv->vlan_entries[vlan_index];
	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0) {
		sf_hnat_table_write(priv, SF_VLAN_ID_TABLE, vlan_index, data);
		e->valid = 0;
		priv->curr_vlan_id_num--;
	}
}

static int sf_hnat_search_vlan(struct sf_hnat_priv *priv, u16 vlan_id,
			       bool is_add)
{
	u8 i;

	for (i = 0; i < SF_VLAN_TABLE_MAX; i++) {
		struct sf_vlan_entry *e = &priv->vlan_entries[i];

		if (!e->valid)
			continue;
		if (e->vlan_id == vlan_id) {
			if (is_add)
				e->ref_count++;
			else
				sf_hnat_del_vlan(priv, i);
			return i;
		}
	}
	return -1;
}

static int sf_hnat_add_vlan(struct sf_hnat_priv *priv, u16 vlan_id)
{
	struct sf_vlan_entry *e;
	u32 data[7] = {0};
	int ret;
	u8 i;

	if (vlan_id == 0)
		return SF_VLAN_INDEX_NONE;

	ret = sf_hnat_search_vlan(priv, vlan_id, true);
	if (ret >= 0)
		return ret;

	for (i = 0; i < SF_VLAN_TABLE_MAX; i++) {
		if (!priv->vlan_entries[i].valid)
			break;
	}
	if (i == SF_VLAN_TABLE_MAX) {
		dev_err(priv->dev, "vlan table full\n");
		return -1;
	}

	e = &priv->vlan_entries[i];
	e->vlan_id = vlan_id;
	data[0] = vlan_id;
	sf_hnat_table_write(priv, SF_VLAN_ID_TABLE, i, data);
	e->valid = 1;
	e->ref_count = 1;
	priv->curr_vlan_id_num++;
	return i;
}

/*
 * PPPoE header table (8 entries)
 */

static void sf_hnat_del_ppphd(struct sf_hnat_priv *priv, u8 ppphd_index)
{
	struct sf_ppphd_entry *e = &priv->ppphd_entries[ppphd_index];
	u32 data[7] = {0};

	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0 && e->valid) {
		sf_hnat_table_write(priv, SF_PPPOE_HD_TABLE, ppphd_index, data);
		e->valid = 0;
		if (priv->curr_ppphd_num)
			priv->curr_ppphd_num--;
	}
}

static int sf_hnat_add_ppphd(struct sf_hnat_priv *priv, u16 session_id)
{
	struct sf_ppphd_entry *e;
	u32 data[7] = {0};
	u8 i;

	for (i = 0; i < SF_PPPHD_TABLE_MAX; i++) {
		e = &priv->ppphd_entries[i];
		if (e->valid && e->session_id == session_id) {
			e->ref_count++;
			return i;
		}
	}

	for (i = 0; i < SF_PPPHD_TABLE_MAX; i++) {
		if (!priv->ppphd_entries[i].valid)
			break;
	}
	if (i == SF_PPPHD_TABLE_MAX) {
		dev_err(priv->dev, "ppphd table full\n");
		return -1;
	}

	e = &priv->ppphd_entries[i];
	e->session_id = session_id;

	/* PPP protocol 0x0021 (IPv4) + PPPoE version/type/session */
	data[0] = 0x00000021;
	data[1] = 0x11000000 | session_id;
	sf_hnat_table_write(priv, SF_PPPOE_HD_TABLE, i, data);

	e->valid = 1;
	e->ref_count = 1;
	priv->curr_ppphd_num++;
	return i;
}

/*
 * Router public network table (16 entries)
 */

static void sf_hnat_del_rt_pub_net(struct sf_hnat_priv *priv, u8 index)
{
	struct sf_rt_pub_net_entry *e = &priv->rt_pub_net_entries[index];
	u32 data[7] = {0};

	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0) {
		e->valid = 0;
		priv->curr_rt_pub_net_num--;
		sf_hnat_table_write(priv, SF_RT_PUB_NET_TABLE, index, data);
	}
}

static int sf_hnat_add_rt_pub_net(struct sf_hnat_priv *priv,
				  u8 pub_vlan_index,
				  struct sf_hashkey *key)
{
	struct sf_rt_pub_net_entry *e;
	u32 data[7] = {0};
	u8 prefix_len;
	u8 i;

	for (i = 0; i < SF_RT_PUB_NET_TABLE_MAX; i++) {
		e = &priv->rt_pub_net_entries[i];
		if (!e->valid)
			continue;
		if (e->pub_vlan_index == pub_vlan_index &&
		    e->router_pub_ip == key->router_pub_ip) {
			e->ref_count++;
			return i;
		}
	}

	for (i = 0; i < SF_RT_PUB_NET_TABLE_MAX; i++) {
		if (!priv->rt_pub_net_entries[i].valid)
			break;
	}
	if (i == SF_RT_PUB_NET_TABLE_MAX) {
		dev_err(priv->dev, "rt_pub_net table full\n");
		return -1;
	}

	e = &priv->rt_pub_net_entries[i];
	prefix_len = priv->wan_subnet[key->wan_subnet_index].prefix_len;
	e->rt_ip_mask = (prefix_len >= 32) ? 31 : prefix_len;
	e->pub_vlan_index = pub_vlan_index;
	e->router_pub_ip = key->router_pub_ip;

	data[0] = (__force u32)e->router_pub_ip;
	data[1] = e->rt_ip_mask | (e->pub_vlan_index << 5);
	sf_hnat_table_write(priv, SF_RT_PUB_NET_TABLE, i, data);

	e->valid = 1;
	e->ref_count = 1;
	priv->curr_rt_pub_net_num++;
	return i;
}

/*
 * DIP table + its two CRC hash banks
 */

static int sf_hnat_dip_hash_add(struct sf_hnat_priv *priv, int tab_no,
				u16 hash_index, u16 dip_index, int nptr)
{
	u32 data[7] = {0};
	u32 valid;
	int i;

	sf_hnat_table_read(priv, tab_no, hash_index, data);
	valid = data[1] & 0xf0;

	for (i = 0; i < 4; i++) {
		/* SDK RM#9392: pointer slot 2 of HASH1 is unusable */
		if (tab_no == SF_DIP_HASH1 && i == 2)
			continue;
		if (!(valid & BIT(i + 4)))
			break;
	}
	if (i >= nptr)
		return -1;

	if (i < 3) {
		data[0] &= ~(0x1ff << (i * 9));
		data[0] |= dip_index << (i * 9);
		data[1] |= BIT(i + 4);
	} else {
		data[0] &= ~(0x1f << (i * 9));
		data[1] &= ~0xf;
		data[0] |= (dip_index & 0x1f) << (i * 9);
		data[1] |= BIT(i + 4) | ((dip_index & 0x1e0) >> 5);
	}
	sf_hnat_table_write(priv, tab_no, hash_index, data);
	return i;
}

static int sf_hnat_add_dip_crc_hash_entry(struct sf_hnat_priv *priv,
					  u16 dip_index, u16 crc_value)
{
	struct sf_dip_crc_info *info = &priv->dip_crc[dip_index];
	u16 *crc_key = info->dip_crc_key;
	int ret;

	crc_key[0] = crc_value & 0xff;
	crc_key[1] = (crc_value & 0xfc00) >> 10;

	ret = sf_hnat_dip_hash_add(priv, SF_DIP_HASH1, crc_key[0],
				   dip_index, 4);
	if (ret >= 0) {
		info->dip_ptr_index = ret;
		return ret;
	}

	ret = sf_hnat_dip_hash_add(priv, SF_DIP_HASH2, crc_key[1],
				   dip_index, 4);
	if (ret >= 0) {
		info->dip_ptr_index = ret + SF_DIP_HASH2_INDEX_OFFSET;
		return ret;
	}

	priv->dip_hash_full_count++;
	return -1;
}

static void sf_hnat_dip_del_crc_hash_entry(struct sf_hnat_priv *priv,
					   struct sf_dip_crc_info *info)
{
	u8 index = info->dip_ptr_index;
	u32 data[7] = {0};

	if (index < SF_DIP_HASH2_INDEX_OFFSET) {
		sf_hnat_table_read(priv, SF_DIP_HASH1, info->dip_crc_key[0], data);
		data[1] &= ~BIT(index + 4);
		sf_hnat_table_write(priv, SF_DIP_HASH1, info->dip_crc_key[0], data);
	} else {
		index -= SF_DIP_HASH2_INDEX_OFFSET;
		sf_hnat_table_read(priv, SF_DIP_HASH2, info->dip_crc_key[1], data);
		data[1] &= ~BIT(index + 4);
		sf_hnat_table_write(priv, SF_DIP_HASH2, info->dip_crc_key[1], data);
	}
}

static void sf_hnat_dip_write(struct sf_hnat_priv *priv, u16 dip_index)
{
	struct sf_dip_entry *e = &priv->dip_entries[dip_index];
	u32 data[7] = {0};

	/* bits 0..31 dip, 32..38 dmac index, 39..45 vlan index */
	data[0] = (__force u32)e->dip;
	data[1] = (e->vlan_index << 7) | e->dmac_index;
	sf_hnat_table_write(priv, SF_DIP_TABLE, dip_index, data);
}

static void sf_hnat_del_dip(struct sf_hnat_priv *priv, u16 dip_index)
{
	struct sf_dip_entry *e = &priv->dip_entries[dip_index];
	u32 data[7] = {0};

	if (e->ref_count > 0)
		e->ref_count--;

	if (e->ref_count == 0) {
		sf_hnat_dip_vld_cfg(priv, dip_index, false);
		sf_hnat_del_dmac(priv, e->dmac_index);
		sf_hnat_table_write(priv, SF_DIP_TABLE, dip_index, data);
		sf_hnat_dip_del_crc_hash_entry(priv, &priv->dip_crc[dip_index]);
		e->valid = 0;
		priv->curr_dip_num--;
	}
}

static int sf_hnat_search_dip(struct sf_hnat_priv *priv, __be32 ip,
			      u8 vlan_index, bool is_add)
{
	u16 i;

	for (i = 0; i < SF_DIP_TABLE_MAX; i++) {
		struct sf_dip_entry *e = &priv->dip_entries[i];

		if (!e->valid)
			continue;
		if (e->dip == ip && e->vlan_index == vlan_index) {
			if (is_add)
				e->ref_count++;
			else
				sf_hnat_del_dip(priv, i);
			return i;
		}
	}
	return -1;
}

/* sip side is the private (LAN) host, dip side is the public peer */
static int sf_hnat_add_dip(struct sf_hnat_priv *priv, struct sf_hashkey *key,
			   bool is_sip)
{
	u8 crc_data[5] = {0};
	u16 crc_key[3] = {0};
	const u8 *op_mac, *router_mac;
	struct sf_dip_entry *e;
	u16 crc_value;
	__be32 op_ip;
	u8 vlan_index;
	int dmac_index;
	int ret;
	u16 i;

	if (is_sip) {
		op_ip = key->sip;
		vlan_index = key->src_vlan_index;
		op_mac = key->src_mac;
		router_mac = key->router_src_mac;
	} else {
		/*
		 * When the remote IP is outside the WAN subnet the next hop
		 * is the WAN gateway: ARP/forwarding must use the router
		 * public IP entry instead of the remote IP itself.
		 */
		if (!priv->snat_arp_force_dip && !key->is_dip_rt_ip_same_subnet)
			op_ip = key->router_pub_ip;
		else
			op_ip = key->dip;
		vlan_index = key->dest_vlan_index;
		op_mac = key->dest_mac;
		router_mac = key->router_dest_mac;
	}

	ret = sf_hnat_search_dip(priv, op_ip, vlan_index, true);
	if (ret >= 0) {
		e = &priv->dip_entries[ret];
		/* Peer MAC changed (ARP update): refresh the DMAC */
		if (!ether_addr_equal(priv->dmac_entries[e->dmac_index].dmac,
				      op_mac)) {
			sf_hnat_del_dmac(priv, e->dmac_index);
			dmac_index = sf_hnat_add_dmac(priv, op_mac, router_mac);
			if (dmac_index < 0) {
				sf_hnat_del_dip(priv, ret);
				return -1;
			}
			e->dmac_index = dmac_index;
			sf_hnat_dip_write(priv, ret);
		}
		return ret;
	}

	for (i = 0; i < SF_DIP_TABLE_MAX; i++) {
		if (!priv->dip_entries[i].valid)
			break;
	}
	if (i == SF_DIP_TABLE_MAX) {
		dev_err(priv->dev, "dip table full\n");
		return -1;
	}

	e = &priv->dip_entries[i];
	e->dip = op_ip;
	e->vlan_index = vlan_index;

	dmac_index = sf_hnat_add_dmac(priv, op_mac, router_mac);
	if (dmac_index < 0)
		return -1;
	e->dmac_index = dmac_index;

	memcpy(crc_data, &e->dip, 4);
	crc_data[4] = vlan_index;
	sf_hnat_rcc_dip(crc_data);
	crc_value = sf_hnat_crc16(crc_data, 5, crc_key);

	ret = sf_hnat_add_dip_crc_hash_entry(priv, i, crc_value);
	if (ret < 0) {
		sf_hnat_del_dmac(priv, dmac_index);
		return -1;
	}

	sf_hnat_dip_write(priv, i);
	sf_hnat_dip_vld_cfg(priv, i, true);
	e->valid = 1;
	e->ref_count = 1;
	priv->curr_dip_num++;
	return i;
}

/*
 * NAPT CRC hash banks (3 per direction)
 */

static int sf_hnat_napt_hash_add_13(struct sf_hnat_priv *priv, int tab_no,
				    u16 hash_index, u16 napt_index)
{
	u32 data[7] = {0};
	u32 valid;
	int i;

	sf_hnat_table_read(priv, tab_no, hash_index, data);
	valid = data[0] & 0x300000;

	for (i = 0; i < 2; i++) {
		if (!(valid & BIT(i + 20)))
			break;
	}
	if (i == 2)
		return -1;

	data[0] &= ~(0x3ff << (i * 10));
	data[0] |= (napt_index << (i * 10)) | BIT(i + 20);
	sf_hnat_table_write(priv, tab_no, hash_index, data);
	return i;
}

static int sf_hnat_napt_hash_add_2(struct sf_hnat_priv *priv, int tab_no,
				   u16 hash_index, u16 napt_index)
{
	u32 data[7] = {0};
	u32 valid;
	int i;

	sf_hnat_table_read(priv, tab_no, hash_index, data);
	valid = data[1] & 0xf00;

	for (i = 0; i < 4; i++) {
		if (!(valid & BIT(i + 8)))
			break;
	}
	if (i == 4)
		return -1;

	if (i < 3) {
		data[0] &= ~(0x3ff << (i * 10));
		data[0] |= napt_index << (i * 10);
		data[1] |= BIT(i + 8);
	} else {
		data[0] &= ~(0x3 << (i * 10));
		data[1] &= ~0xff;
		data[0] |= (napt_index & 0x3) << (i * 10);
		data[1] |= BIT(i + 8) | ((napt_index & 0x3fc) >> 2);
	}
	sf_hnat_table_write(priv, tab_no, hash_index, data);
	return i;
}

static int sf_hnat_napt_hash_add_dir(struct sf_hnat_priv *priv,
				     struct sf_napt_crc_info *info,
				     u16 napt_index,
				     struct sf_hashkey *key, bool is_inat)
{
	int tab_no_start = is_inat ? SF_INAT_NAPT_HASH1 : SF_ENAT_NAPT_HASH1;
	u16 *crc_key = is_inat ? info->inat_crc_key : info->enat_crc_key;
	int ret;

	sf_napt_key_crc_get(priv, key, crc_key, is_inat);

	ret = sf_hnat_napt_hash_add_13(priv, tab_no_start, crc_key[0],
				       napt_index);
	if (ret >= 0)
		return ret;

	ret = sf_hnat_napt_hash_add_2(priv, tab_no_start + 1, crc_key[1],
				      napt_index);
	if (ret >= 0)
		return ret + SF_NAPT_HASH2_INDEX_OFFSET;

	ret = sf_hnat_napt_hash_add_13(priv, tab_no_start + 2, crc_key[2],
				       napt_index);
	if (ret >= 0)
		return ret + SF_NAPT_HASH3_INDEX_OFFSET;

	return -1;
}

static void sf_hnat_napt_hash_del_dir(struct sf_hnat_priv *priv,
				      u16 *crc_key, u8 index, bool is_inat)
{
	int tab_no_start = is_inat ? SF_INAT_NAPT_HASH1 : SF_ENAT_NAPT_HASH1;
	u32 data[7] = {0};

	if (index < SF_NAPT_HASH2_INDEX_OFFSET) {
		sf_hnat_table_read(priv, tab_no_start, crc_key[0], data);
		data[0] &= ~BIT(20 + index);
		sf_hnat_table_write(priv, tab_no_start, crc_key[0], data);
	} else if (index < SF_NAPT_HASH3_INDEX_OFFSET) {
		index -= SF_NAPT_HASH2_INDEX_OFFSET;
		sf_hnat_table_read(priv, tab_no_start + 1, crc_key[1], data);
		data[1] &= ~BIT(8 + index);
		sf_hnat_table_write(priv, tab_no_start + 1, crc_key[1], data);
	} else {
		index -= SF_NAPT_HASH3_INDEX_OFFSET;
		sf_hnat_table_read(priv, tab_no_start + 2, crc_key[2], data);
		data[0] &= ~BIT(20 + index);
		sf_hnat_table_write(priv, tab_no_start + 2, crc_key[2], data);
	}
}

static void sf_hnat_napt_hash_del(struct sf_hnat_priv *priv,
				  struct sf_napt_crc_info *info)
{
	sf_hnat_napt_hash_del_dir(priv, info->inat_crc_key,
				  info->inat_ptr_index, true);
	sf_hnat_napt_hash_del_dir(priv, info->enat_crc_key,
				  info->enat_ptr_index, false);
}

static int sf_hnat_napt_hash_add(struct sf_hnat_priv *priv,
				 struct sf_napt_crc_info *info,
				 u16 napt_index, struct sf_hashkey *key)
{
	int ret;

	info->conflict_flag = 0;
	info->inat_ptr_index = 0;
	info->enat_ptr_index = 0;

	ret = sf_hnat_napt_hash_add_dir(priv, info, napt_index, key, true);
	if (ret < 0)
		info->conflict_flag |= 0x1;
	else
		info->inat_ptr_index = ret;

	ret = sf_hnat_napt_hash_add_dir(priv, info, napt_index, key, false);
	if (ret < 0)
		info->conflict_flag |= 0x2;
	else
		info->enat_ptr_index = ret;

	if (info->conflict_flag) {
		if (!(info->conflict_flag & 0x1))
			sf_hnat_napt_hash_del_dir(priv, info->inat_crc_key,
						  info->inat_ptr_index, true);
		if (!(info->conflict_flag & 0x2))
			sf_hnat_napt_hash_del_dir(priv, info->enat_crc_key,
						  info->enat_ptr_index, false);
		priv->napt_hash_full_count++;
		return -1;
	}
	return 0;
}

/*
 * NAPT main table
 */

static void sf_hnat_napt_write(struct sf_hnat_priv *priv, u16 napt_index)
{
	struct sf_hashkey *key = &priv->napt_keys[napt_index];
	u32 data[7] = {0};

	/*
	 * Word layout (SDK): raw big-endian tuple fields packed as-is.
	 * data[3]: bit 0..3 rt_pub_net_index, 4..19 router public port,
	 * 20..26 private vlan index, 27 proto, 28 INAT-to-host,
	 * 29 PPPoE enable, 30..31 + data[4] bit0 PPPoE index.
	 */
	data[0] = (__force u32)key->dip;
	data[1] = (((__force u32)key->sip & 0xFFFF) << 16) |
		  (__force u16)key->dport;
	data[2] = ((__force u32)(__force u16)key->sport << 16) |
		  (((__force u32)key->sip >> 16) & 0xFFFF);
	data[3] = (key->proto << 27) | (key->src_vlan_index << 20) |
		  ((__force u32)(__force u16)key->router_port << 4) |
		  key->rt_pub_net_index | (key->dnat_to_host << 28);
	if (key->cur_pppoe_en) {
		data[3] |= ((key->ppphd_index & 0x3) << 30) |
			   (key->cur_pppoe_en << 29);
		data[4] = (key->ppphd_index & 0x4) >> 2;
	}

	sf_hnat_table_write(priv, SF_NAPT_TABLE, napt_index, data);
}

static void sf_hnat_del_napt(struct sf_hnat_priv *priv, u16 napt_index)
{
	struct sf_hashkey *key = &priv->napt_keys[napt_index];
	u32 data[7] = {0};

	key->valid = 0;
	sf_hnat_napt_vld_cfg(priv, napt_index, false);
	sf_hnat_napt_hash_del(priv, &priv->napt_crc[napt_index]);

	sf_hnat_del_vlan(priv, key->src_vlan_index);
	sf_hnat_del_vlan(priv, key->dest_vlan_index);
	sf_hnat_del_rt_pub_net(priv, key->rt_pub_net_index);
	if (key->cur_pppoe_en)
		sf_hnat_del_ppphd(priv, key->ppphd_index);

	sf_hnat_table_write(priv, SF_NAPT_TABLE, napt_index, data);
}

static int sf_hnat_add_napt(struct sf_hnat_priv *priv,
			    struct sf_hashkey *src_key,
			    u16 src_vlan, u16 dest_vlan, u16 pppoe_sid)
{
	struct sf_napt_crc_info *info;
	struct sf_hashkey *key;
	int src_vlan_index, dest_vlan_index, rt_pub_net_index, ppphd_index;
	u16 napt_index;
	u16 i;

	for (i = 0; i < SF_NAPT_TABLE_MAX; i++) {
		if (!priv->napt_keys[i].valid)
			break;
	}
	if (i == SF_NAPT_TABLE_MAX)
		return -ENOSPC;
	napt_index = i;

	key = &priv->napt_keys[napt_index];
	memcpy(key, src_key, sizeof(*key));

	src_vlan_index = sf_hnat_add_vlan(priv, src_vlan);
	if (src_vlan_index < 0)
		goto err_src_vlan;
	key->src_vlan_index = src_vlan_index;

	dest_vlan_index = sf_hnat_add_vlan(priv, dest_vlan);
	if (dest_vlan_index < 0)
		goto err_dest_vlan;
	key->dest_vlan_index = dest_vlan_index;

	rt_pub_net_index = sf_hnat_add_rt_pub_net(priv, dest_vlan_index, key);
	if (rt_pub_net_index < 0)
		goto err_rt_pub;
	key->rt_pub_net_index = rt_pub_net_index;

	if (key->cur_pppoe_en) {
		ppphd_index = sf_hnat_add_ppphd(priv, pppoe_sid);
		if (ppphd_index < 0)
			goto err_ppphd;
		key->ppphd_index = ppphd_index;
	}

	info = &priv->napt_crc[napt_index];
	if (sf_hnat_napt_hash_add(priv, info, napt_index, key) < 0)
		goto err_crc;

	sf_hnat_napt_write(priv, napt_index);
	sf_hnat_napt_vld_cfg(priv, napt_index, true);
	key->valid = 1;

	priv->curr_napt_num++;
	if (key->proto == SF_PROTO_TCP)
		priv->curr_napt_tcp_num++;
	else
		priv->curr_napt_udp_num++;

	return napt_index;

err_crc:
	if (key->cur_pppoe_en)
		sf_hnat_del_ppphd(priv, key->ppphd_index);
err_ppphd:
	sf_hnat_del_rt_pub_net(priv, rt_pub_net_index);
err_rt_pub:
	sf_hnat_del_vlan(priv, dest_vlan_index);
err_dest_vlan:
	sf_hnat_del_vlan(priv, src_vlan_index);
err_src_vlan:
	memset(key, 0, sizeof(*key));
	return -1;
}

static void sf_hnat_del_entry_by_index(struct sf_hnat_priv *priv,
				       u16 napt_index)
{
	struct sf_hashkey *key = &priv->napt_keys[napt_index];

	if (napt_index >= SF_NAPT_TABLE_MAX || !key->valid)
		return;

	sf_hnat_del_napt(priv, napt_index);
	sf_hnat_del_dip(priv, key->src_dip_index);
	sf_hnat_del_dip(priv, key->dest_dip_index);

	if (priv->curr_napt_num)
		priv->curr_napt_num--;
	if (key->proto == SF_PROTO_TCP) {
		if (priv->curr_napt_tcp_num)
			priv->curr_napt_tcp_num--;
	} else {
		if (priv->curr_napt_udp_num)
			priv->curr_napt_udp_num--;
	}

	memset(key, 0, sizeof(*key));
}

/*
 * Router subnet configuration (REG16..23 + mask regs 30/31)
 */

static char sf_hnat_is_lan_ip(struct sf_hnat_priv *priv, __be32 client_ip)
{
	u8 masklen;
	u8 i;

	for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
		if (!priv->lan_subnet[i].valid)
			continue;
		masklen = 32 - priv->lan_subnet[i].prefix_len;
		if ((ntohl(client_ip) >> masklen) ==
		    ((__force u32)priv->lan_subnet[i].ipaddr >> masklen))
			return i;
	}
	return -1;
}

static char sf_hnat_is_wan_ip(struct sf_hnat_priv *priv, __be32 rt_pub_ip)
{
	u8 i;

	for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
		if (!priv->wan_subnet[i].valid)
			continue;
		if (rt_pub_ip == htonl((__force u32)priv->wan_subnet[i].ipaddr))
			return i;
	}
	return -1;
}

static void sf_hnat_update_lan_subnet(struct sf_hnat_priv *priv, u8 index)
{
	u32 set_register = SF_HNAT_REG16_CSR + 4 * index;
	unsigned long flags;
	u32 netmask_value;
	u32 data;

	spin_lock_irqsave(&priv->csr_lock, flags);
	sf_hnat_writel(priv, (__force u32)priv->lan_subnet[index].ipaddr,
		       set_register);

	set_register = (index < 4) ? SF_HNAT_REG30_CSR : SF_HNAT_REG31_CSR;
	netmask_value = sf_hnat_readl(priv, set_register) &
			~(0xff << ((index % 4) * 8));
	netmask_value |= ((32 - priv->lan_subnet[index].prefix_len) | 0x20)
			 << ((index % 4) * 8);
	sf_hnat_writel(priv, netmask_value, set_register);

	/* Toggle bit 0 of REG2 to reload the subnet config */
	data = sf_hnat_readl(priv, SF_HNAT_REG2_CSR);
	sf_hnat_writel(priv, data & ~0x1, SF_HNAT_REG2_CSR);
	sf_hnat_writel(priv, data | 0x1, SF_HNAT_REG2_CSR);
	spin_unlock_irqrestore(&priv->csr_lock, flags);

	priv->lan_subnet[index].valid = 1;
}

static void sf_hnat_flush_subnet_flows(struct sf_hnat_priv *priv,
				       bool is_lan, u8 index);

static void sf_hnat_del_lan_subnet_hw(struct sf_hnat_priv *priv, u8 index)
{
	u32 set_register = SF_HNAT_REG16_CSR + 4 * index;
	unsigned long flags;
	u32 netmask_value;
	u32 data;

	priv->lan_subnet[index].valid = 0;
	priv->lan_subnet[index].ipaddr = 0;
	priv->lan_subnet[index].prefix_len = 0;

	sf_hnat_flush_subnet_flows(priv, true, index);

	spin_lock_irqsave(&priv->csr_lock, flags);
	sf_hnat_writel(priv, 0x0, set_register);
	set_register = (index < 4) ? SF_HNAT_REG30_CSR : SF_HNAT_REG31_CSR;
	netmask_value = sf_hnat_readl(priv, set_register) &
			~(0xff << ((index % 4) * 8));
	sf_hnat_writel(priv, netmask_value, set_register);
	data = sf_hnat_readl(priv, SF_HNAT_REG2_CSR);
	sf_hnat_writel(priv, data & ~0x1, SF_HNAT_REG2_CSR);
	sf_hnat_writel(priv, data | 0x1, SF_HNAT_REG2_CSR);
	spin_unlock_irqrestore(&priv->csr_lock, flags);
}

static void sf_hnat_del_wan_subnet_hw(struct sf_hnat_priv *priv, u8 index)
{
	priv->wan_subnet[index].valid = 0;
	priv->wan_subnet[index].ipaddr = 0;
	priv->wan_subnet[index].prefix_len = 0;

	sf_hnat_flush_subnet_flows(priv, false, index);
}

/*
 * Hardware initialization (SDK csr_init)
 */

static void sf_hnat_csr_init(struct sf_hnat_priv *priv)
{
	u32 data;
	int i;

	sf_hnat_writel(priv, 0x0040024f | priv->hnat_mode, SF_HNAT_REG1_CSR);
	sf_hnat_readl(priv, SF_HNAT_REG1_CSR);

	for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
		if (priv->lan_subnet[i].valid)
			sf_hnat_update_lan_subnet(priv, i);
	}
	sf_hnat_writel(priv, 0x64, SF_HNAT_REG4_CSR);

	/* VLAN replace for untagged traffic */
	sf_hnat_writel(priv, priv->vlan_replace ? 0x700000 : 0x400000,
		       SF_HNAT_REG3_CSR);

	data = SF_HNAT_TB_CONFIG_ENTB;
	if (priv->snat_arp_force_dip)
		data |= SF_HNAT_TB_CONFIG_USE_DIP;
	if (priv->use_big_endian)
		data |= SF_HNAT_TB_CONFIG_BIG_ENDIAN;
	data |= SF_HNAT_TB_CONFIG_CRC3_SEL | SF_HNAT_TB_CONFIG_READ_CLR;
	sf_hnat_writel(priv, data, SF_HNAT_TB_CONFIG);

	sf_hnat_writel(priv, 0x1500, SF_HNAT_TB_RFC_TIMER);
	sf_hnat_writel(priv, 0x1500, SF_HNAT_TB_TFC_TIMER);
	sf_hnat_writel(priv, 0x3, SF_HNAT_TB_FC_CFG);
	sf_hnat_writel(priv, 0x0, SF_HNAT_TB_FC_CFG);
	sf_hnat_writel(priv, 0x20f020f, SF_HNAT_TB_BUF_THRESH);
	sf_hnat_writel(priv, 0x165a0bc0, SF_HNAT_REG33_CSR);
	sf_hnat_writel(priv, 0x5f5e10, SF_HNAT_REG34_CSR);
	sf_hnat_writel(priv, 0xffffffff, SF_HNAT_REG35_CSR);
	sf_hnat_writel(priv, 0x47868c0, SF_HNAT_REG36_CSR);
}

int sf_hnat_enable(struct sf_hnat_priv *priv)
{
	sf_hnat_writel(priv, 0x0040024f | priv->hnat_mode, SF_HNAT_REG1_CSR);
	return 0;
}
EXPORT_SYMBOL(sf_hnat_enable);

void sf_hnat_disable(struct sf_hnat_priv *priv)
{
	sf_hnat_writel(priv, 0x0, SF_HNAT_REG1_CSR);
}
EXPORT_SYMBOL(sf_hnat_disable);

/*
 * Flow rule parsing (nf_flow_table offload -> per-direction info)
 *
 * Each offloaded flow arrives as two FLOW_CLS_REPLACE rules — one per
 * tuple direction. The direction whose IP mangle rewrites the *source*
 * address is the private->public ("LAN ingress") half.
 */

struct sf_hnat_dir_info {
	bool valid;
	bool mangles_src;
	u8 l4proto;
	__be32 match_sip, match_dip;
	__be16 match_sport, match_dport;
	__be32 nat_ip;
	__be16 nat_port;
	bool has_nat_ip, has_nat_port;
	/* eth[0..5] = packet dest MAC, eth[6..11] = packet source MAC */
	u8 eth[2 * ETH_ALEN];
	bool has_eth;
	u16 egress_vid;
	bool pppoe;
	u16 pppoe_sid;
	unsigned long cookie;
};

struct sf_canon_key {
	__be32 pub_ip;
	__be32 srv_ip;
	__be16 pub_port;
	__be16 srv_port;
	u8 proto;
	u8 pad[3];
};

struct sf_hnat_flow_pair {
	struct rhash_head pair_node;	/* keyed by ckey */
	struct list_head pending_entry;
	struct sf_canon_key ckey;
	struct sf_hnat_dir_info dir[2];	/* [0] mangles_src, [1] other */
	int napt_index;			/* -1 until programmed */
	int cookies_alive;
	unsigned long created;
	u64 packets, bytes;
	unsigned long last_used;
};

struct sf_hnat_cookie_node {
	struct rhash_head node;
	unsigned long cookie;
	struct sf_hnat_flow_pair *pair;
};

static const struct rhashtable_params sf_cookie_table_params = {
	.head_offset = offsetof(struct sf_hnat_cookie_node, node),
	.key_offset = offsetof(struct sf_hnat_cookie_node, cookie),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};

static const struct rhashtable_params sf_pair_table_params = {
	.head_offset = offsetof(struct sf_hnat_flow_pair, pair_node),
	.key_offset = offsetof(struct sf_hnat_flow_pair, ckey),
	.key_len = sizeof(struct sf_canon_key),
	.automatic_shrinking = true,
};

/* dsa_tag_8021q standalone VID of a switch port, 0 if not a DSA port */
static u16 sf_hnat_dev_vid(struct net_device *dev)
{
	struct dsa_port *dp;

	if (!dev || !dsa_user_dev_check(dev))
		return 0;

	dp = dsa_port_from_netdev(dev);
	if (IS_ERR(dp))
		return 0;

	return dsa_tag_8021q_standalone_vid(dp);
}

static void sf_hnat_mangle_eth(const struct flow_action_entry *act, void *eth)
{
	void *dest = eth + act->mangle.offset;
	const void *src = &act->mangle.val;

	if (act->mangle.offset > 8)
		return;

	if (act->mangle.mask == 0xffff) {
		src += 2;
		dest += 2;
	}

	memcpy(dest, src, act->mangle.mask ? 2 : 4);
}

static int sf_hnat_parse_rule(struct sf_hnat_priv *priv,
			      struct flow_cls_offload *cls,
			      struct sf_hnat_dir_info *di)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(cls);
	struct flow_action_entry *act;
	int i;

	memset(di, 0, sizeof(*di));
	di->cookie = cls->cookie;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		if (match.key->n_proto != htons(ETH_P_IP))
			return -EOPNOTSUPP;
		if (match.key->ip_proto != IPPROTO_TCP &&
		    match.key->ip_proto != IPPROTO_UDP)
			return -EOPNOTSUPP;
		di->l4proto = match.key->ip_proto;
	} else {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);
		di->match_sip = match.key->src;
		di->match_dip = match.key->dst;
	} else {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);
		di->match_sport = match.key->src;
		di->match_dport = match.key->dst;
	} else {
		return -EOPNOTSUPP;
	}

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			switch (act->mangle.htype) {
			case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
				sf_hnat_mangle_eth(act, di->eth);
				di->has_eth = true;
				break;

			case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
				if (act->mangle.offset ==
				    offsetof(struct iphdr, saddr)) {
					memcpy(&di->nat_ip, &act->mangle.val, 4);
					di->has_nat_ip = true;
					di->mangles_src = true;
				} else if (act->mangle.offset ==
					   offsetof(struct iphdr, daddr)) {
					memcpy(&di->nat_ip, &act->mangle.val, 4);
					di->has_nat_ip = true;
					di->mangles_src = false;
				}
				break;

			case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			case FLOW_ACT_MANGLE_HDR_TYPE_UDP: {
				u32 val = ntohl((__force __be32)act->mangle.val);

				switch (act->mangle.offset) {
				case 0:
					if (act->mangle.mask ==
					    (__force u32)~htonl(0xffff))
						di->nat_port = cpu_to_be16(val);
					else
						di->nat_port =
							cpu_to_be16(val >> 16);
					di->has_nat_port = true;
					break;
				case 2:
					di->nat_port = cpu_to_be16(val);
					di->has_nat_port = true;
					break;
				}
				break;
			}
			default:
				return -EOPNOTSUPP;
			}
			break;

		case FLOW_ACTION_REDIRECT:
			di->egress_vid = sf_hnat_dev_vid(act->dev);
			break;

		case FLOW_ACTION_PPPOE_PUSH:
			di->pppoe = true;
			di->pppoe_sid = act->pppoe.sid;
			break;

		case FLOW_ACTION_VLAN_PUSH:
		case FLOW_ACTION_VLAN_POP:
			/* Tagged upstream (e.g. VLAN WAN) not supported yet */
			return -EOPNOTSUPP;

		case FLOW_ACTION_CSUM:
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	/* HNAT can only forward between switch ports */
	if (!di->egress_vid)
		return -EOPNOTSUPP;
	if (!di->has_nat_ip || !di->has_eth)
		return -EOPNOTSUPP;

	di->valid = true;
	return 0;
}

static void sf_hnat_canon_key(const struct sf_hnat_dir_info *di,
			      struct sf_canon_key *ck)
{
	memset(ck, 0, sizeof(*ck));
	ck->proto = di->l4proto;
	if (di->mangles_src) {
		/* private->public half: server is the match destination */
		ck->srv_ip = di->match_dip;
		ck->srv_port = di->match_dport;
		ck->pub_ip = di->nat_ip;
		ck->pub_port = di->has_nat_port ? di->nat_port :
						  di->match_sport;
	} else {
		/* public->private half: server is the match source */
		ck->srv_ip = di->match_sip;
		ck->srv_port = di->match_sport;
		ck->pub_ip = di->match_dip;
		ck->pub_port = di->match_dport;
	}
}

/*
 * Program one assembled pair into the hardware
 */
static int sf_hnat_program_pair(struct sf_hnat_priv *priv,
				struct sf_hnat_flow_pair *pair)
{
	struct sf_hnat_dir_info *lan = &pair->dir[0]; /* mangles_src */
	struct sf_hnat_dir_info *wan = &pair->dir[1];
	struct sf_hashkey key = {};
	int napt_index;
	int dip_index;
	char idx;

	/* 5-tuple as seen on the private side (pre-NAT) */
	key.sip = lan->match_sip;
	key.sport = lan->match_sport;
	key.dip = lan->match_dip;
	key.dport = lan->match_dport;
	key.router_pub_ip = pair->ckey.pub_ip;
	key.router_port = pair->ckey.pub_port;
	key.proto = (lan->l4proto == IPPROTO_TCP) ? SF_PROTO_TCP :
						    SF_PROTO_UDP;

	/* LAN side MACs come from the WAN-ingress rule's eth rewrite */
	memcpy(key.src_mac, wan->eth, ETH_ALEN);
	memcpy(key.router_src_mac, wan->eth + ETH_ALEN, ETH_ALEN);
	/* WAN side MACs come from the LAN-ingress rule's eth rewrite */
	memcpy(key.dest_mac, lan->eth, ETH_ALEN);
	memcpy(key.router_dest_mac, lan->eth + ETH_ALEN, ETH_ALEN);

	key.cur_pppoe_en = lan->pppoe ? 1 : 0;
	key.ppp_sid = lan->pppoe_sid;
	key.dnat_to_host = 0;

	idx = sf_hnat_is_lan_ip(priv, key.sip);
	if (idx < 0)
		return -EOPNOTSUPP;
	key.lan_subnet_index = idx;

	idx = sf_hnat_is_wan_ip(priv, key.router_pub_ip);
	if (idx < 0)
		return -EOPNOTSUPP;
	key.wan_subnet_index = idx;

	/* Is the remote peer inside the WAN subnet? */
	{
		u8 masklen = 32 - priv->wan_subnet[key.wan_subnet_index].prefix_len;

		key.is_dip_rt_ip_same_subnet =
			(ntohl(key.dip) >> masklen) ==
			(ntohl(key.router_pub_ip) >> masklen);
	}

	napt_index = sf_hnat_add_napt(priv, &key,
				      wan->egress_vid /* LAN port VID */,
				      lan->egress_vid /* WAN port VID */,
				      lan->pppoe_sid);
	if (napt_index < 0)
		return -ENOSPC;

	dip_index = sf_hnat_add_dip(priv, &priv->napt_keys[napt_index], true);
	if (dip_index < 0)
		goto err_src_dip;
	priv->napt_keys[napt_index].src_dip_index = dip_index;

	dip_index = sf_hnat_add_dip(priv, &priv->napt_keys[napt_index], false);
	if (dip_index < 0)
		goto err_dest_dip;
	priv->napt_keys[napt_index].dest_dip_index = dip_index;

	pair->napt_index = napt_index;
	priv->offload_cnt++;

	dev_dbg(priv->dev,
		"offloaded %pI4:%d -> %pI4:%d via %pI4:%d napt %d vid %d->%d\n",
		&key.sip, ntohs(key.sport), &key.dip, ntohs(key.dport),
		&key.router_pub_ip, ntohs(key.router_port), napt_index,
		wan->egress_vid, lan->egress_vid);
	return 0;

err_dest_dip:
	sf_hnat_del_dip(priv, priv->napt_keys[napt_index].src_dip_index);
err_src_dip:
	sf_hnat_del_napt(priv, napt_index);
	if (priv->curr_napt_num)
		priv->curr_napt_num--;
	if (key.proto == SF_PROTO_TCP) {
		if (priv->curr_napt_tcp_num)
			priv->curr_napt_tcp_num--;
	} else {
		if (priv->curr_napt_udp_num)
			priv->curr_napt_udp_num--;
	}
	memset(&priv->napt_keys[napt_index], 0, sizeof(struct sf_hashkey));
	return -ENOSPC;
}

static void sf_hnat_pair_teardown_hw(struct sf_hnat_priv *priv,
				     struct sf_hnat_flow_pair *pair)
{
	if (pair->napt_index >= 0) {
		sf_hnat_del_entry_by_index(priv, pair->napt_index);
		pair->napt_index = -1;
		priv->unoffload_cnt++;
	}
}

static void sf_hnat_pair_free(struct sf_hnat_priv *priv,
			      struct sf_hnat_flow_pair *pair)
{
	sf_hnat_pair_teardown_hw(priv, pair);
	if (!list_empty(&pair->pending_entry))
		list_del(&pair->pending_entry);
	rhashtable_remove_fast(&priv->pair_table, &pair->pair_node,
			       sf_pair_table_params);
	kfree(pair);
}

static void sf_hnat_drop_cookie(struct sf_hnat_priv *priv,
				unsigned long cookie)
{
	struct sf_hnat_cookie_node *cn;

	cn = rhashtable_lookup_fast(&priv->flow_table, &cookie,
				    sf_cookie_table_params);
	if (!cn)
		return;
	rhashtable_remove_fast(&priv->flow_table, &cn->node,
			       sf_cookie_table_params);
	if (cn->pair) {
		cn->pair->cookies_alive--;
		/* tear down hardware on the first DESTROY */
		sf_hnat_pair_teardown_hw(priv, cn->pair);
		if (cn->pair->cookies_alive <= 0)
			sf_hnat_pair_free(priv, cn->pair);
	}
	kfree(cn);
}

static void sf_hnat_gc_pending(struct sf_hnat_priv *priv)
{
	struct sf_hnat_flow_pair *pair, *tmp;

	list_for_each_entry_safe(pair, tmp, &priv->pending_list,
				 pending_entry) {
		if (time_before(jiffies,
				pair->created + SF_HNAT_PENDING_TIMEOUT))
			break;
		list_del_init(&pair->pending_entry);
		if (pair->dir[0].valid)
			sf_hnat_drop_cookie(priv, pair->dir[0].cookie);
		else if (pair->dir[1].valid)
			sf_hnat_drop_cookie(priv, pair->dir[1].cookie);
	}
}

static void sf_hnat_flush_subnet_flows(struct sf_hnat_priv *priv,
				       bool is_lan, u8 index)
{
	u16 i;

	for (i = 0; i < SF_NAPT_TABLE_MAX; i++) {
		struct sf_hashkey *key = &priv->napt_keys[i];

		if (!key->valid)
			continue;
		if ((is_lan && key->lan_subnet_index == index) ||
		    (!is_lan && key->wan_subnet_index == index))
			sf_hnat_del_entry_by_index(priv, i);
	}
}

/*
 * Flow entry management (called from the TC flower block callback)
 */

int sf_hnat_flow_add(struct sf_hnat_priv *priv, struct flow_cls_offload *cls)
{
	struct sf_hnat_dir_info di;
	struct sf_hnat_cookie_node *cn;
	struct sf_hnat_flow_pair *pair;
	struct sf_canon_key ck;
	int dslot;
	int ret;

	ret = sf_hnat_parse_rule(priv, cls, &di);
	if (ret)
		return ret;

	sf_hnat_canon_key(&di, &ck);
	dslot = di.mangles_src ? 0 : 1;

	mutex_lock(&priv->flow_mutex);

	sf_hnat_gc_pending(priv);

	if (rhashtable_lookup_fast(&priv->flow_table, &cls->cookie,
				   sf_cookie_table_params)) {
		ret = -EEXIST;
		goto out;
	}

	pair = rhashtable_lookup_fast(&priv->pair_table, &ck,
				      sf_pair_table_params);
	if (!pair) {
		pair = kzalloc(sizeof(*pair), GFP_KERNEL);
		if (!pair) {
			ret = -ENOMEM;
			goto out;
		}
		pair->ckey = ck;
		pair->napt_index = -1;
		pair->created = jiffies;
		pair->last_used = jiffies;
		INIT_LIST_HEAD(&pair->pending_entry);
		ret = rhashtable_insert_fast(&priv->pair_table,
					     &pair->pair_node,
					     sf_pair_table_params);
		if (ret) {
			kfree(pair);
			goto out;
		}
		list_add_tail(&pair->pending_entry, &priv->pending_list);
	}

	if (pair->dir[dslot].valid) {
		ret = -EEXIST;
		goto out;
	}
	pair->dir[dslot] = di;

	cn = kzalloc(sizeof(*cn), GFP_KERNEL);
	if (!cn) {
		ret = -ENOMEM;
		goto out;
	}
	cn->cookie = cls->cookie;
	cn->pair = pair;
	ret = rhashtable_insert_fast(&priv->flow_table, &cn->node,
				     sf_cookie_table_params);
	if (ret) {
		kfree(cn);
		goto out;
	}
	pair->cookies_alive++;

	if (pair->dir[0].valid && pair->dir[1].valid) {
		list_del_init(&pair->pending_entry);
		ret = sf_hnat_program_pair(priv, pair);
		if (ret)
			/* nf_flow_table will undo with DESTROY for both
			 * cookies and keep the flow on the software path
			 */
			priv->add_fail_count++;
	} else {
		ret = 0;
	}

out:
	mutex_unlock(&priv->flow_mutex);
	return ret;
}

int sf_hnat_flow_del(struct sf_hnat_priv *priv, struct flow_cls_offload *cls)
{
	mutex_lock(&priv->flow_mutex);
	sf_hnat_drop_cookie(priv, cls->cookie);
	mutex_unlock(&priv->flow_mutex);
	return 0;
}

int sf_hnat_flow_stats(struct sf_hnat_priv *priv, struct flow_cls_offload *cls)
{
	struct sf_hnat_cookie_node *cn;
	struct sf_hnat_flow_pair *pair;
	struct sf_hashkey *key;
	u64 packets = 0, bytes = 0;
	u32 data[7] = {0};
	u8 dmac_index;

	mutex_lock(&priv->flow_mutex);

	cn = rhashtable_lookup_fast(&priv->flow_table, &cls->cookie,
				    sf_cookie_table_params);
	if (!cn || !cn->pair || cn->pair->napt_index < 0)
		goto out;
	pair = cn->pair;

	/*
	 * The statistics table counts per destination MAC, not per flow.
	 * Use it as a liveness heuristic: any growth on either endpoint
	 * MAC keeps the flow from being aged out by the flowtable.
	 */
	key = &priv->napt_keys[pair->napt_index];
	dmac_index = priv->dip_entries[key->src_dip_index].dmac_index;
	if (!sf_hnat_table_read(priv, SF_STATISTICS_TABLE, dmac_index, data))
		packets += data[0];
	dmac_index = priv->dip_entries[key->dest_dip_index].dmac_index;
	if (!sf_hnat_table_read(priv, SF_STATISTICS_TABLE, dmac_index, data))
		packets += data[0];

	if (packets > pair->packets) {
		bytes = (packets - pair->packets) * 64; /* lower bound */
		pair->last_used = jiffies;
	}

	flow_stats_update(&cls->stats, bytes,
			  packets > pair->packets ?
				packets - pair->packets : 0,
			  0, pair->last_used, FLOW_ACTION_HW_STATS_DELAYED);
	pair->packets = packets;

out:
	mutex_unlock(&priv->flow_mutex);
	return 0;
}

/*
 * TC flower block callback
 */

int sf_hnat_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			      void *cb_priv)
{
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
 * Indirect flow block registration
 *
 * The stmmac driver does not implement ndo_setup_tc(TC_SETUP_FT), so the
 * nf_flow_table hardware offload path falls back to the indirect flow
 * block API. Registering here lets nftables flowtables with
 * 'flags offload' (fw4: flow_offloading_hw) bind to the DSA user ports
 * without any changes to the ethernet driver.
 */
static LIST_HEAD(sf_hnat_indr_block_cb_list);

static void sf_hnat_indr_block_release(void *cb_priv)
{
}

static int sf_hnat_indr_setup_block(struct net_device *netdev,
				    struct Qdisc *sch, void *cb_priv,
				    struct flow_block_offload *f, void *data,
				    void (*cleanup)(struct flow_block_cb *block_cb))
{
	struct flow_block_cb *block_cb;

	/* The HNAT engine sits in the GMAC; only flows traversing the
	 * DSA user ports (wan/lan*) can be accelerated.
	 */
	if (!netdev || !dsa_user_dev_check(netdev))
		return -EOPNOTSUPP;

	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	f->driver_block_list = &sf_hnat_indr_block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		block_cb = flow_indr_block_cb_alloc(sf_hnat_setup_tc_block_cb,
						    netdev, cb_priv,
						    sf_hnat_indr_block_release,
						    f, netdev, sch, data, cb_priv,
						    cleanup);
		if (IS_ERR(block_cb))
			return PTR_ERR(block_cb);

		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list,
			      &sf_hnat_indr_block_cb_list);
		return 0;
	case FLOW_BLOCK_UNBIND:
		block_cb = flow_block_cb_lookup(f->block,
						sf_hnat_setup_tc_block_cb,
						netdev);
		if (!block_cb)
			return -ENOENT;

		flow_indr_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int sf_hnat_indr_setup_cb(struct net_device *netdev, struct Qdisc *sch,
				 void *cb_priv, enum tc_setup_type type,
				 void *type_data, void *data,
				 void (*cleanup)(struct flow_block_cb *block_cb))
{
	switch (type) {
	case TC_SETUP_BLOCK:
	case TC_SETUP_FT:
		return sf_hnat_indr_setup_block(netdev, sch, cb_priv,
						type_data, data, cleanup);
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Router IP tracking: inetaddr notifier replaces the SDK devinet.c patch
 */

static bool sf_hnat_ifname_in_list(const char *ifname, const char *list)
{
	const char *p = list;
	size_t len = strlen(ifname);

	while (p && *p) {
		const char *end = strchr(p, ',');
		size_t n = end ? (size_t)(end - p) : strlen(p);

		if (n == len && !strncmp(p, ifname, n))
			return true;
		p = end ? end + 1 : NULL;
	}
	return false;
}

static int sf_hnat_inetaddr_event(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	struct sf_hnat_priv *priv =
		container_of(nb, struct sf_hnat_priv, inetaddr_nb);
	const char *ifname = ifa->ifa_dev->dev->name;
	bool is_lan, is_wan;
	u8 i;

	is_lan = sf_hnat_ifname_in_list(ifname, lan_ifnames);
	is_wan = !is_lan && sf_hnat_ifname_in_list(ifname, wan_ifnames);
	if (!is_lan && !is_wan)
		return NOTIFY_DONE;

	mutex_lock(&priv->flow_mutex);

	if (event == NETDEV_UP) {
		struct sf_hnat_subnet *tbl = is_lan ? priv->lan_subnet :
						      priv->wan_subnet;

		for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
			if (tbl[i].valid &&
			    !strncmp(tbl[i].ifname, ifname, IFNAMSIZ))
				break;
			if (!tbl[i].valid)
				break;
		}
		if (i == SF_HNAT_SUBNET_MAX)
			goto out;

		if (tbl[i].valid) {
			if (is_lan)
				sf_hnat_del_lan_subnet_hw(priv, i);
			else
				sf_hnat_del_wan_subnet_hw(priv, i);
		}

		/* stored in host byte order, as in the SDK */
		tbl[i].ipaddr = (__force __be32)ntohl(ifa->ifa_address);
		tbl[i].prefix_len = ifa->ifa_prefixlen;
		strscpy(tbl[i].ifname, ifname, IFNAMSIZ);
		if (is_lan) {
			sf_hnat_update_lan_subnet(priv, i);
		} else {
			tbl[i].valid = 1;
		}
		dev_info(priv->dev, "%s subnet %s %pI4h/%d (slot %d)\n",
			 is_lan ? "lan" : "wan", ifname,
			 &tbl[i].ipaddr, tbl[i].prefix_len, i);
	} else if (event == NETDEV_DOWN) {
		struct sf_hnat_subnet *tbl = is_lan ? priv->lan_subnet :
						      priv->wan_subnet;

		for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
			if (!tbl[i].valid ||
			    strncmp(tbl[i].ifname, ifname, IFNAMSIZ))
				continue;
			if (is_lan)
				sf_hnat_del_lan_subnet_hw(priv, i);
			else
				sf_hnat_del_wan_subnet_hw(priv, i);
		}
	}

out:
	mutex_unlock(&priv->flow_mutex);
	return NOTIFY_DONE;
}

/*
 * Core init/teardown
 */

static void sf_hnat_hw_init(struct sf_hnat_priv *priv)
{
	sf_hnat_table_clean(priv);
	sf_hnat_csr_init(priv);
	dev_info(priv->dev, "HNAT hardware initialized, mode=0x%x\n",
		 priv->hnat_mode);
}

int sf_hnat_init(struct sf_hnat_priv *priv)
{
	int ret;

	ret = rhashtable_init(&priv->flow_table, &sf_cookie_table_params);
	if (ret)
		return ret;

	ret = rhashtable_init(&priv->pair_table, &sf_pair_table_params);
	if (ret) {
		rhashtable_destroy(&priv->flow_table);
		return ret;
	}

	INIT_LIST_HEAD(&priv->pending_list);

	sf_hnat_hw_init(priv);

	dev_info(priv->dev, "HNAT initialized with %d max flows\n",
		 SF_NAPT_TABLE_MAX);
	return 0;
}
EXPORT_SYMBOL(sf_hnat_init);

static void sf_hnat_cookie_free_cb(void *ptr, void *arg)
{
	kfree(ptr);
}

void sf_hnat_deinit(struct sf_hnat_priv *priv)
{
	sf_hnat_disable(priv);
	rhashtable_free_and_destroy(&priv->flow_table,
				    sf_hnat_cookie_free_cb, NULL);
	rhashtable_free_and_destroy(&priv->pair_table,
				    sf_hnat_cookie_free_cb, NULL);
	dev_info(priv->dev, "HNAT deinitialized\n");
}
EXPORT_SYMBOL(sf_hnat_deinit);

/*
 * Debug/statistics
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

static int sf_hnat_status_show(struct seq_file *s, void *unused)
{
	struct sf_hnat_priv *priv = s->private;
	u8 i;

	seq_printf(s, "napt: %u (tcp %u udp %u) dip: %u dmac: %u rmac: %u\n",
		   priv->curr_napt_num, priv->curr_napt_tcp_num,
		   priv->curr_napt_udp_num, priv->curr_dip_num,
		   priv->curr_dmac_num, priv->curr_rmac_num);
	seq_printf(s, "vlan: %u ppphd: %u rt_pub_net: %u\n",
		   priv->curr_vlan_id_num, priv->curr_ppphd_num,
		   priv->curr_rt_pub_net_num);
	seq_printf(s, "offloaded: %u unoffloaded: %u add_fail: %u\n",
		   priv->offload_cnt, priv->unoffload_cnt,
		   priv->add_fail_count);
	seq_printf(s, "hash full: napt %u dip %u\n",
		   priv->napt_hash_full_count, priv->dip_hash_full_count);

	for (i = 0; i < SF_HNAT_SUBNET_MAX; i++) {
		if (priv->lan_subnet[i].valid)
			seq_printf(s, "lan[%d]: %s %pI4h/%d\n", i,
				   priv->lan_subnet[i].ifname,
				   &priv->lan_subnet[i].ipaddr,
				   priv->lan_subnet[i].prefix_len);
		if (priv->wan_subnet[i].valid)
			seq_printf(s, "wan[%d]: %s %pI4h/%d\n", i,
				   priv->wan_subnet[i].ifname,
				   &priv->wan_subnet[i].ipaddr,
				   priv->wan_subnet[i].prefix_len);
	}

	for (i = 0; i < SF_VLAN_TABLE_MAX; i++) {
		if (priv->vlan_entries[i].valid)
			seq_printf(s, "vlan[%d]: vid %u ref %u\n", i,
				   priv->vlan_entries[i].vlan_id,
				   priv->vlan_entries[i].ref_count);
	}

	seq_printf(s, "hw: rx_enter %u rx2host %u rx2tx %u tx_nohits %u inat %u enat %u\n",
		   sf_hnat_readl(priv, SF_HNAT_RX_ENTER_SOF_CNT_L),
		   sf_hnat_readl(priv, SF_HNAT_RX_2HOST_SOF_CNT_L),
		   sf_hnat_readl(priv, SF_HNAT_RX2TX_DATA_CNT),
		   sf_hnat_readl(priv, SF_HNAT_TX_NOHITS_CNT),
		   sf_hnat_readl(priv, SF_HNAT_RX_INAT_CNT),
		   sf_hnat_readl(priv, SF_HNAT_TX_ENAT_CNT));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(sf_hnat_status);

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
	priv->snat_arp_force_dip = false;
	priv->vlan_replace = false;

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

	ret = flow_indr_dev_register(sf_hnat_indr_setup_cb, priv);
	if (ret)
		goto err_indr;

	priv->inetaddr_nb.notifier_call = sf_hnat_inetaddr_event;
	ret = register_inetaddr_notifier(&priv->inetaddr_nb);
	if (ret)
		goto err_notifier;

	priv->debugfs = debugfs_create_dir("sf_hnat", NULL);
	debugfs_create_file("status", 0444, priv->debugfs, priv,
			    &sf_hnat_status_fops);

	g_sf_hnat = priv;

	pr_info("Siflower HNAT driver v%s loaded, base=%p\n", DRV_VERSION,
		base);

	return 0;

err_notifier:
	flow_indr_dev_unregister(sf_hnat_indr_setup_cb, priv,
				 sf_hnat_indr_block_release);
err_indr:
	sf_hnat_deinit(priv);
	kfree(priv);
	return ret;
}

static void __exit sf_hnat_module_exit(void)
{
	struct sf_hnat_priv *priv = g_sf_hnat;

	if (!priv)
		return;

	g_sf_hnat = NULL;

	debugfs_remove_recursive(priv->debugfs);
	unregister_inetaddr_notifier(&priv->inetaddr_nb);
	flow_indr_dev_unregister(sf_hnat_indr_setup_cb, priv,
				 sf_hnat_indr_block_release);

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
