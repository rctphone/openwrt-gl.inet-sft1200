/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Siflower SF19A28 HNAT Register Definitions
 *
 * Based on original Siflower SDK code from BPI-WiFi5-Siflower project
 * Adapted for kernel 6.x by OpenWrt community
 *
 * Copyright (C) Siflower Communications
 * Copyright (C) 2024-2026 OpenWrt contributors
 */

#ifndef _SF_HNAT_REG_H_
#define _SF_HNAT_REG_H_

/*
 * HNAT Memory Map (relative to GMAC HNAT base)
 *
 * The HNAT engine in SF19A28 sits between the MAC and DMA engine
 * and intercepts packets for hardware NAT acceleration.
 */

/* Base addresses for HNAT registers */
#define SF_HNAT_CSR_BASE		0x4000
#define SF_HNAT_TABLE_BASE		0x6000

/*
 * Table sizes - these define the maximum capacity of the HNAT engine
 */
#define SF_NAPT_TABLE_MAX		1024	/* Max NAT/NAPT entries */
#define SF_VLAN_TABLE_MAX		128	/* VLAN entries */
#define SF_DIP_TABLE_MAX		512	/* Destination IP entries */
#define SF_RT_PUB_NET_TABLE_MAX		16	/* Router public network entries */
#define SF_PPPHD_TABLE_MAX		8	/* PPPoE header entries */
#define SF_DMAC_TABLE_MAX		128	/* Destination MAC entries */
#define SF_ROUTER_MAC_TABLE_MAX		8	/* Router MAC entries */

/*
 * Table numbers for table access operations
 * Used in HWNAT_REG3_TB_ADDRESS register
 */
enum sf_hnat_table_id {
	/* Ingress NAT hash tables */
	SF_INAT_NAPT_HASH1	= 0,
	SF_INAT_NAPT_HASH2	= 1,
	SF_INAT_NAPT_HASH3	= 2,
	/* Egress NAT hash tables */
	SF_ENAT_NAPT_HASH1	= 3,
	SF_ENAT_NAPT_HASH2	= 4,
	SF_ENAT_NAPT_HASH3	= 5,
	/* Main tables */
	SF_NAPT_TABLE		= 6,
	SF_NAPT_VLD_TABLE	= 7,
	SF_RT_PUB_NET_TABLE	= 8,
	/* Reserved: 9-15 */
	/* DIP tables */
	SF_DIP_HASH1		= 16,
	SF_DIP_HASH2		= 17,
	SF_DIP_TABLE		= 18,
	SF_DIP_VLD_TABLE	= 19,
	/* Additional tables */
	SF_DMAC_TABLE		= 20,
	SF_PPPOE_HD_TABLE	= 21,
	SF_ROUTER_MAC_TABLE	= 22,
	SF_VLAN_ID_TABLE	= 23,
	SF_STATISTICS_TABLE	= 24,
	SF_HNAT_TB_MAX		= 25,
};

/*
 * Register bit definitions
 */

/* REG1 - Table Status */
#define SF_HNAT_TB_STATUS_BUSY		BIT(0)

/* REG2 - Table Config */
#define SF_HNAT_TB_CONFIG_ENTB		0x0fff0000	/* Enable all tables */
#define SF_HNAT_TB_CONFIG_USE_DIP	BIT(0)		/* Use DIP for ENAT ARP search */
#define SF_HNAT_TB_CONFIG_BIG_ENDIAN	BIT(4)		/* Big endian for write */
#define SF_HNAT_TB_CONFIG_CRC3_SEL	BIT(10)		/* Use 0x8005 for crc_key[2] */
#define SF_HNAT_TB_CONFIG_READ_CLR	BIT(2)		/* Host read clear */

/* REG4 - Table Operation Code */
#define SF_HNAT_TB_OP_WRITE		1
#define SF_HNAT_TB_OP_READ		0

/* REG3 - Table Address */
#define SF_HNAT_TB_ADDR_NO_SHIFT	16		/* Table number offset */

/*
 * Control/Status Registers (CSR)
 */
#define SF_HNAT_REG0_CSR		(SF_HNAT_CSR_BASE + 0x0000)
#define SF_HNAT_REG1_CSR		(SF_HNAT_CSR_BASE + 0x0004)
#define SF_HNAT_REG2_CSR		(SF_HNAT_CSR_BASE + 0x0008)
#define SF_HNAT_REG3_CSR		(SF_HNAT_CSR_BASE + 0x000c)
#define SF_HNAT_REG4_CSR		(SF_HNAT_CSR_BASE + 0x0010)
#define SF_HNAT_REG5_CSR		(SF_HNAT_CSR_BASE + 0x0014)
#define SF_HNAT_REG6_CSR		(SF_HNAT_CSR_BASE + 0x0018)
#define SF_HNAT_REG7_CSR		(SF_HNAT_CSR_BASE + 0x001c)
#define SF_HNAT_REG8_CSR		(SF_HNAT_CSR_BASE + 0x0020)

/* LAN subnet registers (8 entries) */
#define SF_HNAT_REG16_CSR		(SF_HNAT_CSR_BASE + 0x0040)
#define SF_HNAT_REG17_CSR		(SF_HNAT_CSR_BASE + 0x0044)
#define SF_HNAT_REG18_CSR		(SF_HNAT_CSR_BASE + 0x0048)
#define SF_HNAT_REG19_CSR		(SF_HNAT_CSR_BASE + 0x004c)
#define SF_HNAT_REG20_CSR		(SF_HNAT_CSR_BASE + 0x0050)
#define SF_HNAT_REG21_CSR		(SF_HNAT_CSR_BASE + 0x0054)
#define SF_HNAT_REG22_CSR		(SF_HNAT_CSR_BASE + 0x0058)
#define SF_HNAT_REG23_CSR		(SF_HNAT_CSR_BASE + 0x005c)

/* Additional CSRs */
#define SF_HNAT_REG30_CSR		(SF_HNAT_CSR_BASE + 0x0080)
#define SF_HNAT_REG31_CSR		(SF_HNAT_CSR_BASE + 0x0084)
#define SF_HNAT_REG33_CSR		(SF_HNAT_CSR_BASE + 0x008c)
#define SF_HNAT_REG34_CSR		(SF_HNAT_CSR_BASE + 0x0090)
#define SF_HNAT_REG35_CSR		(SF_HNAT_CSR_BASE + 0x0094)
#define SF_HNAT_REG36_CSR		(SF_HNAT_CSR_BASE + 0x0098)

/*
 * Statistics Counters
 */
#define SF_HNAT_RX_ENTER_SOF_CNT_L	(SF_HNAT_CSR_BASE + 0x0100)
#define SF_HNAT_RX_ENTER_SOF_CNT_H	(SF_HNAT_CSR_BASE + 0x0104)
#define SF_HNAT_RX_ENTER_EOF_CNT_L	(SF_HNAT_CSR_BASE + 0x0108)
#define SF_HNAT_RX_ENTER_EOF_CNT_H	(SF_HNAT_CSR_BASE + 0x010c)
#define SF_HNAT_RX_ENTER_DROP_CNT	(SF_HNAT_CSR_BASE + 0x0110)
#define SF_HNAT_RX_2HOST_SOF_CNT_L	(SF_HNAT_CSR_BASE + 0x0114)
#define SF_HNAT_RX_2HOST_SOF_CNT_H	(SF_HNAT_CSR_BASE + 0x0118)
#define SF_HNAT_RX_2HOST_EOF_CNT_L	(SF_HNAT_CSR_BASE + 0x011c)
#define SF_HNAT_RX_2HOST_EOF_CNT_H	(SF_HNAT_CSR_BASE + 0x0120)
#define SF_HNAT_RX2TX_DATA_CNT		(SF_HNAT_CSR_BASE + 0x0124)
#define SF_HNAT_TX_RX_FRAME_CNT		(SF_HNAT_CSR_BASE + 0x0128)
#define SF_HNAT_TX_SOF_CNT		(SF_HNAT_CSR_BASE + 0x012c)
#define SF_HNAT_TX_EOF_CNT		(SF_HNAT_CSR_BASE + 0x0130)
#define SF_HNAT_TX_EXIT_SOF_CNT_L	(SF_HNAT_CSR_BASE + 0x0134)
#define SF_HNAT_TX_EXIT_SOF_CNT_H	(SF_HNAT_CSR_BASE + 0x0138)
#define SF_HNAT_TX_EXIT_EOF_CNT_L	(SF_HNAT_CSR_BASE + 0x013c)
#define SF_HNAT_TX_EXIT_EOF_CNT_H	(SF_HNAT_CSR_BASE + 0x0140)
#define SF_HNAT_TX_NOHITS_CNT		(SF_HNAT_CSR_BASE + 0x0144)
#define SF_HNAT_PKT_ERR_CNT		(SF_HNAT_CSR_BASE + 0x0148)
#define SF_HNAT_RCV_STATUS_CNT		(SF_HNAT_CSR_BASE + 0x014c)
#define SF_HNAT_TX_STATUS_CNT		(SF_HNAT_CSR_BASE + 0x0150)
#define SF_HNAT_TX_ENAT_CNT		(SF_HNAT_CSR_BASE + 0x016c)
#define SF_HNAT_RX_ENAT_CNT		(SF_HNAT_CSR_BASE + 0x0170)
#define SF_HNAT_RX_INAT_CNT		(SF_HNAT_CSR_BASE + 0x0174)
#define SF_HNAT_RX_TOTAL_ERR_CNT	(SF_HNAT_CSR_BASE + 0x0178)
#define SF_HNAT_RX_GMII_ERR_CNT		(SF_HNAT_CSR_BASE + 0x017c)
#define SF_HNAT_RX_CRC_ERR_CNT		(SF_HNAT_CSR_BASE + 0x0180)
#define SF_HNAT_RX_LENGTH_ERR_CNT	(SF_HNAT_CSR_BASE + 0x0184)
#define SF_HNAT_RX_IPHDR_ERR_CNT	(SF_HNAT_CSR_BASE + 0x0188)
#define SF_HNAT_RX_PAYLOAD_ERR_CNT	(SF_HNAT_CSR_BASE + 0x018c)
#define SF_HNAT_RX2TX2HOST_CNT		(SF_HNAT_CSR_BASE + 0x0190)
#define SF_HNAT_RX2TX_DROP_CNT		(SF_HNAT_CSR_BASE + 0x0194)

/*
 * Table Access Registers
 */
#define SF_HNAT_TB_STATUS		(SF_HNAT_TABLE_BASE + 0x0000)
#define SF_HNAT_TB_CONFIG		(SF_HNAT_TABLE_BASE + 0x0004)
#define SF_HNAT_TB_ADDRESS		(SF_HNAT_TABLE_BASE + 0x0008)
#define SF_HNAT_TB_OP_CODE		(SF_HNAT_TABLE_BASE + 0x000c)
#define SF_HNAT_TB_WRDATA0		(SF_HNAT_TABLE_BASE + 0x0010)
#define SF_HNAT_TB_WRDATA1		(SF_HNAT_TABLE_BASE + 0x0014)
#define SF_HNAT_TB_WRDATA2		(SF_HNAT_TABLE_BASE + 0x0018)
#define SF_HNAT_TB_WRDATA3		(SF_HNAT_TABLE_BASE + 0x001c)
#define SF_HNAT_TB_WRDATA4		(SF_HNAT_TABLE_BASE + 0x0020)
#define SF_HNAT_TB_RDDATA0		(SF_HNAT_TABLE_BASE + 0x0030)
#define SF_HNAT_TB_RDDATA1		(SF_HNAT_TABLE_BASE + 0x0034)
#define SF_HNAT_TB_RDDATA2		(SF_HNAT_TABLE_BASE + 0x0038)
#define SF_HNAT_TB_RDDATA3		(SF_HNAT_TABLE_BASE + 0x003c)
#define SF_HNAT_TB_RDDATA4		(SF_HNAT_TABLE_BASE + 0x0040)
#define SF_HNAT_TB_RDDATA5		(SF_HNAT_TABLE_BASE + 0x0044)
#define SF_HNAT_TB_RDDATA6		(SF_HNAT_TABLE_BASE + 0x0048)
#define SF_HNAT_TB_BUF_THRESH		(SF_HNAT_TABLE_BASE + 0x0050)
#define SF_HNAT_TB_FC_CFG		(SF_HNAT_TABLE_BASE + 0x0060)
#define SF_HNAT_TB_RFC_TIMER		(SF_HNAT_TABLE_BASE + 0x0064)
#define SF_HNAT_TB_RFC_AGECNT		(SF_HNAT_TABLE_BASE + 0x0068)
#define SF_HNAT_TB_TFC_TIMER		(SF_HNAT_TABLE_BASE + 0x006c)

/*
 * NAT modes supported by HNAT engine
 */
#define SF_HNAT_MODE_BASIC		(0 << 25)
#define SF_HNAT_MODE_SYMMETRIC		(1 << 25)
#define SF_HNAT_MODE_FULL_CONE		(2 << 25)
#define SF_HNAT_MODE_RESTRICT_CONE	(3 << 25)
#define SF_HNAT_MODE_PORT_RESTRICT	(1 << 27)

/*
 * Table entry structures
 */

/* NAPT CRC info for hash lookup */
struct sf_napt_crc_info {
	u16 inat_crc_key[3];
	u16 enat_crc_key[3];
	u8 inat_ptr_index;	/* Hash table pointer (0-7) */
	u8 enat_ptr_index;
	u8 conflict_flag;	/* Bit 1: INAT, Bit 2: ENAT */
};

/* DIP CRC info for hash lookup */
struct sf_dip_crc_info {
	u16 dip_crc_key[2];
	u8 dip_ptr_index;
};

/* Destination IP entry (512 max) */
struct sf_dip_entry {
	__be32 dip;
	u8 dmac_index;
	u8 vlan_index;
	u8 valid;
	u16 ref_count;
};

/* Destination MAC entry (128 max) */
struct sf_dmac_entry {
	u8 dmac[ETH_ALEN];
	u8 router_mac_index;
	u8 valid;
	u16 ref_count;
};

/* Router MAC entry (8 max) */
struct sf_rmac_entry {
	u8 rmac[ETH_ALEN];
	u8 valid;
	u16 ref_count;
};

/* PPPoE header entry (8 max) */
struct sf_ppphd_entry {
	u16 session_id;
	u8 valid;
	u16 ref_count;
};

/* Router public network entry (16 max) */
struct sf_rt_pub_net_entry {
	__be32 router_pub_ip;
	u8 rt_ip_mask;
	u8 pub_vlan_index;
	u8 valid;
	u16 ref_count;
};

/* VLAN ID entry (128 max) */
struct sf_vlan_entry {
	u16 vlan_id;
	u8 valid;
	u16 ref_count;
};

#endif /* _SF_HNAT_REG_H_ */
