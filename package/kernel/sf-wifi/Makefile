# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024 Siflower Communications
# Adapted for OpenWRT mainline by the community
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sf-wifi
PKG_VERSION:=1.0.0
PKG_RELEASE:=2

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/Siflower/sf_wifi.git
PKG_SOURCE_VERSION:=54f084a69087621fa52df2505327faf1d0b0c123
PKG_SOURCE_BRANCH:=sf19a2890-6.9
PKG_SOURCE_DATE:=2024-11-07
PKG_MIRROR_HASH:=b7527260916c236ec737b230e42e584a84fc26b521eae0f74ef8aacfa7ddcf8c

PKG_MAINTAINER:=Ivan Semenov <ivan@ray.app>
PKG_LICENSE:=GPL-2.0

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/sf-wifi
  SUBMENU:=Wireless Drivers
  TITLE:=Siflower SF19A28/SF19A2890 WiFi driver
  DEPENDS:=@TARGET_siflower +kmod-cfg80211
  FILES:= \
	$(PKG_BUILD_DIR)/sf_smac/src/rf/sf16a18_rf.ko \
	$(PKG_BUILD_DIR)/sf_smac/src/startcore/startcore.ko \
	$(PKG_BUILD_DIR)/sf_smac/src/fmac/sf16a18_fmac.ko
  AUTOLOAD:=$(call AutoProbe,sf16a18_rf startcore sf16a18_fmac)
endef

define KernelPackage/sf-wifi/description
  Kernel driver for Siflower SF19A28/SF19A2890 integrated WiFi.
  This provides dual-band 802.11ac WiFi support.
endef

define KernelPackage/sf-wifi/config
	if PACKAGE_kmod-sf-wifi
		config SF_WIFI_DEBUG
			bool "Enable debug output"
			default n
	endif
endef

# Kernel version code for 6.12: (6 << 16) + (12 << 8) + 0 = 396288
KERNEL_VERSION_CODE:=$(shell echo $$(($(LINUX_VERSION_MAJOR) * 65536 + $(LINUX_VERSION_MINOR) * 256 + $(LINUX_VERSION_PATCH))))

EXTRA_KCONFIG:= \
	CONFIG_SF16A18_WIFI_RF=m \
	CONFIG_SF16A18_WIFI_MAC_HOST_OFFLOAD=m \
	CONFIG_SF16A18_WIFI_FULL_MAC=m \
	CONFIG_SF16A18_LMAC_USE_M_SFDSP=y \
	CONFIG_SFA28_FULLMASK=y \
	CONFIG_SIWIFI_ACS_INTERNAL=y \
	CONFIG_DUAL_ANTENNA_CALIBRATE=y \
	CONFIG_UPDATE_GAIN_TABLE=y

NOSTDINC_FLAGS:= \
	$(KERNEL_NOSTDINC_FLAGS) \
	-I$(PKG_BUILD_DIR)/sf_smac/src \
	-I$(PKG_BUILD_DIR)/sf_smac/src/bb_src/umac \
	-I$(PKG_BUILD_DIR)/sf_smac/src/bb_src/umac/fullmac \
	-I$(STAGING_DIR)/usr/include/mac80211-backport/uapi \
	-I$(STAGING_DIR)/usr/include/mac80211-backport \
	-I$(STAGING_DIR)/usr/include/mac80211/uapi \
	-I$(STAGING_DIR)/usr/include/mac80211 \
	-include backport/autoconf.h \
	-include backport/backport.h \
	-DMY_LINUX_VERSION_CODE=$(KERNEL_VERSION_CODE) \
	-DCONFIG_SF16A18_WIFI_RF \
	-DCONFIG_SF16A18_LMAC_USE_M_SFDSP \
	-DCONFIG_SFA28_FULLMASK \
	-DCONFIG_UPDATE_GAIN_TABLE \
	-Werror

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) $(PKG_BUILD_DIR)/sf_smac/src/bb_src $(PKG_BUILD_DIR)/sf_smac/src/fmac/ -rf
endef

define Build/Compile
	+$(KERNEL_MAKE) $(PKG_JOBS) \
		M="$(PKG_BUILD_DIR)/sf_smac/src" \
		NOSTDINC_FLAGS="$(NOSTDINC_FLAGS)" \
		$(EXTRA_KCONFIG) \
		modules
endef

define KernelPackage/sf-wifi/install
	$(INSTALL_DIR) $(1)/lib/firmware
	
	# Core firmware files
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/sf1688_lb_fmac.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/sf1688_hb_fmac.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/agcram.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/agcram_24g.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/ldpcram.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/rf_pmem.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/rf_default_reg.bin $(1)/lib/firmware/
	
	# Configuration files
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/siwifi_settings.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/siwifi_aetnensis.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/tx_adjust_gain_table.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/sf_rf_expa_config.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/dig_gaintable.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/dig_gaintable_expa.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/default_hb_txpower_table.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/default_lb_txpower_table.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/default_hb_txpower_table_expa.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/default_lb_txpower_table_expa.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/rf_gain_table.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/a28fullmask/rf_trx_path.ini $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/cali_table/default_txpower_calibrate_table.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/cali_table/default_txpower_calibrate_expa_table.bin $(1)/lib/firmware/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/cali_table/txp_offset_sleepmode_low.ini $(1)/lib/firmware/
	
	# Scripts
	$(INSTALL_DIR) $(1)/bin
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/sfwifi $(1)/bin/
	$(CP) $(PKG_BUILD_DIR)/sf_smac/config/sfwifi-a28.sh $(1)/lib/sfwifi.sh
	
	$(INSTALL_DIR) $(1)/etc/init.d
endef

$(eval $(call KernelPackage,sf-wifi))
