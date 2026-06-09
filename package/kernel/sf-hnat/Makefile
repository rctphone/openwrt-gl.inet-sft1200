# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2024-2026 OpenWrt contributors
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=sf-hnat
PKG_VERSION:=2.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Ivan Semenov <ivan@ray.app>
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define KernelPackage/sf-hnat
  SUBMENU:=Network Devices
  TITLE:=Siflower SF19A28 Hardware NAT driver
  DEPENDS:=@TARGET_siflower +kmod-nf-flow
  FILES:=$(PKG_BUILD_DIR)/sf-hnat.ko
  AUTOLOAD:=$(call AutoLoad,45,sf-hnat)
endef

define KernelPackage/sf-hnat/description
  Hardware NAT acceleration driver for Siflower SF19A28/SF19A2890 SoCs.
  This driver enables offloading of NAT/NAPT flows to dedicated hardware,
  significantly improving routing performance and reducing CPU load.

  The HNAT engine can handle up to 1024 concurrent flows and supports:
  - IPv4 NAT/NAPT
  - TCP and UDP protocols
  - VLAN tagging
  - PPPoE sessions

  Integration is done via TC flower classifier with nftables flowtable.
endef

define KernelPackage/sf-hnat/config
  if PACKAGE_kmod-sf-hnat
	config SF_HNAT_DEBUG
		bool "Enable HNAT debug output"
		default n
		help
		  Enable verbose debug output for the HNAT driver.
  endif
endef

EXTRA_KCONFIG:= \
	CONFIG_SF_HNAT=m

ifdef CONFIG_SF_HNAT_DEBUG
  EXTRA_KCONFIG += CONFIG_SF_HNAT_DEBUG=y
endif

EXTRA_CFLAGS:= \
	-I$(STAGING_DIR)/usr/include

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		$(EXTRA_KCONFIG) \
		modules
endef

$(eval $(call KernelPackage,sf-hnat))
