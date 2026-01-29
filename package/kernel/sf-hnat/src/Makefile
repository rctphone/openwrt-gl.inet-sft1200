# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for Siflower SF19A28 HNAT driver
#

obj-$(CONFIG_SF_HNAT) += sf-hnat.o
sf-hnat-y := sf_hnat.o

ccflags-y += -I$(src)
ccflags-$(CONFIG_SF_HNAT_DEBUG) += -DDEBUG
