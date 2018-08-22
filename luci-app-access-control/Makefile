# Copyright (C) 2018 By-Ameng Openwrt.org
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=luci-app-access_control
LUCI_DEPENDS:=
LUCI_PKGARCH:=all
PKG_VERSION:=1.0
PKG_RELEASE:=1

define Package/luci-app-access-control/postinst
#!/bin/sh
chmod 755 /etc/init.d/accesscontroltc
chmod 755 /usr/sbin/tc.sh
chmod 755 /usr/sbin/accesscontroltc.lua
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
