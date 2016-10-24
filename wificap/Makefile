#
# Copyright (C) 2012 Jo-Philipp Wich <jow@openwrt.org>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iwcap
PKG_RELEASE:=1
PKG_LICENSE:=20150727

include $(INCLUDE_DIR)/package.mk


define Package/iwcap
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Simple radiotap capture utility
  MAINTAINER:=dujiong@163.com
  DEPENDS:=$(DRV_DEPENDS)+libmysqlclient
endef

define Package/iwcap/description
  The iwcap utility receives radiotap packet data from wifi monitor interfaces
  and outputs it to pcap format. It gathers recived packets in a fixed ring
  buffer to dump them on demand which is useful for background monitoring.
  Alternatively the utility can stream the data to stdout to act as remote
  capture drone for Wireshark or similar programs.
endef

TARGET_CFLAGS += -L$(STAGING_DIR)/usr/lib/mysql
TARGET_LDFLAGS += -lmysqlclient


define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	$(TARGET_CC) \
		-o $(PKG_BUILD_DIR)/iwcap $(PKG_BUILD_DIR)/*.c $(TARGET_CFLAGS) $(TARGET_LDFLAGS)
endef


define Package/iwcap/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iwcap $(1)/usr/sbin/iwcap
endef

$(eval $(call BuildPackage,iwcap))
