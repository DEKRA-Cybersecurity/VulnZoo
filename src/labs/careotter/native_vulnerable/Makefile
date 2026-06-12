# Makefile for CareOtter native vulnerable services
# Cross-compilation target: aarch64-openwrt-linux-musl (OpenWRT bcm2710)

CC = aarch64-openwrt-linux-musl-gcc
CFLAGS_COMMON = -static

# Directories
OUT_DIR_CARESERVICE = ../files/opt/careotter
OUT_DIR_FTP = ../files/opt/careotter-ftp

# ─────────────────────────────────────────────────────────────────────────────

.PHONY: all careservice careotter-ftp clean

all: careservice careotter-ftp

# Target: careservice (IGP v4 admin daemon — intentionally vulnerable)
careservice: $(OUT_DIR_CARESERVICE)/careservice

$(OUT_DIR_CARESERVICE)/careservice: careservice.c | $(OUT_DIR_CARESERVICE)
	$(CC) $(CFLAGS_COMMON) -Wno-format-security -o $@ $<

# Target: careotter-ftp (vulnerable FTP-like service)
careotter-ftp: $(OUT_DIR_FTP)/careotter-ftp

$(OUT_DIR_FTP)/careotter-ftp: careotter-ftp.c | $(OUT_DIR_FTP)
	$(CC) $(CFLAGS_COMMON) -O2 -o $@ $<

# ─────────────────────────────────────────────────────────────────────────────

# Ensure output directories exist
$(OUT_DIR_CARESERVICE):
	mkdir -p $(OUT_DIR_CARESERVICE)

$(OUT_DIR_FTP):
	mkdir -p $(OUT_DIR_FTP)

clean:
	rm -f $(OUT_DIR_CARESERVICE)/careservice
	rm -f $(OUT_DIR_FTP)/careotter-ftp
