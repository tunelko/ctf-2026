#!/usr/bin/env python3
"""
Modem Metamorphosis - DawgCTF 2026
PCAP of someone flashing a Linksys router with OpenWrt.

From Upgrade.asp page:
  - Manufacturer: Linksys (UI_Linksys.gif)
  - Model: WRT610N (in page HTML)
  - Old firmware: 1.00.00 B18

From POST /upgrade.cgi multipart upload:
  - Filename: openwrt-24.10.0-bcm47xx-generic-linksys_wrt610n-v1-squashfs.bin
  - New firmware: OpenWrt 24.10.0

Flag format: DawgCTF{Manufacturer_Model_OldFirmwareVersion_NewFirmwareName_NewFirmwareVersion}
"""
print("[+] FLAG: DawgCTF{Linksys_WRT610N_1.00.00_OpenWrt_24.10.0}")
