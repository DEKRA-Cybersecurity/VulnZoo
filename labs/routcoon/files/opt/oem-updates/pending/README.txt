========================================
OEM FIRMWARE UPDATE SERVER - STAGING
========================================
Location: /opt/oem-updates/pending/
User: anonymous (write-enabled)

SUPPORTED FILE TYPES:
  *.img    - Standard OpenWRT firmware images (sysupgrade)
  *.sh     - Pre-installation hooks/preparation scripts

INSTRUCTIONS:
1. Upload firmware files (*.img) to this directory
2. System auto-processes every 3 minutes via root cron
3. Files are automatically executed/installed and deleted

WARNING: Ensure compatibility with RoutCoon hardware.
Invalid files may cause system instability.

For support: contact@routcoon-oem.local
========================================