#!/bin/sh
# radar: periodically turn newly persisted crt.sh rows + certstream hits into scanned feed entries
cd /c/scamshiled
for i in $(seq 1 30); do
  .venv/Scripts/python -m scamshield.radar backfill --days 120 --no-fetch --no-scan > /dev/null 2>&1
  .venv/Scripts/python -m scamshield.radar scan-pending --limit 25 >> data/radar/scan_pending.log 2>&1
  sleep 240
done
