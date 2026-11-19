#!/bin/bash
# Installs/restores the verify-page systemd unit. Idempotent. Run after VM replacement.
set -e
cp /home/hatch/workspace/verify-page/systemd/verify-page.service /etc/systemd/system/verify-page.service
systemctl daemon-reload
systemctl enable --now verify-page.service
systemctl is-active verify-page.service
