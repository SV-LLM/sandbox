#!/bin/bash
# Installs/restores the chain-export systemd unit. Idempotent. Run after VM replacement.
set -e
cp /home/hatch/workspace/chain-export/systemd/chain-export.service /etc/systemd/system/chain-export.service
systemctl daemon-reload
systemctl enable --now chain-export.service
systemctl is-active chain-export.service
