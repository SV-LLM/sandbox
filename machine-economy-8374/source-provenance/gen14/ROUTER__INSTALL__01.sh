#!/bin/bash
# Installs/restores the machine-economy-router systemd unit. Idempotent. Run after VM replacement.
set -e
cp /home/hatch/workspace/router-8374/systemd/machine-economy-router.service /etc/systemd/system/machine-economy-router.service
systemctl daemon-reload
systemctl enable --now machine-economy-router.service
systemctl is-active machine-economy-router.service
