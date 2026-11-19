#!/bin/bash
# Installs/restores the skap-signing systemd unit. Idempotent. Run after VM replacement.
set -e
cp /home/hatch/workspace/skap-signing/systemd/skap-signing.service /etc/systemd/system/skap-signing.service
systemctl daemon-reload
systemctl enable --now skap-signing.service
systemctl is-active skap-signing.service
