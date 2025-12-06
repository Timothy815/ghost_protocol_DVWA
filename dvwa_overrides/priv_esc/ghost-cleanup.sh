#!/bin/bash
# Writable cron payload for priv-esc exercise (OP-008)
# This script runs as root every minute via /etc/cron.d/ghost-cron.
# Students can edit this file (world-writable) to escalate privileges.

# Default no-op to keep container stable until students modify it.
exit 0
