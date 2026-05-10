#!/bin/sh
# $1 == 0 on full uninstall; > 0 on upgrade (leave the service running)
if [ "$1" -eq 0 ]; then
    systemctl stop    aloha.service >/dev/null 2>&1 || true
    systemctl disable aloha.service >/dev/null 2>&1 || true
fi
