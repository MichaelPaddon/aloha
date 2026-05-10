#!/bin/sh
getent group  aloha >/dev/null || groupadd --system aloha
getent passwd aloha >/dev/null || \
    useradd --system --gid aloha --no-create-home \
            --shell /sbin/nologin aloha
systemctl daemon-reload >/dev/null 2>&1 || true
echo "Run: systemctl enable --now aloha"
