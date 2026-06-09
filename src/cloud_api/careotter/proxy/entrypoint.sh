#!/bin/sh
# Select the nginx ACL by VULNERABLE — the same env toggle the API container uses.
# VULNERABLE=1 (default) → exact-match ACL (trailing-slash bypassable).
# VULNERABLE=0           → normalized ACL (bypass closed).
set -e

if [ "${VULNERABLE:-1}" = "0" ]; then
    cp /etc/nginx/staging/nginx.secure.conf /etc/nginx/conf.d/default.conf
    echo "[careotter-proxy] SECURE ACL (VULNERABLE=0) — normalized matching"
else
    cp /etc/nginx/staging/nginx.vuln.conf /etc/nginx/conf.d/default.conf
    echo "[careotter-proxy] VULNERABLE ACL (exact-match) — trailing-slash bypassable"
fi

nginx -t
exec nginx -g 'daemon off;'
