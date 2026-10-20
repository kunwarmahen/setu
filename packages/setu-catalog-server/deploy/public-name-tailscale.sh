#!/usr/bin/env bash
# A public HTTPS name for the catalog server, without a domain or an open
# router port: Tailscale Funnel. Tailscale gives this computer a name
# (https://<computer>.<your-tailnet>.ts.net), holds its certificate, and
# forwards that name's HTTPS to the server on 127.0.0.1. Run it yourself:
# it signs in to your Tailscale account and asks for your password (sudo).
#
#   packages/setu-catalog-server/deploy/public-name-tailscale.sh [PORT]
#
# PORT is the server's (8796 unless you changed it). Undo with:
#   sudo tailscale funnel --https=443 off
set -euo pipefail
PORT="${1:-8796}"

if ! curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null; then
    echo "The catalog server isn't answering on 127.0.0.1:$PORT."
    echo "Start it first: systemctl --user start setu-catalog"
    exit 1
fi

if ! command -v tailscale >/dev/null; then
    echo "Installing Tailscale with its own installer (tailscale.com/install.sh)..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi

# Signs this computer in to your tailnet; prints a link to open the first time.
sudo tailscale up

# If Funnel isn't allowed for this computer yet, tailscale prints a link to
# allow it in your tailnet's settings: open it, allow, and run this again.
sudo tailscale funnel --bg "$PORT"

NAME=$(tailscale status --json | python3 -c \
    'import json, sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')
echo
echo "The catalog's public address: https://$NAME"
echo -n "It answers: "
curl -fsS "https://$NAME/health" && echo
echo
echo "Next, on any computer with Setu:"
echo "  setu catalog trust setu.key.pub      # your public key (~/keys/setu.key.pub here)"
echo "  setu catalog use https://$NAME"
