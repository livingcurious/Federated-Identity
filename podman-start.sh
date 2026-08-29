#!/usr/bin/env bash
# Start the isolated fabric under Podman (build image, seed via the one-shot
# provisioner, run IdP + both SPs on segmented networks with per-service volumes).
#
#   ./podman-start.sh          # build + up (foreground logs)
#   ./podman-start.sh -d       # build + up detached
#
set -euo pipefail
cd "$(dirname "$0")"

HOSTS_LINE="127.0.0.1  idp  sp-a  sp-b"

# The browser and the tokens must agree on the hostnames, so these names have to resolve
# to loopback on the host. We do NOT edit /etc/hosts for you — check and instruct.
missing=0
for name in idp sp-a sp-b; do
  if ! grep -qE "^[^#]*[[:space:]]$name([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    missing=1
  fi
done
if [ "$missing" -eq 1 ]; then
  echo "!! Add this line to /etc/hosts first (needs sudo), then re-run:"
  echo
  echo "     $HOSTS_LINE"
  echo
  echo "   e.g.  echo '$HOSTS_LINE' | sudo tee -a /etc/hosts"
  exit 1
fi

echo "==> Bringing up the fabric under Podman"
podman compose up --build "$@"

cat <<'EOF'

Fabric is up (or starting). Endpoints:
  IdP           http://idp:9400            (public: login, authorize, jwks)
  IdP internal  http://idp-internal:9410   (token + admin — not published to the host)
  SP-A          http://sp-a:9401
  SP-B          http://sp-b:9402

Admin token (printed once by the provisioner):
  podman compose logs provisioner | grep -A1 'Admin token'

The internal IdP has no published port, so admin calls from your host shell must go
through a container that's on the compose network, e.g.:
  podman compose exec idp-internal \
    curl -s -H "X-Admin-Token: $ADMIN" http://idp-internal:9410/admin/sessions

Stop and remove containers/networks (volumes persist):
  podman compose down
EOF
