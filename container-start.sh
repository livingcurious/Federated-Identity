#!/usr/bin/env bash
# One script to bring the fabric up under containers, whichever engine you have.
#
#   ./container-start.sh          # build + up (foreground logs)
#   ./container-start.sh -d       # build + up detached
#
# Picks Docker if it's installed AND its daemon is actually reachable (`docker info`
# succeeds) — that's the common case on a dev machine with Docker Desktop already
# running. Otherwise it installs Podman (if missing) and uses that instead. Either way
# it's the exact same `compose.yaml` topology underneath — nothing engine-specific in
# there, so this script's only job is picking (and if needed, installing) an engine.
#
set -euo pipefail
cd "$(dirname "$0")"

HOSTS_LINE="127.0.0.1  idp  sp-a  sp-b"

check_hosts() {
  # The browser and the tokens must agree on hostnames, so idp/sp-a/sp-b have to resolve
  # to loopback on the host, under either engine.
  local missing=0
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
}

install_podman() {
  echo "==> Podman not found — installing it"
  case "$(uname -s)" in
    Darwin)
      if ! command -v brew >/dev/null 2>&1; then
        echo "!! Homebrew is required to install Podman on macOS." >&2
        echo "   Install it from https://brew.sh, then re-run this script." >&2
        exit 1
      fi
      brew install podman
      ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y podman
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y podman
      elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm podman
      elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y podman
      else
        echo "!! Could not detect a supported package manager (apt/dnf/pacman/zypper)." >&2
        echo "   Install Podman manually: https://podman.io/docs/installation" >&2
        exit 1
      fi
      ;;
    *)
      echo "!! Unsupported OS for automatic Podman install: $(uname -s)" >&2
      echo "   Install Podman manually: https://podman.io/docs/installation" >&2
      exit 1
      ;;
  esac
}

ensure_podman_machine() {
  # Podman needs a Linux VM on macOS (and Windows); it runs natively on Linux.
  [ "$(uname -s)" = "Darwin" ] || return 0
  if ! podman machine inspect podman-machine-default >/dev/null 2>&1; then
    echo "==> Initializing the Podman machine (first run only)"
    podman machine init
  fi
  if ! podman machine inspect podman-machine-default --format '{{.State}}' 2>/dev/null | grep -q running; then
    echo "==> Starting the Podman machine"
    podman machine start
  fi
}

compose_cmd() {
  case "$ENGINE" in
    docker)
      if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
      elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
      else
        echo "!! Docker is installed but no Compose plugin/binary was found." >&2
        echo "   Install the Compose plugin: https://docs.docker.com/compose/install/" >&2
        exit 1
      fi
      ;;
    podman)
      echo "podman compose"
      ;;
  esac
}

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ENGINE="docker"
elif command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
else
  install_podman
  ENGINE="podman"
fi

if [ "$ENGINE" = "podman" ]; then
  ensure_podman_machine
fi

check_hosts

read -r -a COMPOSE <<< "$(compose_cmd)"
echo "==> Using ${COMPOSE[*]} to bring up the fabric"
"${COMPOSE[@]}" up --build "$@"

cat <<EOF

Fabric is up (or starting). Endpoints:
  IdP           http://idp:9400            (public: login, authorize, jwks)
  IdP internal  http://idp-internal:9410   (token + admin — not published to the host)
  SP-A          http://sp-a:9401
  SP-B          http://sp-b:9402

Admin token (printed once by the provisioner):
  ${COMPOSE[*]} logs provisioner | grep -A1 'Admin token'

The internal IdP has no published port, so admin calls from your host shell must go
through a container that's on the compose network, e.g.:
  ${COMPOSE[*]} exec idp-internal \\
    curl -s -H "X-Admin-Token: \$ADMIN" http://idp-internal:9410/admin/sessions

Stop and remove containers/networks (volumes persist):
  ${COMPOSE[*]} down
EOF
