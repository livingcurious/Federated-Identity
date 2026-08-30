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

ensure_compose_provider() {
  # `podman compose` has no compose engine of its own -- it's a thin wrapper that
  # shells out to docker-compose or podman-compose (see `podman compose --help`).
  # Installing podman alone does not pull either one in, so without this a fresh
  # machine gets all the way through building images and only fails at the very
  # last step with "unable to find any compose provider."
  if command -v docker-compose >/dev/null 2>&1 || command -v podman-compose >/dev/null 2>&1; then
    return 0
  fi
  echo "==> No compose provider found for Podman — installing podman-compose"
  case "$(uname -s)" in
    Darwin)
      if ! command -v brew >/dev/null 2>&1; then
        echo "!! Homebrew is required to install podman-compose on macOS." >&2
        echo "   Install it from https://brew.sh, then re-run this script." >&2
        exit 1
      fi
      brew install podman-compose
      ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y podman-compose
      elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y podman-compose
      elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm podman-compose
      elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y podman-compose
      elif command -v pip3 >/dev/null 2>&1; then
        pip3 install --user podman-compose
      else
        echo "!! Could not detect a supported package manager (apt/dnf/pacman/zypper/pip3)." >&2
        echo "   Install podman-compose manually: https://github.com/containers/podman-compose" >&2
        exit 1
      fi
      ;;
    *)
      echo "!! Unsupported OS for automatic podman-compose install: $(uname -s)" >&2
      echo "   Install podman-compose manually: https://github.com/containers/podman-compose" >&2
      exit 1
      ;;
  esac
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
      if command -v docker-compose >/dev/null 2>&1 || command -v podman-compose >/dev/null 2>&1; then
        echo "podman compose"
      else
        echo "!! Podman has no compose provider (docker-compose or podman-compose) on PATH." >&2
        echo "   Install podman-compose: https://github.com/containers/podman-compose" >&2
        exit 1
      fi
      ;;
  esac
}

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ENGINE="docker"
elif command -v docker >/dev/null 2>&1; then
  echo "==> Docker is installed but its daemon isn't reachable (is Docker Desktop running?)"
  echo "    Falling back to Podman instead of waiting on it."
  if command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
  else
    install_podman
    ENGINE="podman"
  fi
elif command -v podman >/dev/null 2>&1; then
  ENGINE="podman"
else
  install_podman
  ENGINE="podman"
fi

if [ "$ENGINE" = "podman" ]; then
  ensure_podman_machine
  ensure_compose_provider
fi

check_hosts

read -r -a COMPOSE <<< "$(compose_cmd)"
echo "==> Using ${COMPOSE[*]} to bring up the fabric"

DETACHED=0
for arg in "$@"; do
  case "$arg" in
    -d|--detach) DETACHED=1 ;;
  esac
done

if [ "$DETACHED" -eq 0 ]; then
  # Foreground mode: Ctrl+C only kills this script's local compose client, not the
  # containers. That's a no-op under Podman specifically -- the containers run inside
  # the Podman machine VM (reached over SSH), fully decoupled from this process's
  # lifetime, so interrupting or even kill -9'ing this script leaves everything running
  # with nothing to show for it. Don't rely on the underlying tool's own signal
  # handling at all; always bring the stack down ourselves on the way out (volumes are
  # untouched -- this is a plain `down`, not `down -v`).
  cleanup() {
    trap - EXIT INT TERM  # only run once, however we got here
    echo
    echo "==> Stopping the fabric"
    "${COMPOSE[@]}" down
  }
  trap cleanup EXIT INT TERM
fi

"${COMPOSE[@]}" up --build "$@"

if [ "$DETACHED" -eq 0 ]; then
  exit 0
fi

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
