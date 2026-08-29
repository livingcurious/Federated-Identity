#!/usr/bin/env bash
# One command to start everything: create the venv (first run only), install the
# package, seed the databases, and launch the IdP + both SPs. Ctrl+C stops them all.
#
#   ./start.sh
#
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV=".venv"

if [ ! -d "$VENV" ]; then
  echo "==> Creating virtualenv ($VENV) with $($PYTHON --version 2>&1)"
  "$PYTHON" -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Installing dependencies"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e .

echo "==> Launching Identity Fabric (seeds on first run; Ctrl+C to stop)"
exec python run.py
