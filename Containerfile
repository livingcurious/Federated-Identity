# Single image for all three services + the provisioner. The role is chosen by the
# command/env set per service in compose.yaml.
FROM docker.io/library/python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY scripts ./scripts
RUN pip install --no-cache-dir .

# NOTE: containers run as root *inside* the namespace. Under rootless Podman that maps to
# an unprivileged host user, so this is not a host-privilege risk; it keeps the mounted
# data volumes writable without an init/chown dance. Running as a dedicated non-root UID
# (with volume ownership fixed up) is a reasonable hardening step.

# Default role is the one-shot provisioner; servers override `command` in compose.
CMD ["python", "-m", "fabric.seed"]
