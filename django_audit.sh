#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/django_audit.env}"
CONFIG_FILE="${CONFIG_FILE:-${SCRIPT_DIR}/django_audit.json}"

CURRENT_USER="${SUDO_USER:-$(id -un)}"
export CURRENT_USER

if [ -f "${ENV_FILE}" ]; then
  set -a
  # shellcheck disable=SC1090
  . "${ENV_FILE}"
  set +a
fi

PROJECT_ROOT_DIR="${PROJECT_ROOT_DIR:-djangodev}"
BASE_DIR="${BASE_DIR:-/home/${CURRENT_USER}/${PROJECT_ROOT_DIR}}"

AUDIT_VENV="${AUDIT_VENV:-${BASE_DIR}/scripts/.audit-venv}"
AUDIT_PYTHON="${AUDIT_PYTHON:-${AUDIT_VENV}/bin/python}"
AUDIT_SCRIPT="${AUDIT_SCRIPT:-${SCRIPT_DIR}/django_audit.py}"
NVM_DIR="${NVM_DIR:-/home/${CURRENT_USER}/.nvm}"

export PROJECT_ROOT_DIR
export BASE_DIR
export AUDIT_VENV
export AUDIT_PYTHON
export AUDIT_SCRIPT
export NVM_DIR
export PATH="${EXTRA_PATH:-}${EXTRA_PATH:+:}${PATH:-/usr/local/bin:/usr/bin:/bin}"

if [ ! -f "${CONFIG_FILE}" ]; then
  echo "Config file not found: ${CONFIG_FILE}"
  exit 1
fi

if [ ! -f "${AUDIT_SCRIPT}" ]; then
  echo "Audit Python script not found: ${AUDIT_SCRIPT}"
  exit 1
fi

if [ ! -x "${AUDIT_PYTHON}" ]; then
  echo "Audit venv missing: ${AUDIT_PYTHON}"
  echo "Create it with:"
  echo "  cd ${BASE_DIR}/scripts"
  echo "  python3 -m venv .audit-venv"
  echo "  .audit-venv/bin/python -m pip install --upgrade pip"
  echo "  .audit-venv/bin/python -m pip install pip-audit"
  exit 1
fi

exec "${AUDIT_PYTHON}" "${AUDIT_SCRIPT}" --config "${CONFIG_FILE}" "$@"
