#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/masterdnsvpn}"
DATA_DIR="${DATA_DIR:-/data}"
CONFIG_FILE="${CONFIG_FILE:-server_config.toml}"
KEY_FILE="${KEY_FILE:-encrypt_key.txt}"
BIN="${APP_DIR}/masterdnsvpn"
SAMPLE_CONFIG="${APP_DIR}/server_config.toml.simple"

valid_file_name() {
  [[ ${#1} -le 255 && "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
}
if ! valid_file_name "${CONFIG_FILE}" || ! valid_file_name "${KEY_FILE}"; then
  echo "CONFIG_FILE and KEY_FILE must be simple file names." >&2
  exit 1
fi

mkdir -p "${DATA_DIR}"
cd "${DATA_DIR}"

valid_dns_domain() {
  local domain="$1" label
  [[ ${#domain} -le 253 && "$domain" == *.* ]] || return 1
  case "$domain" in *[!A-Za-z0-9.-]*|.*|*.|*..*) return 1;; esac
  IFS='.' read -r -a labels <<< "$domain"
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 ]] || return 1
    case "$label" in -*|*-) return 1;; esac
  done
}

bootstrap_config() {
  local domain_value tmp_config

  domain_value="${DOMAIN:-}"
  if [[ -z "${domain_value}" ]]; then
    echo "ERROR: DOMAIN env is required when /data/${CONFIG_FILE} does not exist." >&2
    exit 1
  fi
  valid_dns_domain "${domain_value}" || { echo "ERROR: DOMAIN must be a valid DNS domain." >&2; exit 1; }

  [[ -f "${SAMPLE_CONFIG}" ]] || { echo "Missing baked sample config: ${SAMPLE_CONFIG}" >&2; exit 1; }
  tmp_config="$(mktemp "${DATA_DIR}/config.XXXXXX")"
  trap 'rm -f "${tmp_config}"' EXIT

  domain_value="${domain_value//&/\\&}"
  sed -E \
    -e "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${domain_value}\"]|" \
    -e "s|^ENCRYPTION_KEY_FILE[[:space:]]*=.*$|ENCRYPTION_KEY_FILE = \"${KEY_FILE}\"|" \
    "${SAMPLE_CONFIG}" > "${tmp_config}"
  grep -q "^ENCRYPTION_KEY_FILE = \"${KEY_FILE}\"$" "${tmp_config}" || {
    echo "Sample config has no ENCRYPTION_KEY_FILE setting." >&2
    exit 1
  }
  chmod 0600 "${tmp_config}"
  mv -f "${tmp_config}" "${DATA_DIR}/${CONFIG_FILE}"
  trap - EXIT
}

if [[ ! -x "${BIN}" ]]; then
  echo "Binary not found or not executable: ${BIN}" >&2
  exit 1
fi

if [[ ! -f "${DATA_DIR}/${CONFIG_FILE}" ]]; then
  bootstrap_config
fi

if ! grep -Eq '^[[:space:]]*KEYRING_FILE[[:space:]]*=[[:space:]]*"[^"]+"' "${DATA_DIR}/${CONFIG_FILE}"; then
  tmp_log="$(mktemp)"
  if ! "${BIN}" -config "${DATA_DIR}/${CONFIG_FILE}" -genkey -nowait >"${tmp_log}" 2>&1; then
    tail -n 100 "${tmp_log}" >&2 || true
    rm -f "${tmp_log}"
    exit 1
  fi
  rm -f "${tmp_log}"
fi

exec "${BIN}" -config "${DATA_DIR}/${CONFIG_FILE}" -nowait "$@"
