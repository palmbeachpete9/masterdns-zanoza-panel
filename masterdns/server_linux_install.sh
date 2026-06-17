#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || log_error "Missing command: $1"; }
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
valid_service_user() {
  case "$1" in
    ''|*[!a-z0-9_-]*|[0-9-]*) return 1;;
  esac
  [[ ${#1} -le 32 ]]
}
valid_installer_path() {
  case "$1" in
    /|''|*[!A-Za-z0-9_./-]*|*/../*|*/..|*/./*|*/.) return 1;;
    /*) return 0;;
    *) return 1;;
  esac
}
assert_root_owned_parent() {
  local cur
  cur="$(dirname "$1")"
  while [[ "$cur" != "/" ]]; do
    [[ ! -L "$cur" ]] || log_error "Unsafe symlink in privileged path: $cur"
    [[ "$(stat -c '%u' "$cur")" == "0" ]] || log_error "Privileged path parent is not root-owned: $cur"
    local mode
    mode="$(stat -c '%a' "$cur")"
    (( (8#$mode & 0022) == 0 )) || log_error "Privileged path parent is writable by group/other: $cur"
    cur="$(dirname "$cur")"
  done
}
backup_file_once() {
  local f="$1"
  [[ -f "$f" && ! -f "${f}.bak" ]] && cp -a "$f" "${f}.bak"
}
extract_config_version() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  runuser -u "$SVC_USER" -- grep '^CONFIG_VERSION' -- "$f" | awk -F'=' '{print $2}' | tr -d ' "' | head -n1
}
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
detect_legacy_linux() {
  local id="${ID:-}"
  local version_major="${VERSION_ID%%.*}"

  case "$id" in
    ubuntu)
      [[ "${version_major:-0}" -le 20 ]]
      ;;
    debian)
      [[ "${version_major:-0}" -le 11 ]]
      ;;
    almalinux|rocky|rhel|centos)
      [[ "${version_major:-0}" -le 8 ]]
      ;;
    *)
      return 1
      ;;
  esac
}
print_usage() {
  cat <<'USAGE'
MasterDnsVPN Server Linux Installer

Usage:
  bash server_linux_install.sh [OPTIONS]

Options:
  -v, --version <VERSION>   Required immutable MasterDnsVPN release tag.
  -s, --sha256 <SHA256>     Required SHA-256 of the selected release ZIP.
  -u, --uninstall           Uninstall MasterDnsVPN: stop and remove the systemd
                            service, drop kernel/limit tunings, and clean up
                            binaries and config files in the install directory.
  -h, --help                Show this help message and exit.

Examples:
  # Install a verified release:
  bash server_linux_install.sh --version v2026.04.12.234117-978faee --sha256 <SHA256>

  # Uninstall MasterDnsVPN:
  bash server_linux_install.sh --uninstall
USAGE
}

select_release_artifact() {
  local arch="$1"
  local version="${2:-}"
  [[ -n "$version" ]] || log_error "An immutable release version is required."
  local legacy=0
  if detect_legacy_linux; then
    legacy=1
    log_info "Legacy system detected (broader Linux compatibility mode)."
  fi

  local base_url="https://github.com/masterking32/MasterDnsVPN/releases/download/${version}"
  log_info "Targeting MasterDnsVPN release: ${version}"

  case "$arch" in
    aarch64|arm64)
      if [[ $legacy -eq 1 ]]; then
        PREFIX="MasterDnsVPN_Server_Linux-Legacy_ARM64"
      else
        PREFIX="MasterDnsVPN_Server_Linux_ARM64"
      fi
      ;;
    armv7l|armv7|armhf)
      PREFIX="MasterDnsVPN_Server_Linux_ARMV7"
      ;;
    x86_64|amd64)
      if [[ $legacy -eq 1 ]]; then
        PREFIX="MasterDnsVPN_Server_Linux-Legacy_AMD64"
      else
        PREFIX="MasterDnsVPN_Server_Linux_AMD64"
      fi
      ;;
    i386|i486|i586|i686|x86)
      PREFIX="MasterDnsVPN_Server_Linux_X86"
      ;;
    *)
      log_error "Unsupported architecture: $arch"
      ;;
  esac

  URL="${base_url}/${PREFIX}.zip"
}

ACTION="install"
TARGET_VERSION=""
RELEASE_SHA256="${MASTERDNS_RELEASE_SHA256:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      [[ $# -ge 2 ]] || { echo "Error: $1 requires a value" >&2; print_usage; exit 2; }
      TARGET_VERSION="$2"
      shift 2
      ;;
    -s|--sha256)
      [[ $# -ge 2 ]] || { echo "Error: $1 requires a value" >&2; print_usage; exit 2; }
      RELEASE_SHA256="$2"
      shift 2
      ;;
    --sha256=*)
      RELEASE_SHA256="${1#*=}"
      shift
      ;;
    --version=*)
      TARGET_VERSION="${1#*=}"
      shift
      ;;
    -u|--uninstall)
      ACTION="uninstall"
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      print_usage
      exit 2
      ;;
  esac
done

if [[ "$ACTION" == "uninstall" && -n "$TARGET_VERSION" ]]; then
  echo "Error: --version cannot be combined with --uninstall" >&2
  exit 2
fi

if [[ -n "$TARGET_VERSION" && ! "$TARGET_VERSION" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "Error: invalid version tag: $TARGET_VERSION" >&2
  exit 2
fi
if [[ "$ACTION" == "install" ]]; then
  [[ -n "$TARGET_VERSION" ]] || { echo "Error: --version is required for verified installation" >&2; exit 2; }
  [[ "$RELEASE_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Error: --sha256 must be exactly 64 hex characters" >&2; exit 2; }
fi

if [[ -n "$TARGET_VERSION" ]]; then
  log_info "Requested release tag: $TARGET_VERSION"
fi

if [[ "${EUID}" -ne 0 ]]; then
  log_error "Run this script as root (sudo)."
fi

INSTALL_DIR="${MASTERDNS_STATE_DIR:-/var/lib/masterdnsvpn}"
BIN_DIR="${MASTERDNS_BIN_DIR:-/usr/local/lib/masterdnsvpn}"
BIN_PATH="$BIN_DIR/masterdnsvpn"
SVC_USER="${MASTERDNS_SERVICE_USER:-masterdnsvpn}"
valid_installer_path "$INSTALL_DIR" || log_error "Invalid state directory: $INSTALL_DIR"
valid_installer_path "$BIN_DIR" || log_error "Invalid binary directory: $BIN_DIR"
valid_service_user "$SVC_USER" || log_error "Invalid service user: $SVC_USER"
[[ ! -L "$INSTALL_DIR" && ! -L "$BIN_DIR" ]] || log_error "Install paths must not be symlinks."
if [[ "$ACTION" == "install" ]] && ! id -u "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" || log_error "Could not create service user."
fi
if [[ "$ACTION" == "install" ]]; then
  [[ "$(id -u "$SVC_USER")" -ne 0 ]] || log_error "Service user must not be root."
fi
assert_root_owned_parent "$BIN_DIR"
assert_root_owned_parent "$INSTALL_DIR"
if [[ "$ACTION" == "install" ]]; then
  install -d -o root -g root -m 0755 "$BIN_DIR"
  if [[ ! -e "$INSTALL_DIR" ]]; then
    install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$INSTALL_DIR"
  fi
  [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] || log_error "State path must be a real directory."
  [[ "$(stat -c '%U' "$INSTALL_DIR")" == "$SVC_USER" ]] || log_error "State directory must belong to $SVC_USER."
  [[ -z "$(find "$INSTALL_DIR" -xdev -type l -print -quit)" ]] || log_error "State directory contains symlinks; refusing privileged update."
  cd "$INSTALL_DIR" || log_error "Cannot access state directory: $INSTALL_DIR"
else
  [[ ! -e "$BIN_DIR" || ( -d "$BIN_DIR" && ! -L "$BIN_DIR" ) ]] || log_error "Binary path must be a real directory."
  [[ ! -e "$INSTALL_DIR" || ( -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ) ]] || log_error "State path must be a real directory."
fi
log_info "State directory: $INSTALL_DIR"
log_info "Binary path: $BIN_PATH"
if [[ "$ACTION" == "install" && -f "server_config.toml" && -f "server_config.toml.backup" ]]; then
  log_error "Both server_config.toml and server_config.toml.backup exist. Remove one and retry."
fi

if [[ "$ACTION" == "install" && -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
elif [[ "$ACTION" == "install" ]]; then
  log_error "OS detection failed (/etc/os-release missing)."
fi

echo -e "${MAGENTA}${BOLD}"
echo "  __  __           _             _____  _   _  _____ "
echo " |  \/  |         | |           |  __ \| \ | |/ ____|"
echo " | \  / | __ _ ___| |_ ___ _ __ | |  | |  \| | (___  "
echo " | |\/| |/ _\` / __| __/ _ \ '__|| |  | | . \ |\___ \ "
echo " | |  | | (_| \__ \ ||  __/ |   | |__| | |\  |____) |"
echo " |_|  |_|\__,_|___/\__\___|_|   |_____/|_| \_|_____/ "
if [[ "$ACTION" == "uninstall" ]]; then
  echo -e "          MasterDnsVPN Server Auto-Uninstaller${NC}"
else
  echo -e "           MasterDnsVPN Server Auto-Installer${NC}"
fi
echo -e "${CYAN}------------------------------------------------------${NC}"

TMP_LOG="$(mktemp /tmp/masterdnsvpn_init.XXXXXX)"
DOWNLOAD_DIR=""
ROLLBACK_DIR=""
ROLLBACK_READY=false
INSTALL_COMMITTED=false
PREVIOUS_SERVICE_ACTIVE=false

snapshot_artifact() {
  local label="$1" path="$2"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a --no-dereference -- "$path" "$ROLLBACK_DIR/$label"
    : > "$ROLLBACK_DIR/$label.present"
  fi
}

restore_artifact() {
  local label="$1" path="$2"
  rm -rf -- "$path" || true
  if [[ -f "$ROLLBACK_DIR/$label.present" ]]; then
    cp -a --no-dereference -- "$ROLLBACK_DIR/$label" "$path" || true
  fi
}

cleanup() {
  local status=$?
  if [[ "$ACTION" == "install" && "$ROLLBACK_READY" == true && "$INSTALL_COMMITTED" != true && -n "${ROLLBACK_DIR:-}" && -d "${ROLLBACK_DIR:-}" ]]; then
    restore_artifact binary "$BIN_PATH"
    restore_artifact config "$INSTALL_DIR/server_config.toml"
    restore_artifact config_backup "$INSTALL_DIR/server_config.toml.backup"
    restore_artifact key "$INSTALL_DIR/encrypt_key.txt"
    restore_artifact unit /etc/systemd/system/masterdnsvpn.service
    restore_artifact sysctl /etc/sysctl.d/99-masterdnsvpn.conf
    restore_artifact limits /etc/security/limits.d/99-masterdnsvpn.conf
    systemctl daemon-reload >/dev/null 2>&1 || true
    sysctl --system >/dev/null 2>&1 || true
    if [[ "$PREVIOUS_SERVICE_ACTIVE" == true ]]; then
      systemctl restart masterdnsvpn >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$TMP_LOG" 2>/dev/null || true
  if [[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]]; then
    rm -rf "$DOWNLOAD_DIR" 2>/dev/null || true
  fi
  if [[ -n "${ROLLBACK_DIR:-}" && -d "${ROLLBACK_DIR:-}" ]]; then
    rm -rf "$ROLLBACK_DIR" 2>/dev/null || true
  fi
  return "$status"
}
trap cleanup EXIT

if [[ "$ACTION" == "install" ]]; then
  ROLLBACK_DIR="$(mktemp -d /tmp/masterdnsvpn_rollback.XXXXXX 2>/dev/null || true)"
  [[ -n "${ROLLBACK_DIR:-}" && -d "${ROLLBACK_DIR:-}" ]] || log_error "Failed to create rollback directory."
  systemctl is-active --quiet masterdnsvpn && PREVIOUS_SERVICE_ACTIVE=true
  snapshot_artifact binary "$BIN_PATH"
  snapshot_artifact config "$INSTALL_DIR/server_config.toml"
  snapshot_artifact config_backup "$INSTALL_DIR/server_config.toml.backup"
  snapshot_artifact key "$INSTALL_DIR/encrypt_key.txt"
  snapshot_artifact unit /etc/systemd/system/masterdnsvpn.service
  snapshot_artifact sysctl /etc/sysctl.d/99-masterdnsvpn.conf
  snapshot_artifact limits /etc/security/limits.d/99-masterdnsvpn.conf
  ROLLBACK_READY=true
fi

check_port53() {
  ss -H -lun "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  ss -H -ltn "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  return 1
}

show_port53_usage() {
  log_warn "Current listeners on port 53:"
  ss -lupn "sport = :53" 2>/dev/null || true
  ss -ltpn "sport = :53" 2>/dev/null || true
  lsof -nP -iUDP:53 -iTCP:53 2>/dev/null || true
}

get_port53_pids() {
  local pids_udp pids_tcp pids
  pids_udp="$(ss -H -lupn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids_tcp="$(ss -H -ltpn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids="$(printf '%s\n%s\n' "$pids_udp" "$pids_tcp" | sed '/^$/d' | sort -u)"
  if [[ -n "$pids" ]]; then
    echo "$pids"
    return 0
  fi
  lsof -ti :53 2>/dev/null || true
}

terminate_port53_pid() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  local cmdline
  cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
  log_warn "Trying to terminate PID on port 53: $pid (${cmdline:-unknown})"

  kill "$pid" 2>/dev/null || true
  for _ in 1 2 3; do
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  done

  kill -9 "$pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    log_warn "PID $pid is still alive after SIGKILL."
    return 1
  fi
  return 0
}

is_managed_masterdns_pid() {
  local pid="$1" process_exe managed_exe
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  process_exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  managed_exe="$(readlink -f "$BIN_PATH" 2>/dev/null || true)"
  [[ -n "$process_exe" && -n "$managed_exe" && "$process_exe" == "$managed_exe" ]]
}

do_uninstall() {
  log_header "Uninstalling MasterDnsVPN"

  if systemctl list-unit-files --all 2>/dev/null | grep -q '^masterdnsvpn\.service'; then
    log_info "Stopping and disabling masterdnsvpn service..."
    systemctl stop masterdnsvpn 2>/dev/null || true
    systemctl disable masterdnsvpn >/dev/null 2>&1 || true
    systemctl reset-failed masterdnsvpn 2>/dev/null || true
  else
    log_info "No masterdnsvpn systemd unit found."
  fi

  if [[ -f /etc/systemd/system/masterdnsvpn.service ]]; then
    rm -f /etc/systemd/system/masterdnsvpn.service
    log_success "Removed /etc/systemd/system/masterdnsvpn.service"
  fi
  systemctl daemon-reload 2>/dev/null || true

  local pid proc_exe
  for proc_exe in /proc/[0-9]*/exe; do
    pid="${proc_exe#/proc/}"
    pid="${pid%/exe}"
    if is_managed_masterdns_pid "$pid"; then
      log_warn "Terminating stray process using the managed MasterDnsVPN binary (PID: $pid)..."
      kill "$pid" 2>/dev/null || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
  done

  if [[ -f /etc/sysctl.d/99-masterdnsvpn.conf ]]; then
    rm -f /etc/sysctl.d/99-masterdnsvpn.conf
    sysctl --system >/dev/null 2>&1 || true
    log_success "Removed kernel tuning (/etc/sysctl.d/99-masterdnsvpn.conf)."
  fi
  if [[ -f /etc/security/limits.d/99-masterdnsvpn.conf ]]; then
    rm -f /etc/security/limits.d/99-masterdnsvpn.conf
    log_success "Removed file descriptor limits (/etc/security/limits.d/99-masterdnsvpn.conf)."
  fi

  log_header "Cleaning Install Directory"
  log_info "Install directory: $INSTALL_DIR"
  shopt -s nullglob
  local removed=0
  for f in \
    "$INSTALL_DIR"/MasterDnsVPN_Server_Linux*_v* \
    "$INSTALL_DIR"/server_config.toml \
    "$INSTALL_DIR"/server_config.toml.backup \
    "$INSTALL_DIR"/server_config.toml.bak \
    "$INSTALL_DIR"/server_config_*.toml \
    "$INSTALL_DIR"/encrypt_key.txt \
    "$INSTALL_DIR"/init_logs.tmp \
    "$INSTALL_DIR"/*.spec; do
    if [[ -e "$f" ]]; then
      rm -f -- "$f"
      log_info "Removed: $f"
      removed=1
    fi
  done
  shopt -u nullglob
  if [[ $removed -eq 0 ]]; then
    log_warn "No MasterDnsVPN files found in $INSTALL_DIR. If you installed elsewhere, run the uninstaller from that directory."
  fi
  # Remove only installer-owned artifacts. Custom state/binary directories may
  # contain unrelated administrator files, and the service account may have
  # pre-dated this installation or be shared by another service.
  rm -f -- "$BIN_PATH"
  rmdir -- "$BIN_DIR" "$INSTALL_DIR" 2>/dev/null || true

  echo -e "\n${CYAN}======================================================${NC}"
  echo -e " ${GREEN}${BOLD}        MASTERDNSVPN UNINSTALL COMPLETED${NC}"
  echo -e "${CYAN}======================================================${NC}"
  echo -e "${YELLOW}Note:${NC} Firewall rules for port 53 (UDP/TCP) were left in place."
  echo -e "      Remove them manually if no longer needed."
}

stop_existing_masterdnsvpn_service() {
  local unit_present=0
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^masterdnsvpn\.service'; then
    unit_present=1
    log_info "Stopping existing MasterDnsVPN service..."
    systemctl stop masterdnsvpn 2>/dev/null || true

    for _ in 1 2 3 4 5; do
      if ! systemctl is-active --quiet masterdnsvpn; then
        break
      fi
      sleep 1
    done

    local main_pid
    main_pid="$(systemctl show masterdnsvpn --property MainPID --value 2>/dev/null || true)"
    if [[ -n "${main_pid:-}" && "$main_pid" != "0" ]] && kill -0 "$main_pid" 2>/dev/null; then
      log_warn "masterdnsvpn service is still active. Trying to terminate MainPID: $main_pid"
      terminate_port53_pid "$main_pid" || true
    fi

    systemctl stop masterdnsvpn 2>/dev/null || true
    systemctl reset-failed masterdnsvpn 2>/dev/null || true
  fi

  local pid killed=0
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    if is_managed_masterdns_pid "$pid"; then
      if [[ $killed -eq 0 && $unit_present -eq 0 ]]; then
        log_info "Stopping process using the managed MasterDnsVPN binary that was started outside systemd..."
      fi
      terminate_port53_pid "$pid" || true
      killed=1
    fi
  done <<< "$(get_port53_pids)"
}

if [[ "$ACTION" == "uninstall" ]]; then
  do_uninstall
  exit 0
fi

PM=""
if command -v apt-get >/dev/null 2>&1; then PM="apt";
elif command -v dnf >/dev/null 2>&1; then PM="dnf";
elif command -v yum >/dev/null 2>&1; then PM="yum";
else log_error "No supported package manager found (apt/dnf/yum)."; fi

log_header "Preparing Environment"
log_info "Installing dependencies..."
if [[ "$PM" == "apt" ]]; then
  apt-get update -y >/dev/null 2>&1
  apt-get install -y lsof net-tools wget unzip curl ca-certificates iproute2 procps >/dev/null 2>&1
elif [[ "$PM" == "dnf" ]]; then
  dnf -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng >/dev/null 2>&1
else
  yum -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng >/dev/null 2>&1
fi
require_cmd ss
require_cmd unzip
require_cmd systemctl
require_cmd sysctl
require_cmd runuser
log_success "System tools are ready."

log_header "Stopping Existing MasterDnsVPN"
stop_existing_masterdnsvpn_service

log_header "Managing Network Ports (Port 53)"
if check_port53; then
  show_port53_usage
  OCC_INFO="$(ss -H -lupn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
  [[ -z "${OCC_INFO:-}" ]] && OCC_INFO="$(ss -H -ltn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
  log_error "Port 53 is occupied by ${OCC_INFO:-an existing DNS service}. The installer will not disable services, kill unrelated processes, or remove firewall/NAT rules; resolve the conflict explicitly and retry."
fi
log_success "Port 53 is available."

log_header "Firewall"
log_warn "Firewall policy is not changed automatically. Explicitly allow inbound UDP/TCP port 53 according to your host policy."

log_header "Tuning Kernel & Limits"
cat > /etc/sysctl.d/99-masterdnsvpn.conf <<'EOF'
# MasterDnsVPN high-load tuning
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 25165824
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_mem = 65536 131072 262144
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 15
net.netfilter.nf_conntrack_udp_timeout_stream = 60
net.ipv4.ip_local_port_range = 10240 65535
EOF
sysctl --system >/dev/null 2>&1 || log_warn "Could not fully apply sysctl settings."

cat > /etc/security/limits.d/99-masterdnsvpn.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
log_success "Kernel and file descriptor limits configured."

log_header "Fetching Verified Release ${TARGET_VERSION}"
ARCH="$(uname -m)"
select_release_artifact "$ARCH" "$TARGET_VERSION"
log_info "Download URL: $URL"

if [[ -f "server_config.toml" ]]; then
  runuser -u "$SVC_USER" -- mv -f server_config.toml server_config.toml.backup
  log_info "Existing config backed up."
fi

log_info "Downloading server binaries..."
DOWNLOAD_DIR="$(mktemp -d /tmp/masterdnsvpn_download.XXXXXX 2>/dev/null || true)"
[[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]] || log_error "Failed to create temporary download directory. Check free space and /tmp permissions."
ZIP_PATH="${DOWNLOAD_DIR}/server.zip"

if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$ZIP_PATH" "$URL"; then
  log_warn "curl download failed, trying wget..."
  wget -qO "$ZIP_PATH" "$URL" || {
    log_warn "Disk usage snapshot:"
    df -h "$INSTALL_DIR" /tmp 2>/dev/null || true
    log_error "Download failed."
  }
fi

[[ -s "$ZIP_PATH" ]] || log_error "Downloaded archive is missing or empty: $ZIP_PATH"
GOT_SHA256="$(sha256sum "$ZIP_PATH" | awk '{print $1}')"
[[ "${GOT_SHA256,,}" == "${RELEASE_SHA256,,}" ]] || log_error "Release checksum mismatch."

STAGE_DIR="$DOWNLOAD_DIR/extracted"
mkdir -m 0700 "$STAGE_DIR"
unzip -q -o "$ZIP_PATH" -d "$STAGE_DIR" || log_error "Failed to extract archive."
log_success "Files extracted."

STAGED_EXECUTABLE="$(find "$STAGE_DIR" -maxdepth 2 -type f -name "${PREFIX}_v*" | sort -V | tail -n1)"
[[ -n "$STAGED_EXECUTABLE" ]] || log_error "Binary not found in package."
install -o root -g root -m 0755 "$STAGED_EXECUTABLE" "$BIN_PATH"
EXECUTABLE="$BIN_PATH"
if [[ ! -f "server_config.toml" ]]; then
  STAGED_CONFIG="$(find "$STAGE_DIR" -maxdepth 2 -type f -name server_config.toml | head -n1)"
  [[ -n "$STAGED_CONFIG" ]] || log_error "server_config.toml not found in package."
  # shellcheck disable=SC2016 # positional parameter expands inside the child shell
  runuser -u "$SVC_USER" -- sh -c 'umask 027; cat > "$1"' sh "$INSTALL_DIR/server_config.toml" < "$STAGED_CONFIG"
fi

log_header "Configuration"
[[ -f "server_config.toml" ]] || log_error "server_config.toml not found after extraction."
CURRENT_VERSION="$(extract_config_version server_config.toml)"
if [[ -z "${CURRENT_VERSION:-}" ]]; then
  log_error "Downloaded server_config.toml is invalid (CONFIG_VERSION missing)."
fi
if [[ -f "server_config.toml.backup" ]]; then
  BACKUP_VERSION="$(extract_config_version server_config.toml.backup)"
  if [[ -z "${BACKUP_VERSION:-}" ]]; then
    log_error "Backup config is too old (CONFIG_VERSION missing). Merge manually."
  fi

  if [[ "$BACKUP_VERSION" == "$CURRENT_VERSION" ]]; then
    runuser -u "$SVC_USER" -- mv -f server_config.toml.backup server_config.toml
    log_info "Config restored from backup."
  elif version_lt "$BACKUP_VERSION" "$CURRENT_VERSION"; then
    OLD_CFG_NAME="server_config_$(date +%Y%m%d_%H%M%S).toml"
    runuser -u "$SVC_USER" -- mv -f server_config.toml.backup "$OLD_CFG_NAME"
    log_warn "Old config version detected (backup=$BACKUP_VERSION < new=$CURRENT_VERSION)."
    log_warn "Previous config renamed to: $OLD_CFG_NAME"
    log_info "Using fresh config template; please set DOMAIN and other required fields."
  else
    log_error "Backup config version is newer than package config (backup=$BACKUP_VERSION, new=$CURRENT_VERSION). Merge manually."
  fi
fi

if [[ -f "server_config.toml" ]] && runuser -u "$SVC_USER" -- grep -q '"v.domain.com"' server_config.toml; then
  echo -e "${YELLOW}${BOLD}Attention:${NC} Set your NS domain."
  read -r -p ">>> Enter your Domain (e.g. vpn.example.com): " USER_DOMAIN </dev/tty || true
  if [[ -n "${USER_DOMAIN:-}" ]]; then
    valid_dns_domain "$USER_DOMAIN" || log_error "Invalid DNS domain: $USER_DOMAIN"
    runuser -u "$SVC_USER" -- sed -i -E "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${USER_DOMAIN}\"]|" server_config.toml
  fi
fi

runuser -u "$SVC_USER" -- chmod 0750 "$INSTALL_DIR"

log_header "Security Initialization"
log_info "Starting server once to generate encryption key..."
SERVICE_ARGS="-nowait"
KEY_GENERATED=false

# Try with -genkey -nowait (newest versions)
if runuser -u "$SVC_USER" -- "$EXECUTABLE" -genkey -nowait > "$TMP_LOG" 2>&1; then
  log_success "Key generated!"
  KEY_GENERATED=true
fi

# Try running normally to trigger key generation (older versions < commit 86d1d9d)
if [[ "$KEY_GENERATED" != true ]]; then
  runuser -u "$SVC_USER" -- "$EXECUTABLE" > "$TMP_LOG" 2>&1 &
  APP_PID=$!
  READY=false
  for _ in {1..10}; do
    if grep -q "Active Encryption Key" "$TMP_LOG" 2>/dev/null; then
      READY=true
      break
    fi
    sleep 1
  done
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true

  if grep -q "Active Encryption Key" "$TMP_LOG" 2>/dev/null; then
    READY=true
  fi

  if [[ "$READY" == true ]]; then
    log_success "Key generated."
    SERVICE_ARGS=""
    KEY_GENERATED=true
  else
    log_warn "Initialization log tail:"
    tail -n 20 "$TMP_LOG" || true
    log_error "Could not verify key generation."
  fi
fi

echo -e "${GREEN}${BOLD}------------------------------------------------------"
echo -e "  YOUR ENCRYPTION KEY: ${NC}${CYAN}$(runuser -u "$SVC_USER" -- cat encrypt_key.txt 2>/dev/null)${NC}"
echo -e "${GREEN}${BOLD}------------------------------------------------------${NC}"

log_header "Installing System Service"
SVC="/etc/systemd/system/masterdnsvpn.service"
cat > "$SVC" <<EOF
[Unit]
Description=MasterDnsVPN Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN_PATH $SERVICE_ARGS
Restart=always
RestartSec=3
User=$SVC_USER
Group=$SVC_USER
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$INSTALL_DIR
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
TimeoutStopSec=15
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable masterdnsvpn >/dev/null 2>&1
systemctl restart masterdnsvpn
sleep 3

SERVICE_RESTARTS="$(systemctl show masterdnsvpn --property NRestarts --value 2>/dev/null || echo unknown)"
if ! systemctl is-active --quiet masterdnsvpn || [[ "$SERVICE_RESTARTS" != "0" ]]; then
  journalctl -u masterdnsvpn -n 50 --no-pager || true
  log_error "Service failed to stay healthy (restarts=${SERVICE_RESTARTS}). See logs above."
fi

log_success "MasterDnsVPN service is running."
INSTALL_COMMITTED=true

echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${YELLOW}>${NC} Start:   systemctl start masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Stop:    systemctl stop masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Restart: systemctl restart masterdnsvpn"
echo -e "  ${YELLOW}>${NC} Logs:    journalctl -u masterdnsvpn -f"
echo -e "\n${BOLD}Files:${NC}"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/server_config.toml"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/encrypt_key.txt"
echo -e "${YELLOW}Final Note:${NC} If config changes, run: systemctl restart masterdnsvpn"

rm -f -- ./*.spec >/dev/null 2>&1 || true
