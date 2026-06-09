#!/usr/bin/env bash
# ==============================================================================
# Zanoza Panel installer (Debian/Ubuntu, run as root).
#   curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/masterdns-zanoza-panel/main/scripts/install.sh | sudo bash
# Prompts for port, admin path and TLS certificate (3x-ui style), generates
# admin credentials, builds the forked MasterDnsVPN server + the panel, and
# installs the `zanoza` management command.
# ==============================================================================
set -euo pipefail

# MODE=install (default) runs the interactive first-time setup; MODE=update is
# set by `zanoza update` to rebuild + atomically replace binaries while
# preserving config, credentials, bind address, port, path, TLS mode and
# instances (F10).
MODE="${ZANOZA_MODE:-install}"

REPO="${ZANOZA_REPO:-https://github.com/palmbeachpete9/masterdns-zanoza-panel.git}"
REF="${ZANOZA_REF:-main}"
SRC_DIR="${ZANOZA_SRC_DIR:-/opt/masterdns-zanoza-panel}"
CONFIG_DIR="${ZANOZA_CONFIG_DIR:-/etc/zanoza-panel}"
CONFIG_PATH="$CONFIG_DIR/config.json"
# Certificates live in a ROOT-owned subdir (service-readable via group) so the
# root renewal job never follows a service-planted symlink (V4-01).
TLS_DIR="$CONFIG_DIR/certs"
TLS_CERT="$TLS_DIR/tls.crt"
TLS_KEY="$TLS_DIR/tls.key"
SVC_USER="${ZANOZA_SVC_USER:-zanoza}"  # unprivileged service account (R-09)
PANEL_BIN="/usr/local/bin/zanoza-panel"
SERVER_BIN="/usr/local/bin/masterdns-server"
CLI_BIN="/usr/local/bin/zanoza"
# Pin to a Go patch level at/above the known-fixed stdlib floor (N01), which is
# also >= the `go 1.25.0` directive in go.mod / masterdns/go.mod (F17).
GO_VERSION="${GO_VERSION:-1.25.11}"
GO_MIN_VERSION="1.25.11"
# Optional pinned Go toolchain SHA-256 (linux). When set (env or here), the
# downloaded tarball is verified before extraction; otherwise the official
# checksum published at go.dev is fetched and enforced (F27).
GO_SHA256_amd64="${GO_SHA256_amd64:-}"
GO_SHA256_arm64="${GO_SHA256_arm64:-}"

log()  { printf '\033[1;32m[zanoza]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[zanoza]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[zanoza] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo)."

read_tty() { # prompt -> echoes answer; falls back to default with no tty
	local prompt="$1" def="${2:-}"
	if [ -r /dev/tty ]; then read -r -p "$prompt" REPLY </dev/tty || REPLY="$def"; else REPLY="$def"; fi
	printf '%s' "${REPLY:-$def}"
}

random_port() {
	local p
	for _ in $(seq 1 20); do
		p=$(( (RANDOM<<2 ^ RANDOM) % 40000 + 20000 ))
		ss -ltn "( sport = :$p )" 2>/dev/null | grep -q ":$p" || { printf '%s' "$p"; return; }
	done
	printf '8443'
}
# `tr` keeps writing to the endless /dev/urandom after `head` closes the pipe,
# so under `set -o pipefail` the SIGPIPE (141) would abort the script. The
# trailing `|| true` swallows it; the N chars are already on stdout.
random_alnum() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "$1" || true; }

# valid_port echoes a port in 1..65535 or fails (F14).
valid_port() {
	case "$1" in
		''|*[!0-9]*) return 1;;
	esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ] || return 1
	printf '%s' "$1"
}

# norm_path applies the backend's panel-path rules: one leading slash, no bare
# root, no trailing/nested slash, no whitespace/query/fragment characters (F14).
norm_path() {
	local p="${1#"${1%%[![:space:]]*}"}"; p="${p%"${p##*[![:space:]]}"}" # trim
	[ -n "$p" ] || return 1
	[ "${p#/}" = "$p" ] && p="/$p"
	p="/$(printf '%s' "$p" | sed 's#^/*##; s#/*$##')"
	[ "$p" = "/" ] && return 1
	# Single safe-slug segment only — rejects spaces, tabs, newlines, control
	# characters, query/fragment and nested slashes (R-07).
	case "${p#/}" in *[!A-Za-z0-9_-]*) return 1;; esac
	printf '%s' "$p"
}

# --------------------------------------------------------------------------
# Packages + Go
# --------------------------------------------------------------------------
log "Установка пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y git curl ca-certificates openssl iproute2 build-essential socat cron >/dev/null

# Dedicated unprivileged service account (R-09).
ensure_svc_user() {
	id -u "$SVC_USER" >/dev/null 2>&1 && return
	log "Создание системного пользователя ${SVC_USER}..."
	useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
		|| adduser --system --no-create-home --group "$SVC_USER" 2>/dev/null \
		|| die "не удалось создать пользователя ${SVC_USER}"
}
ensure_svc_user

# go_expected_sha256 returns the pinned checksum for arch, or fetches the
# official one published at go.dev (HTTPS) so a corrupted download is rejected
# before extraction (F27).
go_expected_sha256() {
	local arch="$1" pinned=""
	case "$arch" in
		amd64) pinned="$GO_SHA256_amd64";;
		arm64) pinned="$GO_SHA256_arm64";;
	esac
	if [ -n "$pinned" ]; then printf '%s' "$pinned"; return; fi
	# Official per-file checksum from the go.dev release metadata.
	curl -fsSL "https://go.dev/dl/?mode=json&include=all" 2>/dev/null \
		| tr -d ' \n' \
		| grep -o "\"filename\":\"go${GO_VERSION}.linux-${arch}.tar.gz\"[^}]*\"sha256\":\"[0-9a-f]*\"" \
		| grep -o '"sha256":"[0-9a-f]*"' | head -1 | sed 's/.*"sha256":"//; s/"//'
}

ensure_go() {
	if command -v go >/dev/null 2>&1; then
		local have; have="$(go version | awk '{print $3}' | sed 's/go//')"
		[ "$(printf '%s\n%s\n' "$GO_MIN_VERSION" "$have" | sort -V | head -1)" = "$GO_MIN_VERSION" ] && return
	fi
	log "Установка Go ${GO_VERSION}..."
	local arch; arch="$(dpkg --print-architecture)"
	case "$arch" in amd64) arch=amd64;; arm64) arch=arm64;; *) die "неизвестная архитектура: $arch";; esac
	# Download into a root-owned private temp dir (mode 0700) so an unprivileged
	# user can't pre-create/symlink the artifact path (V4-01).
	local td; td="$(mktemp -d)" || die "mktemp не удался"
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o "$td/go.tgz" || { rm -rf "$td"; die "не удалось скачать Go"; }
	local want; want="$(go_expected_sha256 "$arch")"
	if [ -z "$want" ]; then
		# Fail closed: never extract an unverified toolchain (F27). An operator
		# can pin GO_SHA256_${arch} or set ZANOZA_ALLOW_UNVERIFIED_GO=1 to override.
		if [ "${ZANOZA_ALLOW_UNVERIFIED_GO:-0}" = "1" ]; then
			warn "контрольная сумма Go не получена; проверка отключена (ZANOZA_ALLOW_UNVERIFIED_GO=1)."
		else
			rm -rf "$td"
			die "не удалось получить контрольную сумму Go ${GO_VERSION}; установка прервана (задайте GO_SHA256_${arch} или ZANOZA_ALLOW_UNVERIFIED_GO=1)."
		fi
	else
		local got; got="$(sha256sum "$td/go.tgz" | awk '{print $1}')"
		[ "$got" = "$want" ] || { rm -rf "$td"; die "контрольная сумма Go не совпала (ожидалось ${want}, получено ${got})"; }
		log "Go tarball verified (sha256 ok)."
	fi
	rm -rf /usr/local/go && tar -C /usr/local -xzf "$td/go.tgz"
	rm -rf "$td"
	export PATH="/usr/local/go/bin:$PATH"
}
ensure_go
export PATH="/usr/local/go/bin:$PATH"

# --------------------------------------------------------------------------
# Source + build
# --------------------------------------------------------------------------
# Pin the build source for reproducibility/supply-chain safety: warn (or refuse)
# when building from a mutable branch instead of a tag/commit SHA (R-08). Set
# ZANOZA_REF to an immutable tag/commit, or ZANOZA_ALLOW_MUTABLE_REF=1 to silence.
case "$REF" in
	main|master)
		if [ "${ZANOZA_ALLOW_MUTABLE_REF:-0}" = "1" ]; then
			warn "Сборка из изменяемой ветки '$REF' (ZANOZA_ALLOW_MUTABLE_REF=1)."
		else
			warn "Сборка из изменяемой ветки '$REF'. Для воспроизводимости задайте ZANOZA_REF=<тег|коммит>."
		fi
		;;
esac

# A failed fetch/reset must NOT silently fall through to building stale local
# source (F27). On update we hard-fail; on fresh install we clone or die.
# Fetch EXACTLY $REF (branch, tag, or commit SHA) and check out FETCH_HEAD. We
# never fall back to a different ref, so a commit pin is honoured or the install
# fails (V4-05).
if [ ! -d "$SRC_DIR/.git" ]; then
	log "Инициализация исходников из $REPO..."
	rm -rf "$SRC_DIR"
	git init -q "$SRC_DIR"
	git -C "$SRC_DIR" remote add origin "$REPO"
fi
log "Получение ref '$REF'..."
git -C "$SRC_DIR" fetch --depth 1 origin "$REF" || die "git fetch '$REF' не удался — установка прервана"
git -C "$SRC_DIR" checkout -q --force --detach FETCH_HEAD || die "git checkout не удался"
# If REF is a full commit SHA, prove HEAD matches it exactly (V4-05).
case "$REF" in
	[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
		head="$(git -C "$SRC_DIR" rev-parse HEAD)"
		[ "$head" = "$REF" ] || die "ожидался коммит $REF, получен $head — установка прервана"
		log "Проверено: HEAD = $REF"
		;;
esac
INSTALLED_COMMIT="$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
log "Сборка из коммита ${INSTALLED_COMMIT}"

# Build to temporary paths; live binaries are only swapped in after BOTH builds
# succeed, and are rolled back if the service fails to come up (F10).
log "Сборка панели (web/dist встроен в бинарь)..."
( cd "$SRC_DIR" && CGO_ENABLED=0 go build -o "${PANEL_BIN}.new" ./cmd/zanoza-panel ) || die "сборка панели не удалась — установка прервана"
log "Сборка форка сервера MasterDnsVPN..."
( cd "$SRC_DIR/masterdns" && CGO_ENABLED=0 go build -o "${SERVER_BIN}.new" ./cmd/server ) || die "сборка сервера не удалась — установка прервана"

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/masterdns" "$TLS_DIR"

# --------------------------------------------------------------------------
# Prompts: port, path, certificate (3x-ui style) — fresh install only.
# Update mode preserves all of this (F10).
# --------------------------------------------------------------------------
# SERVER_IP is needed by BOTH install and update branches (F10).
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

if [ "$MODE" = "update" ]; then
	[ -f "$CONFIG_PATH" ] || die "обновление невозможно: $CONFIG_PATH не найден (сначала установите панель)"
	command -v python3 >/dev/null 2>&1 || die "python3 требуется для обновления"
	log "Режим обновления: конфиг, учётные данные и сертификат сохранены."
	PORT="$(python3 -c "import json;print(json.load(open('$CONFIG_PATH')).get('panel_port',8443))")"
	PANEL_PATH="$(python3 -c "import json;print(json.load(open('$CONFIG_PATH')).get('panel_path','/admin'))")"
	PANEL_ADDR="$(python3 -c "import json;print(json.load(open('$CONFIG_PATH')).get('panel_addr','127.0.0.1'))")"
	if python3 -c "import json,sys;sys.exit(0 if json.load(open('$CONFIG_PATH')).get('tls_cert') else 1)"; then USE_TLS=1; else USE_TLS=0; fi
	CERT_HOST="$SERVER_IP"; [ "$PANEL_ADDR" = "127.0.0.1" ] && CERT_HOST="127.0.0.1"
	cert_choice="update"
else
PORT="$(random_port)"
ans="$(read_tty "A random port will be assigned. Customise? y/N: " "N")"
case "$ans" in y|Y)
	while :; do
		p="$(read_tty "Введите порт: " "$PORT")"
		if PORT="$(valid_port "$p")"; then break; fi
		warn "порт должен быть числом 1..65535"
	done;;
esac

PANEL_PATH="/admin"
ans="$(read_tty "Path /admin will be assigned. Customise? y/N: " "N")"
case "$ans" in y|Y)
	while :; do
		p="$(read_tty "Введите путь (например /secret): " "/admin")"
		if PANEL_PATH="$(norm_path "$p")"; then break; fi
		warn "путь должен быть вида /secret (без пробелов, ? # %, вложенных слешей, и не «/»)"
	done;;
esac

PANEL_ADDR="0.0.0.0"
USE_TLS=1
CERT_HOST="$SERVER_IP"

cat <<EOF

Выберите сертификат для веб-панели:
  1) IP-сертификат, срок 6 дней, автопродление (self-signed на ${SERVER_IP})
  2) Доменный сертификат Let's Encrypt (A-запись домена -> ${SERVER_IP}, напр. panel.example.com)
  3) Без сертификата — панель слушает ТОЛЬКО на 127.0.0.1 (доступ через nginx/ssh-туннель)
EOF
cert_choice="$(read_tty "Вариант [1/2/3] (по умолчанию 1): " "1")"

setup_self_signed() {
	local host="$1"
	openssl req -x509 -newkey rsa:2048 -nodes -days 6 \
		-keyout "$TLS_KEY" -out "$TLS_CERT" \
		-subj "/CN=${host}" -addext "subjectAltName=IP:${host}" >/dev/null 2>&1 || \
	openssl req -x509 -newkey rsa:2048 -nodes -days 6 \
		-keyout "$TLS_KEY" -out "$TLS_CERT" -subj "/CN=${host}" >/dev/null 2>&1
	chmod 600 "$TLS_KEY"
	# Auto-renewal: regenerate every day, restart panel.
	cat > /usr/local/bin/zanoza-renew-cert <<RENEW
#!/usr/bin/env bash
set -e
host="\$(hostname -I 2>/dev/null | awk '{print \$1}')"
openssl req -x509 -newkey rsa:2048 -nodes -days 6 \
  -keyout "$TLS_KEY" -out "$TLS_CERT" -subj "/CN=\${host}" -addext "subjectAltName=IP:\${host}" 2>/dev/null || \
openssl req -x509 -newkey rsa:2048 -nodes -days 6 -keyout "$TLS_KEY" -out "$TLS_CERT" -subj "/CN=\${host}" 2>/dev/null
chown root:${SVC_USER} "$TLS_CERT" "$TLS_KEY" 2>/dev/null || true
chmod 0640 "$TLS_CERT" "$TLS_KEY"
systemctl restart zanoza-panel 2>/dev/null || true
RENEW
	chmod 755 /usr/local/bin/zanoza-renew-cert
	cat > /etc/systemd/system/zanoza-cert.service <<UNIT
[Unit]
Description=Renew Zanoza Panel self-signed certificate
[Service]
Type=oneshot
ExecStart=/usr/local/bin/zanoza-renew-cert
UNIT
	cat > /etc/systemd/system/zanoza-cert.timer <<UNIT
[Unit]
Description=Daily Zanoza Panel certificate renewal
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
UNIT
	systemctl daemon-reload
	systemctl enable --now zanoza-cert.timer >/dev/null 2>&1 || true
}

# disable_self_signed_renewal idempotently tears down the self-signed renewal
# timer/service/script so a later switch to Let's Encrypt or no-TLS cannot leave
# a stale timer that overwrites the new certificate (F11).
disable_self_signed_renewal() {
	systemctl disable --now zanoza-cert.timer >/dev/null 2>&1 || true
	systemctl stop zanoza-cert.service >/dev/null 2>&1 || true
	rm -f /etc/systemd/system/zanoza-cert.timer \
	      /etc/systemd/system/zanoza-cert.service \
	      /usr/local/bin/zanoza-renew-cert
	systemctl daemon-reload >/dev/null 2>&1 || true
}

# ACME_SH_REF pins the acme.sh installer to an immutable tag instead of piping a
# mutable master branch into a shell (F27).
ACME_SH_REF="${ACME_SH_REF:-3.1.0}"

case "$cert_choice" in
	2)
		domain="$(read_tty "Домен панели (A-запись -> ${SERVER_IP}): " "")"
		[ -n "$domain" ] || die "домен обязателен для варианта 2."
		CERT_HOST="$domain"
		disable_self_signed_renewal
		log "Выпуск сертификата Let's Encrypt через acme.sh (${ACME_SH_REF}) для ${domain}..."
		# Root-owned private temp dir (mode 0700): no predictable, pre-creatable
		# download/extract paths (V4-01).
		acme_td="$(mktemp -d)" || die "mktemp не удался"
		acme_tarball="$acme_td/acme.tar.gz"
		if curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_REF}.tar.gz" -o "$acme_tarball"; then
			# Verify the tarball against a pinned checksum when provided (F27).
			if [ -n "${ACME_SH_SHA256:-}" ]; then
				got="$(sha256sum "$acme_tarball" | awk '{print $1}')"
				[ "$got" = "$ACME_SH_SHA256" ] || { rm -rf "$acme_td"; die "контрольная сумма acme.sh не совпала"; }
			fi
			tar -xzf "$acme_tarball" -C "$acme_td"
			( cd "$acme_td/acme.sh-${ACME_SH_REF}" && ./acme.sh --install -m "admin@${domain}" >/dev/null 2>&1 ) || warn "acme.sh установлен с предупреждениями"
		else
			warn "не удалось скачать acme.sh ${ACME_SH_REF}; откат на self-signed."
		fi
		rm -rf "$acme_td"
		if [ -x ~/.acme.sh/acme.sh ]; then
			~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
			if ~/.acme.sh/acme.sh --issue --standalone -d "$domain" >/dev/null 2>&1; then
				~/.acme.sh/acme.sh --install-cert -d "$domain" \
					--key-file "$TLS_KEY" --fullchain-file "$TLS_CERT" \
					--reloadcmd "chown root:${SVC_USER} '$TLS_CERT' '$TLS_KEY' 2>/dev/null; chmod 0640 '$TLS_CERT' '$TLS_KEY' 2>/dev/null; systemctl restart zanoza-panel" >/dev/null 2>&1
			else
				warn "Let's Encrypt не удался (проверьте A-запись и свободный :80). Откат на self-signed."
				setup_self_signed "$domain"
			fi
		else
			setup_self_signed "$domain"
		fi
		;;
	3)
		disable_self_signed_renewal
		USE_TLS=0
		PANEL_ADDR="127.0.0.1"
		;;
	*)
		setup_self_signed "$SERVER_IP"
		;;
esac

# --------------------------------------------------------------------------
# Credentials (login 10, password 20) + config
# --------------------------------------------------------------------------
ADMIN_USER="$(random_alnum 10)"
ADMIN_PASS="$(random_alnum 20)"
umask 077
# Use the freshly built panel binary to hash + persist credentials with bcrypt
# atomically — no legacy SHA-256 in shell (F07/F24).
"${PANEL_BIN}.new" -config "$CONFIG_PATH" -set-credentials -user "$ADMIN_USER" -password "$ADMIN_PASS" >/dev/null \
	|| die "не удалось задать учётные данные администратора"

CERT_JSON=""
if [ "$USE_TLS" -eq 1 ]; then
	CERT_JSON=",\n  \"tls_cert\": \"${TLS_CERT}\",\n  \"tls_key\": \"${TLS_KEY}\""
fi

# Preserve existing instances if reinstalling.
if [ -f "$CONFIG_PATH" ] && command -v python3 >/dev/null 2>&1; then
	python3 - "$CONFIG_PATH" "$PORT" "$PANEL_PATH" "$PANEL_ADDR" "$TLS_CERT" "$TLS_KEY" "$USE_TLS" <<'PY'
import json,sys
path,port,p,addr,cert,key,tls=sys.argv[1:8]
cfg=json.load(open(path))
cfg.update({"panel_addr":addr,"panel_port":int(port),"panel_path":p})
if tls=="1": cfg["tls_cert"]=cert; cfg["tls_key"]=key
else: cfg.pop("tls_cert",None); cfg.pop("tls_key",None)
json.dump(cfg,open(path,"w"),indent=2,ensure_ascii=False)
PY
else
	printf '{\n  "version": 1,\n  "name": "Zanoza Panel",\n  "panel_addr": "%s",\n  "panel_port": %s,\n  "panel_path": "%s",\n  "instances": []%b\n}\n' \
		"$PANEL_ADDR" "$PORT" "$PANEL_PATH" "$CERT_JSON" > "$CONFIG_PATH"
fi
chmod 600 "$CONFIG_PATH"
fi   # end fresh-install-only block (MODE != update)

# --------------------------------------------------------------------------
# systemd + CLI + atomic swap with full-artifact rollback (F10)
# --------------------------------------------------------------------------
UNIT_PATH="/etc/systemd/system/zanoza-panel.service"

# Back up EVERY replaced artifact (panel + server binaries, unit, CLI) so a
# failed update is rolled back as one transaction (F10).
[ -f "$PANEL_BIN" ]  && cp -f "$PANEL_BIN"  "${PANEL_BIN}.bak"
[ -f "$SERVER_BIN" ] && cp -f "$SERVER_BIN" "${SERVER_BIN}.bak"
[ -f "$UNIT_PATH" ]  && cp -f "$UNIT_PATH"  "${UNIT_PATH}.bak"
[ -f "$CLI_BIN" ]    && cp -f "$CLI_BIN"    "${CLI_BIN}.bak"

# Render the unit + CLI with the SELECTED config dir and service user, so
# non-default ZANOZA_CONFIG_DIR / ZANOZA_SRC_DIR / ZANOZA_SVC_USER overrides are
# actually honoured by the installed service and management command (V4-08).
sed -e "s#/etc/zanoza-panel#${CONFIG_DIR}#g" \
    -e "s#^User=zanoza#User=${SVC_USER}#" \
    -e "s#^Group=zanoza#Group=${SVC_USER}#" \
    "$SRC_DIR/packaging/systemd/zanoza-panel.service" > "${UNIT_PATH}.gen"
install -m 0644 "${UNIT_PATH}.gen" "$UNIT_PATH"; rm -f "${UNIT_PATH}.gen"
sed -e "s#^CONFIG_DIR=\"/etc/zanoza-panel\"#CONFIG_DIR=\"${CONFIG_DIR}\"#" \
    -e "s#^SRC_DIR=\"/opt/masterdns-zanoza-panel\"#SRC_DIR=\"${SRC_DIR}\"#" \
    -e "s#:-zanoza}#:-${SVC_USER}}#" \
    "$SRC_DIR/scripts/zanoza" > "${CLI_BIN}.gen"
install -m 0755 "${CLI_BIN}.gen" "$CLI_BIN"; rm -f "${CLI_BIN}.gen"
mv -f "${PANEL_BIN}.new"  "$PANEL_BIN"
mv -f "${SERVER_BIN}.new" "$SERVER_BIN"

# Hand mutable runtime state (config, creds, keyring) to the unprivileged
# service user so the panel can run without root (R-09). Binaries stay
# root-owned + world-executable.
mkdir -p "$CONFIG_DIR/masterdns" "$TLS_DIR"
chown -R "${SVC_USER}:${SVC_USER}" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
# Certificates: the DIRECTORY stays root-owned (service cannot create/symlink
# inside it) while the files are root-owned + service-group-readable, so the
# root renewal job writes safely and the service reads via group (V4-01).
chown -R "root:${SVC_USER}" "$TLS_DIR"
chmod 0750 "$TLS_DIR"
[ -f "$TLS_CERT" ] && chmod 0640 "$TLS_CERT"
[ -f "$TLS_KEY" ]  && chmod 0640 "$TLS_KEY"

# rollback_update restores each replaced artifact from its .bak, or REMOVES it
# when there was no prior version (a failed fresh install must not leave a
# partial installation behind) (R-07).
rollback_update() {
	warn "$1 — откат."
	for art in "$PANEL_BIN" "$SERVER_BIN" "$UNIT_PATH" "$CLI_BIN"; do
		if [ -f "${art}.bak" ]; then
			mv -f "${art}.bak" "$art"
		else
			rm -f "$art"
		fi
	done
	systemctl daemon-reload 2>/dev/null || true
	systemctl restart zanoza-panel 2>/dev/null || true
	die "установка/обновление откатаны: $1"
}

systemctl daemon-reload
systemctl enable zanoza-panel >/dev/null 2>&1 || true
systemctl restart zanoza-panel || true
sleep 2
if ! systemctl is-active --quiet zanoza-panel; then
	rollback_update "панель не запустилась"
fi

# If hosts are configured, the supervised MasterDNS child must come up too
# (a live panel alone is not a healthy update). Allow a few seconds for the
# panel's supervisor to start it (F10).
HAS_INSTANCES=0
if command -v python3 >/dev/null 2>&1 && [ -f "$CONFIG_PATH" ]; then
	python3 -c "import json,sys;sys.exit(0 if json.load(open('$CONFIG_PATH')).get('instances') else 1)" && HAS_INSTANCES=1 || true
fi
if [ "$HAS_INSTANCES" = "1" ]; then
	# Content-bound readiness: the running server must acknowledge the EXACT
	# keyring digest we wrote (keyring.json.applied), not merely have a process
	# whose path matches (R-07/R-03).
	kr="$CONFIG_DIR/masterdns/keyring.json"
	ok=0
	for _ in 1 2 3 4 5 6 7 8; do
		if [ -f "$kr" ] && [ -f "$kr.applied" ]; then
			want="$(sha256sum "$kr" | awk '{print $1}')"
			got="$(tr -d '[:space:]' < "$kr.applied" 2>/dev/null)"
			[ -n "$want" ] && [ "$want" = "$got" ] && { ok=1; break; }
		fi
		sleep 1
	done
	[ "$ok" = "1" ] || rollback_update "MasterDNS не подтвердил применённый keyring (хосты настроены)"
fi

rm -f "${PANEL_BIN}.bak" "${SERVER_BIN}.bak" "${UNIT_PATH}.bak" "${CLI_BIN}.bak"

if [ "$MODE" = "update" ]; then
	SCHEME="https"; [ "$USE_TLS" -eq 1 ] || SCHEME="http"
	DISPLAY_HOST="$CERT_HOST"; [ "$PANEL_ADDR" = "127.0.0.1" ] && DISPLAY_HOST="127.0.0.1"
	log "Обновление завершено. Панель: ${SCHEME}://${DISPLAY_HOST}:${PORT}${PANEL_PATH}"
	exit 0
fi

SCHEME="https"; [ "$USE_TLS" -eq 1 ] || SCHEME="http"
DISPLAY_HOST="$CERT_HOST"; [ "$PANEL_ADDR" = "127.0.0.1" ] && DISPLAY_HOST="127.0.0.1"
URL="${SCHEME}://${DISPLAY_HOST}:${PORT}${PANEL_PATH}"

cat <<EOF

============================================================
  Zanoza Panel установлена и запущена.

  Адрес панели : ${URL}
  Логин        : ${ADMIN_USER}
  Пароль       : ${ADMIN_PASS}

  Управление   : команда  zanoza
  (zanoza restart | zanoza uninstall | zanoza --help)
============================================================
EOF
[ "$PANEL_ADDR" = "127.0.0.1" ] && warn "Панель слушает только на 127.0.0.1 — настройте nginx/ssh-туннель для внешнего доступа."
[ "$cert_choice" = "1" ] && warn "Используется self-signed сертификат — браузер покажет предупреждение, это нормально."
