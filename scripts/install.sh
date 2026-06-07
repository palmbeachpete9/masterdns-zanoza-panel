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
ENV_PATH="$CONFIG_DIR/panel.env"
TLS_CERT="$CONFIG_DIR/tls.crt"
TLS_KEY="$CONFIG_DIR/tls.key"
PANEL_BIN="/usr/local/bin/zanoza-panel"
SERVER_BIN="/usr/local/bin/masterdns-server"
CLI_BIN="/usr/local/bin/zanoza"
# Must satisfy the `go 1.25.0` directive in go.mod / masterdns/go.mod (F17).
GO_VERSION="${GO_VERSION:-1.25.4}"
GO_MIN_VERSION="1.25.0"
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

# --------------------------------------------------------------------------
# Packages + Go
# --------------------------------------------------------------------------
log "Установка пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y git curl ca-certificates openssl iproute2 build-essential socat cron >/dev/null

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
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tgz || die "не удалось скачать Go"
	local want; want="$(go_expected_sha256 "$arch")"
	if [ -n "$want" ]; then
		local got; got="$(sha256sum /tmp/go.tgz | awk '{print $1}')"
		[ "$got" = "$want" ] || { rm -f /tmp/go.tgz; die "контрольная сумма Go не совпала (ожидалось ${want}, получено ${got})"; }
		log "Go tarball verified (sha256 ok)."
	else
		warn "не удалось получить контрольную сумму Go — пропускаю проверку (задайте GO_SHA256_${arch})."
	fi
	rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
	rm -f /tmp/go.tgz
	export PATH="/usr/local/go/bin:$PATH"
}
ensure_go
export PATH="/usr/local/go/bin:$PATH"

# --------------------------------------------------------------------------
# Source + build
# --------------------------------------------------------------------------
# A failed fetch/reset must NOT silently fall through to building stale local
# source (F27). On update we hard-fail; on fresh install we clone or die.
if [ -d "$SRC_DIR/.git" ]; then
	log "Обновление исходников..."
	git -C "$SRC_DIR" fetch --depth 1 origin "$REF" || die "git fetch не удался — установка прервана (исходники не изменены)"
	git -C "$SRC_DIR" reset --hard "FETCH_HEAD" || die "git reset не удался — установка прервана"
else
	log "Клонирование $REPO..."
	rm -rf "$SRC_DIR"
	git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR" 2>/dev/null || git clone --depth 1 "$REPO" "$SRC_DIR" || die "git clone не удался"
fi

# Build to temporary paths; live binaries are only swapped in after BOTH builds
# succeed, and are rolled back if the service fails to come up (F10).
log "Сборка панели (web/dist встроен в бинарь)..."
( cd "$SRC_DIR" && CGO_ENABLED=0 go build -o "${PANEL_BIN}.new" ./cmd/zanoza-panel ) || die "сборка панели не удалась — установка прервана"
log "Сборка форка сервера MasterDnsVPN..."
( cd "$SRC_DIR/masterdns" && CGO_ENABLED=0 go build -o "${SERVER_BIN}.new" ./cmd/server ) || die "сборка сервера не удалась — установка прервана"

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/masterdns"

# --------------------------------------------------------------------------
# Prompts: port, path, certificate (3x-ui style) — fresh install only.
# Update mode preserves all of this (F10).
# --------------------------------------------------------------------------
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
case "$ans" in y|Y) PORT="$(read_tty "Введите порт: " "$PORT")";; esac

PANEL_PATH="/admin"
ans="$(read_tty "Path /admin will be assigned. Customise? y/N: " "N")"
case "$ans" in y|Y)
	p="$(read_tty "Введите путь (например /secret): " "/admin")"
	[ "${p:0:1}" = "/" ] || p="/$p"; PANEL_PATH="$p";;
esac

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
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
chmod 600 "$TLS_KEY"
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
		acme_tarball="/tmp/acme-${ACME_SH_REF}.tar.gz"
		if curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_REF}.tar.gz" -o "$acme_tarball"; then
			tar -xzf "$acme_tarball" -C /tmp
			( cd "/tmp/acme.sh-${ACME_SH_REF}" && ./acme.sh --install -m "admin@${domain}" >/dev/null 2>&1 ) || warn "acme.sh установлен с предупреждениями"
			rm -rf "$acme_tarball" "/tmp/acme.sh-${ACME_SH_REF}"
		else
			warn "не удалось скачать acme.sh ${ACME_SH_REF}; откат на self-signed."
		fi
		if [ -x ~/.acme.sh/acme.sh ]; then
			~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
			if ~/.acme.sh/acme.sh --issue --standalone -d "$domain" >/dev/null 2>&1; then
				~/.acme.sh/acme.sh --install-cert -d "$domain" \
					--key-file "$TLS_KEY" --fullchain-file "$TLS_CERT" \
					--reloadcmd "systemctl restart zanoza-panel" >/dev/null 2>&1
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
SALT="$(openssl rand -hex 16)"
PASS_HASH="$(printf '%s' "${SALT}:${ADMIN_PASS}" | sha256sum | awk '{print $1}')"

umask 077
cat > "$ENV_PATH" <<EOF
ZANOZA_PANEL_USER='${ADMIN_USER}'
ZANOZA_PANEL_SALT='${SALT}'
ZANOZA_PANEL_PASS_HASH='${PASS_HASH}'
EOF

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
# systemd + CLI + atomic binary swap with rollback (F10)
# --------------------------------------------------------------------------
install -m 0644 "$SRC_DIR/packaging/systemd/zanoza-panel.service" /etc/systemd/system/zanoza-panel.service
install -m 0755 "$SRC_DIR/scripts/zanoza" "$CLI_BIN"

# Back up current binaries so a failed start can be rolled back.
[ -f "$PANEL_BIN" ]  && cp -f "$PANEL_BIN"  "${PANEL_BIN}.bak"
[ -f "$SERVER_BIN" ] && cp -f "$SERVER_BIN" "${SERVER_BIN}.bak"
mv -f "${PANEL_BIN}.new"  "$PANEL_BIN"
mv -f "${SERVER_BIN}.new" "$SERVER_BIN"

systemctl daemon-reload
systemctl enable zanoza-panel >/dev/null 2>&1 || true
systemctl restart zanoza-panel || true
sleep 2
if ! systemctl is-active --quiet zanoza-panel; then
	warn "панель не запустилась — откат к предыдущим бинарникам."
	[ -f "${PANEL_BIN}.bak" ]  && mv -f "${PANEL_BIN}.bak"  "$PANEL_BIN"
	[ -f "${SERVER_BIN}.bak" ] && mv -f "${SERVER_BIN}.bak" "$SERVER_BIN"
	systemctl restart zanoza-panel || true
	die "обновление откатано: новая сборка не запустилась."
fi
rm -f "${PANEL_BIN}.bak" "${SERVER_BIN}.bak"

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
