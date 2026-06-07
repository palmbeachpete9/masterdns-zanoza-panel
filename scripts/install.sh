#!/usr/bin/env bash
# ==============================================================================
# Zanoza Panel installer (Debian/Ubuntu, run as root).
#   curl -fsSL https://raw.githubusercontent.com/palmbeachpete9/masterdns-zanoza-panel/main/scripts/install.sh | sudo bash
# Prompts for port, admin path and TLS certificate (3x-ui style), generates
# admin credentials, builds the forked MasterDnsVPN server + the panel, and
# installs the `zanoza` management command.
# ==============================================================================
set -euo pipefail

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
GO_VERSION="${GO_VERSION:-1.24.4}"

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

ensure_go() {
	if command -v go >/dev/null 2>&1; then
		local have; have="$(go version | awk '{print $3}' | sed 's/go//')"
		[ "$(printf '%s\n%s\n' "1.24.0" "$have" | sort -V | head -1)" = "1.24.0" ] && return
	fi
	log "Установка Go ${GO_VERSION}..."
	local arch; arch="$(dpkg --print-architecture)"
	case "$arch" in amd64) arch=amd64;; arm64) arch=arm64;; *) die "неизвестная архитектура: $arch";; esac
	curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o /tmp/go.tgz
	rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz
	export PATH="/usr/local/go/bin:$PATH"
}
ensure_go
export PATH="/usr/local/go/bin:$PATH"

# --------------------------------------------------------------------------
# Source + build
# --------------------------------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
	log "Обновление исходников..."
	git -C "$SRC_DIR" fetch --depth 1 origin "$REF" >/dev/null 2>&1 && git -C "$SRC_DIR" reset --hard "origin/$REF" >/dev/null 2>&1 || true
else
	log "Клонирование $REPO..."
	rm -rf "$SRC_DIR"
	git clone --depth 1 --branch "$REF" "$REPO" "$SRC_DIR" >/dev/null 2>&1 || git clone --depth 1 "$REPO" "$SRC_DIR" >/dev/null
fi

log "Сборка панели (web/dist встроен в бинарь)..."
( cd "$SRC_DIR" && CGO_ENABLED=0 go build -o "$PANEL_BIN" ./cmd/zanoza-panel )
log "Сборка форка сервера MasterDnsVPN..."
( cd "$SRC_DIR/masterdns" && CGO_ENABLED=0 go build -o "$SERVER_BIN" ./cmd/server )

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/masterdns"

# --------------------------------------------------------------------------
# Prompts: port, path, certificate (3x-ui style)
# --------------------------------------------------------------------------
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

case "$cert_choice" in
	2)
		domain="$(read_tty "Домен панели (A-запись -> ${SERVER_IP}): " "")"
		[ -n "$domain" ] || die "домен обязателен для варианта 2."
		CERT_HOST="$domain"
		log "Выпуск сертификата Let's Encrypt через acme.sh для ${domain}..."
		curl -fsSL https://get.acme.sh | sh -s email="admin@${domain}" >/dev/null 2>&1 || warn "acme.sh установлен с предупреждениями"
		~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
		if ~/.acme.sh/acme.sh --issue --standalone -d "$domain" >/dev/null 2>&1; then
			~/.acme.sh/acme.sh --install-cert -d "$domain" \
				--key-file "$TLS_KEY" --fullchain-file "$TLS_CERT" \
				--reloadcmd "systemctl restart zanoza-panel" >/dev/null 2>&1
		else
			warn "Let's Encrypt не удался (проверьте A-запись и свободный :80). Откат на self-signed."
			setup_self_signed "$domain"
		fi
		;;
	3)
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

# --------------------------------------------------------------------------
# systemd + CLI
# --------------------------------------------------------------------------
install -m 0644 "$SRC_DIR/packaging/systemd/zanoza-panel.service" /etc/systemd/system/zanoza-panel.service
install -m 0755 "$SRC_DIR/scripts/zanoza" "$CLI_BIN"
systemctl daemon-reload
systemctl enable --now zanoza-panel >/dev/null 2>&1
sleep 1

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
