#!/usr/bin/env bash
set -euo pipefail

# =========================
# INSTALL ALL (install.sh)
# 1) Install Nginx + set Domain + issue SSL (Let's Encrypt via acme.sh)
# 2) Install Xray (official XTLS/Xray-install)
# 3) Write XRAY config template:
#    - Trojan TLS (domain)  : 443/tcp
#    - VLESS  TLS + WS      : 8442/tcp (path /vless)
#    - VMESS  TLS + WS      : 8443/tcp (path /vmess)
#    - VLESS  REALITY (no domain): 8444/tcp
# 4) Install ZIVPN (zahidbd2/udp-zivpn zi.sh)
# 5) Install UDPGW (udpgw.sh from your repo)
# 6) Install Speedtest CLI (speedtest-cli)
# 7) Install Manager (download scripts from your GitHub repo)
# 8) Install Telegram Bot (xzbot.py) + deps + systemd service
#    - Token & Admin IDs DISET hanya lewat menu Utility (utility.sh) -> Bot Telegram (bot.env)
# =========================

REPO_OWNER="${REPO_OWNER:-harunkl}"
REPO_NAME="${REPO_NAME:-xz-manager}"
REPO_BRANCH="${REPO_BRANCH:-main}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"

APP_DIR="${APP_DIR:-/usr/local/sbin/xz-manager}"
DATA_DIR="${DATA_DIR:-/usr/local/etc/xz-manager}"

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
XRAY_DOMAIN_FILE="${XRAY_DOMAIN_FILE:-/usr/local/etc/xray/domain}"
XRAY_CERT="${XRAY_CERT:-/usr/local/etc/xray/xray.crt}"
XRAY_KEY="${XRAY_KEY:-/usr/local/etc/xray/xray.key}"

# Self-signed (no domain) for trojan legacy
XRAY_SELFSIGN_CERT="${XRAY_SELFSIGN_CERT:-/usr/local/etc/xray/selfsigned.crt}"
XRAY_SELFSIGN_KEY="${XRAY_SELFSIGN_KEY:-/usr/local/etc/xray/selfsigned.key}"

# Reality key files
REALITY_PRIV_FILE="${REALITY_PRIV_FILE:-/usr/local/etc/xray/reality.private}"
REALITY_PUB_FILE="${REALITY_PUB_FILE:-/usr/local/etc/xray/reality.public}"
REALITY_SHORTID_FILE="${REALITY_SHORTID_FILE:-/usr/local/etc/xray/reality.shortid}"

# Bot paths
BOT_ENV="${BOT_ENV:-${DATA_DIR}/bot.env}"
BOT_VENV="${BOT_VENV:-/opt/xzbot}"
BOT_SCRIPT="${BOT_SCRIPT:-${APP_DIR}/xzbot.py}"
BOT_SERVICE="${BOT_SERVICE:-/etc/systemd/system/xzbot.service}"

# Backup path (dipakai bot untuk fitur backup/restore jika ada)
BACKUP_DIR="${BACKUP_DIR:-/root/xz-backup}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; W="\e[97;1m"
die(){ echo -e "${R}[ERROR]${NC} $*"; exit 1; }

need_root(){
  [[ ${EUID:-0} -eq 0 ]] || die "Jalankan sebagai root (sudo su)."
}

pkg_install(){
  local pkgs=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${pkgs[@]}" >/dev/null 2>&1
  else
    die "Package manager tidak didukung. Install manual: ${pkgs[*]}"
  fi
}

need_tools(){
  local need=()
  command -v curl >/dev/null 2>&1 || need+=("curl")
  command -v wget >/dev/null 2>&1 || need+=("wget")
  command -v jq   >/dev/null 2>&1 || need+=("jq")
  command -v tar  >/dev/null 2>&1 || need+=("tar")
  command -v openssl >/dev/null 2>&1 || need+=("openssl")
  if ((${#need[@]})); then
    echo -e "${Y}Install dependency:${NC} ${need[*]}"
    pkg_install "${need[@]}"
  fi
}

# =========================
# IDP / SKIP IF EXISTS
# =========================
have_cmd(){ command -v "$1" >/dev/null 2>&1; }
have_service(){
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "$1"
}
svc_active(){
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl is-active --quiet "$1" 2>/dev/null
}

skip(){ echo -e "${Y}SKIP:${NC} $*"; }

is_nginx_installed(){ have_cmd nginx || have_service nginx.service; }
is_xray_installed(){ have_cmd xray || have_service xray.service || [[ -x /usr/local/bin/xray ]]; }
is_zivpn_installed(){ [[ -d /etc/zivpn ]] || have_service zivpn.service || have_service zi-vpn.service || have_service udp-zivpn.service; }
is_udpgw_installed(){ [[ -x /usr/local/bin/udpgw ]] || have_service udpgw.service; }
is_speedtest_installed(){ have_cmd speedtest || have_cmd speedtest-cli; }
is_manager_installed(){ [[ -x "${APP_DIR}/menu.sh" && -L /usr/bin/xz ]]; }
is_bot_deps_installed(){ [[ -x "${BOT_VENV}/bin/python" ]]; }
is_bot_service_installed(){ [[ -f "${BOT_SERVICE}" ]]; }

install_speedtest(){
if is_speedtest_installed; then
  skip "Speedtest sudah terpasang"
  return 0
fi

  echo -e "${C}==> Install Speedtest CLI${NC}"

  # Debian/Ubuntu: paket umum adalah speedtest-cli
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y speedtest-cli >/dev/null 2>&1 || true
  else
    # fallback minimal untuk distro lain: coba paket speedtest-cli bila ada
    pkg_install speedtest-cli >/dev/null 2>&1 || true
  fi

  # pastikan menu.sh (yang cek 'speedtest') tetap bisa jalan
  if ! command -v speedtest >/dev/null 2>&1; then
    if command -v speedtest-cli >/dev/null 2>&1; then
      ln -sf "$(command -v speedtest-cli)" /usr/local/bin/speedtest
    fi
  fi

  if command -v speedtest >/dev/null 2>&1; then
    echo -e "${G}OK:${NC} speedtest siap digunakan."
  else
    echo -e "${Y}INFO:${NC} speedtest belum tersedia di distro ini (tidak fatal)."
  fi
}

read_domain(){
  local d="${DOMAIN:-}"
  if [[ -z "${d}" ]] && [[ -f "${XRAY_DOMAIN_FILE}" ]]; then
    d="$(cat "${XRAY_DOMAIN_FILE}" 2>/dev/null || true)"
  fi
  if [[ -z "${d}" ]]; then
    read -rp "Masukkan domain (A record sudah mengarah ke VPS) : " d
    d="${d// /}"
  fi
  [[ -n "${d}" ]] || die "Domain kosong."
  echo "${d}"
}

install_nginx(){
if is_nginx_installed; then
  skip "Nginx sudah terpasang"
  return 0
fi

  echo -e "${C}==> Install Nginx${NC}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y nginx >/dev/null 2>&1
  else
    pkg_install nginx >/dev/null 2>&1
  fi

  mkdir -p /var/www/html
  cat >/var/www/html/index.html <<'EOF'
<!doctype html>
<html>
<head><meta charset="utf-8"><title>OK</title></head>
<body><h3>It works.</h3></body>
</html>
EOF

  # pastikan nginx listen 80 saja (443 dipakai xray untuk TLS trojan)
  if [[ -d /etc/nginx/sites-available ]]; then
    cat >/etc/nginx/sites-available/default <<'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  root /var/www/html;
  index index.html;

  # WebSocket proxy for Xray WS inbounds (port 80)
  location /vless {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
  }
  location /vmess {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:2083;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
  }

  location / {
    try_files $uri $uri/ =404;
  }
}
EOF
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default >/dev/null 2>&1 || true
  fi

  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
  echo -e "${G}OK:${NC} Nginx aktif (port 80)."
}

configure_nginx_ws_proxy(){
  # memastikan nginx punya:
  # - /.well-known/acme-challenge/ untuk acme.sh webroot
  # - /vless dan /vmess untuk WS proxy (2082/2083)
  # Catatan: mode DOMAIN akan memakai nginx di port 80 (fallback website + acme challenge)
  local domain="${1:-_}"

  mkdir -p /var/www/acme /var/www/html >/dev/null 2>&1 || true
  # www-data mungkin tidak ada di beberapa distro minimal, jadi jangan fail
  chown -R www-data:www-data /var/www/acme >/dev/null 2>&1 || true
  chmod -R 755 /var/www/acme >/dev/null 2>&1 || true

  if [[ -d /etc/nginx/sites-available ]]; then
    # tulis ulang default agar konsisten (lebih aman daripada patch kecil-kecilan)
    cat >/etc/nginx/sites-available/default <<EOF
server {
  listen 80 default_server;
  listen [::]:80 default_server;

  server_name ${domain};
  root /var/www/html;
  index index.html;

  # ACME http-01 (Let's Encrypt)
  location ^~ /.well-known/acme-challenge/ {
    root /var/www/acme;
    allow all;
    default_type "text/plain";
  }

  # WS proxy untuk XRAY fallback (xray inbound ws di 2082/2083)
  location /vless {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:2082;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
  }

  location /vmess {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:2083;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
  }

  location / {
    try_files \$uri \$uri/ =404;
  }
}
EOF
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default >/dev/null 2>&1 || true
  fi

  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
}

ensure_selfsigned_cert(){
  mkdir -p "$(dirname "${XRAY_SELFSIGN_CERT}")" || true
  if [[ -s "${XRAY_SELFSIGN_CERT}" && -s "${XRAY_SELFSIGN_KEY}" ]]; then
    return 0
  fi
  echo -e "${C}==> Generate self-signed cert (no domain) untuk TROJAN legacy${NC}"
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout "${XRAY_SELFSIGN_KEY}" -out "${XRAY_SELFSIGN_CERT}" \
      -subj "/CN=localhost" >/dev/null 2>&1 || die "Gagal buat self-signed cert"
    chmod 600 "${XRAY_SELFSIGN_KEY}" >/dev/null 2>&1 || true
  else
    die "openssl tidak ditemukan. Install openssl dulu."
  fi
}


install_acme_and_issue_cert(){
  local domain="$1"
  echo -e "${C}==> Issue/Renew SSL (Let's Encrypt via acme.sh) untuk domain: ${W}${domain}${NC}"
  echo -e "${C}    Metode: webroot (stabil, tidak bentrok port 80)${NC}"

  # dependency acme.sh (webroot tidak butuh socat, tapi tetap aman)
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl ca-certificates socat >/dev/null 2>&1 || true
  else
    pkg_install curl ca-certificates socat >/dev/null 2>&1 || true
  fi

  # simpan domain agar dipakai menu/skrip lain
  mkdir -p "$(dirname "${XRAY_DOMAIN_FILE}")" /etc/xray /root || true
  echo "${domain}" >"${XRAY_DOMAIN_FILE}"
  echo "${domain}" >/root/domain
  echo "${domain}" >/etc/xray/domain

  # pastikan webroot + nginx siap melayani challenge
  mkdir -p /var/www/acme >/dev/null 2>&1 || true
  chown -R www-data:www-data /var/www/acme >/dev/null 2>&1 || true
  chmod -R 755 /var/www/acme >/dev/null 2>&1 || true

  # preflight DNS A record (mengurangi "error terus" yang tidak jelas)
  local public_ip dns_a
  public_ip="$(curl -fsSL -4 ifconfig.me 2>/dev/null || true)"
  dns_a="$(dig +short A "${domain}" 2>/dev/null | head -n1 || true)"
  if [[ -n "${public_ip}" && -n "${dns_a}" && "${dns_a}" != "${public_ip}" ]]; then
    die "DNS A record tidak sesuai.
Domain: ${domain}
A record: ${dns_a}
IP VPS  : ${public_ip}

Perbaiki A record dulu (pointing ke IP VPS), lalu jalankan ulang."
  fi

  # install acme
  if [[ ! -d /root/.acme.sh ]]; then
    curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1 || die "Gagal install acme.sh"
  fi

  # pastikan nginx aktif (webroot membutuhkan nginx melayani port 80)
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true

  # quick self-test: pastikan lokasi challenge bisa diakses lokal
  mkdir -p /var/www/acme/.well-known/acme-challenge >/dev/null 2>&1 || true
  echo "ok" >/var/www/acme/.well-known/acme-challenge/ping.txt
  if ! curl -fsS "http://127.0.0.1/.well-known/acme-challenge/ping.txt" >/dev/null 2>&1; then
    die "Nginx belum melayani path /.well-known/acme-challenge/.
Pastikan configure_nginx_ws_proxy sudah menambahkan location challenge."
  fi

  # issue + install (ECC 256)
  /root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

  mkdir -p "$(dirname "${XRAY_CERT}")" || true

  # webroot mode (tidak perlu stop nginx)
  /root/.acme.sh/acme.sh --issue -d "${domain}" --webroot /var/www/acme -k ec-256 --force || die "Gagal issue SSL.
Penyebab paling umum:
- Domain belum pointing (A record salah / belum propagasi)
- Ada AAAA record (IPv6) yang salah
- Port 80 tidak bisa diakses dari luar (firewall provider / security group)"

  /root/.acme.sh/acme.sh --installcert -d "${domain}" \
    --ecc \
    --key-file "${XRAY_KEY}" \
    --fullchain-file "${XRAY_CERT}" \
    --reloadcmd "systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true; systemctl reload xray >/dev/null 2>&1 || systemctl restart xray >/dev/null 2>&1 || true" \
    >/dev/null 2>&1 || die "Gagal install cert"

  chmod 600 "${XRAY_KEY}" >/dev/null 2>&1 || true
  chmod 644 "${XRAY_CERT}" >/dev/null 2>&1 || true

  echo -e "${G}OK:${NC} SSL terpasang:"
  echo -e "  - Cert: ${W}${XRAY_CERT}${NC}"
  echo -e "  - Key : ${W}${XRAY_KEY}${NC}"
}

install_xray(){
if is_xray_installed; then
  skip "Xray sudah terpasang"
  return 0
fi

  echo -e "${C}==> Install Xray (official XTLS/Xray-install)${NC}"
  # sesuai request: jalankan sebagai root
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root

  mkdir -p /etc/xray || true
  if [[ -f "$XRAY_JSON" ]]; then
    ln -sf "$XRAY_JSON" /etc/xray/config.json
  fi
}

ensure_reality_keys(){
  echo -e "${C}==> Setup VLESS REALITY keys${NC}"
  mkdir -p "$(dirname "${REALITY_PRIV_FILE}")" || true

  if [[ -s "${REALITY_PRIV_FILE}" && -s "${REALITY_PUB_FILE}" ]]; then
    return 0
  fi

  local xray_bin
  xray_bin="/usr/local/bin/xray"
  [[ -x "${xray_bin}" ]] || xray_bin="$(command -v xray || true)"
  [[ -n "${xray_bin}" ]] || die "Binary xray tidak ditemukan. Pastikan install_xray sukses."

  # Output format Xray bisa berbeda antar versi:
  # - Format lama: "Private key:" / "Public key:"
  # - Format baru: "PrivateKey:" / "Password:" (Password = publicKey untuk client)
  local out priv pub
  out="$("${xray_bin}" x25519 2>/dev/null || true)"

  if echo "${out}" | grep -q '^PrivateKey:'; then
    priv="$(echo "${out}" | awk -F': ' '/^PrivateKey:/ {print $2; exit}')"
    pub="$(echo "${out}"  | awk -F': ' '/^Password:/  {print $2; exit}')"
  else
    priv="$(echo "${out}" | awk -F': ' '/Private key/ {print $2; exit}')"
    pub="$(echo "${out}"  | awk -F': ' '/Public key/  {print $2; exit}')"
  fi

  [[ -n "${priv}" && -n "${pub}" ]] || die "Gagal generate REALITY keypair."

  echo "${priv}" > "${REALITY_PRIV_FILE}"
  echo "${pub}"  > "${REALITY_PUB_FILE}"
  chmod 600 "${REALITY_PRIV_FILE}" >/dev/null 2>&1 || true
  chmod 644 "${REALITY_PUB_FILE}" >/dev/null 2>&1 || true

  # shortid random 8 hex
  if [[ ! -s "${REALITY_SHORTID_FILE}" ]]; then
    local sid
    sid="$(openssl rand -hex 4 2>/dev/null || true)"
    [[ -n "${sid:-}" ]] || sid="a1b2c3d4"
    echo "${sid}" > "${REALITY_SHORTID_FILE}"
    chmod 600 "${REALITY_SHORTID_FILE}" >/dev/null 2>&1 || true
  fi
}


write_xray_config_if_empty(){
  [[ -f "$XRAY_JSON" ]] || return 0

  if jq -e '.inbounds and (.inbounds|type=="array") and (.inbounds|length>0)' "$XRAY_JSON" >/dev/null 2>&1; then
    echo -e "${Y}==> XRAY config sudah ada (inbounds tidak kosong). Tidak ditimpa.${NC}"
    return 0
  fi

  # Pilih mode
  local mode="${XRAY_MODE:-}"
  if [[ -z "${mode}" ]]; then
    echo ""
    echo -e "${C}=== PILIH MODE XRAY ===${NC}"
    echo " [1] PAKAI DOMAIN + SSL  (VMESS/VLESS/TROJAN di 443 TLS, VMESS/VLESS juga bisa di 80 WS)"
    echo " [2] TANPA DOMAIN        (VLESS REALITY di 443, VMESS/VLESS/TROJAN pakai port legacy 10001/10002/10003)"
    read -rp "Pilih mode [1/2] (default 1): " mode
    [[ -z "${mode}" ]] && mode="1"
  fi

  if [[ "$mode" == "1" ]]; then
    local domain
    domain="$(read_domain)"
    install_nginx
    configure_nginx_ws_proxy "$domain"  # /vless & /vmess + ACME challenge di port 80
    install_acme_and_issue_cert "$domain"
    echo -e "${Y}==> Menulis XRAY config: DOMAIN+SSL (443 fallback + 80 ws) + REALITY (8444).${NC}"
    cp -a "$XRAY_JSON" "${XRAY_JSON}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

    local priv sid
    priv="$(cat "${REALITY_PRIV_FILE}" 2>/dev/null || true)"
    sid="$(cat "${REALITY_SHORTID_FILE}" 2>/dev/null || true)"

    # 443: VLESS TLS inbound dengan fallbacks:
    # - /vless -> ws inbound (2082)
    # - /vmess -> ws inbound (2083)
    # - trojan bytes -> trojan inbound (8446)
    # - default -> nginx (80) untuk website
    cat > "$XRAY_JSON" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-443-tls-fallback",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none",
        "fallbacks": [
          { "path": "/vless", "dest": 2082 },
          { "path": "/vmess", "dest": 2083 },
          { "dest": 8446 },
          { "dest": 80 }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["h2","http/1.1"],
          "certificates": [
            { "certificateFile": "${XRAY_CERT}", "keyFile": "${XRAY_KEY}" }
          ]
        }
      }
    },
    {
      "tag": "trojan-fallback-in",
      "listen": "127.0.0.1",
      "port": 8446,
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "vless-ws-in",
      "listen": "127.0.0.1",
      "port": 2082,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vless" } }
    },
    {
      "tag": "vmess-ws-in",
      "listen": "127.0.0.1",
      "port": 2083,
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "security": "none", "wsSettings": { "path": "/vmess" } }
    },
    {
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "port": 8444,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com","cloudflare.com"],
          "privateKey": "${priv}",
          "shortIds": ["${sid}"]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now nginx >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
    systemctl restart xray >/dev/null 2>&1 || true
    systemctl enable xray >/dev/null 2>&1 || true

    echo -e "${G}OK:${NC} Template XRAY (DOMAIN) dibuat."
    echo -e "  Domain        : ${W}${domain}${NC}"
    echo -e "  TROJAN TLS    : 443"
    echo -e "  VLESS WS TLS  : 443  path=/vless"
    echo -e "  VMESS WS TLS  : 443  path=/vmess"
    echo -e "  VLESS WS (80) : 80   path=/vless (tanpa TLS)"
    echo -e "  VMESS WS (80) : 80   path=/vmess (tanpa TLS)"
    echo -e "  VLESS REALITY : 8444 (tanpa domain VPS)"
    return 0
  fi

  # Mode 2: Tanpa domain
  echo -e "${Y}==> Menulis XRAY config: TANPA DOMAIN (REALITY 443 + port legacy 10001/10002/10003).${NC}"
  cp -a "$XRAY_JSON" "${XRAY_JSON}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

  # Self-signed untuk trojan legacy (client harus allowInsecure=true)
  ensure_selfsigned_cert

  local priv sid
  priv="$(cat "${REALITY_PRIV_FILE}" 2>/dev/null || true)"
  sid="$(cat "${REALITY_SHORTID_FILE}" 2>/dev/null || true)"

  cat > "$XRAY_JSON" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-reality-443",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.cloudflare.com:443",
          "xver": 0,
          "serverNames": ["www.cloudflare.com","cloudflare.com"],
          "privateKey": "${priv}",
          "shortIds": ["${sid}"]
        }
      }
    },
    {
      "tag": "vmess-legacy",
      "listen": "0.0.0.0",
      "port": 10001,
      "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "vless-legacy",
      "listen": "0.0.0.0",
      "port": 10002,
      "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "tcp", "security": "none" }
    },
    {
      "tag": "trojan-legacy-selfsigned",
      "listen": "0.0.0.0",
      "port": 10003,
      "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [
            { "certificateFile": "${XRAY_SELFSIGN_CERT}", "keyFile": "${XRAY_SELFSIGN_KEY}" }
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1 || true

  echo -e "${G}OK:${NC} Template XRAY (NO DOMAIN) dibuat."
  echo -e "  VLESS REALITY : 443  (tanpa domain VPS)"
  echo -e "  VMESS legacy  : 10001"
  echo -e "  VLESS legacy  : 10002"
  echo -e "  TROJAN legacy : 10003 (self-signed, client allowInsecure=true)"
}

open_basic_ports(){
  echo -e "${C}==> Open basic ports (best-effort)${NC}"
  if command -v iptables >/dev/null 2>&1; then
    for p in 80 443 8444 10001 10002 10003; do
      iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
    done
  fi
  if command -v ufw >/dev/null 2>&1; then
    for p in 80 443 8444 10001 10002 10003; do
      ufw allow ${p}/tcp >/dev/null 2>&1 || true
    done
  fi
}

install_zivpn(){
if is_zivpn_installed; then
  skip "ZIVPN sudah terpasang"
  return 0
fi

  echo -e "${C}==> Install ZIVPN${NC}"
  wget -O /tmp/zi.sh https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/zi.sh
  chmod +x /tmp/zi.sh
  /tmp/zi.sh
}

install_udpgw(){
if is_udpgw_installed; then
  skip "UDPGW sudah terpasang"
  return 0
fi

  echo -e "${C}==> Install UDPGW (from your repo)${NC}"
  curl -fsSL "${RAW_BASE}/udpgw.sh" -o /tmp/udpgw.sh || die "Gagal download udpgw.sh dari repo"
  chmod +x /tmp/udpgw.sh
  /tmp/udpgw.sh
}

download_manager_files(){
if is_manager_installed; then
  skip "Manager xz sudah ada di VPS"
  return 0
fi

  echo -e "${C}==> Install Manager from GitHub repo${NC}"
  mkdir -p "$APP_DIR" "$DATA_DIR"
  chmod 755 "$APP_DIR"
  chmod 700 "$DATA_DIR" || true
  mkdir -p "$BACKUP_DIR" || true

  # WAJIB: xzbot.py ikut di-download dari repo
  for f in menu.sh vmess.sh vless.sh trojan.sh zivpn.sh udpgw.sh utility.sh xzbot.py; do
    echo -e "  - Download ${W}${f}${NC}"
    curl -fsSL "${RAW_BASE}/${f}" -o "${APP_DIR}/${f}" || die "Gagal download ${f}"
    chmod +x "${APP_DIR}/${f}"
  done

  # data files
  touch "${DATA_DIR}/expiry.db"
  chmod 600 "${DATA_DIR}/expiry.db" 2>/dev/null || true

  # bot.env dibuat kosong sekali. Token & admin akan di-set via utility.sh
  if [[ ! -f "${BOT_ENV}" ]]; then
    cat > "${BOT_ENV}" <<'EOF'
BOT_TOKEN=""
BOT_ADMIN_IDS=""
EOF
    chmod 600 "${BOT_ENV}" 2>/dev/null || true
  fi

  ln -sf "${APP_DIR}/menu.sh" /usr/bin/xz
}

install_bot_deps(){
if is_bot_deps_installed; then
  skip "Python venv bot sudah ada (deps diasumsikan sudah terpasang)"
  return 0
fi

  echo -e "${C}==> Install Python deps for xzbot${NC}"

  # Debian/Ubuntu:
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3 python3-venv >/dev/null 2>&1
  else
    # fallback distro lain (best-effort)
    pkg_install python3 >/dev/null 2>&1 || true
    pkg_install python3-venv >/dev/null 2>&1 || true
  fi

  # create venv idempotent
  if [[ ! -x "${BOT_VENV}/bin/python" ]]; then
    python3 -m venv "${BOT_VENV}"
  fi

  "${BOT_VENV}/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
  "${BOT_VENV}/bin/pip" install -U python-telegram-bot >/dev/null 2>&1 || die "Gagal install python-telegram-bot"
}

install_bot_service(){
if is_bot_service_installed; then
  skip "Service xzbot sudah ada (tidak ditimpa). Hapus file service jika ingin buat ulang"
  return 0
fi

  echo -e "${C}==> Install xzbot systemd service${NC}"

  if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${Y}INFO:${NC} systemctl tidak tersedia. Lewati pemasangan service."
    return 0
  fi

  # pastikan file bot & env ada
  [[ -f "${BOT_SCRIPT}" ]] || die "xzbot.py tidak ditemukan di ${BOT_SCRIPT} (cek download_manager_files)."
  [[ -f "${BOT_ENV}" ]] || die "bot.env tidak ditemukan di ${BOT_ENV}."

  cat > "${BOT_SERVICE}" <<EOF
[Unit]
Description=XZ Manager Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
Environment=BOT_ENV=${BOT_ENV}
Environment=EXPIRY_DB=${DATA_DIR}/expiry.db
Environment=XRAY_JSON=${XRAY_JSON}
Environment=ZIVPN_JSON=/etc/zivpn/config.json
Environment=BACKUP_DIR=${BACKUP_DIR}
ExecStart=${BOT_VENV}/bin/python ${BOT_SCRIPT}
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true

  # Jangan start kalau token belum di-set, biar gak restart loop.
  if grep -qE '^BOT_TOKEN="?[^"]+' "${BOT_ENV}" 2>/dev/null; then
    systemctl enable --now xzbot >/dev/null 2>&1 || true
    echo -e "${G}OK:${NC} xzbot service diaktifkan & dijalankan."
  else
    systemctl disable xzbot >/dev/null 2>&1 || true
    echo -e "${Y}INFO:${NC} BOT_TOKEN masih kosong. Service xzbot dibuat tapi belum dijalankan."
    echo -e "Set token via: ${W}xz -> Utility -> Bot Telegram (set token & user id)${NC}"
    echo -e "Lalu jalankan: ${W}systemctl enable --now xzbot${NC}"
  fi
}

main(){
  need_root
  need_tools

  install_speedtest
  # XRAY config template akan meminta pilihan mode (domain / no-domain)

  install_xray
  ensure_reality_keys
  write_xray_config_if_empty
  open_basic_ports

  install_zivpn
  install_udpgw

  download_manager_files

  install_bot_deps
  install_bot_service

  echo -e "${G}Selesai.${NC}"
  echo -e "Jalankan manager: ${W}xz${NC}"

echo ""
echo -e "${C}=== INFO PORT XRAY (dari config.json) ===${NC}"
if [[ -f "${XRAY_JSON}" ]]; then
  jq -r '
    (.inbounds // [])[]? |
    "proto=\(.protocol) port=\(.port) tag=\(.tag // "-") sec=\(.streamSettings.security // "none") net=\(.streamSettings.network // "tcp")"
  ' "${XRAY_JSON}" 2>/dev/null | awk 'NF' | sort -u || true
else
  echo "Config tidak ditemukan: ${XRAY_JSON}"
fi

if [[ -s "${REALITY_PUB_FILE}" ]]; then
  local rport
  rport="$(jq -r '.inbounds[]?|select(.protocol=="vless")|select(.streamSettings.security=="reality")|.port' "${XRAY_JSON}" 2>/dev/null | head -n1 || true)"
  [[ -z "${rport}" ]] && rport="-"
  echo ""
  echo -e "${C}=== INFO VLESS REALITY ===${NC}"
  echo -e "Port      : ${W}${rport}${NC}"
  echo -e "PublicKey : ${W}$(cat "${REALITY_PUB_FILE}")${NC}"
  echo -e "ShortID   : ${W}$(cat "${REALITY_SHORTID_FILE}")${NC}"
  echo -e "SNI       : ${W}www.cloudflare.com${NC} (atau cloudflare.com)"
  echo -e "Fingerprint: ${W}chrome${NC}"
  echo ""
fi
}

main "$@"
