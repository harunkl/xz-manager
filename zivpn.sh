#!/usr/bin/env bash
set -euo pipefail

# =========================
# ZIVPN SUB MENU (zivpn.sh)
# =========================

ZIVPN_JSON="${ZIVPN_JSON:-/etc/zivpn/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; W="\e[97;1m"; B="\e[94;1m"
pause() { read -rp "Tekan Enter untuk kembali..."; }


cls() { clear; }

# --- Iconic UI helpers
DIM="${DIM:-\e[90m}"

ui_header() {
  local title="${1:-MENU}"
  clear
  echo -e "${C}⟦ XzV ⟧${NC} ${W}${title}${NC}\n"
  echo -e "${DIM}╭────────────────────────────────────────────╮${NC}"
  printf "${DIM}│${NC} %-42s ${DIM}│${NC}\n" " "
  printf "${DIM}│${NC} %-42s ${DIM}│${NC}\n" "  ${title}"
  printf "${DIM}│${NC} %-42s ${DIM}│${NC}\n" " "
  echo -e "${DIM}╰────────────────────────────────────────────╯${NC}"
  echo
}

prompt_menu() { read -rp "➤ Pilih menu : " "${1:-c}"; }
# --- Helper: domain / ip / port / telegram
DOMAIN_FILE="${DOMAIN_FILE:-/usr/local/etc/xray/domain}"

read_domain() {
  if [[ -f "$DOMAIN_FILE" ]]; then
    tr -d ' \r\n' < "$DOMAIN_FILE"
    return 0
  fi
  for f in /etc/xray/domain /root/domain; do
    [[ -f "$f" ]] && { tr -d ' \r\n' < "$f"; return 0; }
  done
  return 1
}

public_ip() {
  curl -fsS https://api.ipify.org 2>/dev/null || curl -fsS https://ifconfig.me 2>/dev/null || echo ""
}

get_host() {
  local d
  d="$(read_domain 2>/dev/null || true)"
  if [[ -n "${d:-}" ]]; then
    echo "$d"
  else
    local ip
    ip="$(public_ip)"
    echo "${ip:-YOUR_IP}"
  fi
}

zivpn_port() {
  [[ -f "$ZIVPN_JSON" ]] || { echo ""; return 0; }
  jq -r '
    .listen_port // .port // .listenPort // .server.port // .config.port // empty
  ' "$ZIVPN_JSON" 2>/dev/null | head -n1
}

# Telegram optional: /etc/bot/.bot.db
tg_send() {
  local text="$1"
  local CHATID KEY URL
  if [[ -f /etc/bot/.bot.db ]]; then
    CHATID="$(grep -E "^#bot# " /etc/bot/.bot.db | awk "{print \$3}" | head -n1)"
    KEY="$(grep -E "^#bot# " /etc/bot/.bot.db | awk "{print \$2}" | head -n1)"
    if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
      URL="https://api.telegram.org/bot${KEY}/sendMessage"
      curl -fsS -X POST "$URL"         -d chat_id="$CHATID"         --data-urlencode text="$text"         -d disable_web_page_preview=true >/dev/null 2>&1 || true
    fi
  fi
}

zivpn_send_created() {
  local user="$1" exp="$2"
  local host port
  host="$(get_host)"
  port="$(zivpn_port)"
  [[ -z "${port:-}" ]] && port="(cek config)"
  local msg
  msg="✅ ZIVPN AKUN
\nUser/Pass : ${user}\nExpired   : ${exp}\nServer    : ${host}\nPort      : ${port}\n\nCatatan: gunakan user di atas sebagai password/login sesuai client ZIVPN kamu."
  echo -e "${C}\n--- INFO (COPY) ---${NC}\n${msg}\n"
  tg_send "$msg"
}

need_deps() {
  command -v jq >/dev/null 2>&1 || { echo -e "${R}Butuh jq. Install dulu: apt-get install -y jq${NC}"; exit 1; }
  mkdir -p "$MANAGER_DIR"
  touch "$EXPIRY_DB"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
}
file_ok() { [[ -f "$1" ]]; }

today() { date +"%Y-%m-%d"; }
add_days_from_today() { date -d "$(today) +$1 day" +"%Y-%m-%d"; }
is_valid_date() { date -d "$1" +"%Y-%m-%d" >/dev/null 2>&1; }

# expiry db format: TAG|USER|YYYY-MM-DD
expiry_get() { awk -F'|' -v t="ZIVPN" -v u="$1" '$1==t && $2==u {print $3}' "$EXPIRY_DB" | tail -n1; }
expiry_set() {
  local user="$1" exp="$2"
  awk -F'|' -v t="ZIVPN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
  echo "ZIVPN|${user}|${exp}" >> "$EXPIRY_DB"
}
expiry_del() {
  local user="$1"
  awk -F'|' -v t="ZIVPN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
}

zivpn_restart() { systemctl restart zivpn 2>/dev/null || true; }

zivpn_exists() {
  file_ok "$ZIVPN_JSON" || return 1
  jq -e --arg u "$1" '.auth.config // [] | index($u) != null' "$ZIVPN_JSON" >/dev/null 2>&1
}

zivpn_list() {
  clear
  echo -e "${C}=== LIST AKUN ZIVPN ===${NC}"
  if ! file_ok "$ZIVPN_JSON"; then
    echo -e "${R}Config ZIVPN tidak ditemukan:${NC} $ZIVPN_JSON"; pause; return
  fi
  local total
  total="$(jq -r '.auth.config | length' "$ZIVPN_JSON" 2>/dev/null || echo 0)"
  echo -e "${Y}Total akun:${NC} $total\n"

  jq -r '.auth.config[]?' "$ZIVPN_JSON" 2>/dev/null | while read -r u; do
    exp="$(expiry_get "$u")"
    [[ -z "${exp:-}" ]] && exp="-"
    printf "%-22s  exp: %s\n" "$u" "$exp"
  done | nl -w2 -s". "
  echo ""; pause
}

zivpn_add() {
  clear
  echo -e "${C}=== ADD AKUN ZIVPN ===${NC}"
  if ! file_ok "$ZIVPN_JSON"; then
    echo -e "${R}Config ZIVPN tidak ditemukan:${NC} $ZIVPN_JSON"; pause; return
  fi

  read -rp "Masukkan nama pengguna: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama pengguna kosong.${NC}"; pause; return; }

  if zivpn_exists "$user"; then
    echo -e "${Y}Akun sudah ada.${NC}"; pause; return
  fi

  read -rp "Expired dalam berapa hari? (default 30): " days
  [[ -z "${days:-}" ]] && days=30
  if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ "$days" -le 0 ]]; then
    echo -e "${R}Input hari tidak valid.${NC}"; pause; return
  fi

  exp="$(add_days_from_today "$days")"
  tmp="$(mktemp)"
  jq --arg u "$user" '.auth.config = ((.auth.config // []) + [$u] | unique)' "$ZIVPN_JSON" > "$tmp" && mv "$tmp" "$ZIVPN_JSON"

  expiry_set "$user" "$exp"
  zivpn_restart

  echo -e "${G}OK: Akun berhasil dibuat.${NC}"
  zivpn_send_created "$user" "$exp"
    pause
}

zivpn_delete() {
  clear
  echo -e "${C}=== DELETE AKUN ZIVPN ===${NC}"
  if ! file_ok "$ZIVPN_JSON"; then
    echo -e "${R}Config ZIVPN tidak ditemukan:${NC} $ZIVPN_JSON"; pause; return
  fi

  read -rp "Masukkan nama akun yang ingin dihapus: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  if ! zivpn_exists "$user"; then
    echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return
  fi

  tmp="$(mktemp)"
  jq --arg u "$user" '.auth.config = ((.auth.config // []) | map(select(. != $u)))' "$ZIVPN_JSON" > "$tmp" && mv "$tmp" "$ZIVPN_JSON"

  expiry_del "$user"
  zivpn_restart

  echo -e "${G}OK: Akun berhasil dihapus.${NC}"
  pause
}

zivpn_extend() {
  clear
  echo -e "${C}=== PERPANJANG AKUN ZIVPN ===${NC}"
  if ! file_ok "$ZIVPN_JSON"; then
    echo -e "${R}Config ZIVPN tidak ditemukan:${NC} $ZIVPN_JSON"; pause; return
  fi

  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  if ! zivpn_exists "$user"; then
    echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return
  fi

  cur="$(expiry_get "$user")"; [[ -z "${cur:-}" ]] && cur="-"
  echo -e "Expiry saat ini: ${Y}$cur${NC}"

  read -rp "Tambah perpanjangan (hari) (default 30): " days
  [[ -z "${days:-}" ]] && days=30
  if ! [[ "$days" =~ ^[0-9]+$ ]] || [[ "$days" -le 0 ]]; then
    echo -e "${R}Input hari tidak valid.${NC}"; pause; return
  fi

  if [[ "$cur" != "-" ]] && is_valid_date "$cur"; then
    new="$(date -d "$cur +$days day" +"%Y-%m-%d")"
  else
    new="$(add_days_from_today "$days")"
  fi

  expiry_set "$user" "$new"
  echo -e "${G}OK: Akun diperpanjang.${NC}"
  zivpn_send_created "$user" "$new"
    pause
}

zivpn_view() {
  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  cls
  ui_header "DETAIL AKUN ZIVPN"

  if ! file_ok "$ZIVPN_JSON"; then
    echo -e "${R}Config ZIVPN tidak ditemukan:${NC} $ZIVPN_JSON"
    pause; return
  fi

  zivpn_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  local exp host port
  exp="$(expiry_get "$user")"; [[ -z "${exp:-}" ]] && exp="-"
  host="$(get_host)"
  port="$(zivpn_port)"; [[ -z "${port:-}" ]] && port="(cek config)"

  echo -e "${Y}===== INFORMASI AKUN ZIVPN =====${NC}"
  echo -e "User/Pass : ${W}${user}${NC}"
  echo -e "Expired   : ${Y}${exp}${NC}"
  echo -e "Server    : ${W}${host}${NC}"
  echo -e "Port      : ${W}${port}${NC}"
  echo -e "${Y}===============================${NC}"
  echo ""
  pause
}

menu_zivpn() {
  while true; do
    ui_header "MENU ZIVPN MANAGER"
    echo -e " ${Y}[1]${NC} 📋 List akun"
    echo -e " ${Y}[2]${NC} ➕ Add akun"
    echo -e " ${Y}[3]${NC} 🗑️ Delete akun"
    echo -e " ${Y}[4]${NC} ⏳ Perpanjang akun"
    echo -e " ${Y}[5]${NC} 🔎 Lihat akun"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) zivpn_list ;;
      2) zivpn_add ;;
      3) zivpn_delete ;;
      4) zivpn_extend ;;
      5) zivpn_view ;;
      0) cls; exit 0 ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

need_deps
menu_zivpn