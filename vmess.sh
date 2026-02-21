#!/usr/bin/env bash
set -euo pipefail

# =========================
# VMESS SUB MENU (vmess.sh)
# JSON-safe (jq), expiry in /usr/local/etc/xz-manager/expiry.db
# =========================

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"
USER_LOG_DIR="${USER_LOG_DIR:-/etc/user-create}"
USER_LOG="${USER_LOG:-$USER_LOG_DIR/user.log}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; B="\e[94;1m"; W="\e[97;1m"; DIM="\e[90m"
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
need_root() { [[ $EUID -eq 0 ]] || { echo -e "${R}[ERROR] Jalankan sebagai root.${NC}"; exit 1; }; }
need_deps() {
  command -v jq >/dev/null 2>&1 || { echo -e "${R}Butuh jq. Install: apt-get install -y jq${NC}"; exit 1; }
  mkdir -p "$MANAGER_DIR" "$USER_LOG_DIR"
  touch "$EXPIRY_DB" "$USER_LOG"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
}

file_ok() { [[ -f "$1" ]]; }
new_uuid() { cat /proc/sys/kernel/random/uuid; }

today_ymd() { date +"%Y-%m-%d"; }
add_days_from_today() { date -d "$(today_ymd) +$1 day" +"%Y-%m-%d"; }
is_valid_date() { date -d "$1" +"%Y-%m-%d" >/dev/null 2>&1; }
fmt_pretty_date() { date -d "$1" +"%d %b, %Y" 2>/dev/null || echo "-"; }

xray_restart() {
  systemctl restart xray >/dev/null 2>&1 || true
  service cron restart >/dev/null 2>&1 || true
}

domain_get() {
  for f in /usr/local/etc/xz-manager/domain /usr/local/etc/xray/domain /etc/xray/domain /root/domain; do
    [[ -f "$f" ]] || continue
    d="$(head -n1 "$f" 2>/dev/null | tr -d ' \t\r\n')"
    [[ -n "$d" ]] && { echo "$d"; return; }
  done
  echo ""
}

server_ip_only() {
  ip="$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  [[ -z "${ip:-}" ]] && ip="$(curl -fsSL --max-time 4 https://ipinfo.io/ip 2>/dev/null || true)"
  [[ -z "${ip:-}" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "${ip:-}"
}

server_host() {
  d="$(domain_get)"
  if [[ -n "$d" ]]; then echo "$d"; else echo "$(server_ip_only)"; fi
}

b64() {
  # GNU base64 uses -w 0; busybox may not
  if base64 -w 0 >/dev/null 2>&1 <<<"test"; then
    base64 -w 0
  else
    base64 | tr -d '\n'
  fi
}

vmess_uri_ws() {
  local user="$1" uuid="$2" host="$3" port="$4" tls="$5" path="$6"
  local tlsflag=""
  [[ "$tls" == "tls" ]] && tlsflag="tls"
  local json
  json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"ws","type":"none","host":"%s","path":"%s","tls":"%s"}' \
    "$user" "$host" "$port" "$uuid" "$host" "$path" "$tlsflag")
  printf "vmess://%s" "$(echo -n "$json" | b64)"
}

vmess_uri_tcp() {
  local user="$1" uuid="$2" host="$3" port="$4"
  local json
  json=$(printf '{"v":"2","ps":"%s","add":"%s","port":"%s","id":"%s","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":""}' \
    "$user" "$host" "$port" "$uuid")
  printf "vmess://%s" "$(echo -n "$json" | b64)"
}

tg_load() {
  # /etc/bot/.bot.db: line like "#bot# <TOKEN> <CHATID>"
  if [[ -f /etc/bot/.bot.db ]]; then
    KEY="$(grep -E "^#bot# " /etc/bot/.bot.db | awk '{print $2}' | head -n1)"
    CHATID="$(grep -E "^#bot# " /etc/bot/.bot.db | awk '{print $3}' | head -n1)"
  else
    KEY=""; CHATID=""
  fi
}

tg_send() {
  local text="$1"
  [[ -z "${KEY:-}" || -z "${CHATID:-}" ]] && return 0
  curl -fsSL --max-time 8 -X POST "https://api.telegram.org/bot${KEY}/sendMessage" \
    -d "chat_id=${CHATID}" -d "text=${text}" -d "parse_mode=HTML" >/dev/null 2>&1 || true
}

expiry_get() { awk -F'|' -v t="VMESS" -v u="$1" '$1==t && $2==u {print $3}' "$EXPIRY_DB" | tail -n1; }
expiry_set() {
  local user="$1" exp="$2"
  awk -F'|' -v t="VMESS" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
  echo "VMESS|${user}|${exp}" >> "$EXPIRY_DB"
}
expiry_del() {
  local user="$1"
  awk -F'|' -v t="VMESS" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
}

has_vmess_inbound() {
  file_ok "$XRAY_JSON" || return 1
  jq -e '(.inbounds // []) | map(select(.protocol=="vmess")) | length > 0' "$XRAY_JSON" >/dev/null 2>&1
}

vmess_user_exists() {
  jq -e --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="vmess"))
    | any((.settings.clients // []) | any(.email == $u))
  ' "$XRAY_JSON" >/dev/null 2>&1
}

vmess_get_uuid() {
  jq -r --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="vmess"))
    | .[].settings.clients[]?
    | select(.email == $u)
    | .id
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF{print; exit}'
}

vmess_list_raw() {
  jq -r '
    (.inbounds // [])
    | map(select(.protocol=="vmess"))
    | .[].settings.clients[]?
    | "\(.email)|\(.id)"
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF' | sort -t'|' -k1,1 -u
}

vmess_add_to_all_inbounds() {
  local user="$1" uuid="$2"
  local tmp
  tmp="$(mktemp)"
  jq --arg u "$user" --arg id "$uuid" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="vmess" then
            .settings.clients = (
              ((.settings.clients // []) + [{"id":$id,"alterId":0,"email":$u}])
              | unique_by(.email)
            )
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

vmess_delete_all_inbounds() {
  local user="$1"
  local tmp
  tmp="$(mktemp)"
  jq --arg u "$user" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="vmess" then
            .settings.clients = ((.settings.clients // []) | map(select(.email != $u)))
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

log_create() {
  local user="$1" uuid="$2" masaaktif="$3" created="$4" exp_pretty="$5"
  {
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo -e "    🧿 Status Create VMESS Success 🧿"
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo -e "Username         : ${user}"
    echo -e "User ID (UUID)   : ${uuid}"
    echo -e "alterId          : 0"
    echo -e "Aktif Selama     : ${masaaktif} Hari"
    echo -e "Dibuat Pada      : ${created}"
    echo -e "Berakhir Pada    : ${exp_pretty}"
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo ""
  } | tee -a "$USER_LOG" >/dev/null
}

vmess_add() {
  clear
  echo -e "${C}=== CREATE VMESS ACCOUNT ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}[ERROR] Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_vmess_inbound || { echo -e "${R}[ERROR] Inbound VMESS belum ada di config.${NC}"; pause; return; }

  local user
  while true; do
    read -rp "User (a-zA-Z0-9_): " user
    user="${user// /}"
    [[ "$user" =~ ^[a-zA-Z0-9_]+$ ]] || { echo -e "${R}Username tidak valid.${NC}"; continue; }
    vmess_user_exists "$user" && { echo -e "${Y}Akun sudah ada.${NC}"; continue; }
    break
  done

  read -rp "Expired (days) [default 30]: " masaaktif
  masaaktif="${masaaktif// /}"; [[ -z "$masaaktif" ]] && masaaktif="30"
  [[ "$masaaktif" =~ ^[0-9]+$ ]] && [[ "$masaaktif" -gt 0 ]] || { echo -e "${R}[ERROR] Expired days tidak valid.${NC}"; pause; return; }

  local uuid exp created_pretty exp_pretty
  uuid="$(new_uuid)"
  exp="$(add_days_from_today "$masaaktif")"
  created_pretty="$(date +"%d %b, %Y")"
  exp_pretty="$(fmt_pretty_date "$exp")"

  vmess_add_to_all_inbounds "$user" "$uuid"
  expiry_set "$user" "$exp"
  xray_restart

  log_create "$user" "$uuid" "$masaaktif" "$created_pretty" "$exp_pretty"
  echo -e "${G}OK: VMESS dibuat.${NC}"

  # ---- Output info + links ----
  local domain host ip path link_tls link_80 link_legacy
  domain="$(domain_get)"
  ip="$(server_ip_only)"
  host="${domain:-$ip}"
  path="/vmess"

  if [[ -n "${domain:-}" ]]; then
    link_tls="$(vmess_uri_ws "$user" "$uuid" "$host" "443" "tls" "$path")"
    link_80="$(vmess_uri_ws "$user" "$uuid" "$host" "80" "none" "$path")"
  else
    link_tls=""
    link_80=""
  fi

  # legacy VMESS (tanpa domain) biasanya port 10001 (tcp)
  if jq -e '(.inbounds//[]) | any(.protocol=="vmess" and (.port==10001))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="$(vmess_uri_tcp "$user" "$uuid" "$ip" "10001")"
  else
    link_legacy=""
  fi

  echo ""
  echo -e "${Y}===== INFORMASI AKUN VMESS =====${NC}"
  echo -e "User  : ${W}${user}${NC}"
  echo -e "UUID  : ${W}${uuid}${NC}"
  echo -e "Exp   : ${Y}${exp}${NC}"
  echo -e "Host  : ${W}${host}${NC}"
  echo -e "Path  : ${W}${path}${NC}"
  echo ""
  if [[ -n "${link_tls:-}" ]]; then
    echo -e "${C}VMESS WS TLS (443) link:${NC}"
    echo -e "${W}${link_tls}${NC}"
    echo ""
    echo -e "${C}VMESS WS (80) link:${NC}"
    echo -e "${W}${link_80}${NC}"
  fi
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}VMESS LEGACY (10001) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}===============================${NC}"
  echo ""

  # Optional Telegram
  tg_load
  if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
    local tmsg
    tmsg="<b>VMESS Account</b>
<code>User: ${user}
UUID: ${uuid}
Exp: ${exp}
Host: ${host}
Path: ${path}
</code>"
    if [[ -n "${link_tls:-}" ]]; then
      tmsg="${tmsg}
<b>VMESS 443 TLS</b>
<code>${link_tls}</code>
<b>VMESS 80 WS</b>
<code>${link_80}</code>"
    fi
    [[ -n "${link_legacy:-}" ]] && tmsg="${tmsg}
<b>LEGACY 10001</b>
<code>${link_legacy}</code>"
    tg_send "$tmsg"
  fi
  pause
}

vmess_list() {
  clear
  echo -e "${C}=== LIST AKUN VMESS ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_vmess_inbound || { echo -e "${R}Inbound VMESS belum ada.${NC}"; pause; return; }

  local total
  total="$(vmess_list_raw | wc -l | tr -d ' ')"
  echo -e "${Y}Total akun VMESS:${NC} $total\n"

  vmess_list_raw | while IFS='|' read -r u id; do
    exp="$(expiry_get "$u")"; [[ -z "${exp:-}" ]] && exp="-"
    printf "%-18s  uuid: %-36s  exp: %s\n" "$u" "$id" "$exp"
  done | nl -w2 -s". "

  echo ""
  pause
}

vmess_delete() {
  clear
  echo -e "${C}=== DELETE AKUN VMESS ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }

  read -rp "Masukkan nama akun yang ingin dihapus: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  vmess_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  vmess_delete_all_inbounds "$user"
  expiry_del "$user"
  xray_restart

  echo -e "${G}OK: Akun VMESS dihapus.${NC}"
  pause
}

vmess_extend() {
  clear
  echo -e "${C}=== PERPANJANG AKUN VMESS ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }

  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  vmess_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  cur="$(expiry_get "$user")"; [[ -z "${cur:-}" ]] && cur="-"
  echo -e "Expiry saat ini: ${Y}${cur}${NC}"

  read -rp "Tambah perpanjangan (hari) [default 30]: " days
  days="${days// /}"; [[ -z "$days" ]] && days="30"
  [[ "$days" =~ ^[0-9]+$ ]] && [[ "$days" -gt 0 ]] || { echo -e "${R}Input hari tidak valid.${NC}"; pause; return; }

  if [[ "$cur" != "-" ]] && is_valid_date "$cur"; then
    newexp="$(date -d "$cur +$days day" +"%Y-%m-%d")"
  else
    newexp="$(add_days_from_today "$days")"
  fi

  expiry_set "$user" "$newexp"
  echo -e "${G}OK: Akun diperpanjang.${NC}"
  echo -e "User: ${W}${user}${NC}"
  echo -e "Exp : ${Y}${newexp}${NC}"
  pause
}

vmess_view() {
  # Lihat detail akun + link
  read -rp "Masukkan username: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  # Bersihkan layar setelah input agar output rapi
  cls
  ui_header "DETAIL AKUN VMESS"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  vmess_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  local uuid exp domain ip host path link_tls link_80 link_legacy
  uuid="$(vmess_get_uuid "$user")"
  exp="$(expiry_get "$user")"; [[ -z "${exp:-}" ]] && exp="-"
  domain="$(domain_get)"
  ip="$(server_ip_only)"
  host="${domain:-$ip}"
  path="/vmess"

  if [[ -n "${domain:-}" ]]; then
    link_tls="$(vmess_uri_ws "$user" "$uuid" "$host" "443" "tls" "$path")"
    link_80="$(vmess_uri_ws "$user" "$uuid" "$host" "80" "none" "$path")"
  else
    link_tls=""
    link_80=""
  fi

  if jq -e '(.inbounds//[]) | any(.protocol=="vmess" and (.port==10001))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="$(vmess_uri_tcp "$user" "$uuid" "$ip" "10001")"
  else
    link_legacy=""
  fi

  echo -e "${Y}===== INFORMASI AKUN VMESS =====${NC}"
  echo -e "User  : ${W}${user}${NC}"
  echo -e "UUID  : ${W}${uuid}${NC}"
  echo -e "Exp   : ${Y}${exp}${NC}"
  echo -e "Host  : ${W}${host}${NC}"
  echo -e "Path  : ${W}${path}${NC}"
  echo ""
  if [[ -n "${link_tls:-}" ]]; then
    echo -e "${C}VMESS WS TLS (443) link:${NC}"
    echo -e "${W}${link_tls}${NC}"
    echo ""
    echo -e "${C}VMESS WS (80) link:${NC}"
    echo -e "${W}${link_80}${NC}"
  fi
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}VMESS LEGACY (10001) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}===============================${NC}"
  echo ""
  pause
}

menu_vmess() {
  while true; do
    ui_header "MENU VMESS MANAGER"
    echo -e " ${Y}[1]${NC} 📋 List akun"
    echo -e " ${Y}[2]${NC} ➕ Add akun"
    echo -e " ${Y}[3]${NC} 🗑️ Delete akun"
    echo -e " ${Y}[4]${NC} ⏳ Perpanjang akun"
    echo -e " ${Y}[5]${NC} 🔎 Lihat akun"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) vmess_list ;;
      2) vmess_add ;;
      3) vmess_delete ;;
      4) vmess_extend ;;
      5) vmess_view ;;
      0) cls; break ;;  # FIX: back benar-benar keluar
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

need_root
need_deps
menu_vmess