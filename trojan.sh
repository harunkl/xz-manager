#!/usr/bin/env bash
set -euo pipefail

# =========================
# TROJAN SUB MENU (trojan.sh)
# JSON-safe (jq), expiry in /usr/local/etc/xz-manager/expiry.db
# Telegram optional: /etc/bot/.bot.db
# =========================

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"

TROJAN_DIR="${TROJAN_DIR:-/etc/trojan}"
LOG_DIR="${LOG_DIR:-/etc/user-create}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/user.log}"
BOT_DB="${BOT_DB:-/etc/bot/.bot.db}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; B="\e[94;1m"; W="\e[97;1m"
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
need_root(){ [[ $EUID -eq 0 ]] || { echo -e "${R}[ERROR] Jalankan sebagai root.${NC}"; exit 1; }; }
need_deps() {
  command -v jq >/dev/null 2>&1 || { echo -e "${R}Butuh jq. Install: apt-get install -y jq${NC}"; exit 1; }
  command -v curl >/dev/null 2>&1 || true
  mkdir -p "$MANAGER_DIR" "$TROJAN_DIR" "$LOG_DIR"
  touch "$EXPIRY_DB" "$LOG_FILE"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
}

# ----- Host / Mode / Link builder -----
domain_get() {
  local f
  for f in /usr/local/etc/xray/domain /etc/xray/domain /root/domain; do
    [[ -s "$f" ]] && { tr -d ' \r\n' < "$f" | head -n1; return 0; }
  done
  return 1
}
public_ip() {
  command -v curl >/dev/null 2>&1 || { echo ""; return 0; }
  curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null \
    || curl -fsS --max-time 6 https://ipv4.icanhazip.com 2>/dev/null \
    || echo ""
}
server_host() {
  local d; d="$(domain_get 2>/dev/null || true)"
  if [[ -n "${d:-}" ]]; then echo "$d"; else public_ip; fi
}
server_ip_only() {
  local ip; ip="$(public_ip)"
  [[ -n "${ip:-}" ]] && echo "$ip" || echo "$(server_host)"
}

b64_oneline() {
  if base64 --help 2>/dev/null | grep -q -- "-w"; then
    base64 -w 0
  else
    base64 | tr -d '\n'
  fi
}

url_path_enc() { echo "$1" | sed 's|/|%2F|g'; }

# REALITY params (best-effort)
reality_port() {
  jq -r '(.inbounds // []) | map(select(.protocol=="vless" and (.streamSettings.security=="reality"))) | .[0].port // empty' "$XRAY_JSON" 2>/dev/null
}
reality_sni() {
  jq -r '(.inbounds // []) | map(select(.protocol=="vless" and (.streamSettings.security=="reality"))) | .[0].streamSettings.realitySettings.serverNames[0] // "www.cloudflare.com"' "$XRAY_JSON" 2>/dev/null
}
reality_pubkey() {
  local f
  for f in /usr/local/etc/xray/reality.public /etc/xray/reality.public; do
    [[ -s "$f" ]] && { tr -d ' \r\n' < "$f" | head -n1; return 0; }
  done
  echo ""
}
reality_shortid() {
  local f
  for f in /usr/local/etc/xray/reality.shortid /etc/xray/reality.shortid; do
    [[ -s "$f" ]] && { tr -d ' \r\n' < "$f" | head -n1; return 0; }
  done
  # fallback: ambil dari config bila ada
  jq -r '(.inbounds // []) | map(select(.protocol=="vless" and (.streamSettings.security=="reality"))) | .[0].streamSettings.realitySettings.shortIds[0] // empty' "$XRAY_JSON" 2>/dev/null
}

ws_path_for_proto() {
  local proto="$1"
  jq -r --arg p "$proto" '
    (.inbounds // [])
    | map(select(.protocol==$p and (.streamSettings.network=="ws")))
    | .[0].streamSettings.wsSettings.path // empty
  ' "$XRAY_JSON" 2>/dev/null
}

tg_load() {
  local db="/etc/bot/.bot.db"
  if [[ -f "$db" ]]; then
    CHATID="$(grep -E "^#bot# " "$db" 2>/dev/null | awk '{print $3}' | head -n1 || true)"
    KEY="$(grep -E "^#bot# " "$db" 2>/dev/null | awk '{print $2}' | head -n1 || true)"
    TIME="10"
    URL="https://api.telegram.org/bot${KEY}/sendMessage"
  else
    CHATID=""; KEY=""; TIME="10"; URL=""
  fi
}
tg_send() {
  local text="$1"
  command -v curl >/dev/null 2>&1 || return 0
  [[ -z "${CHATID:-}" || -z "${KEY:-}" || -z "${URL:-}" ]] && return 0
  curl -s --max-time "${TIME:-10}" \
    -d "chat_id=$CHATID&disable_web_page_preview=1&text=$text&parse_mode=html" \
    "$URL" >/dev/null 2>&1 || true
}



file_ok(){ [[ -f "$1" ]]; }
new_uuid(){ cat /proc/sys/kernel/random/uuid; }

today_ymd(){ date +"%Y-%m-%d"; }
add_days_from_today(){ date -d "$(today_ymd) +$1 day" +"%Y-%m-%d"; }
is_valid_date(){ date -d "$1" +"%Y-%m-%d" >/dev/null 2>&1; }
fmt_pretty(){ date -d "$1" +"%d %b, %Y" 2>/dev/null || echo "$1"; }

restart_services(){
  systemctl restart xray >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
  service cron restart >/dev/null 2>&1 || true
}

expiry_get(){ awk -F'|' -v t="TROJAN" -v u="$1" '$1==t && $2==u {print $3}' "$EXPIRY_DB" | tail -n1; }
expiry_set(){
  local user="$1" exp="$2"
  awk -F'|' -v t="TROJAN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
  echo "TROJAN|${user}|${exp}" >> "$EXPIRY_DB"
}
expiry_del(){
  local user="$1"
  awk -F'|' -v t="TROJAN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
}

# ----- Telegram optional -----
tg_load() {
  if [[ -f "$BOT_DB" ]]; then
    CHATID="$(grep -E "^#bot# " "$BOT_DB" 2>/dev/null | awk '{print $3}' | head -n1 || true)"
    KEY="$(grep -E "^#bot# " "$BOT_DB" 2>/dev/null | awk '{print $2}' | head -n1 || true)"
    TIME="10"
    URL="https://api.telegram.org/bot${KEY}/sendMessage"
  else
    CHATID=""; KEY=""; TIME="10"; URL=""
  fi
}
tg_send() {
  local text="$1"
  [[ -z "${CHATID:-}" || -z "${KEY:-}" || -z "${URL:-}" ]] && return 0
  curl -s --max-time "${TIME:-10}" \
    -d "chat_id=$CHATID&disable_web_page_preview=1&text=$text&parse_mode=html" \
    "$URL" >/dev/null 2>&1 || true
}

has_trojan_inbound(){
  file_ok "$XRAY_JSON" || return 1
  jq -e '(.inbounds // []) | map(select(.protocol=="trojan")) | length > 0' "$XRAY_JSON" >/dev/null 2>&1
}
trojan_user_exists(){
  jq -e --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="trojan"))
    | any((.settings.clients // []) | any(.email == $u))
  ' "$XRAY_JSON" >/dev/null 2>&1
}
trojan_get_pass(){
  jq -r --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="trojan"))
    | .[].settings.clients[]?
    | select(.email == $u)
    | .password
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF{print; exit}'
}
trojan_list_raw(){
  jq -r '
    (.inbounds // [])
    | map(select(.protocol=="trojan"))
    | .[].settings.clients[]?
    | "\(.email)|\(.password)"
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF' | sort -t'|' -k1,1 -u
}

trojan_add_to_all_inbounds(){
  local user="$1" pass="$2"
  local tmp; tmp="$(mktemp)"
  jq --arg u "$user" --arg p "$pass" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="trojan" then
            .settings.clients = (
              ((.settings.clients // []) + [{"password":$p,"email":$u}])
              | unique_by(.email)
            )
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}
trojan_delete_all_inbounds(){
  local user="$1"
  local tmp; tmp="$(mktemp)"
  jq --arg u "$user" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="trojan" then
            .settings.clients = ((.settings.clients // []) | map(select(.email != $u)))
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

trojan_add(){
  clear
  echo -e "${C}=== CREATE TROJAN ACCOUNT ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_trojan_inbound || { echo -e "${R}Inbound TROJAN belum ada di config.${NC}"; pause; return; }

  local user
  while true; do
    read -rp "User (a-zA-Z0-9_): " user
    user="${user// /}"
    [[ "$user" =~ ^[a-zA-Z0-9_]+$ ]] || { echo -e "${R}Username tidak valid.${NC}"; continue; }
    trojan_user_exists "$user" && { echo -e "${Y}Akun sudah ada.${NC}"; continue; }
    break
  done

  read -rp "Expired (days) [default 30]: " masaaktif
  masaaktif="${masaaktif// /}"; [[ -z "$masaaktif" ]] && masaaktif="30"
  [[ "$masaaktif" =~ ^[0-9]+$ ]] && [[ "$masaaktif" -gt 0 ]] || { echo -e "${R}Expired days tidak valid.${NC}"; pause; return; }

  local pass exp exp_pretty created
  pass="$(new_uuid)"
  exp="$(add_days_from_today "$masaaktif")"
  exp_pretty="$(fmt_pretty "$exp")"
  created="$(date +"%d %b, %Y")"

  trojan_add_to_all_inbounds "$user" "$pass"
  expiry_set "$user" "$exp"
  restart_services


  {
    echo ""
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo "🧿Status Create TROJAN Success🧿"
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo "Remarks          : ${user}"
    echo "Key/Password     : ${pass}"
    echo "Aktif Selama     : ${masaaktif} Hari"
    echo "Dibuat Pada      : ${created}"
    echo "Berakhir Pada    : ${exp_pretty}"
    echo -e "${Y}☉━━━━━━━━━━━━━━━━━━━━━━━━━━☉${NC}"
    echo ""
  } | tee -a "$LOG_FILE" >/dev/null

  
  # ---- Output info + links ----
  local host ip link_tls link_legacy
  host="$(server_host)"
  ip="$(server_ip_only)"

  link_tls="trojan://${pass}@${host}:443?security=tls&type=tcp&sni=${host}#${user}"

  if jq -e '(.inbounds//[]) | any(.protocol=="trojan" and (.port==10003))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="trojan://${pass}@${ip}:10003?security=tls&type=tcp&allowInsecure=1#${user}"
  else
    link_legacy=""
  fi

  # Optional Telegram (send links too)
  tg_load
  if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
    local tmsg
    tmsg="<b>TROJAN Account</b>
<code>User: ${user}
Pass: ${pass}
Exp : ${exp}
Host: ${host}
</code>
<b>TROJAN TLS (443)</b>
<code>${link_tls}</code>"
    [[ -n "${link_legacy:-}" ]] && tmsg="${tmsg}
<b>LEGACY 10003 (allowInsecure)</b>
<code>${link_legacy}</code>"
    tg_send "$tmsg"
  fi


  echo ""
  echo -e "${Y}===== INFORMASI AKUN TROJAN =====${NC}"
  echo -e "User   : ${W}${user}${NC}"
  echo -e "Pass   : ${W}${pass}${NC}"
  echo -e "Exp    : ${Y}${exp}${NC}"
  echo -e "Host   : ${W}${host}${NC}"
  echo ""
  echo -e "${C}TROJAN TLS (443) link:${NC}"
  echo -e "${W}${link_tls}${NC}"
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}TROJAN LEGACY (10003, allowInsecure) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}================================${NC}"
  echo ""

  # Telegram: kirim link juga
  tg_load
  if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
    local tmsg
    tmsg="<b>TROJAN Account</b>
<code>User: ${user}
Pass: ${pass}
Exp: ${exp}
Host: ${host}</code>
<b>TROJAN 443 TLS</b>
<code>${link_tls}</code>"
    [[ -n "${link_legacy:-}" ]] && tmsg="${tmsg}
<b>LEGACY 10003</b>
<code>${link_legacy}</code>"
    tg_send "$tmsg"
  fi
echo -e "${G}OK: Trojan dibuat.${NC}"
  pause
}

trojan_list(){
  clear
  echo -e "${C}=== LIST AKUN TROJAN ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_trojan_inbound || { echo -e "${R}Inbound TROJAN belum ada.${NC}"; pause; return; }

  local total
  total="$(trojan_list_raw | wc -l | tr -d ' ')"
  echo -e "${Y}Total akun TROJAN:${NC} $total\n"

  trojan_list_raw | while IFS='|' read -r u pass; do
    exp="$(expiry_get "$u")"; [[ -z "${exp:-}" ]] && exp="-"
    printf "%-18s  pass: %-36s  exp: %s\n" "$u" "$pass" "$exp"
  done | nl -w2 -s". "
  echo ""; pause
}

trojan_delete(){
  clear
  echo -e "${C}=== DELETE AKUN TROJAN ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }

  read -rp "Masukkan nama akun yang ingin dihapus: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  trojan_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  trojan_delete_all_inbounds "$user"
  expiry_del "$user"
  restart_services

  echo -e "${G}OK: Akun TROJAN dihapus.${NC}"
  pause
}

trojan_extend(){
  clear
  echo -e "${C}=== PERPANJANG AKUN TROJAN ===${NC}"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }

  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  trojan_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

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

trojan_view() {
  read -rp "Masukkan username: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  cls
  ui_header "DETAIL AKUN TROJAN"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  trojan_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  local pass exp domain ip host link_tls link_legacy
  pass="$(trojan_get_pass "$user")"
  exp="$(expiry_get "$user")"; [[ -z "${exp:-}" ]] && exp="-"
  domain="$(domain_get 2>/dev/null || true)"
  ip="$(server_ip_only)"
  host="${domain:-$ip}"

  link_tls=""
  if [[ -n "${domain:-}" ]]; then
    link_tls="trojan://${pass}@${host}:443?security=tls&type=tcp&sni=${host}#${user}"
  fi

  if jq -e '(.inbounds//[]) | any(.protocol=="trojan" and (.port==10003))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="trojan://${pass}@${ip}:10003?security=tls&type=tcp&allowInsecure=1#${user}"
  else
    link_legacy=""
  fi

  echo -e "${Y}===== INFORMASI AKUN TROJAN =====${NC}"
  echo -e "User  : ${W}${user}${NC}"
  echo -e "Pass  : ${W}${pass}${NC}"
  echo -e "Exp   : ${Y}${exp}${NC}"
  echo -e "Host  : ${W}${host}${NC}"
  echo ""
  if [[ -n "${link_tls:-}" ]]; then
    echo -e "${C}TROJAN TLS (443) link:${NC}"
    echo -e "${W}${link_tls}${NC}"
  fi
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}TROJAN LEGACY (10003) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}================================${NC}"
  echo ""
  pause
}

menu_trojan() {
  while true; do
    ui_header "MENU TROJAN MANAGER"
    echo -e " ${Y}[1]${NC} 📋 List akun"
    echo -e " ${Y}[2]${NC} ➕ Add akun"
    echo -e " ${Y}[3]${NC} 🗑️ Delete akun"
    echo -e " ${Y}[4]${NC} ⏳ Perpanjang akun"
    echo -e " ${Y}[5]${NC} 🔎 Lihat akun"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) trojan_list ;;
      2) trojan_add ;;
      3) trojan_delete ;;
      4) trojan_extend ;;
      5) trojan_view ;;
      0) cls; break ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

need_root
need_deps
menu_trojan