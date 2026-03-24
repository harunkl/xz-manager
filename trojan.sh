#!/usr/bin/env bash
set -euo pipefail

XRAY_JSON="${XRAY_JSON:-/etc/xray/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"
TROJAN_DIR="${TROJAN_DIR:-/etc/trojan}"
LOG_DIR="${LOG_DIR:-/etc/user-create}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/user.log}"
BOT_DB="${BOT_DB:-/etc/bot/.bot.db}"
TROJAN_DB="${TROJAN_DB:-/etc/trojan/.trojan.db}"
IPVPS_CONF="${IPVPS_CONF:-/var/lib/kyt/ipvps.conf}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; W="\e[97;1m"; DIM="${DIM:-\e[90m}"

pause() { read -rp "Tekan Enter untuk kembali..."; }
cls() { clear; }
need_root(){ [[ $EUID -eq 0 ]] || { echo -e "${R}[ERROR] Jalankan sebagai root.${NC}"; exit 1; }; }
need_deps(){
  command -v sed >/dev/null 2>&1 || { echo -e "${R}sed tidak tersedia.${NC}"; exit 1; }
  command -v grep >/dev/null 2>&1 || { echo -e "${R}grep tidak tersedia.${NC}"; exit 1; }
  command -v awk >/dev/null 2>&1 || { echo -e "${R}awk tidak tersedia.${NC}"; exit 1; }
  command -v curl >/dev/null 2>&1 || true
  mkdir -p "$MANAGER_DIR" "$TROJAN_DIR" "$LOG_DIR" "$(dirname "$TROJAN_DB")"
  touch "$EXPIRY_DB" "$LOG_FILE" "$TROJAN_DB"
  chmod 600 "$EXPIRY_DB" "$TROJAN_DB" 2>/dev/null || true
}

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

file_ok(){ [[ -f "$1" ]]; }
new_uuid(){ cat /proc/sys/kernel/random/uuid; }
today_ymd(){ date +"%Y-%m-%d"; }
add_days_from_today(){ date -d "$(today_ymd) +$1 day" +"%Y-%m-%d"; }
is_valid_date(){ date -d "$1" +"%Y-%m-%d" >/dev/null 2>&1; }
fmt_pretty(){ date -d "$1" +"%d %b, %Y" 2>/dev/null || echo "$1"; }
restart_services(){ systemctl restart xray >/dev/null 2>&1 || true; systemctl restart nginx >/dev/null 2>&1 || true; service cron restart >/dev/null 2>&1 || true; }

expiry_get(){
  local from_db
  from_db="$(awk -F'|' -v t="TROJAN" -v u="$1" '$1==t && $2==u {print $3}' "$EXPIRY_DB" 2>/dev/null | tail -n1)"
  if [[ -n "$from_db" ]]; then
    echo "$from_db"
    return 0
  fi
  grep -wE "^#![[:space:]]+$1[[:space:]]+" "$XRAY_JSON" 2>/dev/null | awk '{print $3}' | tail -n1
}
expiry_set(){
  local user="$1" exp="$2"
  awk -F'|' -v t="TROJAN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp" 2>/dev/null || true
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB" 2>/dev/null || true
  echo "TROJAN|${user}|${exp}" >> "$EXPIRY_DB"
}
expiry_del(){
  local user="$1"
  awk -F'|' -v t="TROJAN" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp" 2>/dev/null || true
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB" 2>/dev/null || true
}

public_ip(){
  command -v curl >/dev/null 2>&1 || { echo ""; return 0; }
  curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 6 https://ipv4.icanhazip.com 2>/dev/null || echo ""
}

domain_get(){
  local ip="" f=""
  if [[ -f "$IPVPS_CONF" ]]; then
    ip="$(grep -E '^IP=' "$IPVPS_CONF" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d ' \r\n')"
    if [[ -n "$ip" ]]; then
      echo "$ip"
      return 0
    fi
  fi
  for f in /etc/xray/domain /usr/local/etc/xray/domain /root/domain; do
    [[ -s "$f" ]] && { tr -d ' \r\n' < "$f" | head -n1; return 0; }
  done
  return 1
}
server_host(){ local d; d="$(domain_get 2>/dev/null || true)"; [[ -n "$d" ]] && echo "$d" || public_ip; }
server_ip_only(){ local ip; ip="$(public_ip)"; [[ -n "$ip" ]] && echo "$ip" || echo "$(server_host)"; }

is_domain_mode(){
  local host="${1:-$(server_host)}"
  [[ "$host" =~ [A-Za-z] ]]
}

# Telegram optional
TG_CHATID=""; TG_KEY=""; TG_TIME="10"; TG_URL=""
tg_load(){
  if [[ -f "$BOT_DB" ]]; then
    TG_CHATID="$(grep -E '^#bot# ' "$BOT_DB" 2>/dev/null | awk '{print $3}' | head -n1 || true)"
    TG_KEY="$(grep -E '^#bot# ' "$BOT_DB" 2>/dev/null | awk '{print $2}' | head -n1 || true)"
    TG_URL="https://api.telegram.org/bot${TG_KEY}/sendMessage"
  fi
}
tg_send(){
  local text="$1"
  command -v curl >/dev/null 2>&1 || return 0
  [[ -z "$TG_CHATID" || -z "$TG_KEY" ]] && return 0
  curl -s --max-time "$TG_TIME" -d "chat_id=$TG_CHATID&disable_web_page_preview=1&text=$text&parse_mode=html" "$TG_URL" >/dev/null 2>&1 || true
}

has_trojan_markers(){
  grep -q '#trojanws' "$XRAY_JSON" 2>/dev/null && grep -q '#trojangrpc' "$XRAY_JSON" 2>/dev/null
}
has_trojan_inbound(){
  file_ok "$XRAY_JSON" || return 1
  has_trojan_markers && return 0
  grep -q '"protocol"[[:space:]]*:[[:space:]]*"trojan"' "$XRAY_JSON" 2>/dev/null
}

trojan_user_exists(){
  local user="$1"
  grep -qwE "^#![[:space:]]+$user[[:space:]]+" "$XRAY_JSON" 2>/dev/null && return 0
  grep -q '"email"[[:space:]]*:[[:space:]]*"'"$user"'"' "$XRAY_JSON" 2>/dev/null
}

trojan_get_pass(){
  local user="$1"
  awk -v u="$user" '$1=="###" && $2==u {print $4}' "$TROJAN_DB" 2>/dev/null | tail -n1 | awk 'NF{print; exit}' || true
  grep -oP '(?<="password": ")[^"]+(?=","email": "'"$user"'")' "$XRAY_JSON" 2>/dev/null | head -n1 || true
}

trojan_list_raw(){
  if grep -q '^### ' "$TROJAN_DB" 2>/dev/null; then
    awk '$1=="###"{print $2"|"$4}' "$TROJAN_DB" 2>/dev/null | awk 'NF' | sort -t'|' -k1,1 -u
    return 0
  fi
  awk '/^#! /{user=$2; exp=$3} /"password"[[:space:]]*:[[:space:]]*"[^"]+"[[:space:]]*,[[:space:]]*"email"[[:space:]]*:[[:space:]]*"[^"]+"/{
    if (match($0,/"password"[[:space:]]*:[[:space:]]*"([^"]+)"[[:space:]]*,[[:space:]]*"email"[[:space:]]*:[[:space:]]*"([^"]+)"/,m)) {
      print m[2] "|" m[1]
    }
  }' "$XRAY_JSON" 2>/dev/null | awk 'NF' | sort -t'|' -k1,1 -u
}

insert_after_marker(){
  local marker="$1" line1="$2" line2="$3"
  sed -i "/${marker}$/a\\${line1}\n${line2}" "$XRAY_JSON"
}

trojan_add_sc_vvip(){
  local user="$1" pass="$2" exp="$3"
  has_trojan_markers || return 1
  insert_after_marker '#trojanws' "#! ${user} ${exp}" '},{"password": "'"${pass}"'","email": "'"${user}"'"'
  insert_after_marker '#trojangrpc' "#! ${user} ${exp}" '},{"password": "'"${pass}"'","email": "'"${user}"'"'
}

trojan_delete_sc_vvip(){
  local user="$1" exp="$2"
  sed -i "/^#! ${user} ${exp}$/,/^},{/d" "$XRAY_JSON"
}

trojan_add_to_all_inbounds_text(){
  # fallback ringan bila marker ala sc-vvip tidak ditemukan
  local user="$1" pass="$2"
  local tmp
  tmp="$(mktemp)"
  awk -v u="$user" -v p="$pass" '
  BEGIN{done=0}
  {print}
  /"clients"[[:space:]]*:[[:space:]]*\[/ && done==0 {
    print "        {\"password\": \"" p "\", \"email\": \"" u "\"},"
    done=1
  }' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

trojan_add_account(){
  local user="$1" pass="$2" exp="$3"
  if has_trojan_markers; then
    trojan_add_sc_vvip "$user" "$pass" "$exp"
  else
    trojan_add_to_all_inbounds_text "$user" "$pass"
  fi
}

trojan_delete_account(){
  local user="$1" exp="$2"
  if has_trojan_markers; then
    trojan_delete_sc_vvip "$user" "$exp"
  else
    local tmp
    tmp="$(mktemp)"
    awk -v u="$user" 'index($0,"\"email\": \"" u "\""){skip=1; next} skip && /^\s*},?\s*$/{skip=0; next} !skip{print}' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
  fi
}

trojan_ws_path(){
  grep -oP '"path"\s*:\s*"\K[^"]+' "$XRAY_JSON" 2>/dev/null | grep 'trojan' | head -n1 || echo "/trojan-ws"
}
trojan_grpc_service(){
  grep -oP '"serviceName"\s*:\s*"\K[^"]+' "$XRAY_JSON" 2>/dev/null | grep 'trojan' | head -n1 || echo "trojan-grpc"
}
trojan_ws_port(){
  awk 'BEGIN{found=0} /#trojanws/{for(i=NR;i>=1;i--){} }' /dev/null >/dev/null 2>&1 || true
  awk '
    /#trojanws/{seen=1}
    seen && match($0,/"port"[[:space:]]*:[[:space:]]*([0-9]+)/,m){print m[1]; exit}
  ' "$XRAY_JSON" 2>/dev/null | head -n1 || true
}
trojan_grpc_port(){
  awk '
    /#trojangrpc/{seen=1}
    seen && match($0,/"port"[[:space:]]*:[[:space:]]*([0-9]+)/,m){print m[1]; exit}
  ' "$XRAY_JSON" 2>/dev/null | head -n1 || true
}

url_path_enc(){ echo "$1" | sed 's|/|%2F|g'; }

trojan_link_info(){
  local user="$1" pass="$2"
  local host mode server_display ws_path grpc_service ws_port grpc_port direct_port
  host="$(server_host)"
  server_display="$host"
  if is_domain_mode "$host"; then mode="domain"; else mode="non-domain"; fi

  ws_path="$(trojan_ws_path)"
  grpc_service="$(trojan_grpc_service)"
  ws_port="$(trojan_ws_port)"; [[ -z "$ws_port" ]] && ws_port="443"
  grpc_port="$(trojan_grpc_port)"; [[ -z "$grpc_port" ]] && grpc_port="443"
  direct_port="$ws_port"

  printf 'mode=%q\n' "$mode"
  printf 'server_display=%q\n' "$server_display"
  if [[ "$mode" == "domain" ]]; then
    printf 'ws_label=%q\n' 'TROJAN WS link:'
    printf 'ws_link=%q\n' "trojan://${pass}@${host}:${ws_port}?path=$(url_path_enc "$ws_path")&security=tls&host=${host}&type=ws&sni=${host}#${user}"
    printf 'grpc_label=%q\n' 'TROJAN gRPC link:'
    printf 'grpc_link=%q\n' "trojan://${pass}@${host}:${grpc_port}?mode=gun&security=tls&type=grpc&serviceName=${grpc_service}&sni=${host}#${user}"
  else
    printf 'primary_label=%q\n' 'TROJAN direct link:'
    printf 'primary_link=%q\n' "trojan://${pass}@${host}:${direct_port}?security=tls&type=tcp&allowInsecure=1#${user}"
  fi
}

trojan_show_account(){
  local user="$1" pass="$2" exp="$3"
  local mode server_display ws_label ws_link grpc_label grpc_link primary_label primary_link
  eval "$(trojan_link_info "$user" "$pass")"
  echo ""
  echo -e "${Y}===== INFORMASI AKUN TROJAN =====${NC}"
  echo -e "Mode   : ${W}${mode}${NC}"
  echo -e "User   : ${W}${user}${NC}"
  echo -e "Pass   : ${W}${pass}${NC}"
  echo -e "Exp    : ${Y}${exp}${NC}"
  echo -e "Server : ${W}${server_display}${NC}"
  echo ""
  if [[ "$mode" == "domain" ]]; then
    echo -e "${C}${ws_label}${NC}"
    echo -e "${W}${ws_link}${NC}"
    echo ""
    echo -e "${C}${grpc_label}${NC}"
    echo -e "${W}${grpc_link}${NC}"
  else
    echo -e "${C}${primary_label}${NC}"
    echo -e "${W}${primary_link}${NC}"
  fi
  echo -e "${Y}================================${NC}"
  echo ""
}

trojan_add(){
  clear
  echo -e "${C}=== CREATE TROJAN ACCOUNT ===${NC}"
  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_trojan_inbound || { echo -e "${R}Inbound TROJAN belum ada di config.${NC}"; pause; return; }

  local user masaaktif pass exp exp_pretty created
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

  pass="$(new_uuid)"
  exp="$(add_days_from_today "$masaaktif")"
  exp_pretty="$(fmt_pretty "$exp")"
  created="$(date +"%d %b, %Y")"

  trojan_add_account "$user" "$pass" "$exp"
  expiry_set "$user" "$exp"
  awk -v u="$user" -v e="$exp" -v p="$pass" '$1=="###" && $2==u {next} {print} END{print "### " u " " e " " p " 0 0"}' "$TROJAN_DB" > "$TROJAN_DB.tmp" && mv "$TROJAN_DB.tmp" "$TROJAN_DB"
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

  trojan_show_account "$user" "$pass" "$exp"

  tg_load
  if [[ -n "$TG_CHATID" && -n "$TG_KEY" ]]; then
    local mode server_display ws_label ws_link grpc_label grpc_link primary_label primary_link tmsg
    eval "$(trojan_link_info "$user" "$pass")"
    if [[ "$mode" == "domain" ]]; then
      tmsg="<b>TROJAN Account</b>\n<code>User: ${user}\nPass: ${pass}\nExp : ${exp}\nHost: ${server_display}</code>\n<b>${ws_label}</b>\n<code>${ws_link}</code>\n<b>${grpc_label}</b>\n<code>${grpc_link}</code>"
    else
      tmsg="<b>TROJAN Account</b>\n<code>User: ${user}\nPass: ${pass}\nExp : ${exp}\nHost: ${server_display}</code>\n<b>${primary_label}</b>\n<code>${primary_link}</code>"
    fi
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
  local total exp
  total="$(trojan_list_raw | wc -l | tr -d ' ')"
  echo -e "${Y}Total akun TROJAN:${NC} $total\n"
  trojan_list_raw | while IFS='|' read -r u pass; do
    exp="$(expiry_get "$u")"; [[ -z "$exp" ]] && exp="-"
    printf "%-18s  pass: %-36s  exp: %s\n" "$u" "$pass" "$exp"
  done | nl -w2 -s'. '
  echo ""
  pause
}

trojan_delete(){
  clear
  echo -e "${C}=== DELETE AKUN TROJAN ===${NC}"
  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  read -rp "Masukkan nama akun yang ingin dihapus: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }
  trojan_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }
  local exp
  exp="$(expiry_get "$user")"
  trojan_delete_account "$user" "$exp"
  expiry_del "$user"
  awk -v u="$user" '$1=="###" && $2==u {next} {print}' "$TROJAN_DB" > "$TROJAN_DB.tmp" && mv "$TROJAN_DB.tmp" "$TROJAN_DB"
  rm -f "$TROJAN_DIR/$user" "/etc/hokage/limit/trojan/ip/$user" "/etc/kyt/limit/trojan/ip/$user" 2>/dev/null || true
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
  local cur days newexp
  cur="$(expiry_get "$user")"; [[ -z "$cur" ]] && cur="-"
  echo -e "Expiry saat ini: ${Y}${cur}${NC}"
  read -rp "Tambah perpanjangan (hari) [default 30]: " days
  days="${days// /}"; [[ -z "$days" ]] && days="30"
  [[ "$days" =~ ^[0-9]+$ ]] && [[ "$days" -gt 0 ]] || { echo -e "${R}Input hari tidak valid.${NC}"; pause; return; }
  if [[ "$cur" != "-" ]] && is_valid_date "$cur"; then
    newexp="$(date -d "$cur +$days day" +"%Y-%m-%d")"
  else
    newexp="$(add_days_from_today "$days")"
  fi
  if [[ "$cur" != "-" ]]; then
    sed -i "s/^#! ${user} ${cur}$/#! ${user} ${newexp}/" "$XRAY_JSON" 2>/dev/null || true
  fi
  expiry_set "$user" "$newexp"
  awk -v u="$user" -v e="$newexp" '$1=="###" && $2==u {$3=e} {print}' "$TROJAN_DB" > "$TROJAN_DB.tmp" && mv "$TROJAN_DB.tmp" "$TROJAN_DB"
  echo -e "${G}OK: Akun diperpanjang.${NC}"
  echo -e "User: ${W}${user}${NC}"
  echo -e "Exp : ${Y}${newexp}${NC}"
  pause
}

trojan_view(){
  read -rp "Masukkan username: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }
  cls
  ui_header "DETAIL AKUN TROJAN"
  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  trojan_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }
  local pass exp
  pass="$(trojan_get_pass "$user")"
  exp="$(expiry_get "$user")"; [[ -z "$exp" ]] && exp="-"
  trojan_show_account "$user" "$pass" "$exp"
  pause
}

menu_trojan(){
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
