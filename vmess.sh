#!/usr/bin/env bash
set -euo pipefail

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"
USER_LOG_DIR="${USER_LOG_DIR:-/etc/user-create}"
USER_LOG="${USER_LOG:-$USER_LOG_DIR/user.log}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; W="\e[97;1m"; DIM="\e[90m"
pause() { read -rp "Tekan Enter untuk kembali..."; }
cls() { clear; }

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

need_root() { [[ $EUID -eq 0 ]] || { echo -e "${R}[ERROR] Jalankan sebagai root.${NC}"; exit 1; }; }
need_deps() {
  command -v jq >/dev/null 2>&1 || { echo -e "${R}Butuh jq. Install: apt-get install -y jq${NC}"; exit 1; }
  command -v curl >/dev/null 2>&1 || true
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
  systemctl restart nginx >/dev/null 2>&1 || true
  service cron restart >/dev/null 2>&1 || true
}

domain_get() {
  local f d
  for f in /usr/local/etc/xz-manager/domain /usr/local/etc/xray/domain /etc/xray/domain /root/domain; do
    [[ -f "$f" ]] || continue
    d="$(head -n1 "$f" 2>/dev/null | tr -d ' \t\r\n')"
    [[ -n "$d" ]] && { echo "$d"; return; }
  done
  echo ""
}

server_ip_only() {
  local ip
  ip="$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  [[ -z "${ip:-}" ]] && ip="$(curl -fsSL --max-time 4 https://ipinfo.io/ip 2>/dev/null || true)"
  [[ -z "${ip:-}" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "${ip:-}"
}

b64() {
  if base64 -w 0 >/dev/null 2>&1 <<<"test"; then
    base64 -w 0
  else
    base64 | tr -d '\n'
  fi
}

json_escape() { jq -Rsa . <<<"${1:-}"; }

vmess_json_uri() {
  local payload="$1"
  printf 'vmess://%s' "$(printf '%s' "$payload" | b64)"
}

# --- inbound helpers ---
get_vmess_ws_inbound_json() {
  local tls_mode="${1:-tls}"
  jq -c --arg tls_mode "$tls_mode" '
    (.inbounds // [])
    | map(select(.protocol=="vmess" and (.streamSettings.network // "") == "ws"))
    | map(select(((.streamSettings.security // "none") == (if $tls_mode=="tls" then "tls" else "none" end))))
    | .[0] // empty
  ' "$XRAY_JSON" 2>/dev/null
}

get_vmess_tcp_inbound_json() {
  jq -c '
    (.inbounds // [])
    | map(select(.protocol=="vmess" and ((.streamSettings.network // "tcp") == "tcp")))
    | .[0] // empty
  ' "$XRAY_JSON" 2>/dev/null
}

vmess_public_port_for_inbound() {
  local inbound_json="$1" domain="$2"
  local network security port
  network="$(jq -r '.streamSettings.network // "tcp"' <<<"$inbound_json")"
  security="$(jq -r '.streamSettings.security // "none"' <<<"$inbound_json")"
  port="$(jq -r '.port // empty' <<<"$inbound_json")"
  if [[ -n "$domain" && "$network" == "ws" ]]; then
    if [[ "$security" == "tls" ]]; then echo "443"; else echo "80"; fi
    return
  fi
  echo "$port"
}

vmess_public_host_for_inbound() {
  local inbound_json="$1" domain="$2" ip="$3"
  local listen
  listen="$(jq -r '.listen // ""' <<<"$inbound_json")"
  if [[ -n "$domain" ]]; then
    echo "$domain"
  elif [[ "$listen" == "127.0.0.1" || "$listen" == "::1" ]]; then
    echo ""
  else
    echo "$ip"
  fi
}

vmess_uri_ws_manual() {
  local user="$1" uuid="$2" host="$3" port="$4" path="$5" security="$6"
  local tlsflag sni ps payload
  [[ -n "$host" && -n "$port" ]] || return 1
  [[ -z "$path" ]] && path="/vmess"
  tlsflag=""; sni=""; ps="${user}-WS"
  if [[ "$security" == "tls" ]]; then
    tlsflag="tls"
    sni="$host"
    ps="${user}-WS-TLS"
  fi
  payload=$(jq -cn     --arg v "2"     --arg ps "$ps"     --arg add "$host"     --arg port "$port"     --arg id "$uuid"     --arg aid "0"     --arg net "ws"     --arg type "none"     --arg host "$host"     --arg path "$path"     --arg tls "$tlsflag"     --arg sni "$sni"     '{v:$v,ps:$ps,add:$add,port:$port,id:$id,aid:$aid,net:$net,type:$type,host:$host,path:$path,tls:$tls} + (if $sni != "" then {sni:$sni} else {} end)')
  vmess_json_uri "$payload"
}

vmess_uri_ws_from_inbound() {
  local user="$1" uuid="$2" inbound_json="$3"
  local domain ip host port path security
  domain="$(domain_get)"
  ip="$(server_ip_only)"
  path="$(jq -r '.streamSettings.wsSettings.path // "/vmess"' <<<"$inbound_json")"
  security="$(jq -r '.streamSettings.security // "none"' <<<"$inbound_json")"
  port="$(vmess_public_port_for_inbound "$inbound_json" "$domain")"
  host="$(vmess_public_host_for_inbound "$inbound_json" "$domain" "$ip")"
  vmess_uri_ws_manual "$user" "$uuid" "$host" "$port" "$path" "$security"
}

vmess_uri_tcp_manual() {
  local user="$1" uuid="$2" host="$3" port="$4" security="${5:-none}" sni="${6:-}"
  local tlsflag ps payload
  [[ -n "$host" && -n "$port" ]] || return 1
  tlsflag=""; ps="${user}-TCP"
  [[ "$security" == "tls" ]] && tlsflag="tls"
  payload=$(jq -cn     --arg v "2"     --arg ps "$ps"     --arg add "$host"     --arg port "$port"     --arg id "$uuid"     --arg aid "0"     --arg net "tcp"     --arg type "none"     --arg path ""     --arg hostv ""     --arg tls "$tlsflag"     --arg sni "$sni"     '{v:$v,ps:$ps,add:$add,port:$port,id:$id,aid:$aid,net:$net,type:$type,host:$hostv,path:$path,tls:$tls} + (if $sni != "" then {sni:$sni} else {} end)')
  vmess_json_uri "$payload"
}

vmess_uri_tcp_from_inbound() {
  local user="$1" uuid="$2" inbound_json="$3"
  local domain ip host port security sni
  domain="$(domain_get)"
  ip="$(server_ip_only)"
  port="$(jq -r '.port // empty' <<<"$inbound_json")"
  security="$(jq -r '.streamSettings.security // "none"' <<<"$inbound_json")"
  sni=""
  if [[ "$security" == "tls" && -n "$domain" ]]; then
    host="$domain"
    sni="$domain"
  else
    host="$ip"
  fi
  vmess_uri_tcp_manual "$user" "$uuid" "$host" "$port" "$security" "$sni"
}

vmess_clash_ws_block() {
  local name="$1" uuid="$2" inbound_json="$3"
  local domain ip host port path security host_header
  domain="$(domain_get)"; ip="$(server_ip_only)"
  path="$(jq -r '.streamSettings.wsSettings.path // "/vmess"' <<<"$inbound_json")"
  security="$(jq -r '.streamSettings.security // "none"' <<<"$inbound_json")"
  port="$(vmess_public_port_for_inbound "$inbound_json" "$domain")"
  host="$(vmess_public_host_for_inbound "$inbound_json" "$domain" "$ip")"
  [[ -n "$host" && -n "$port" ]] || return 1
  host_header="$host"
  cat <<BLOCK
- name: ${name}
  type: vmess
  server: ${host}
  port: ${port}
  uuid: ${uuid}
  alterId: 0
  cipher: auto
  tls: $( [[ "$security" == "tls" ]] && echo true || echo false )
  servername: $( [[ "$security" == "tls" ]] && echo "$host" || echo "" )
  skip-cert-verify: $( [[ "$security" == "tls" ]] && echo true || echo false )
  network: ws
  ws-opts:
    path: ${path}
    headers:
      Host: ${host_header}
BLOCK
}

# telegram

tg_load() {
  if [[ -f /etc/bot/.bot.db ]]; then
    KEY="$(grep -E '^#bot# ' /etc/bot/.bot.db | awk '{print $2}' | head -n1)"
    CHATID="$(grep -E '^#bot# ' /etc/bot/.bot.db | awk '{print $3}' | head -n1)"
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
  local user="$1" uuid="$2" tmp
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
  local user="$1" tmp
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


render_vmess_info() {
  local user="$1" uuid="$2" exp="$3"
  local domain ip mode host ws_tls_json ws_none_json tcp_json path_tls path_ws
  local link_tls link_80 link_tcp tcp_port
  domain="$(domain_get)"
  ip="$(server_ip_only)"
  mode="domain"; [[ -z "$domain" ]] && mode="non-domain"
  host="${domain:-$ip}"
  ws_tls_json="$(get_vmess_ws_inbound_json tls)"
  ws_none_json="$(get_vmess_ws_inbound_json none)"
  tcp_json="$(get_vmess_tcp_inbound_json)"
  path_tls="$(jq -r '.streamSettings.wsSettings.path // empty' <<<"${ws_tls_json:-}" 2>/dev/null)"
  path_ws="$(jq -r '.streamSettings.wsSettings.path // empty' <<<"${ws_none_json:-}" 2>/dev/null)"
  [[ -z "$path_tls" ]] && path_tls="$(jq -r '.streamSettings.wsSettings.path // empty' <<<"${ws_none_json:-}" 2>/dev/null)"
  [[ -z "$path_ws" ]] && path_ws="$(jq -r '.streamSettings.wsSettings.path // empty' <<<"${ws_tls_json:-}" 2>/dev/null)"
  [[ -z "$path_tls" ]] && path_tls="/vmess"
  [[ -z "$path_ws" ]] && path_ws="/vmess"
  tcp_port="$(jq -r '.port // empty' <<<"${tcp_json:-}" 2>/dev/null)"
  link_tls=""; link_80=""; link_tcp=""

  if [[ -n "$domain" ]]; then
    if [[ -n "${ws_tls_json:-}" && "${ws_tls_json:-}" != "null" ]]; then
      link_tls="$(vmess_uri_ws_from_inbound "$user" "$uuid" "$ws_tls_json" || true)"
    else
      link_tls="$(vmess_uri_ws_manual "$user" "$uuid" "$domain" "443" "$path_tls" "tls" || true)"
    fi

    if [[ -n "${ws_none_json:-}" && "${ws_none_json:-}" != "null" ]]; then
      link_80="$(vmess_uri_ws_from_inbound "$user" "$uuid" "$ws_none_json" || true)"
    else
      link_80="$(vmess_uri_ws_manual "$user" "$uuid" "$domain" "80" "$path_ws" "none" || true)"
    fi
  else
    [[ -n "${ws_none_json:-}" && "${ws_none_json:-}" != "null" ]] && link_80="$(vmess_uri_ws_from_inbound "$user" "$uuid" "$ws_none_json" || true)"
  fi

  [[ -n "${tcp_json:-}" && "${tcp_json:-}" != "null" ]] && link_tcp="$(vmess_uri_tcp_from_inbound "$user" "$uuid" "$tcp_json" || true)"

  echo -e "${Y}===== INFORMASI AKUN VMESS =====${NC}"
  echo -e "Mode   : ${W}${mode}${NC}"
  echo -e "User   : ${W}${user}${NC}"
  echo -e "UUID   : ${W}${uuid}${NC}"
  echo -e "Exp    : ${Y}${exp}${NC}"
  echo -e "Server : ${W}${host}${NC}"
  [[ -n "$link_tls" ]] && echo -e "Path TLS : ${W}${path_tls}${NC}"
  [[ -n "$link_80" ]] && echo -e "Path WS  : ${W}${path_ws}${NC}"
  [[ -n "$link_tcp" && -n "$tcp_port" ]] && echo -e "Port TCP : ${W}${tcp_port}${NC}"
  echo

  if [[ -n "$link_tls" ]]; then
    echo -e "${C}VMESS WS TLS (publik 443) link:${NC}"
    echo -e "${W}${link_tls}${NC}"
    echo
  fi
  if [[ -n "$link_80" ]]; then
    if [[ -n "$domain" ]]; then
      echo -e "${C}VMESS WS (publik 80) link:${NC}"
    else
      echo -e "${C}VMESS WS link:${NC}"
    fi
    echo -e "${W}${link_80}${NC}"
    echo
  fi
  if [[ -n "$link_tcp" ]]; then
    echo -e "${C}VMESS TCP link:${NC}"
    echo -e "${W}${link_tcp}${NC}"
    echo
  fi

  tg_load
  if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
    local tmsg
    tmsg="<b>VMESS Account</b>
<code>Mode   : ${mode}
User   : ${user}
UUID   : ${uuid}
Exp    : ${exp}
Server : ${host}</code>"
    [[ -n "$link_tls" ]] && tmsg+=$'
<code>Path TLS : '"${path_tls}"$'</code>'
    [[ -n "$link_80" ]] && tmsg+=$'
<code>Path WS  : '"${path_ws}"$'</code>'
    [[ -n "$link_tcp" && -n "$tcp_port" ]] && tmsg+=$'
<code>Port TCP : '"${tcp_port}"$'</code>'
    [[ -n "$link_tls" ]] && tmsg+=$'

<b>VMESS WS TLS (publik 443)</b>
<code>'"$link_tls"$'</code>'
    [[ -n "$link_80" ]] && tmsg+=$'

<b>VMESS WS (publik 80)</b>
<code>'"$link_80"$'</code>'
    [[ -n "$link_tcp" ]] && tmsg+=$'

<b>VMESS TCP</b>
<code>'"$link_tcp"$'</code>'
    tg_send "$tmsg"
  fi
}

vmess_add() {
  clear
  echo -e "${C}=== CREATE VMESS ACCOUNT ===${NC}"
  file_ok "$XRAY_JSON" || { echo -e "${R}[ERROR] Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  has_vmess_inbound || { echo -e "${R}[ERROR] Inbound VMESS belum ada di config.${NC}"; pause; return; }

  local user masaaktif uuid exp created_pretty exp_pretty
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

  uuid="$(new_uuid)"
  exp="$(add_days_from_today "$masaaktif")"
  created_pretty="$(date +"%d %b, %Y")"
  exp_pretty="$(fmt_pretty_date "$exp")"

  vmess_add_to_all_inbounds "$user" "$uuid"
  expiry_set "$user" "$exp"
  xray_restart
  log_create "$user" "$uuid" "$masaaktif" "$created_pretty" "$exp_pretty"
  echo -e "${G}OK: VMESS dibuat.${NC}"
  echo
  render_vmess_info "$user" "$uuid" "$exp"
  echo
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
  echo
  pause
}

vmess_delete() {
  clear
  echo -e "${C}=== DELETE AKUN VMESS ===${NC}"
  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  local user
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
  local user cur days newexp
  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }
  vmess_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }
  cur="$(expiry_get "$user")"; [[ -z "${cur:-}" ]] && cur="-"
  echo -e "Expiry saat ini: ${Y}${cur}${NC}"
  read -rp "Tambah perpanjangan (hari) [default 30]: " days
  days="${days// /}"; [[ -z "$days" ]] && days="30"
  [[ "$days" =~ ^[0-9]+$ ]] && [[ "$days" -gt 0 ]] || { echo -e "${R}Input hari tidak valid.${NC}"; pause; return; }
  if [[ "$cur" != "-" ]] && is_valid_date "$cur"; then newexp="$(date -d "$cur +$days day" +"%Y-%m-%d")"; else newexp="$(add_days_from_today "$days")"; fi
  expiry_set "$user" "$newexp"
  echo -e "${G}OK: Akun diperpanjang.${NC}"
  echo -e "User: ${W}${user}${NC}"
  echo -e "Exp : ${Y}${newexp}${NC}"
  pause
}

vmess_view() {
  local user uuid exp
  read -rp "Masukkan username: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }
  cls
  ui_header "DETAIL AKUN VMESS"
  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  vmess_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }
  uuid="$(vmess_get_uuid "$user")"
  exp="$(expiry_get "$user")"; [[ -z "${exp:-}" ]] && exp="-"
  render_vmess_info "$user" "$uuid" "$exp"
  echo
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
      0) cls; break ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

need_root
need_deps
menu_vmess
