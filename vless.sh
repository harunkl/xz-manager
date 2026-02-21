#!/usr/bin/env bash
set -euo pipefail

# =========================
# VLESS SUB MENU (vless.sh)
# =========================

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93m"; C="\e[96;1m"; W="\e[97;1m"; B="\e[94;1m"
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
is_sourced() { [[ "${BASH_SOURCE[0]}" != "$0" ]]; }

need_deps() {
  command -v jq >/dev/null 2>&1 || { echo -e "${R}Butuh jq. Install: apt-get install -y jq${NC}"; exit 1; }
  mkdir -p "$MANAGER_DIR" >/dev/null 2>&1 || true
  touch "$EXPIRY_DB" >/dev/null 2>&1 || true
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

reality_exists() {
  jq -e '(.inbounds // []) | any(.protocol=="vless" and (.streamSettings.security=="reality"))' "$XRAY_JSON" >/dev/null 2>&1
}

port_in_use() {
  local p="$1"
  jq -e --argjson p "$p" '(.inbounds // []) | any(.port == $p)' "$XRAY_JSON" >/dev/null 2>&1
}

gen_reality_keys() {
  # Output: "priv|pub"
  # Support output format Xray yang berbeda:
  # - Format lama: Private key / Public key
  # - Format baru: PrivateKey / Password (Password = publicKey)
  local xb out priv pub
  xb="/usr/local/bin/xray"
  [[ -x "$xb" ]] || xb="$(command -v xray || true)"
  [[ -n "$xb" ]] || return 1

  out="$("$xb" x25519 2>/dev/null || true)"

  if echo "$out" | grep -q '^PrivateKey:'; then
    priv="$(echo "$out" | awk -F': ' '/^PrivateKey:/ {print $2; exit}')"
    pub="$(echo "$out"  | awk -F': ' '/^Password:/  {print $2; exit}')"
  else
    priv="$(echo "$out" | awk -F': ' '/Private key/ {print $2; exit}')"
    pub="$(echo "$out"  | awk -F': ' '/Public key/  {print $2; exit}')"
  fi

  [[ -n "$priv" && -n "$pub" ]] || return 1
  echo "${priv}|${pub}"
}


ensure_reality_inbound() {
  # Selalu pastikan inbound VLESS REALITY ada, terlepas ada/tidaknya domain.
  file_ok "$XRAY_JSON" || return 1
  reality_exists && return 0

  local domain ip port sni sid kp priv pub tmp
  domain="$(domain_get 2>/dev/null || true)"
  ip="$(server_ip_only)"
  sni="www.cloudflare.com"

  # Port default:
  # - Jika ada domain, 443 biasanya dipakai TLS; pakai 8444 untuk REALITY.
  # - Jika tidak ada domain, prioritaskan 443 untuk REALITY.
  if [[ -n "${domain:-}" ]]; then
    port=8444
  else
    port=443
  fi

  # Cari port yang kosong (fallback)
  for p in "$port" 8444 443 12444; do
    if ! port_in_use "$p"; then port="$p"; break; fi
  done

  kp="$(gen_reality_keys || true)"
  priv="${kp%%|*}"
  pub="${kp#*|}"
  [[ -n "${priv:-}" && -n "${pub:-}" && "$pub" != "$kp" ]] || { echo -e "${R}Gagal generate REALITY keypair.${NC}"; return 1; }

  if command -v openssl >/dev/null 2>&1; then
    sid="$(openssl rand -hex 4 2>/dev/null || true)"
  else
    sid=""
  fi
  [[ -n "${sid:-}" ]] || sid="$(head -c 4 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null || echo "a1b2c3d4")"
  sid="$(echo "$sid" | tr -d ' \r\n' | head -c 8)"

  mkdir -p /usr/local/etc/xray /etc/xray "$MANAGER_DIR" >/dev/null 2>&1 || true
  printf "%s" "$pub" > /usr/local/etc/xray/reality.public
  printf "%s" "$sid" > /usr/local/etc/xray/reality.shortid

  tmp="$(mktemp)"
  jq --arg port "$port" --arg priv "$priv" --arg sni "$sni" --arg sid "$sid" '
    .inbounds = (.inbounds // []) + [{
      "tag":"vless-reality",
      "listen":"0.0.0.0",
      "port": ($port|tonumber),
      "protocol":"vless",
      "settings":{
        "clients":[],
        "decryption":"none"
      },
      "streamSettings":{
        "network":"tcp",
        "security":"reality",
        "realitySettings":{
          "show":false,
          "dest":"www.cloudflare.com:443",
          "xver":0,
          "serverNames":[ $sni ],
          "privateKey": $priv,
          "shortIds":[ $sid ]
        }
      },
      "sniffing":{
        "enabled":true,
        "destOverride":["http","tls","quic"],
        "routeOnly":true
      }
    }]' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"

  echo -e "${G}REALITY inbound dibuat (tag: vless-reality) pada port ${port}.${NC}"
  return 0
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


file_ok() { [[ -f "$1" ]]; }

today() { date +"%Y-%m-%d"; }
add_days_from_today() { date -d "$(today) +$1 day" +"%Y-%m-%d"; }
is_valid_date() { date -d "$1" +"%Y-%m-%d" >/dev/null 2>&1; }
new_uuid() { cat /proc/sys/kernel/random/uuid; }

expiry_get() { awk -F'|' -v t="VLESS" -v u="$1" '$1==t && $2==u {print $3}' "$EXPIRY_DB" | tail -n1; }
expiry_set() {
  local user="$1" exp="$2"
  awk -F'|' -v t="VLESS" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
  echo "VLESS|${user}|${exp}" >> "$EXPIRY_DB"
}
expiry_del() {
  local user="$1"
  awk -F'|' -v t="VLESS" -v u="$user" '!( $1==t && $2==u )' "$EXPIRY_DB" > "$EXPIRY_DB.tmp"
  mv "$EXPIRY_DB.tmp" "$EXPIRY_DB"
}

xray_restart() { systemctl restart xray 2>/dev/null || true; }

has_vless_inbound() {
  file_ok "$XRAY_JSON" || return 1
  jq -e '(.inbounds // []) | map(select(.protocol=="vless")) | length > 0' "$XRAY_JSON" >/dev/null 2>&1
}

vless_user_exists() {
  file_ok "$XRAY_JSON" || return 1
  jq -e --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="vless"))
    | any( ( .settings.clients // [] ) | any(.email == $u) )
  ' "$XRAY_JSON" >/dev/null 2>&1
}

vless_get_uuid() {
  jq -r --arg u "$1" '
    (.inbounds // [])
    | map(select(.protocol=="vless"))
    | .[].settings.clients[]?
    | select(.email == $u)
    | .id
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF{print; exit}'
}

vless_list_users_info_raw() {
  jq -r '
    (.inbounds // [])
    | map(select(.protocol=="vless"))
    | .[].settings.clients[]?
    | "\(.email)|\(.id)"
  ' "$XRAY_JSON" 2>/dev/null | awk 'NF' | sort -t'|' -k1,1 -u
}

vless_add_user_to_all_inbounds() {
  local user="$1" uuid="$2"
  local tmp
  tmp="$(mktemp)"
  jq --arg u "$user" --arg id "$uuid" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="vless" then
            .settings.clients = (
              ((.settings.clients // []) + [{"id":$id,"email":$u}])
              | unique_by(.email)
            )
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

vless_delete_user_all_inbounds() {
  local user="$1"
  local tmp
  tmp="$(mktemp)"
  jq --arg u "$user" '
    .inbounds = (
      (.inbounds // [])
      | map(
          if .protocol=="vless" then
            .settings.clients = ((.settings.clients // []) | map(select(.email != $u)))
          else .
          end
        )
    )
  ' "$XRAY_JSON" > "$tmp" && mv "$tmp" "$XRAY_JSON"
}

vless_list() {
  clear
  echo -e "${C}=== LIST AKUN VLESS ===${NC}"
  if ! file_ok "$XRAY_JSON"; then echo -e "${R}Config XRAY tidak ditemukan:${NC} $XRAY_JSON"; pause; return; fi
  if ! has_vless_inbound; then echo -e "${R}Inbound VLESS tidak ditemukan di XRAY config.${NC}"; pause; return; fi

  local total
  total="$(vless_list_users_info_raw | wc -l | tr -d ' ')"
  echo -e "${Y}Total akun VLESS:${NC} $total\n"

  vless_list_users_info_raw | while IFS='|' read -r u id; do
    exp="$(expiry_get "$u")"; [[ -z "${exp:-}" ]] && exp="-"
    printf "%-18s  uuid: %-36s  exp: %s\n" "$u" "${id:-"-"}" "$exp"
  done | nl -w2 -s". "
  echo ""; pause
}

vless_add() {
  clear
  echo -e "${C}=== ADD AKUN VLESS ===${NC}"
  if ! file_ok "$XRAY_JSON"; then echo -e "${R}Config XRAY tidak ditemukan:${NC} $XRAY_JSON"; pause; return; fi
    # Pastikan REALITY selalu ada (baik ada domain maupun tidak)
  if ! ensure_reality_inbound; then
    echo -e "${Y}Peringatan: gagal membuat inbound REALITY. Lanjut tanpa REALITY.${NC}"
  fi
  if ! has_vless_inbound; then echo -e "${R}Inbound VLESS tidak ditemukan.${NC}"; pause; return; fi

  local user
  while true; do
    read -rp "User (a-zA-Z0-9_): " user
    user="${user// /}"
    [[ -z "$user" ]] && { echo -e "${R}Nama pengguna kosong.${NC}"; continue; }
    [[ "$user" =~ ^[a-zA-Z0-9_]+$ ]] || { echo -e "${R}Format user tidak valid.${NC}"; continue; }
    vless_user_exists "$user" && { echo -e "${Y}Akun sudah ada.${NC}"; continue; }
    break
  done

  read -rp "Expired (days) [default 30]: " days
  [[ -z "${days:-}" ]] && days=30
  [[ "$days" =~ ^[0-9]+$ ]] && [[ "$days" -gt 0 ]] || { echo -e "${R}Input hari tidak valid.${NC}"; pause; return; }

  exp="$(add_days_from_today "$days")"
  uuid="$(new_uuid)"

  vless_add_user_to_all_inbounds "$user" "$uuid"
  expiry_set "$user" "$exp"
  xray_restart

  echo -e "${G}OK: Akun VLESS dibuat.${NC}"
  echo -e "User : ${W}${user}${NC}"
  echo -e "UUID : ${W}${uuid}${NC}"
  echo -e "Exp  : ${Y}${exp}${NC}"

  # ---- Output info + links ----
  local domain host ip path enc_path link_tls link_80 link_legacy link_reality
  domain="$(domain_get 2>/dev/null || true)"
  host="$(server_host)"
  ip="$(server_ip_only)"
  path="$(ws_path_for_proto vless)"; [[ -z "${path:-}" ]] && path="/vless"
  enc_path="$(url_path_enc "$path")"

  # VLESS WS TLS (443) + WS (80)
  link_tls="vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&path=${enc_path}#${user}"
  link_80="vless://${uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=${enc_path}#${user}"

  # VLESS legacy (10002) bila ada
  if jq -e '(.inbounds//[]) | any(.protocol=="vless" and (.port==10002) and (.streamSettings.security=="none"))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="vless://${uuid}@${ip}:10002?encryption=none&security=none&type=tcp#${user}"
  else
    link_legacy=""
  fi

  # VLESS REALITY bila ada inbound reality
  local rport pbk sid sni
  rport="$(reality_port)"; pbk="$(reality_pubkey)"; sid="$(reality_shortid)"; sni="$(reality_sni)"
  if [[ -n "${rport:-}" && -n "${pbk:-}" && -n "${sid:-}" ]]; then
    link_reality="vless://${uuid}@${ip}:${rport}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}#${user}"
  else
    link_reality=""
  fi

  echo ""
  echo -e "${Y}===== INFORMASI AKUN VLESS =====${NC}"
  echo -e "User   : ${W}${user}${NC}"
  echo -e "UUID   : ${W}${uuid}${NC}"
  echo -e "Exp    : ${Y}${exp}${NC}"
  echo -e "Host   : ${W}${host}${NC}"
  echo -e "Path   : ${W}${path}${NC}"
  echo ""
  echo -e "${C}VLESS WS TLS (443) link:${NC}"
  echo -e "${W}${link_tls}${NC}"
  echo ""
  echo -e "${C}VLESS WS (80) link:${NC}"
  echo -e "${W}${link_80}${NC}"
  if [[ -n "${link_reality:-}" ]]; then
    echo ""
    echo -e "${C}VLESS REALITY link:${NC}"
    echo -e "${W}${link_reality}${NC}"
  fi
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}VLESS LEGACY (10002) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}===============================${NC}"
  echo ""

  # Optional Telegram
  tg_load
  if [[ -n "${CHATID:-}" && -n "${KEY:-}" ]]; then
    local tmsg
    tmsg="<b>VLESS Account</b>
<code>User: ${user}
UUID: ${uuid}
Exp: ${exp}
Host: ${host}
Path: ${path}
</code>
<b>VLESS 443 TLS</b>
<code>${link_tls}</code>
<b>VLESS 80 WS</b>
<code>${link_80}</code>"
    [[ -n "${link_reality:-}" ]] && tmsg="${tmsg}
<b>REALITY</b>
<code>${link_reality}</code>"
    [[ -n "${link_legacy:-}" ]] && tmsg="${tmsg}
<b>LEGACY 10002</b>
<code>${link_legacy}</code>"
    tg_send "$tmsg"
  fi
  pause
}

vless_delete() {
  clear
  echo -e "${C}=== DELETE AKUN VLESS ===${NC}"
  if ! file_ok "$XRAY_JSON"; then echo -e "${R}Config XRAY tidak ditemukan:${NC} $XRAY_JSON"; pause; return; fi

  read -rp "Masukkan nama akun yang ingin dihapus: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  vless_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  uuid="$(vless_get_uuid "$user")"; [[ -z "${uuid:-}" ]] && uuid="-"
  vless_delete_user_all_inbounds "$user"
  expiry_del "$user"
  xray_restart

  echo -e "${G}OK: Akun VLESS dihapus.${NC}"
  echo -e "User : ${W}${user}${NC}"
  echo -e "UUID : ${W}${uuid}${NC}"
  pause
}

vless_extend() {
  clear
  echo -e "${C}=== PERPANJANG AKUN VLESS ===${NC}"
  if ! file_ok "$XRAY_JSON"; then echo -e "${R}Config XRAY tidak ditemukan:${NC} $XRAY_JSON"; pause; return; fi

  read -rp "Masukkan nama akun: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  vless_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  cur="$(expiry_get "$user")"; [[ -z "${cur:-}" ]] && cur="-"
  echo -e "Expiry saat ini: ${Y}$cur${NC}"

  read -rp "Tambah perpanjangan (hari) [default 30]: " days
  [[ -z "${days:-}" ]] && days=30
  [[ "$days" =~ ^[0-9]+$ ]] && [[ "$days" -gt 0 ]] || { echo -e "${R}Input hari tidak valid.${NC}"; pause; return; }

  if [[ "$cur" != "-" ]] && is_valid_date "$cur"; then
    new="$(date -d "$cur +$days day" +"%Y-%m-%d")"
  else
    new="$(add_days_from_today "$days")"
  fi

  expiry_set "$user" "$new"
  uuid="$(vless_get_uuid "$user")"; [[ -z "${uuid:-}" ]] && uuid="-"

  echo -e "${G}OK: Akun diperpanjang.${NC}"
  echo -e "User : ${W}$user${NC}"
  echo -e "UUID : ${W}$uuid${NC}"
  echo -e "Exp  : ${Y}$new${NC}"
  pause
}

vless_view() {
  read -rp "Masukkan username: " user
  user="${user// /}"
  [[ -z "$user" ]] && { echo -e "${R}Nama kosong.${NC}"; pause; return; }

  cls
  ui_header "DETAIL AKUN VLESS"

  file_ok "$XRAY_JSON" || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; pause; return; }
  vless_user_exists "$user" || { echo -e "${R}Akun tidak ditemukan.${NC}"; pause; return; }

  local uuid exp domain ip host path enc_path link_tls link_80 link_legacy link_reality
  uuid="$(vless_get_uuid "$user")"
  exp="$(expiry_get "$user")"; [[ -z "${exp:-}" ]] && exp="-"

  domain="$(domain_get 2>/dev/null || true)"
  ip="$(server_ip_only)"
  host="${domain:-$ip}"

  path="$(ws_path_for_proto vless)"
  [[ -z "${path:-}" ]] && path="/vless"
  enc_path="$(url_path_enc "$path")"

  link_tls=""
  link_80=""
  if [[ -n "${domain:-}" ]]; then
    link_tls="vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&path=${enc_path}#${user}"
    link_80="vless://${uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=${enc_path}#${user}"
  fi

  if jq -e '(.inbounds//[]) | any(.protocol=="vless" and (.port==10002))' "$XRAY_JSON" >/dev/null 2>&1; then
    link_legacy="vless://${uuid}@${ip}:10002?encryption=none&security=none&type=tcp#${user}"
  else
    link_legacy=""
  fi

  link_reality=""
  if ensure_reality_inbound >/dev/null 2>&1; then
    local rport sni pbk sid
    rport="$(reality_port)"; sni="$(reality_sni)"
    pbk="$(reality_pubkey)"; sid="$(reality_shortid)"
    if [[ -n "${rport:-}" && -n "${pbk:-}" && -n "${sid:-}" ]]; then
      link_reality="vless://${uuid}@${ip}:${rport}?encryption=none&security=reality&type=tcp&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}#${user}"
    fi
  fi

  echo -e "${Y}===== INFORMASI AKUN VLESS =====${NC}"
  echo -e "User  : ${W}${user}${NC}"
  echo -e "UUID  : ${W}${uuid}${NC}"
  echo -e "Exp   : ${Y}${exp}${NC}"
  echo -e "Host  : ${W}${host}${NC}"
  echo -e "Path  : ${W}${path}${NC}"
  echo ""
  if [[ -n "${link_tls:-}" ]]; then
    echo -e "${C}VLESS WS TLS (443) link:${NC}"
    echo -e "${W}${link_tls}${NC}"
    echo ""
    echo -e "${C}VLESS WS (80) link:${NC}"
    echo -e "${W}${link_80}${NC}"
  fi
  if [[ -n "${link_reality:-}" ]]; then
    echo ""
    echo -e "${C}VLESS REALITY link:${NC}"
    echo -e "${W}${link_reality}${NC}"
  fi
  if [[ -n "${link_legacy:-}" ]]; then
    echo ""
    echo -e "${C}VLESS LEGACY (10002) link:${NC}"
    echo -e "${W}${link_legacy}${NC}"
  fi
  echo -e "${Y}===============================${NC}"
  echo ""
  pause
}

menu_vless() {
  while true; do
    ui_header "MENU VLESS MANAGER"
    echo -e " ${Y}[1]${NC} 📋 List akun"
    echo -e " ${Y}[2]${NC} ➕ Add akun"
    echo -e " ${Y}[3]${NC} 🗑️ Delete akun"
    echo -e " ${Y}[4]${NC} ⏳ Perpanjang akun"
    echo -e " ${Y}[5]${NC} 🔎 Lihat akun"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) vless_list ;;
      2) vless_add ;;
      3) vless_delete ;;
      4) vless_extend ;;
      5) vless_view ;;
      0) cls; if is_sourced; then return 0; else exit 0; fi ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

need_deps
menu_vless