#!/usr/bin/env bash
set -euo pipefail

# =========================
# XRAY + ZIVPN MANAGER
# MAIN MENU (menu.sh) - ICONIC UI
# =========================

# --- PATH CONFIG
XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
ZIVPN_JSON="${ZIVPN_JSON:-/etc/zivpn/config.json}"
DOMAIN_FILE="${DOMAIN_FILE:-/usr/local/etc/xray/domain}"

# resolve symlink (biar aman kalau dipanggil dari /usr/bin/xz)
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
BASE_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

# --- Colors
NC="\e[0m"
G="\e[92;1m"
R="\e[91;1m"
Y="\e[93;1m"
C="\e[96;1m"
W="\e[97;1m"
DIM="\e[90m"
B="\e[94;1m"

pause() { read -rp "Tekan Enter untuk kembali..."; }

cls() { clear; }

is_root() { [[ "${EUID}" -eq 0 ]]; }
file_ok() { [[ -f "$1" ]]; }

# --- dependency minimal (jq & curl)
pkg_install() {
  local pkgs=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${pkgs[@]}" >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${pkgs[@]}" >/dev/null 2>&1
  else
    echo -e "${R}Tidak bisa install dependency otomatis. Install manual: ${pkgs[*]}${NC}"
    return 1
  fi
}

need_deps() {
  local need=()
  command -v jq   >/dev/null 2>&1 || need+=("jq")
  command -v curl >/dev/null 2>&1 || need+=("curl")
  if ((${#need[@]})); then
    echo -e "${Y}Install dependency: ${need[*]}...${NC}"
    pkg_install "${need[@]}"
  fi
}

# --- UI: Logo (ikonik)
logo() {
  echo -e "${C}"
  echo "   ██╗  ██╗███████╗██╗   ██╗"
  echo "   ╚██╗██╔╝╚══███╔╝██║   ██║"
  echo "    ╚███╔╝   ███╔╝ ██║   ██║"
  echo "    ██╔██╗  ███╔╝  ╚██╗ ██╔╝"
  echo "   ██╔╝ ██╗███████╗ ╚████╔╝ "
  echo "   ╚═╝  ╚═╝╚══════╝  ╚═══╝  "
  echo -e "${W}     XRAY • ZIVPN • MANAGER${NC}"
  echo
}

# --- VPS Info
get_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${PRETTY_NAME:-Unknown}"
  else
    uname -srm
  fi
}
get_ram_usage() {
  # RAM: 255Mi/957Mi (27%) | Avail: 539Mi
  free -m 2>/dev/null | awk '
    /^Mem:/ {
      total=$2; used=$3; avail=$7;
      if (total>0) pct=(used/total)*100; else pct=0;
      printf "%dMi/%dMi (%.0f%%)", used, total, pct, avail;
    }
  ' || echo "-"
}

get_cpu_usage() {
  # Pemakaian CPU (%). Hitung dari /proc/stat (2 sampel)
  if [[ ! -r /proc/stat ]]; then
    echo "-"
    return
  fi
  local cpu user nice system idle iowait irq softirq steal _
  read -r cpu user nice system idle iowait irq softirq steal _ < /proc/stat
  local idle1=$((idle+iowait))
  local total1=$((user+nice+system+idle+iowait+irq+softirq+steal))
  sleep 0.4
  read -r cpu user nice system idle iowait irq softirq steal _ < /proc/stat
  local idle2=$((idle+iowait))
  local total2=$((user+nice+system+idle+iowait+irq+softirq+steal))
  local dt=$((total2-total1))
  local di=$((idle2-idle1))
  if ((dt<=0)); then
    echo "-"
    return
  fi
  local usage
  usage=$(( ( (dt-di)*100 + dt/2 ) / dt ))
  echo "${usage}%"
}

get_cpu_cores() { command -v nproc >/dev/null 2>&1 && echo "$(nproc) CPU" || echo "-"; }
get_uptime() { uptime -p 2>/dev/null | sed 's/^up //g' || echo "-"; }
get_date() { date +"%d-%m-%Y"; }
get_time() { date +"%H:%M:%S"; }
get_ip_vps() {
  local ip
  ip="$(curl -fsS --max-time 2 https://ipinfo.io/ip 2>/dev/null || true)"
  ip="${ip//$'\r'/}"
  ip="${ip//$'\n'/}"
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  [[ -z "$ip" ]] && ip="-"
  echo "$ip"
}
get_domain() {
  if [[ -f "$DOMAIN_FILE" ]]; then
    head -n1 "$DOMAIN_FILE" | tr -d ' \t\r\n'
  else
    echo "-"
  fi
}
get_isp_city() {
  local isp city
  isp="$(curl -fsS --max-time 2 https://ipinfo.io/org 2>/dev/null || true)"
  isp="$(echo "$isp" | sed -E 's/^AS[0-9]+[[:space:]]+//')"
  city="$(curl -fsS --max-time 2 https://ipinfo.io/city 2>/dev/null || true)"
  [[ -z "$isp" ]] && isp="-"
  [[ -z "$city" ]] && city="-"
  echo "$isp|$city"
}

# --- Count Accounts (DEDUP / tidak dobel)
count_zivpn() {
  if file_ok "$ZIVPN_JSON"; then
    jq -r '
      (.auth.config // []) as $a
      | if ($a|type) != "array" or ($a|length)==0 then 0
        else
          if ($a[0]|type) == "object" then
            $a
            | map(.user? // .username? // .name? // .id? // .email? // empty)
            | map(tostring)
            | unique
            | length
          else
            $a
            | map(tostring)
            | unique
            | length
          end
        end
    ' "$ZIVPN_JSON" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

count_xray_proto() {
  local proto="$1"
  if ! file_ok "$XRAY_JSON"; then
    echo 0
    return
  fi

  jq -r --arg p "$proto" '
    (
      (.inbounds // [])
      | map(select(.protocol == $p))
      | map((.settings // {}).clients // [])
      | add
    ) // []
    | map(.email? // .id? // .password? // .uuid? // .user? // empty)
    | map(tostring)
    | unique
    | length
  ' "$XRAY_JSON" 2>/dev/null || echo 0
}

# --- BOT STATUS (xzbot)
xzbot_status_raw() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "na"
    return
  fi
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "xzbot.service"; then
    local st
    st="$(systemctl is-active xzbot 2>/dev/null || true)"
    [[ -z "${st:-}" ]] && st="inactive"
    echo "$st"
  else
    echo "na"
  fi
}

xzbot_plain() {
  local st
  st="$(xzbot_status_raw)"
  case "$st" in
    active) echo "ON" ;;
    na)     echo "NA" ;;
    *)      echo "OFF" ;;
  esac
}

# badge ikon: ● ON / ● OFF / ● NA
xzbot_badge3() {
  local p
  p="$(xzbot_plain)"
  case "$p" in
    ON)  echo -e "${G}● ON${NC}" ;;
    NA)  echo -e "${DIM}● NA${NC}" ;;
    *)   echo -e "${R}● OFF${NC}" ;;
  esac
}

# --- UI: Banner + Info (ikonik)
banner() {
  clear
  logo

  local os isp city ram cpu up dt tm ip dom
  os="$(get_os)"
  ram="$(get_ram_usage)"
  cpu="$(get_cpu_usage)"
  up="$(get_uptime)"
  dt="$(get_date)"
  tm="$(get_time)"
  ip="$(get_ip_vps)"
  dom="$(get_domain)"

  IFS="|" read -r isp city < <(get_isp_city)

  local c_zivpn c_vmess c_vless c_trojan
  c_zivpn="$(count_zivpn)"
  c_vmess="$(count_xray_proto vmess)"
  c_vless="$(count_xray_proto vless)"
  c_trojan="$(count_xray_proto trojan)"

  # --- INFORMASI VPS (card style)
  echo -e "${DIM}╭────────────────────────────────────────────╮${NC}"
  echo -e "${DIM}│${NC}            ${W}INFORMASI VPS${NC}                   ${DIM}│${NC}"
  echo -e "${DIM}╰────────────────────────────────────────────╯${NC}"
  printf " ${Y}🖥️ OS${NC}     : %s\n" "$os"
  printf " ${Y}🏢 ISP${NC}     : %s\n" "$isp"
  printf " ${Y}📍 CITY${NC}    : %s\n" "$city"
  printf " ${Y}💾 RAM${NC}     : %s\n" "$ram"
  printf " ${Y}⚙️ CPU${NC}     : %s\n" "$cpu"
  printf " ${Y}⏱️ UPTIME${NC}  : %s\n" "$up"
  printf " ${Y}📅 DATE${NC}    : %s\n" "$dt"
  printf " ${Y}🕒 TIME${NC}    : %s\n" "$tm"
  printf " ${Y}🌐 IP${NC}      : %s\n" "$ip"
  printf " ${Y}🔗 DOMAIN${NC}  : %s\n" "$dom"
  echo

  # --- INFORMASI AKUN (card style)
  echo -e "${DIM}╭────────────────────────────────────────────╮${NC}"
  echo -e "${DIM}│${NC}           ${W}INFORMASI AKUN${NC}                   ${DIM}│${NC}"
  echo -e "${DIM}╰────────────────────────────────────────────╯${NC}"
  printf " ${W}🔐 ZIVPN/UDP${NC} : %s\n" "$c_zivpn"
  printf " ${W}🌐 VMESS${NC}     : %s\n" "$c_vmess"
  printf " ${W}🚀 VLESS${NC}     : %s\n" "$c_vless"
  printf " ${W}🛡️ TROJAN${NC}   : %s\n" "$c_trojan"
  echo
}

# --- Runner untuk submenu
run_submenu() {
  local f="$1"
  cls
  if [[ -f "$BASE_DIR/$f" ]]; then
    bash "$BASE_DIR/$f"
    cls
  else
    echo -e "${R}File submenu tidak ditemukan:${NC} $BASE_DIR/$f"
    pause
    cls
  fi
}
# --- SPEEDTEST
menu_speedtest() {
  clear
  banner
  echo -e "${B}📶 SPEEDTEST${NC}"
  echo -e "${DIM}────────────────────────────────────────────${NC}"

  if command -v speedtest >/dev/null 2>&1; then
    speedtest || true
    pause
    return
  fi

  echo -e "${Y}Perintah 'speedtest' belum ada.${NC}"
  echo " ${Y}[1]${NC} Install speedtest-cli (pip)"
  echo " ${Y}[2]${NC} Install paket speedtest (repo OS jika tersedia)"
  echo " ${Y}[0]${NC} Kembali"
  read -rp "➤ Pilih menu : " c
  case "$c" in
    1)
      pkg_install python3 python3-pip >/dev/null 2>&1 || true
      pip3 install -U speedtest-cli >/dev/null 2>&1 || true
      echo -e "${G}OK. Jalankan lagi menu speedtest.${NC}"
      pause
      ;;
    2)
      pkg_install speedtest >/dev/null 2>&1 || true
      echo -e "${G}OK (jika paket tersedia). Coba lagi.${NC}"
      pause
      ;;
    0) return ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
}

# --- Menu utama (ikonik)
menu_manager() {
  local badge
  badge="$(xzbot_badge3)"

  echo -e "${DIM}╭────────────────────────────────────────────╮${NC}"
  echo -e "${DIM}│${NC}          ${W}FITUR SC TUNNELING${NC}                ${DIM}│${NC}"
  echo -e "${DIM}╰────────────────────────────────────────────╯${NC}"

  echo -e " ${Y}[1]${NC} 🔐 ZIVPN / UDP"
  echo -e " ${Y}[2]${NC} 🌐 VMESS"
  echo -e " ${Y}[3]${NC} 🚀 VLESS"
  echo -e " ${Y}[4]${NC} 🛡️ TROJAN"
  echo -e " ${Y}[5]${NC} 📶 SPEEDTEST"
  echo -e " ${Y}[6]${NC} ⚙️ UTILITY ${DIM}(BOT:${NC} ${badge}${DIM})${NC}"
  echo -e " ${Y}[0]${NC} ❌ KELUAR"
  echo

  read -rp "➤ Pilih menu : " opt
  case "${opt:-}" in
    1|01) run_submenu "zivpn.sh" ;;
    2|02) run_submenu "vmess.sh" ;;
    3|03) run_submenu "vless.sh" ;;
    4|04) run_submenu "trojan.sh" ;;
    5|05) menu_speedtest ;;
    6|06) run_submenu "utility.sh" ;;
    0|00|q|Q) echo -e "${Y}Keluar...${NC}"; exit 0 ;;
    *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
  esac
}

main() {
  if ! is_root; then
    echo -e "${R}Harus dijalankan sebagai root.${NC}"
    exit 1
  fi
  need_deps

  while true; do
    banner
    menu_manager
  done
}

main
