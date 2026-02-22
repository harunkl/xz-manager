#!/usr/bin/env bash
set -euo pipefail

# =========================
# UTILITY SUB MENU (utility.sh)
# Backup/Restore: XRAY + ZIVPN + expiry.db only
# Bot env NOT included in backup
# =========================

XRAY_JSON="${XRAY_JSON:-/usr/local/etc/xray/config.json}"
XRAY_DIR="${XRAY_DIR:-/usr/local/etc/xray}"

ZIVPN_JSON="${ZIVPN_JSON:-/etc/zivpn/config.json}"
ZIVPN_DIR="${ZIVPN_DIR:-/etc/zivpn}"

MANAGER_DIR="${MANAGER_DIR:-/usr/local/etc/xz-manager}"
EXPIRY_DB="${EXPIRY_DB:-$MANAGER_DIR/expiry.db}"
BOT_ENV="${BOT_ENV:-$MANAGER_DIR/bot.env}"

BACKUP_DIR="${BACKUP_DIR:-/root/xz-backup}"

NC="\e[0m"; G="\e[92;1m"; R="\e[91;1m"; Y="\e[93;1m"; C="\e[96;1m"; W="\e[97;1m"; DIM="\e[90m"; B="\e[94;1m"

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
pause() {
  # Aman walau stdin bukan TTY; tidak mematikan script saat read gagal (set -e)
  if [ -r /dev/tty ]; then
    read -rp "Tekan Enter untuk kembali..." _ </dev/tty 2>/dev/null || true
  else
    read -rp "Tekan Enter untuk kembali..." _ 2>/dev/null || true
  fi
}

cls() { clear; }

file_ok() { [[ -f "$1" ]]; }
dir_ok() { [[ -d "$1" ]]; }

need_deps() {
  command -v tar >/dev/null 2>&1 || { echo -e "${R}Butuh tar. Install: apt-get install -y tar${NC}"; exit 1; }
  mkdir -p "$MANAGER_DIR" "$BACKUP_DIR"
  touch "$EXPIRY_DB"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true
}

restart_zivpn() { systemctl restart zivpn 2>/dev/null || true; echo -e "${G}OK:${NC} ZIVPN direstart."; }
restart_xray()  { systemctl restart xray 2>/dev/null || true; echo -e "${G}OK:${NC} XRAY direstart."; }

# =========================
# BOT ENV + SERVICE HELPERS
# =========================
bot_env_ensure() {
  mkdir -p "$MANAGER_DIR"
  if [[ ! -f "$BOT_ENV" ]]; then
    cat > "$BOT_ENV" <<'EOF'
BOT_TOKEN=""
BOT_ADMIN_IDS=""
EOF
    chmod 600 "$BOT_ENV" 2>/dev/null || true
  fi
}

mask_token() {
  local t="${1:-}"
  if [[ -z "$t" ]]; then
    echo ""
    return
  fi
  # tampilkan sebagian saja biar aman
  local n=${#t}
  if (( n <= 10 )); then
    echo "**********"
  else
    echo "${t:0:6}******${t:n-4:4}"
  fi
}

bot_load() {
  bot_env_ensure
  # hindari error karena "set -u"
  set +u
  # shellcheck disable=SC1090
  source "$BOT_ENV" 2>/dev/null || true
  set -u
  BOT_TOKEN="${BOT_TOKEN:-}"
  BOT_ADMIN_IDS="${BOT_ADMIN_IDS:-}"
}

bot_show() {
  bot_load
  local masked
  masked="$(mask_token "$BOT_TOKEN")"
  echo -e "${C}Konfigurasi Bot (env):${NC}"
  echo -e " File      : ${W}$BOT_ENV${NC}"
  echo -e " BOT_TOKEN  : ${Y}${masked:-"(kosong)"}${NC}"
  echo -e " ADMIN_IDS  : ${Y}${BOT_ADMIN_IDS:-"(kosong)"}${NC}"
}

bot_write_kv() {
  local key="$1" val="$2"
  bot_env_ensure
  awk -v k="$key" -v v="$val" '
    BEGIN{found=0}
    $0 ~ "^"k"=" {print k"=\""v"\""; found=1; next}
    {print}
    END{ if(!found) print k"=\""v"\"" }
  ' "$BOT_ENV" > "$BOT_ENV.tmp" && mv "$BOT_ENV.tmp" "$BOT_ENV"
  chmod 600 "$BOT_ENV" 2>/dev/null || true
}

bot_set_token() {
  bot_env_ensure
  read -rp "Masukkan Bot Token: " token
  [[ -z "${token:-}" ]] && { echo -e "${R}Token kosong.${NC}"; return; }
  bot_write_kv "BOT_TOKEN" "$token"
  echo -e "${G}OK:${NC} Token tersimpan."
}

bot_add_admin_id() {
  bot_load
  read -rp "Masukkan User ID Admin (angka): " uid
  [[ -z "${uid:-}" ]] && { echo -e "${R}User ID kosong.${NC}"; return; }
  [[ "$uid" =~ ^[0-9]+$ ]] || { echo -e "${R}User ID harus angka.${NC}"; return; }

  local cur="${BOT_ADMIN_IDS:-}"
  if [[ -n "$cur" ]]; then
    if echo "$cur" | tr ',' '\n' | grep -qx "$uid"; then
      echo -e "${Y}INFO:${NC} User ID sudah ada."
      return
    fi
    cur="${cur},${uid}"
  else
    cur="$uid"
  fi
  bot_write_kv "BOT_ADMIN_IDS" "$cur"
  echo -e "${G}OK:${NC} Admin ID ditambahkan."
}

xzbot_is_installed() {
  systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "xzbot.service"
}

xzbot_status() {
  if ! xzbot_is_installed; then
    echo -e "${Y}INFO:${NC} xzbot.service belum terpasang (cek install.sh)."
    return
  fi
  local st
  st="$(systemctl is-active xzbot 2>/dev/null || true)"
  echo -e "Status xzbot: ${W}${st:-unknown}${NC}"
  systemctl status xzbot --no-pager -l 2>/dev/null || true
}

xzbot_start() {
  xzbot_is_installed || { echo -e "${Y}INFO:${NC} xzbot.service belum terpasang."; return; }
  systemctl enable xzbot 2>/dev/null || true
  systemctl restart xzbot 2>/dev/null || true
  echo -e "${G}OK:${NC} xzbot start/restart."
}

xzbot_stop() {
  xzbot_is_installed || { echo -e "${Y}INFO:${NC} xzbot.service belum terpasang."; return; }
  systemctl stop xzbot 2>/dev/null || true
  echo -e "${G}OK:${NC} xzbot stop."
}

xzbot_logs() {
  xzbot_is_installed || { echo -e "${Y}INFO:${NC} xzbot.service belum terpasang."; return; }
  echo -e "${C}Log xzbot (CTRL+C untuk keluar)${NC}"
  journalctl -u xzbot -f --no-pager
}

bot_can_run() {
  bot_load
  [[ -n "${BOT_TOKEN:-}" ]]
}

bot_offer_start() {
  if ! xzbot_is_installed; then
    echo -e "${Y}INFO:${NC} xzbot.service belum terpasang (akan dipasang oleh install.sh)."
    return
  fi
  if bot_can_run; then
    read -rp "Token sudah terisi. Start/Restart xzbot sekarang? [y/N]: " yn
    case "${yn:-}" in
      y|Y) xzbot_start ;;
      *) echo -e "${DIM}Lewati.${NC}" ;;
    esac
  else
    echo -e "${Y}INFO:${NC} BOT_TOKEN masih kosong. Isi token dulu agar bot bisa jalan."
  fi
}

# =========================
# BACKUP / RESTORE
# =========================
backup_now() {
  local ts out tmpdir
  ts="$(date +"%Y%m%d-%H%M%S")"
  out="$BACKUP_DIR/xz-backup-$ts.tar.gz"
  tmpdir="$(mktemp -d)"
  mkdir -p "$tmpdir/xray" "$tmpdir/zivpn" "$tmpdir/manager"

  if dir_ok "$XRAY_DIR"; then
    cp -a "$XRAY_DIR/." "$tmpdir/xray/" 2>/dev/null || true
  elif file_ok "$XRAY_JSON"; then
    cp -a "$XRAY_JSON" "$tmpdir/xray/" 2>/dev/null || true
  fi

  if dir_ok "$ZIVPN_DIR"; then
    cp -a "$ZIVPN_DIR/." "$tmpdir/zivpn/" 2>/dev/null || true
  elif file_ok "$ZIVPN_JSON"; then
    cp -a "$ZIVPN_JSON" "$tmpdir/zivpn/" 2>/dev/null || true
  fi

  if file_ok "$EXPIRY_DB"; then
    cp -a "$EXPIRY_DB" "$tmpdir/manager/" 2>/dev/null || true
  fi

  tar -czf "$out" -C "$tmpdir" .
  rm -rf "$tmpdir"

  echo -e "${G}OK:${NC} Backup dibuat."
  echo -e "File: ${W}$out${NC}"
  echo -e "${Y}Isi:${NC} xray/  zivpn/  manager(expiry.db)"
  echo -e "${DIM}Catatan: bot.env tidak ikut backup.${NC}"
}

list_backups() {
  echo -e "${C}Backup tersedia di:${NC} ${W}$BACKUP_DIR${NC}"
  local files=()
  mapfile -t files < <(ls -1t "$BACKUP_DIR"/*.tar.gz 2>/dev/null || true)
  if ((${#files[@]} == 0)); then
    echo "- (belum ada backup)"
    return 0
  fi
  local i=1
  for f in "${files[@]}"; do
    echo " [$i] $(basename "$f")"
    ((i++))
    [[ $i -gt 20 ]] && break
  done
  return 0
}

restore_from() {
  local files=() pick f tmpdir
  mapfile -t files < <(ls -1t "$BACKUP_DIR"/*.tar.gz 2>/dev/null || true)

  echo -e "${C}RESTORE BACKUP${NC}"
  if ((${#files[@]} == 0)); then
    echo -e "${Y}INFO:${NC} Belum ada backup di $BACKUP_DIR"
    return 0
  fi

  echo -e "${C}Pilih backup:${NC}"
  local i=1
  for f in "${files[@]}"; do
    echo " [$i] $(basename "$f")"
    ((i++))
    [[ $i -gt 20 ]] && break
  done
  echo ""
  echo -e "${DIM}Ketik angka (contoh: 1) atau masukkan path/nama file .tar.gz${NC}"
  read -rp "Input: " pick
  [[ -z "${pick:-}" ]] && { echo -e "${R}Input kosong.${NC}"; return; }

  if [[ "$pick" =~ ^[0-9]+$ ]]; then
    local idx=$((pick-1))
    [[ $idx -ge 0 && $idx -lt ${#files[@]} ]] || { echo -e "${R}Index tidak valid.${NC}"; return; }
    f="${files[$idx]}"
  else
    # user input path / filename
    if [[ "$pick" == /* ]]; then
      f="$pick"
    else
      f="$BACKUP_DIR/$pick"
    fi
  fi

  [[ -f "$f" ]] || { echo -e "${R}File tidak ditemukan:${NC} $f"; return; }

  echo -e "${Y}WARNING:${NC} Restore akan menimpa data XRAY/ZIVPN/expiry.db dan restart service."
  read -rp "Lanjutkan restore? [y/N]: " yn
  case "${yn:-}" in
    y|Y) ;;
    *) echo -e "${DIM}Batal.${NC}"; return ;;
  esac

  tmpdir="$(mktemp -d)"
  tar -xzf "$f" -C "$tmpdir" >/dev/null 2>&1 || { echo -e "${R}Gagal extract backup.${NC}"; rm -rf "$tmpdir"; return; }

  mkdir -p "$XRAY_DIR" "$ZIVPN_DIR" "$MANAGER_DIR"
  [[ -d "$tmpdir/xray" ]] && cp -a "$tmpdir/xray/." "$XRAY_DIR/" 2>/dev/null || true
  [[ -d "$tmpdir/zivpn" ]] && cp -a "$tmpdir/zivpn/." "$ZIVPN_DIR/" 2>/dev/null || true
  if [[ -f "$tmpdir/manager/expiry.db" ]]; then
    cp -a "$tmpdir/manager/expiry.db" "$EXPIRY_DB" 2>/dev/null || true
    chmod 600 "$EXPIRY_DB" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"

  restart_xray || true
  restart_zivpn || true
  echo -e "${G}OK:${NC} Restore selesai dari $(basename "$f")."
}


# =========================
# AUTO DELETE EXPIRED ACCOUNTS
# - Uses expiry.db as source of truth
# - Tries to remove users from XRAY and ZIVPN configs (best-effort)
# - Designed to be safe: if format unknown, it won't delete blindly
# =========================

EXPIRY_CRON_FILE="${EXPIRY_CRON_FILE:-/etc/cron.d/xz-expiry-cleanup}"

today_epoch() { date -d "$(date +%F) 00:00:00" +%s 2>/dev/null || date +%s; }

# Parse expiry.db into tab-separated: name<TAB>exp_epoch<TAB>type
# Supported formats per-line (comments allowed with #):
# 1) name|YYYY-MM-DD|type
# 2) name,YYYY-MM-DD,type
# 3) type name YYYY-MM-DD
# 4) name YYYY-MM-DD type
# 5) name|epochSeconds|type
# If can't parse date -> skip line (safe)
parse_expiry_db() {
  [[ -f "$EXPIRY_DB" ]] || return 0
  awk '
    function trim(s){gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s); return s}
    function isdate(s){ return (s ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/) }
    function isepoch(s){ return (s ~ /^[0-9]{10,}$/) }

    function epoch_from_any(d,   cmd, out){
      d=trim(d)
      if(isepoch(d)){ return d+0 }               # epoch seconds
      if(isdate(d)){
        cmd="date -d \"" d " 00:00:00\" +%s 2>/dev/null"
        cmd | getline out
        close(cmd)
        if(out ~ /^[0-9]+$/) return out+0
      }
      return -1
    }

    function date_from_epoch(ep,   cmd, out){
      if(!(ep ~ /^[0-9]+$/)) return ""
      cmd="date -d \"@" ep "\" +%F 2>/dev/null"
      cmd | getline out
      close(cmd)
      if(isdate(out)) return out
      return ""
    }

    BEGIN{FS=""; OFS="\t"}
    /^[ \t]*#/ {next}
    /^[ \t]*$/ {next}
    {
      line=$0
      tag=""; name=""; dt=""; typ=""

      # Try split by | or ,
      n=split(line, a, /\||,/)
      if(n>=2){
        a1=trim(a[1]); a2=trim(a[2]); a3=(n>=3?trim(a[3]):"")
        # Support bot format: TAG|USER|YYYY-MM-DD
        if(n>=3 && (isdate(a3) || isepoch(a3))){
          typ=a1; name=a2; dt=a3
        } else {
          # Support legacy: name|date|type
          name=a1; dt=a2; typ=a3
        }
      } else {
        # whitespace-based patterns
        n=split(line, a, /[ \t]+/)
        if(n>=3){
          # type name date
          if(isdate(a[3]) || isepoch(a[3])){
            typ=trim(a[1]); name=trim(a[2]); dt=trim(a[3])
          } else if(isdate(a[2]) || isepoch(a[2])){
            # name date type?
            name=trim(a[1]); dt=trim(a[2]); typ=(n>=3?trim(a[3]):"")
          }
        }
      }

      ep=epoch_from_any(dt)
      if(name!="" && ep>0){
        dnorm = (isdate(dt)? dt : date_from_epoch(ep))
        if(dnorm=="") dnorm=dt
        print name, ep, typ, dnorm
      }
    }
  ' "$EXPIRY_DB" 2>/dev/null || true
}

xray_remove_user_by_email() {
  local email="$1"
  [[ -f "$XRAY_JSON" ]] || return 0
  command -v jq >/dev/null 2>&1 || { echo -e "${Y}INFO:${NC} jq belum ada, install..."; pkg_install_utility jq; }
  [[ -x "$(command -v jq)" ]] || return 0

  local tmp; tmp="$(mktemp)"
  jq --arg e "$email" '
    .inbounds = ((.inbounds // []) | map(
      if (.settings? and .settings.clients?) then
        .settings.clients = (.settings.clients | map(select((.email // "") != $e)))
      else . end
    ))
  ' "$XRAY_JSON" > "$tmp" 2>/dev/null && mv "$tmp" "$XRAY_JSON" || { rm -f "$tmp"; return 0; }
}

zivpn_remove_user_guess() {
  # Best-effort: remove by "name" match in common keys
  local name="$1"
  [[ -f "$ZIVPN_JSON" ]] || return 0
  command -v jq >/dev/null 2>&1 || { echo -e "${Y}INFO:${NC} jq belum ada, install..."; pkg_install_utility jq; }
  [[ -x "$(command -v jq)" ]] || return 0

  local tmp; tmp="$(mktemp)"
  # Try common structures: .users[], .clients[], .accounts[]
  jq --arg n "$name" '
    def rm_from(key):
      if (.[key]? and (.[key] | type) == "array") then
        .[key] = (.[key] | map(
          if (type=="object") then
            select(((.name // .username // .email // "") != $n))
          else
            select(. != $n)
          end
        ))
      else . end;

    rm_from("users")
    | rm_from("clients")
    | rm_from("accounts")
  ' "$ZIVPN_JSON" > "$tmp" 2>/dev/null && mv "$tmp" "$ZIVPN_JSON" || { rm -f "$tmp"; return 0; }
}

cleanup_expired_now() {
  need_deps
  local now; now="$(today_epoch)"
  local removed=0 kept=0 skipped=0 total=0

  echo -e "${C}AUTO HAPUS AKUN EXPIRED${NC}"
  echo -e "DB: ${W}$EXPIRY_DB${NC}"
  [[ -f "$EXPIRY_DB" ]] || { echo -e "${Y}INFO:${NC} expiry.db belum ada."; return 0; }

  local tmpdb; tmpdb="$(mktemp)"
  : > "$tmpdb"

  while IFS=$'	' read -r name expepoch typ datestr; do
    [[ -z "${name:-}" || -z "${expepoch:-}" ]] && continue
    total=$((total+1))
    # Ensure we have a YYYY-MM-DD to write back for bot compatibility
    if [[ -z "${datestr:-}" && "${expepoch:-}" =~ ^[0-9]+$ ]]; then
      datestr="$(date -d "@$expepoch" +%F 2>/dev/null || true)"
    fi
    if [[ "$expepoch" =~ ^[0-9]+$ ]] && (( expepoch <= now )); then
      echo -e "${Y}• Expired:${NC} ${W}${name}${NC} ${DIM}(type:${typ:-?})${NC}"
      # XRAY delete by email (most scripts store username/email in .email)
      xray_remove_user_by_email "$name" || true
      # ZIVPN best-effort
      zivpn_remove_user_guess "$name" || true
      removed=$((removed+1))
      # do NOT keep in db
    else
      # keep original line (as-is) by searching it in the db and writing minimal normalized format
      # normalize as: name|YYYY-MM-DD|type (if possible)
      # store epoch to avoid date parsing issues
      # Keep DB compatible with bot: TAG|USER|YYYY-MM-DD (or legacy: USER|YYYY-MM-DD|TAG)
      if [[ -n "${typ:-}" ]]; then
        echo "${typ}|${name}|${datestr:-}" >> "$tmpdb"
      else
        echo "${name}|${datestr:-}|${typ:-}" >> "$tmpdb"
      fi
      kept=$((kept+1))
    fi
  done < <(parse_expiry_db)

  if (( total == 0 )); then
    echo -e "${Y}INFO:${NC} Tidak ada entry valid di expiry.db (format tidak dikenali)."
    rm -f "$tmpdb"
    return 0
  fi

  # Replace DB with normalized content (epoch-based) safely
  cp -a "$EXPIRY_DB" "${EXPIRY_DB}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  cat "$tmpdb" > "$EXPIRY_DB"
  rm -f "$tmpdb"
  chmod 600 "$EXPIRY_DB" 2>/dev/null || true

  # Restart services to apply
  restart_xray || true
  restart_zivpn || true

  echo ""
  echo -e "${G}Selesai.${NC} Total:${W}$total${NC} | Dihapus:${W}$removed${NC} | Disimpan:${W}$kept${NC}"
  echo -e "${DIM}Catatan: Jika struktur config ZIVPN berbeda, penghapusan ZIVPN bisa tidak berefek (best-effort).${NC}"
}

enable_auto_cleanup_cron() {
  need_deps
  cat > "$EXPIRY_CRON_FILE" <<EOF
# Auto cleanup expired accounts (XZ Manager)
# Runs daily at 00:15
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Force DB path to match bot defaults (so utility + bot always read the same file)
EXPIRY_DB="/usr/local/etc/xz-manager/expiry.db"
XRAY_JSON="$XRAY_JSON"
ZIVPN_JSON="$ZIVPN_JSON"

15 0 * * * root bash -lc '/usr/local/sbin/xz-manager/utility.sh --cleanup-expired >>/var/log/xz-expiry-cleanup.log 2>&1'
EOF
  chmod 644 "$EXPIRY_CRON_FILE" 2>/dev/null || true
  systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || true
  echo -e "${G}OK:${NC} Auto hapus expired diaktifkan (cron harian 00:15)."
  echo -e "${DIM}Log: /var/log/xz-expiry-cleanup.log${NC}"
}

disable_auto_cleanup_cron() {
  rm -f "$EXPIRY_CRON_FILE" 2>/dev/null || true
  systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null || true
  echo -e "${G}OK:${NC} Auto hapus expired dimatikan."
}

menu_expired_accounts() {
  while true; do
    ui_header "EXPIRED AKUN"
    echo -e " ${Y}[1]${NC} 🧹 Hapus akun expired sekarang"
    echo -e " ${Y}[2]${NC} ⏱️  Aktifkan auto hapus (cron harian 00:15)"
    echo -e " ${Y}[3]${NC} 📴 Matikan auto hapus"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " x
    case "$x" in
      1) cleanup_expired_now; pause ;;
      2) enable_auto_cleanup_cron; pause ;;
      3) disable_auto_cleanup_cron; pause ;;
      0) cls; return 0 ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}



# =========================
# MENUS
# =========================
menu_bot() {
  while true; do
    ui_header "MENU UTILITY"
    bot_show
    echo ""
    if xzbot_is_installed; then
      echo -e " Service   : ${W}xzbot${NC} (status: ${Y}$(systemctl is-active xzbot 2>/dev/null || echo inactive)${NC})"
    else
      echo -e " Service   : ${Y}xzbot.service belum terpasang${NC}"
    fi

    echo ""
    echo " [1] Set Token Bot"
    echo " [2] Tambahkan User ID Admin"
    echo " [3] Start/Restart xzbot"
    echo " [4] Stop xzbot"
    echo " [5] Status xzbot"
    echo " [6] Lihat log xzbot (live)"
    echo -e " ${Y}[0]${NC} ↩️  Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) bot_set_token; bot_offer_start; pause ;;
      2) bot_add_admin_id; pause ;;
      3) if bot_can_run; then xzbot_start; else echo -e "${R}BOT_TOKEN masih kosong.${NC}"; fi; pause ;;
      4) xzbot_stop; pause ;;
      5) xzbot_status; pause ;;
      6) xzbot_logs ;;
      0) cls; return ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

# =========================
# DOMAIN / SSL / XRAY MODE
# =========================
DOMAIN_FILE="${DOMAIN_FILE:-/usr/local/etc/xray/domain}"
XRAY_CERT="${XRAY_CERT:-/usr/local/etc/xray/xray.crt}"
XRAY_KEY="${XRAY_KEY:-/usr/local/etc/xray/xray.key}"
REALITY_PRIV_FILE="${REALITY_PRIV_FILE:-/usr/local/etc/xray/reality.private}"
REALITY_PUB_FILE="${REALITY_PUB_FILE:-/usr/local/etc/xray/reality.public}"
REALITY_SHORTID_FILE="${REALITY_SHORTID_FILE:-/usr/local/etc/xray/reality.shortid}"
XRAY_SELFSIGN_CERT="${XRAY_SELFSIGN_CERT:-/usr/local/etc/xray/selfsigned.crt}"
XRAY_SELFSIGN_KEY="${XRAY_SELFSIGN_KEY:-/usr/local/etc/xray/selfsigned.key}"

pkg_install_utility() {
  local pkgs=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "${pkgs[@]}" >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${pkgs[@]}" >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${pkgs[@]}" >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${pkgs[@]}" >/dev/null 2>&1 || true
  fi
}

domain_get() {
  if [[ -f "$DOMAIN_FILE" ]]; then
    head -n1 "$DOMAIN_FILE" | tr -d ' \t\r\n'
  else
    echo ""
  fi
}

domain_set() {
  read -rp "Masukkan domain (A record harus ke IP VPS): " d
  d="${d// /}"
  [[ -z "$d" ]] && { echo -e "${Y}Batal.${NC}"; return 0; }
  mkdir -p "$(dirname "$DOMAIN_FILE")" /etc/xray /root >/dev/null 2>&1 || true
  echo "$d" > "$DOMAIN_FILE"
  echo "$d" > /etc/xray/domain 2>/dev/null || true
  echo "$d" > /root/domain 2>/dev/null || true
  echo -e "${G}OK:${NC} Domain tersimpan: ${W}$d${NC}"
}

nginx_write_default_with_ws() {
  mkdir -p /var/www/html >/dev/null 2>&1 || true
  cat >/var/www/html/index.html <<'EOF'
<!doctype html><html><head><meta charset="utf-8"><title>OK</title></head><body><h3>It works.</h3></body></html>
EOF
  if [[ -d /etc/nginx/sites-available ]]; then
    cat >/etc/nginx/sites-available/default <<'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  root /var/www/html;
  index index.html;

  # ACME challenge (Let's Encrypt)
  location ^~ /.well-known/acme-challenge/ {
    root /var/www/acme;
    allow all;
  }

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

  location / { try_files $uri $uri/ =404; }
}
EOF
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default >/dev/null 2>&1 || true
  fi
}

nginx_ensure() {
  if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${Y}INFO:${NC} nginx belum ada, install..."
    pkg_install_utility nginx
  fi
  nginx_write_default_with_ws
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl restart nginx >/dev/null 2>&1 || true
  echo -e "${G}OK:${NC} nginx aktif (port 80) + proxy WS /vless /vmess."
}

acme_issue_ssl() {
  local d
  d="$(domain_get)"
  [[ -z "$d" ]] && { echo -e "${R}Domain belum diset.${NC}"; return 1; }

  echo -e "${C}Issue/Renew SSL Let's Encrypt untuk:${NC} ${W}$d${NC}"
  pkg_install_utility socat openssl curl

  # Pastikan webroot untuk challenge ada
  mkdir -p /var/www/acme >/dev/null 2>&1 || true
  chmod -R 755 /var/www/acme >/dev/null 2>&1 || true

  # Pastikan nginx aktif dan punya lokasi acme-challenge
  nginx_ensure >/dev/null 2>&1 || true

  if [[ ! -d /root/.acme.sh ]]; then
    curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1 || { echo -e "${R}Gagal install acme.sh${NC}"; return 1; }
  fi

  /root/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

  # Webroot mode (stabil, tidak bentrok port 80)
  /root/.acme.sh/acme.sh --issue -d "$d" --webroot /var/www/acme -k ec-256 --force >/dev/null 2>&1 || {
    echo -e "${R}Gagal issue sertifikat. Pastikan A record domain benar & port 80 bisa diakses dari internet.${NC}"
    return 1
  }

  mkdir -p "$(dirname "$XRAY_CERT")" >/dev/null 2>&1 || true
  /root/.acme.sh/acme.sh --installcert -d "$d" --ecc \
    --fullchain-file "$XRAY_CERT" \
    --key-file "$XRAY_KEY" \
    --reloadcmd "systemctl reload nginx 2>/dev/null || true; systemctl restart xray 2>/dev/null || true" >/dev/null 2>&1 || {
      echo -e "${R}Gagal install cert ke path xray.${NC}"
      return 1
    }

  chmod 600 "$XRAY_KEY" >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true

  echo -e "${G}OK:${NC} SSL terpasang di:"
  echo -e " Cert: ${W}$XRAY_CERT${NC}"
  echo -e " Key : ${W}$XRAY_KEY${NC}"
}


reality_ensure() {
  mkdir -p "$(dirname "$REALITY_PRIV_FILE")" >/dev/null 2>&1 || true
  if [[ -s "$REALITY_PRIV_FILE" && -s "$REALITY_PUB_FILE" && -s "$REALITY_SHORTID_FILE" ]]; then
    return 0
  fi
  local xb
  xb="/usr/local/bin/xray"
  [[ -x "$xb" ]] || xb="$(command -v xray || true)"
  [[ -n "$xb" ]] && [[ -x "$xb" ]] || { echo -e "${R}xray binary tidak ditemukan.${NC}"; return 1; }

  local out priv pub sid
  out="$("$xb" x25519 2>/dev/null || true)"

  # support format baru (PrivateKey/Password) dan format lama (Private key/Public key)
  if echo "$out" | grep -q '^PrivateKey:'; then
    priv="$(echo "$out" | awk -F': ' '/^PrivateKey:/ {print $2; exit}')"
    pub="$(echo "$out"  | awk -F': ' '/^Password:/  {print $2; exit}')"
  else
    priv="$(echo "$out" | awk -F': ' '/Private key/ {print $2; exit}')"
    pub="$(echo "$out"  | awk -F': ' '/Public key/  {print $2; exit}')"
  fi

  [[ -n "$priv" && -n "$pub" ]] || { echo -e "${R}Gagal generate key REALITY.${NC}"; return 1; }

  sid="$(openssl rand -hex 4 2>/dev/null || echo "a1b2c3d4")"
  echo "$priv" >"$REALITY_PRIV_FILE"
  echo "$pub"  >"$REALITY_PUB_FILE"
  echo "$sid"  >"$REALITY_SHORTID_FILE"
  chmod 600 "$REALITY_PRIV_FILE" "$REALITY_SHORTID_FILE" >/dev/null 2>&1 || true
}


reality_show() {
  reality_ensure || return 1
  echo -e "${C}=== REALITY KEYS ===${NC}"
  echo -e "PublicKey: ${W}$(cat "$REALITY_PUB_FILE")${NC}"
  echo -e "ShortID  : ${W}$(cat "$REALITY_SHORTID_FILE")${NC}"
  echo -e "SNI      : ${W}www.cloudflare.com${NC} (atau cloudflare.com)"
  echo -e "FP       : ${W}chrome${NC}"
}

selfsigned_ensure() {
  mkdir -p "$(dirname "$XRAY_SELFSIGN_CERT")" >/dev/null 2>&1 || true
  if [[ -s "$XRAY_SELFSIGN_CERT" && -s "$XRAY_SELFSIGN_KEY" ]]; then
    return 0
  fi
  pkg_install_utility openssl
  openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
    -keyout "$XRAY_SELFSIGN_KEY" -out "$XRAY_SELFSIGN_CERT" \
    -subj "/CN=localhost" >/dev/null 2>&1 || { echo -e "${R}Gagal buat self-signed cert${NC}"; return 1; }
  chmod 600 "$XRAY_SELFSIGN_KEY" >/dev/null 2>&1 || true
}

xray_extract_clients_json() {
  local old="$1"
  jq -c '[.inbounds[]?|select(.protocol=="vmess")|.settings.clients[]?] | unique_by(.email)' "$old" 2>/dev/null || echo '[]'
  jq -c '[.inbounds[]?|select(.protocol=="vless")|.settings.clients[]?] | unique_by(.email)' "$old" 2>/dev/null || echo '[]'
  jq -c '[.inbounds[]?|select(.protocol=="trojan")|.settings.clients[]?] | unique_by(.email)' "$old" 2>/dev/null || echo '[]'
}

xray_inject_clients(){
  local cfg="$1" vmj="$2" vlj="$3" trj="$4"
  local tmp; tmp="$(mktemp)"
  jq --argjson vm "$vmj" --argjson vl "$vlj" --argjson tr "$trj" '
    .inbounds = (
      (.inbounds // []) | map(
        if .protocol=="vmess" then .settings.clients=$vm
        elif .protocol=="vless" then .settings.clients=$vl
        elif .protocol=="trojan" then .settings.clients=$tr
        else .
        end
      )
    )
  ' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
}

xray_write_template_domain(){
  reality_ensure || return 1
  nginx_ensure
  acme_issue_ssl || return 1
  local priv sid
  priv="$(cat "$REALITY_PRIV_FILE")"
  sid="$(cat "$REALITY_SHORTID_FILE")"

  cat >"$XRAY_JSON" <<EOF
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
}

xray_write_template_nodomain(){
  reality_ensure || return 1
  selfsigned_ensure || return 1
  local priv sid
  priv="$(cat "$REALITY_PRIV_FILE")"
  sid="$(cat "$REALITY_SHORTID_FILE")"
  cat >"$XRAY_JSON" <<EOF
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
}

xray_switch_mode(){
  [[ -f "$XRAY_JSON" ]] || { echo -e "${R}Config XRAY tidak ditemukan: $XRAY_JSON${NC}"; return 1; }
  local bak; bak="${XRAY_JSON}.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$XRAY_JSON" "$bak" >/dev/null 2>&1 || true

  local vmj vlj trj
  vmj="$(xray_extract_clients_json "$bak" | sed -n '1p')"
  vlj="$(xray_extract_clients_json "$bak" | sed -n '2p')"
  trj="$(xray_extract_clients_json "$bak" | sed -n '3p')"
  vmj="${vmj:-[]}" ; vlj="${vlj:-[]}" ; trj="${trj:-[]}"

  echo ""
  echo -e "${C}Pilih mode XRAY:${NC}"
  echo " [1] DOMAIN+SSL (443 fallback + 80 ws + reality 8444)"
  echo " [2] NO DOMAIN  (reality 443 + legacy 10001/10002/10003)"
  while true; do
  read -rp "Pilih [1/2/0] (Enter=Kembali): " c
  [[ -z "$c" || "$c" == "0" ]] && { echo -e "${Y}Batal.${NC}"; return 0; }
  case "$c" in
    1) xray_write_template_domain || { echo -e "${R}Gagal set mode DOMAIN.${NC}"; sleep 1; continue; } ; break ;;
    2) xray_write_template_nodomain || { echo -e "${R}Gagal set mode NO DOMAIN.${NC}"; sleep 1; continue; } ; break ;;
    *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
  esac
done

  xray_inject_clients "$XRAY_JSON" "$vmj" "$vlj" "$trj"

  systemctl restart xray >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1 || true
  echo -e "${G}OK:${NC} Mode XRAY berhasil diganti. Backup: ${W}$bak${NC}"
}

xray_show_ports(){
  echo -e "${C}=== INFO PORT XRAY (dari config.json) ===${NC}"
  if [[ -f "${XRAY_JSON}" ]]; then
    jq -r '
      (.inbounds // [])[]? |
      "proto=\(.protocol) port=\(.port) tag=\(.tag // "-") sec=\(.streamSettings.security // "none") net=\(.streamSettings.network // "tcp")"
    ' "${XRAY_JSON}" 2>/dev/null | awk 'NF' | sort -u || true
  else
    echo -e "${R}Config tidak ditemukan.${NC}"
  fi
}

menu_domain_ssl(){
  while true; do
    clear
    local d; d="$(domain_get)"
    echo -e "${C}=== DOMAIN / SSL ===${NC}"
    echo -e "Domain tersimpan : ${W}${d:-"(belum ada)"}${NC}"
    echo " [1] Set/ubah domain"
    echo " [2] Issue/Renew SSL Let's Encrypt (simpan ke xray.crt/key)"
    echo " [3] Install/Restart nginx + proxy WS (/vless /vmess di port 80)"
    echo " [4] Tampilkan info REALITY keys"
    echo -e " ${Y}[0]${NC} ↩️  Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) domain_set; pause ;;
      2) acme_issue_ssl; pause ;;
      3) nginx_ensure; pause ;;
      4) reality_show; pause ;;
      0) cls; return 0 ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}

menu_utility() {
  while true; do
    ui_header "MENU UTILITY"
    echo " [1] 🤖 Bot Telegram (set token/admin + kontrol xzbot)"
    echo -e " ${Y}[2]${NC} 🔄 Restart ZIVPN"
    echo -e " ${Y}[3]${NC} 🔄 Restart XRAY"
    echo -e " ${Y}[4]${NC} 💾 Backup (ZIVPN + XRAY + expiry)"
    echo -e " ${Y}[5]${NC} ♻️ Restore (ZIVPN + XRAY + expiry)"
    echo -e " ${Y}[6]${NC} 📦 Lihat daftar backup"
    echo -e " ${Y}[7]${NC} 🌐 Domain/SSL (nginx + letsencrypt + reality info)"
    echo -e " ${Y}[8]${NC} 🔀 Switch XRAY Mode (Domain 443+80 / No-domain Reality+legacy)"
    echo -e " ${Y}[9]${NC} 🧾 Info port XRAY (cek inbounds)"
    echo -e " ${Y}[10]${NC} ⏳ Expired Akun (hapus/auto hapus)"
    echo -e " ${Y}[0]${NC} ↩️ Kembali"
    read -rp "➤ Pilih menu : " c
    case "$c" in
      1) menu_bot ;;
      2) restart_zivpn; pause ;;
      3) restart_xray; pause ;;
      4) backup_now; pause ;;
      5) restore_from; pause ;;
      6) list_backups; pause ;;
      7) menu_domain_ssl ;;
      8) xray_switch_mode; pause ;;
      9) xray_show_ports; pause ;;
      10) menu_expired_accounts ;;
      0) cls; return 0 ;;
      *) echo -e "${R}Pilihan tidak valid.${NC}"; sleep 1 ;;
    esac
  done
}


# CLI mode (non-interactive)
if [[ "${1:-}" == "--cleanup-expired" ]]; then
  cleanup_expired_now
  exit 0
fi

need_deps
menu_utility