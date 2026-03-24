#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XZ Manager Telegram Bot (polling)
- Menu: ZIVPN / VMESS / VLESS / TROJAN / UTILITY
- Semua pakai inline button (InlineKeyboardMarkup)
- Admin auth dari bot.env (BOT_ADMIN_IDS)
- Utility bot:
  - Info VPS (OS/RAM/CPU/Uptime/Domain/IP/ISP/City/Status service/Jumlah akun)
  - Restart/Status XRAY & ZIVPN
  - Backup now + Restore (pilih backup via tombol + konfirmasi)

Kebutuhan:
  pip install python-telegram-bot
"""

import os
import re
import json
import time
import shlex
import asyncio
import subprocess
import shutil
import base64
import secrets
from urllib.parse import quote, urlencode
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.constants import ParseMode
from html import escape as htmlesc

# =========================
# DEFAULT PATHS
# =========================
BOT_ENV = os.environ.get("BOT_ENV", "/usr/local/etc/xz-manager/bot.env")
EXPIRY_DB = os.environ.get("EXPIRY_DB", "/usr/local/etc/xz-manager/expiry.db")
EXPIRY_CRON_FILE = os.environ.get("EXPIRY_CRON_FILE", "/etc/cron.d/xz-expiry-cleanup")

XRAY_JSON = os.environ.get("XRAY_JSON", "/usr/local/etc/xray/config.json")
ZIVPN_JSON = os.environ.get("ZIVPN_JSON", "/etc/zivpn/config.json")

DOMAIN_FILE = os.environ.get("DOMAIN_FILE", "/usr/local/etc/xray/domain")

# domain/ssl/xray-mode (konsisten dengan utility.sh)
XRAY_CERT = os.environ.get("XRAY_CERT", "/usr/local/etc/xray/xray.crt")
XRAY_KEY = os.environ.get("XRAY_KEY", "/usr/local/etc/xray/xray.key")
REALITY_PRIV_FILE = os.environ.get("REALITY_PRIV_FILE", "/usr/local/etc/xray/reality.private")
REALITY_PUB_FILE = os.environ.get("REALITY_PUB_FILE", "/usr/local/etc/xray/reality.public")
REALITY_SHORTID_FILE = os.environ.get("REALITY_SHORTID_FILE", "/usr/local/etc/xray/reality.shortid")
XRAY_SELFSIGN_CERT = os.environ.get("XRAY_SELFSIGN_CERT", "/usr/local/etc/xray/selfsigned.crt")
XRAY_SELFSIGN_KEY = os.environ.get("XRAY_SELFSIGN_KEY", "/usr/local/etc/xray/selfsigned.key")


# backup
BACKUP_DIR = os.environ.get("BACKUP_DIR", "/root/xz-backup")
XRAY_DIR = os.environ.get("XRAY_DIR", "/usr/local/etc/xray")
ZIVPN_DIR = os.environ.get("ZIVPN_DIR", "/etc/zivpn")
MANAGER_DIR = os.environ.get("MANAGER_DIR", "/usr/local/etc/xz-manager")

# systemd services
SRV_XRAY = "xray"
SRV_ZIVPN = "zivpn"
SRV_NGINX = "nginx"
SRV_CRON = "cron"
SRV_XZBOT = "xzbot"

# expiry tags (konsisten dengan manager bash)
TAG_ZIVPN = "ZIVPN"
TAG_VMESS = "VMESS"
TAG_VLESS = "VLESS"
TAG_TROJAN = "TROJAN"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")


# =========================
# CHAT CLEANUP (hapus pesan bot sebelumnya)
# =========================
async def _delete_last_bot_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        chat = update.effective_chat
        if not chat:
            return
        last_id = context.user_data.get("last_bot_msg_id")
        if not last_id:
            return
        try:
            await context.bot.delete_message(chat_id=chat.id, message_id=int(last_id))
        except Exception:
            pass
        context.user_data.pop("last_bot_msg_id", None)
    except Exception:
        return




async def _try_delete_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, message_id: int) -> None:
    """Coba hapus message (abaikan error jika tidak punya izin / sudah terhapus)."""
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except Exception:
        return


async def delete_user_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Hapus pesan yang dikirim user (hanya berhasil jika Telegram mengizinkan).
    - Private chat: biasanya hanya bisa hapus pesan bot sendiri, jadi ini bisa gagal dan akan diabaikan.
    - Group/Supergroup: bisa hapus pesan user jika bot admin punya izin delete.
    """
    if not update.message:
        return
    chat = update.effective_chat
    if not chat:
        return
    await _try_delete_message(context, chat.id, update.message.message_id)

async def reply_clean(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, **kwargs):
    """Hapus pesan bot sebelumnya (jika ada), lalu kirim pesan baru dan simpan message_id-nya."""
    await _delete_last_bot_message(update, context)
    chat = update.effective_chat
    msg = await context.bot.send_message(chat_id=chat.id, text=text, **kwargs)
    context.user_data["last_bot_msg_id"] = msg.message_id
    return msg


def _track_last_bot_message_from_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Saat kita edit message (bukan kirim baru), tetap track message_id agar bisa dihapus saat user input berikutnya."""
    try:
        q = update.callback_query
        if q and q.message:
            context.user_data["last_bot_msg_id"] = q.message.message_id
    except Exception:
        pass


# =========================
# UTIL HELPERS
# =========================
def load_env(path: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not os.path.isfile(path):
        return env
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"').strip("'")
            env[k.strip()] = v
    return env


def parse_admin_ids(s: str) -> List[int]:
    out: List[int] = []
    for part in (s or "").split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out


def is_admin(user_id: int, admins: List[int]) -> bool:
    return user_id in set(admins)


def atomic_write(path: str, data: str) -> None:
    tmp = f"{path}.tmp.{int(time.time())}"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)


def run_cmd(cmd: List[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return p.returncode, (p.stdout or "").strip()
    except Exception as e:
        return 1, str(e)


def systemctl_restart(service: str) -> Tuple[int, str]:
    return run_cmd(["systemctl", "restart", service])


def systemctl_status(service: str) -> str:
    rc, out = run_cmd(["systemctl", "is-active", service])
    return out if rc == 0 else "inactive"


def systemctl_restart_checked(service: str) -> Tuple[bool, str]:
    rc, out = systemctl_restart(service)
    # beri jeda singkat agar systemd sempat update state service
    time.sleep(1)
    st = systemctl_status(service)
    if rc == 0 and st == "active":
        return True, f"✅ {service.upper()} direstart.\n📌 Status: {st}"

    detail = out.strip() or "restart gagal"
    return False, f"❌ Gagal restart {service.upper()}.\n📌 Status: {st}\n📝 Detail: {detail}"


def add_days_from_today(days: int) -> str:
    d = datetime.now() + timedelta(days=days)
    return d.strftime("%Y-%m-%d")


def is_valid_date_ymd(s: str) -> bool:
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except Exception:
        return False


def date_add_days_from(base_ymd: str, days: int) -> str:
    base = datetime.strptime(base_ymd, "%Y-%m-%d")
    return (base + timedelta(days=days)).strftime("%Y-%m-%d")


def gen_uuid() -> str:
    try:
        with open("/proc/sys/kernel/random/uuid", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        import uuid
        return str(uuid.uuid4())


def fmt_err(e: Exception) -> str:
    return f"{type(e).__name__}: {e}"


# =========================
# VPS INFO (UTILITY BOT)
# =========================
def read_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return (f.readline() or "").strip() or "-"
    except Exception:
        return "-"


def get_os_pretty() -> str:
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read()
        m = re.search(r'^PRETTY_NAME="?(.*?)"?$', txt, re.M)
        return m.group(1) if m else "Linux"
    except Exception:
        return "Linux"


def get_ram_total_mb() -> str:
    rc, out = run_cmd(["bash", "-lc", "free -m | awk '/Mem:/ {print $2}'"])
    return f"{out} MB" if rc == 0 and out.strip().isdigit() else "-"


def get_cpu_cores() -> str:
    rc, out = run_cmd(["bash", "-lc", "nproc 2>/dev/null || echo -"])
    return out.strip() or "-"


def get_uptime_pretty() -> str:
    rc, out = run_cmd(["bash", "-lc", "uptime -p 2>/dev/null | sed 's/^up //g'"])
    return out.strip() if rc == 0 and out.strip() else "-"


def fetch_ipinfo() -> Tuple[str, str, str]:
    """Best-effort: (ip, org, city) via ipinfo.io."""
    ip = org = city = "-"
    _, out = run_cmd(["bash", "-lc", "curl -fsS --max-time 3 https://ipinfo.io/ip 2>/dev/null || true"])
    if out.strip():
        ip = out.strip()
    _, out = run_cmd(["bash", "-lc", "curl -fsS --max-time 3 https://ipinfo.io/org 2>/dev/null || true"])
    if out.strip():
        org = out.strip()
    _, out = run_cmd(["bash", "-lc", "curl -fsS --max-time 3 https://ipinfo.io/city 2>/dev/null || true"])
    if out.strip():
        city = out.strip()
    return ip, org, city


def _fmt_bytes_bin(n: int) -> str:
    """Binary units similar to `free -h` (Ki/Mi/Gi...)."""
    try:
        n = int(n)
    except Exception:
        return "-"
    if n < 0:
        n = 0
    units = ["B", "Ki", "Mi", "Gi", "Ti", "Pi"]
    f = float(n)
    u = 0
    while f >= 1024.0 and u < len(units) - 1:
        f /= 1024.0
        u += 1
    # mimic free -h style: Mi usually integer; Gi may show 1 decimal for <10
    if units[u] in ("B", "Ki", "Mi"):
        val = f"{int(round(f))}"
    else:
        if f < 10:
            val = f"{f:.1f}".rstrip("0").rstrip(".")
        else:
            val = f"{int(round(f))}"
    return f"{val}{units[u]}"


def get_ram_usage_line() -> str:
    """Return: 'USED/TOTAL (PCT%)' using free -m."""
    # free -m outputs MiB integers on Ubuntu; we label as Mi to match UI.
    rc, outp = run_cmd(["bash", "-lc", "free -m | awk '/Mem:/ {print $2 \" \" $3 \" \" $7}'"])
    if rc != 0 or not outp.strip():
        return "-"
    parts = outp.split()
    if len(parts) < 3:
        return "-"
    try:
        total_m = int(parts[0]); used_m = int(parts[1]); avail_m = int(parts[2])
        pct = int(round((used_m / total_m) * 100)) if total_m > 0 else 0
        return f"{used_m}Mi/{total_m}Mi ({pct}%)"
    except Exception:
        return "-"


def get_cpu_usage_percent() -> str:
    """Return CPU usage percentage (0-100) computed from /proc/stat."""
    def read_cpu():
        with open("/proc/stat", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("cpu "):
                    nums = [int(x) for x in line.split()[1:]]
                    # idle = idle + iowait
                    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
                    total = sum(nums)
                    return total, idle
        return 0, 0

    try:
        t1, i1 = read_cpu()
        time.sleep(0.25)
        t2, i2 = read_cpu()
        dt = t2 - t1
        di = i2 - i1
        if dt <= 0:
            return "-"
        usage = (1.0 - (di / dt)) * 100.0
        usage = max(0.0, min(100.0, usage))
        val = int(round(usage))
        if 0 < usage < 1:
            return "<1%"
        return f"{val}%"
    except Exception:
        return "-"

# =========================
# LINK BUILDER (SEND AFTER CREATE)
# =========================
def read_domain_any() -> str:
    for p in [DOMAIN_FILE, "/etc/xray/domain", "/usr/local/etc/xray/domain", "/root/domain"]:
        d = read_first_line(p)
        if d and d != "-" and d.lower() not in ("null", "none"):
            return d.strip()
    return "-"


def get_public_ip_fast() -> str:
    # best-effort: ipinfo already used in fetch_ipinfo()
    ip, _, _ = fetch_ipinfo()
    if ip and ip != "-":
        return ip
    rc, out = run_cmd(["bash", "-lc", "curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true"])
    return out.strip() if out.strip() else "-"


def looks_like_domain(s: str) -> bool:
    if not s or s in ("-", "null", "none"):
        return False
    s = s.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s):
        return False
    return "." in s and " " not in s and len(s) >= 3


def xray_find_first_port(cfg: dict, proto: str) -> Optional[int]:
    for ib in xray_inbounds(cfg):
        if (ib or {}).get("protocol") != proto:
            continue
        try:
            p = int((ib or {}).get("port"))
            return p
        except Exception:
            continue
    return None


def xray_find_first_inbound(cfg: dict, proto: str, network: Optional[str] = None, security: Optional[str] = None) -> Optional[dict]:
    for ib in xray_inbounds(cfg):
        if (ib or {}).get("protocol") != proto:
            continue
        ss = (ib or {}).get("streamSettings") or {}
        ib_network = (ss.get("network") or "tcp").lower()
        ib_security = (ss.get("security") or "none").lower()
        if network is not None and ib_network != network.lower():
            continue
        if security is not None and ib_security != security.lower():
            continue
        return ib
    return None


def xray_ws_path(cfg: dict, proto: str, security: Optional[str] = None, default: str = "/") -> str:
    ib = xray_find_first_inbound(cfg, proto, network="ws", security=security)
    if not ib:
        return default
    ws = ((ib.get("streamSettings") or {}).get("wsSettings") or {})
    path = str(ws.get("path") or "").strip()
    return path or default


def xray_first_port_for(cfg: dict, proto: str, network: Optional[str] = None, security: Optional[str] = None, default: Optional[int] = None) -> Optional[int]:
    ib = xray_find_first_inbound(cfg, proto, network=network, security=security)
    if not ib:
        return default
    try:
        return int(ib.get("port"))
    except Exception:
        return default


def read_first_nonempty_line(*paths: str) -> str:
    for p in paths:
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    v = (f.readline() or "").strip()
                if v:
                    return v
        except Exception:
            continue
    return ""


def xray_find_reality(cfg: dict) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Return (port, sni, shortId, publicKey) best-effort."""
    for ib in xray_inbounds(cfg):
        if (ib or {}).get("protocol") != "vless":
            continue
        ss = (ib or {}).get("streamSettings") or {}
        if (ss.get("security") or "").lower() != "reality":
            continue
        port = None
        try:
            port = int((ib or {}).get("port"))
        except Exception:
            port = None

        rs = ss.get("realitySettings") or {}
        sni = None
        sns = rs.get("serverNames")
        if isinstance(sns, list) and sns:
            sni = str(sns[0]).strip() or None
        shortId = None
        sids = rs.get("shortIds")
        if isinstance(sids, list) and sids:
            shortId = str(sids[0]).strip() or None

        publicKey = read_first_nonempty_line(
            "/usr/local/etc/xray/reality.public",
            "/etc/xray/reality.public",
        ) or None
        if not publicKey:
            privateKey = (rs.get("privateKey") or "").strip()
            if privateKey:
                rc, out = run_cmd(["bash", "-lc", f"xray x25519 -i {shlex.quote(privateKey)} 2>/dev/null || true"])
                m = re.search(r"Public\s*key\s*:\s*([A-Za-z0-9_-]+)", out)
                if m:
                    publicKey = m.group(1).strip()

        return port, sni, shortId, publicKey
    return None, None, None, None


def vmess_uri(user: str, host: str, port: int, uuid: str, path: str, tls: bool) -> str:
    obj = {
        "v": "2",
        "ps": f"{user}-{'WS-TLS' if tls else 'WS'}",
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls" if tls else ""
    }
    if tls:
        obj["sni"] = host
    raw = json.dumps(obj, ensure_ascii=False)
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    return "vmess://" + b64


def vmess_tcp_uri(user: str, host: str, port: int, uuid: str, security: str = "none", sni: str = "") -> str:
    obj = {
        "v": "2",
        "ps": f"{user}-TCP",
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "net": "tcp",
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if security == "tls" else "",
    }
    if sni:
        obj["sni"] = sni
    raw = json.dumps(obj, ensure_ascii=False)
    b64 = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
    return "vmess://" + b64



def vless_ws_uri(user: str, host: str, port: int, uuid: str, path: str, tls: bool) -> str:
    q = {
        "encryption": "none",
        "type": "ws",
        "host": host,
        "path": path,
    }
    if tls:
        q["security"] = "tls"
        q["sni"] = host
    else:
        q["security"] = "none"
    return f"vless://{uuid}@{host}:{port}?{urlencode(q, quote_via=quote)}#{quote(user)}"



def vless_reality_uri(user: str, ip: str, port: int, uuid: str, sni: str, shortId: str, publicKey: Optional[str], flow: str = "xtls-rprx-vision") -> str:
    q = {
        "encryption": "none",
        "flow": flow,
        "security": "reality",
        "sni": sni or "www.cloudflare.com",
        "fp": "chrome",
        "type": "tcp",
    }
    if publicKey:
        q["pbk"] = publicKey
    if shortId:
        q["sid"] = shortId
    q["spx"] = "/"
    return f"vless://{uuid}@{ip}:{port}?{urlencode(q, quote_via=quote)}#{quote(user)}"



def trojan_uri(user: str, host: str, port: int, password: str, insecure: bool = False) -> str:
    q = {"security": "tls", "type": "tcp"}
    if insecure:
        q["allowInsecure"] = "1"
    return f"trojan://{password}@{host}:{port}?{urlencode(q, quote_via=quote)}#{quote(user)}"



def trojan_ws_uri(user: str, host: str, port: int, password: str, path: str) -> str:
    q = {
        "path": path,
        "security": "tls",
        "host": host,
        "type": "ws",
        "sni": host,
    }
    return f"trojan://{password}@{host}:{port}?{urlencode(q, quote_via=quote)}#{quote(user)}"



def trojan_grpc_uri(user: str, host: str, port: int, password: str, service_name: str) -> str:
    q = {
        "mode": "gun",
        "security": "tls",
        "type": "grpc",
        "serviceName": service_name,
        "sni": host,
    }
    return f"trojan://{password}@{host}:{port}?{urlencode(q, quote_via=quote)}#{quote(user)}"



def print_code_line(label: str, value: str) -> str:
    return f"<code>{htmlesc(label):<13}: {htmlesc(value)}</code>"



def build_account_message(proto: str, user: str, value: str, exp: str, mode: str = "create") -> str:
    domain = read_domain_any()
    ip = get_public_ip_fast()
    host = domain if looks_like_domain(domain) else (ip if ip != "-" else domain)
    mode_name = "domain" if looks_like_domain(domain) else "non-domain"

    def pre(s: str) -> str:
        return f"<pre>{htmlesc(s)}</pre>"

    if proto == "ZIVPN":
        try:
            zcfg = zivpn_load()
        except Exception:
            zcfg = {}
        zport = zivpn_port_from_cfg(zcfg)
        title = "ZIVPN Account"
        return (
            f"<b>{title}</b>\n"
            f"{print_code_line('User', user)}\n"
            f"{print_code_line('Exp', exp)}\n"
            f"{print_code_line('Server', host)}\n"
            f"{print_code_line('Port', str(zport))}"
        )

    try:
        xcfg = xray_load()
    except Exception:
        xcfg = {}

    lines: List[str] = [f"<b>{proto} Account</b>"]

    if proto == "VMESS":
        ws_tls_path = xray_ws_path(xcfg, "vmess", security="tls", default="")
        ws_none_path = xray_ws_path(xcfg, "vmess", security="none", default="")
        if not ws_tls_path:
            ws_tls_path = ws_none_path or "/vmess"
        if not ws_none_path:
            ws_none_path = ws_tls_path or "/vmess"

        tcp_ib = xray_find_first_inbound(xcfg, "vmess", network="tcp")
        tcp_port = ""
        tcp_link = ""
        if tcp_ib:
            ss = (tcp_ib.get("streamSettings") or {})
            security = (ss.get("security") or "none").lower()
            try:
                tcp_port = str(int(tcp_ib.get("port")))
            except Exception:
                tcp_port = ""
            tcp_host = host
            tcp_sni = ""
            if security == "tls" and looks_like_domain(domain):
                tcp_host = domain
                tcp_sni = domain
            elif not looks_like_domain(domain) and ip != "-":
                tcp_host = ip
            if tcp_port and tcp_host:
                tcp_link = vmess_tcp_uri(user, tcp_host, int(tcp_port), value, security=security, sni=tcp_sni)

        link_tls = ""
        link_ws = ""
        if looks_like_domain(domain):
            link_tls = vmess_uri(user, domain, 443, value, ws_tls_path, tls=True)
            link_ws = vmess_uri(user, domain, 80, value, ws_none_path, tls=False)
        elif ws_none_path and ip != "-":
            ws_port = xray_first_port_for(xcfg, "vmess", network="ws", security="none", default=80) or 80
            link_ws = vmess_uri(user, ip, ws_port, value, ws_none_path, tls=False)

        lines += [
            print_code_line("Mode", mode_name),
            print_code_line("User", user),
            print_code_line("UUID", value),
            print_code_line("Exp", exp),
            print_code_line("Server", host),
        ]
        if link_tls:
            lines.append(print_code_line("Path TLS", ws_tls_path))
        if link_ws:
            lines.append(print_code_line("Path WS", ws_none_path))
        if tcp_link and tcp_port:
            lines.append(print_code_line("Port TCP", tcp_port))
        if link_tls:
            lines += ["", "<b>VMESS WS TLS (publik 443) link:</b>", pre(link_tls)]
        if link_ws:
            label = "VMESS WS (publik 80) link:" if looks_like_domain(domain) else "VMESS WS link:"
            lines += ["", f"<b>{label}</b>", pre(link_ws)]
        if tcp_link:
            lines += ["", "<b>VMESS TCP link:</b>", pre(tcp_link)]
        return "\n".join(lines)

    if proto == "VLESS":
        ws_tls_path = xray_ws_path(xcfg, "vless", security="tls", default="")
        ws_none_path = xray_ws_path(xcfg, "vless", security="none", default="")
        if not ws_tls_path and ws_none_path:
            ws_tls_path = ws_none_path
        if not ws_tls_path:
            ws_tls_path = "/vless"
        if not ws_none_path:
            ws_none_path = ws_tls_path or "/vless"

        reality_ib = xray_find_first_inbound(xcfg, "vless", security="reality")
        reality_port, reality_sni, reality_sid, reality_pbk = xray_find_reality(xcfg)
        reality_flow = "xtls-rprx-vision"
        if reality_ib:
            clients = (((reality_ib.get("settings") or {}).get("clients") or []))
            if clients:
                reality_flow = str((clients[0] or {}).get("flow") or "xtls-rprx-vision")

        link_tls = ""
        link_ws = ""
        link_reality = ""
        if looks_like_domain(domain):
            link_tls = vless_ws_uri(user, domain, 443, value, ws_tls_path, tls=True)
            link_ws = vless_ws_uri(user, domain, 80, value, ws_none_path, tls=False)
        elif ws_none_path and ip != "-":
            ws_port = xray_first_port_for(xcfg, "vless", network="ws", security="none", default=80) or 80
            link_ws = vless_ws_uri(user, ip, ws_port, value, ws_none_path, tls=False)

        if reality_port and ip != "-" and reality_pbk:
            link_reality = vless_reality_uri(user, ip, int(reality_port), value, reality_sni or "www.cloudflare.com", reality_sid or "", reality_pbk, flow=reality_flow)

        lines += [
            print_code_line("Mode", mode_name),
            print_code_line("User", user),
            print_code_line("UUID", value),
            print_code_line("Exp", exp),
            print_code_line("Server", host),
        ]
        if link_tls:
            lines.append(print_code_line("Path TLS", ws_tls_path))
        if link_ws:
            lines.append(print_code_line("Path WS", ws_none_path))
        if link_reality and reality_port:
            lines.append(print_code_line("Port REALITY", str(reality_port)))
        if link_reality and reality_sni:
            lines.append(print_code_line("SNI REALITY", reality_sni))
        if link_reality and reality_flow:
            lines.append(print_code_line("Flow REALITY", reality_flow))
        if link_reality and reality_pbk:
            lines.append(print_code_line("Public Key", reality_pbk))
        if link_reality and reality_sid:
            lines.append(print_code_line("Short ID", reality_sid))
        if link_reality:
            lines += ["", "<b>VLESS REALITY link:</b>", pre(link_reality)]
        if link_tls:
            lines += ["", "<b>VLESS WS TLS link:</b>", pre(link_tls)]
        if link_ws:
            lines += ["", "<b>VLESS WS link:</b>", pre(link_ws)]
        return "\n".join(lines)

    if proto == "TROJAN":
        ws_path = xray_ws_path(xcfg, "trojan", security="tls", default="/trojan-ws")
        grpc_ib = xray_find_first_inbound(xcfg, "trojan", network="grpc")
        grpc_service = "trojan-grpc"
        grpc_port = None
        if grpc_ib:
            grpc_service = str(((((grpc_ib.get("streamSettings") or {}).get("grpcSettings") or {}).get("serviceName")) or grpc_service))
            try:
                grpc_port = int(grpc_ib.get("port"))
            except Exception:
                grpc_port = None
        ws_ib = xray_find_first_inbound(xcfg, "trojan", network="ws")
        ws_port = None
        if ws_ib:
            try:
                ws_port = int(ws_ib.get("port"))
            except Exception:
                ws_port = None
        if ws_port is None:
            ws_port = xray_find_first_port(xcfg, "trojan") or 443
        if grpc_port is None:
            grpc_port = ws_port

        lines += [
            print_code_line("Mode", mode_name),
            print_code_line("User", user),
            print_code_line("Pass", value),
            print_code_line("Exp", exp),
            print_code_line("Server", host),
        ]

        if looks_like_domain(domain):
            ws_link = trojan_ws_uri(user, domain, int(ws_port), value, ws_path)
            grpc_link = trojan_grpc_uri(user, domain, int(grpc_port), value, grpc_service)
            lines += ["", "<b>TROJAN WS link:</b>", pre(ws_link), "", "<b>TROJAN gRPC link:</b>", pre(grpc_link)]
        else:
            direct_host = ip if ip != "-" else host
            direct_link = trojan_uri(user, direct_host, int(ws_port), value, insecure=True)
            lines += ["", "<b>TROJAN direct link:</b>", pre(direct_link)]
        return "\n".join(lines)

    return f"<b>{htmlesc(proto)} Account</b>"


def build_account_detail_message(proto: str, user: str, value: str, exp: str) -> str:
    """Futuristic detail view (includes links for VMESS/VLESS/TROJAN)."""
    return build_account_message(proto, user, value, exp, mode="detail")
# =========================
# EXPIRY DB: TAG|USER|YYYY-MM-DD
# =========================
def expiry_get(tag: str, user: str) -> str:
    if not os.path.isfile(EXPIRY_DB):
        return "-"
    last = "-"
    with open(EXPIRY_DB, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) != 3:
                continue
            t, u, exp = parts
            if t == tag and u == user:
                last = exp
    return last or "-"


def expiry_set(tag: str, user: str, exp: str) -> None:
    os.makedirs(os.path.dirname(EXPIRY_DB), exist_ok=True)
    lines: List[str] = []
    if os.path.isfile(EXPIRY_DB):
        with open(EXPIRY_DB, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) == 3 and parts[0] == tag and parts[1] == user:
                    continue
                lines.append(line)
    lines.append(f"{tag}|{user}|{exp}")
    atomic_write(EXPIRY_DB, "\n".join(lines) + "\n")
    try:
        os.chmod(EXPIRY_DB, 0o600)
    except Exception:
        pass


def expiry_del(tag: str, user: str) -> None:
    if not os.path.isfile(EXPIRY_DB):
        return
    lines: List[str] = []
    with open(EXPIRY_DB, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("|")
            if len(parts) == 3 and parts[0] == tag and parts[1] == user:
                continue
            lines.append(line)
    atomic_write(EXPIRY_DB, "\n".join(lines) + ("\n" if lines else ""))
    try:
        os.chmod(EXPIRY_DB, 0o600)
    except Exception:
        pass

# =========================
# EXPIRED CLEANUP (UTILITY)
# =========================
def cron_expiry_is_enabled() -> bool:
    return os.path.isfile(EXPIRY_CRON_FILE)

def cron_expiry_enable() -> None:
    # run daily at 00:15 as root
    content = (
        "# Auto cleanup expired accounts (XZ Manager)\n"
        "SHELL=/bin/bash\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "15 0 * * * root bash -lc '/usr/local/sbin/xz-manager/utility.sh --cleanup-expired >/dev/null 2>&1'\n"
    )
    os.makedirs(os.path.dirname(EXPIRY_CRON_FILE), exist_ok=True)
    atomic_write(EXPIRY_CRON_FILE, content)
    try:
        os.chmod(EXPIRY_CRON_FILE, 0o644)
    except Exception:
        pass
    # restart cron best-effort
    systemctl_restart(SRV_CRON)

def cron_expiry_disable() -> None:
    try:
        if os.path.isfile(EXPIRY_CRON_FILE):
            os.remove(EXPIRY_CRON_FILE)
    except Exception:
        pass
    systemctl_restart(SRV_CRON)

def expiry_cleanup_now() -> Tuple[int, List[str]]:
    """
    Remove expired accounts based on EXPIRY_DB format TAG|USER|YYYY-MM-DD.
    Returns (removed_count, removed_users).
    """
    ensure_dirs()
    removed_users: List[str] = []
    today = datetime.now().strftime("%Y-%m-%d")

    # read db
    entries: List[Tuple[str, str, str]] = []
    if os.path.isfile(EXPIRY_DB):
        with open(EXPIRY_DB, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) != 3:
                    continue
                t, u, exp = parts
                t = (t or "").strip()
                u = (u or "").strip()
                exp = (exp or "").strip()
                if not (t and u and is_valid_date_ymd(exp)):
                    continue
                entries.append((t, u, exp))

    # separate keep vs expired
    keep: List[str] = []
    expired: List[Tuple[str, str, str]] = []
    for t, u, exp in entries:
        if exp <= today:
            expired.append((t, u, exp))
        else:
            keep.append(f"{t}|{u}|{exp}")

    if not expired:
        return 0, []

    # delete from services
    need_restart_xray = False
    need_restart_zivpn = False

    # preload configs (best-effort)
    xcfg = None
    zcfg = None
    try:
        xcfg = xray_load()
    except Exception:
        xcfg = None
    try:
        zcfg = zivpn_load()
    except Exception:
        zcfg = None

    for t, u, exp in expired:
        try:
            if t.upper() == TAG_ZIVPN:
                if zcfg is not None:
                    if zivpn_exists(zcfg, u):
                        zivpn_del_user(zcfg, u)
                        need_restart_zivpn = True
            elif t.upper() in (TAG_VMESS, TAG_VLESS, TAG_TROJAN):
                if xcfg is not None:
                    xproto = t.lower()
                    if xray_user_exists(xcfg, xproto, u):
                        xray_del_user_all_inbounds(xcfg, xproto, u)
                        need_restart_xray = True
            # always remove expiry record
            removed_users.append(u)
        except Exception:
            # ignore per-user errors
            continue

    # save configs
    try:
        if need_restart_zivpn and zcfg is not None:
            zivpn_save(zcfg)
    except Exception:
        pass
    try:
        if need_restart_xray and xcfg is not None:
            xray_save(xcfg)
    except Exception:
        pass

    # rewrite expiry db with kept lines
    atomic_write(EXPIRY_DB, ("\n".join(keep) + ("\n" if keep else "")))

    # restart services
    if need_restart_zivpn:
        systemctl_restart(SRV_ZIVPN)
    if need_restart_xray:
        systemctl_restart(SRV_XRAY)

    return len(removed_users), removed_users




# =========================
# JSON HELPERS
# =========================
def read_json(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def write_json(path: str, obj: dict) -> None:
    atomic_write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


# =========================
# ZIVPN ACCOUNTS (FIX: auth.config)
# =========================
def zivpn_normalize(cfg: dict) -> Tuple[dict, bool]:
    """Pastikan schema ZIVPN konsisten:
    - daftar akun/password berada di auth.config (list of str)
    - hapus key legacy auth.password jika ada
    Return: (cfg, changed)
    """
    changed = False
    auth = cfg.setdefault("auth", {}) or {}
    cfg_list = auth.get("config", [])
    pwd_list = auth.get("password", [])

    merged: List[str] = []
    if isinstance(cfg_list, list):
        merged += [str(x).strip() for x in cfg_list if str(x).strip()]
    else:
        changed = True

    if isinstance(pwd_list, list) and pwd_list:
        merged += [str(x).strip() for x in pwd_list if str(x).strip()]
        changed = True  # pindah password -> config

    merged = sorted(set(merged))
    if auth.get("config") != merged:
        auth["config"] = merged
        changed = True

    if "password" in auth:
        auth.pop("password", None)
        changed = True

    cfg["auth"] = auth
    return cfg, changed


def zivpn_load() -> dict:
    if not os.path.isfile(ZIVPN_JSON):
        raise FileNotFoundError(f"ZIVPN config tidak ditemukan: {ZIVPN_JSON}")
    with open(ZIVPN_JSON, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    # migrasi schema lama (auth.password) -> schema benar (auth.config)
    cfg, changed = zivpn_normalize(cfg)
    if changed:
        zivpn_save(cfg)
    return cfg


def zivpn_save(cfg: dict) -> None:
    atomic_write(ZIVPN_JSON, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")


def zivpn_list_users(cfg: dict) -> List[str]:
    cfg, _ = zivpn_normalize(cfg)
    return list((cfg.get("auth", {}) or {}).get("config", []) or [])


def zivpn_exists(cfg: dict, user: str) -> bool:
    return user in set(zivpn_list_users(cfg))


def zivpn_add_user(cfg: dict, user: str) -> None:
    cfg, _ = zivpn_normalize(cfg)
    auth = cfg.setdefault("auth", {})
    arr = auth.get("config", [])
    if not isinstance(arr, list):
        arr = []
    arr = sorted(set([x for x in arr if isinstance(x, str)] + [user]))
    auth["config"] = arr
    # pastikan key legacy tidak ada
    auth.pop("password", None)


def zivpn_del_user(cfg: dict, user: str) -> None:
    cfg, _ = zivpn_normalize(cfg)
    auth = cfg.setdefault("auth", {})
    arr = auth.get("config", [])
    if not isinstance(arr, list):
        arr = []
    auth["config"] = [x for x in arr if x != user]
    auth.pop("password", None)


# =========================
# XRAY JSON HELPERS
# =========================
def xray_load() -> dict:
    if not os.path.isfile(XRAY_JSON):
        raise FileNotFoundError(f"XRAY config tidak ditemukan: {XRAY_JSON}")
    with open(XRAY_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def xray_save(cfg: dict) -> None:
    atomic_write(XRAY_JSON, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")


def xray_inbounds(cfg: dict) -> List[dict]:
    ib = cfg.get("inbounds", [])
    if not isinstance(ib, list):
        return []
    return ib


def xray_has_proto(cfg: dict, proto: str) -> bool:
    for i in xray_inbounds(cfg):
        if (i or {}).get("protocol") == proto:
            return True
    return False


def xray_list_clients(cfg: dict, proto: str) -> Dict[str, str]:
    """Return dict email->id/password."""
    out: Dict[str, str] = {}
    for i in xray_inbounds(cfg):
        if (i or {}).get("protocol") != proto:
            continue
        st = (i or {}).get("settings") or {}
        clients = st.get("clients", [])
        if not isinstance(clients, list):
            continue
        for c in clients:
            email = (c or {}).get("email")
            if not email:
                continue
            if proto == "trojan":
                val = (c or {}).get("password", "-")
            else:
                val = (c or {}).get("id", "-")
            out[email] = val
    return out


def xray_user_exists(cfg: dict, proto: str, user: str) -> bool:
    return user in set(xray_list_clients(cfg, proto).keys())


def xray_add_user_all_inbounds(cfg: dict, proto: str, user: str, value: str) -> None:
    ib = xray_inbounds(cfg)
    for i in ib:
        if i.get("protocol") != proto:
            continue
        st = i.setdefault("settings", {})
        clients = st.get("clients", [])
        if not isinstance(clients, list):
            clients = []

        if proto == "trojan":
            clients.append({"password": value, "email": user})
        elif proto == "vmess":
            clients.append({"id": value, "alterId": 0, "email": user})
        else:  # vless
            clients.append({"id": value, "email": user})

        # unique by email
        seen = set()
        uniq = []
        for c in clients:
            em = (c or {}).get("email")
            if not em or em in seen:
                continue
            seen.add(em)
            uniq.append(c)
        st["clients"] = uniq
    cfg["inbounds"] = ib


def xray_del_user_all_inbounds(cfg: dict, proto: str, user: str) -> None:
    ib = xray_inbounds(cfg)
    for i in ib:
        if i.get("protocol") != proto:
            continue
        st = i.get("settings") or {}
        clients = st.get("clients", [])
        if not isinstance(clients, list):
            clients = []
        st["clients"] = [c for c in clients if (c or {}).get("email") != user]
    cfg["inbounds"] = ib


# =========================
# BACKUP / RESTORE
# =========================
def ensure_dirs() -> None:
    os.makedirs(MANAGER_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.isfile(EXPIRY_DB):
        atomic_write(EXPIRY_DB, "")
    try:
        os.chmod(EXPIRY_DB, 0o600)
    except Exception:
        pass


def prune_backups(keep: int = 2) -> None:
    """Keep only the newest N backups in BACKUP_DIR (both folder and .tar.gz)."""
    try:
        if keep < 1:
            keep = 1
        if not os.path.isdir(BACKUP_DIR):
            return

        # Backup folders are named backup-YYYYmmdd-HHMMSS (sortable lexicographically)
        folders = []
        for n in os.listdir(BACKUP_DIR):
            p = os.path.join(BACKUP_DIR, n)
            if n.startswith("backup-") and os.path.isdir(p):
                folders.append(n)
        folders = sorted(folders)
        keep_set = set(folders[-keep:]) if folders else set()

        # Remove old folders + their archives
        for n in folders[:-keep]:
            p = os.path.join(BACKUP_DIR, n)
            try:
                shutil.rmtree(p, ignore_errors=True)
            except Exception:
                pass
            try:
                a = os.path.join(BACKUP_DIR, f"{n}.tar.gz")
                if os.path.isfile(a):
                    os.remove(a)
            except Exception:
                pass

        # Remove orphan/old archives not in keep_set
        for n in os.listdir(BACKUP_DIR):
            if n.startswith("backup-") and n.endswith(".tar.gz"):
                base = n[:-7]  # strip .tar.gz
                if base not in keep_set:
                    try:
                        os.remove(os.path.join(BACKUP_DIR, n))
                    except Exception:
                        pass
    except Exception:
        return


def backup_make() -> str:
    ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"backup-{ts}"
    dst = os.path.join(BACKUP_DIR, name)
    os.makedirs(dst, exist_ok=True)

    # copy files/dirs (best effort)
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(XRAY_DIR)} {shlex.quote(dst)}/xray 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(ZIVPN_DIR)} {shlex.quote(dst)}/zivpn 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(MANAGER_DIR)} {shlex.quote(dst)}/manager 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(EXPIRY_DB)} {shlex.quote(dst)}/expiry.db 2>/dev/null || true"])

    return name

def backup_pack(name: str) -> str:
    """Create a tar.gz archive for a backup folder and return the archive path."""
    ensure_dirs()
    src_dir = os.path.join(BACKUP_DIR, name)
    if not os.path.isdir(src_dir):
        raise FileNotFoundError(src_dir)

    archive = os.path.join(BACKUP_DIR, f"{name}.tar.gz")
    # Create archive with stable relative paths
    run_cmd(["bash", "-lc", f"tar -czf {shlex.quote(archive)} -C {shlex.quote(BACKUP_DIR)} {shlex.quote(name)} 2>/dev/null"])
    prune_backups(keep=2)
    return archive


def backup_list() -> List[str]:
    if not os.path.isdir(BACKUP_DIR):
        return []
    items = []
    for n in sorted(os.listdir(BACKUP_DIR)):
        p = os.path.join(BACKUP_DIR, n)
        if os.path.isdir(p) and n.startswith("backup-"):
            items.append(n)
    return items


def backup_restore(name: str) -> str:
    src = os.path.join(BACKUP_DIR, name)
    if not os.path.isdir(src):
        return "❌ Backup tidak ditemukan."

    # restore best effort
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(src)}/xray/* {shlex.quote(XRAY_DIR)}/ 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(src)}/zivpn/* {shlex.quote(ZIVPN_DIR)}/ 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(src)}/manager/* {shlex.quote(MANAGER_DIR)}/ 2>/dev/null || true"])
    run_cmd(["bash", "-lc", f"cp -a {shlex.quote(src)}/expiry.db {shlex.quote(EXPIRY_DB)} 2>/dev/null || true"])

    systemctl_restart(SRV_XRAY)
    systemctl_restart(SRV_ZIVPN)
    return f"✅ Restore selesai: {name}"


# =========================
# OPS (LIST/ADD/DEL/EXT)
# =========================
def op_list(proto: str) -> str:
    """
    List akun: hanya username + exp, plus keterangan jumlah akun.
    (Plain text supaya aman untuk edit_message_text tanpa parse_mode)
    """
    try:
        ico = ICON_PROTO.get(proto, "🔹")
        header = f"⟦ 📋 {ico} {proto} • LIST AKUN ⟧\n{FUTURISTIC_LINE}"
        if proto == "ZIVPN":
            cfg = zivpn_load()
            users = zivpn_list_users(cfg)
            if not users:
                return f"{header}\n👥 Jumlah akun: 0\n\n— Belum ada akun —"
            lines = []
            for u in users:
                exp = expiry_get(TAG_ZIVPN, u) or "-"
                lines.append(f"👤 {u}  ⏳ {exp}")
            return f"{header}\n👥 Jumlah akun: {len(users)}\n\n" + "\n\n".join(lines)

        cfg = xray_load()
        xproto = proto.lower()
        if not xray_has_proto(cfg, xproto):
            return f"{header}\n⚠️ Inbound {proto} belum ada di XRAY config."
        items = xray_list_clients(cfg, xproto)  # {user: uuid/pass}
        if not items:
            return f"{header}\n👥 Jumlah akun: 0\n\n— Belum ada akun —"
        users = sorted(items.keys())
        lines = []
        for u in users:
            exp = expiry_get(proto, u) or "-"
            lines.append(f"👤 {u}  ⏳ {exp}")
        return f"{header}\n👥 Jumlah akun: {len(users)}\n\n" + "\n\n".join(lines)

    except Exception as e:
        return f"❌ Error list: {fmt_err(e)}"


def op_view(proto: str, user: str) -> str:
    """Lihat detail akun berdasarkan username. Untuk VMESS/VLESS/TROJAN akan menyertakan link."""
    if not USERNAME_RE.match(user):
        return "❌ Username tidak valid. Gunakan a-zA-Z0-9_"
    try:
        if proto == "ZIVPN":
            cfg = zivpn_load()
            if not zivpn_exists(cfg, user):
                return "❌ Akun tidak ditemukan."
            exp = expiry_get(TAG_ZIVPN, user) or "-"
            return build_account_detail_message("ZIVPN", user, user, exp)

        cfg = xray_load()
        xproto = proto.lower()
        if not xray_has_proto(cfg, xproto):
            return f"❌ Inbound {proto} belum ada di XRAY config."
        items = xray_list_clients(cfg, xproto)
        if user not in items:
            return "❌ Akun tidak ditemukan."
        value = items.get(user) or "-"
        exp = expiry_get(proto, user) or "-"
        return build_account_detail_message(proto, user, value, exp)
    except Exception as e:
        return f"❌ Error lihat akun: {fmt_err(e)}"
def op_add(proto: str, user: str, days: int) -> str:
    if not USERNAME_RE.match(user):
        return "❌ Username tidak valid. Gunakan a-zA-Z0-9_"
    if days <= 0:
        return "❌ Jumlah hari harus > 0"

    try:
        if proto == "ZIVPN":
            cfg = zivpn_load()
            if zivpn_exists(cfg, user):
                return "❌ Akun sudah ada."
            zivpn_add_user(cfg, user)
            zivpn_save(cfg)
            exp = add_days_from_today(days)
            expiry_set(TAG_ZIVPN, user, exp)
            systemctl_restart(SRV_ZIVPN)
            return build_account_message("ZIVPN", user, user, exp)

        cfg = xray_load()
        xproto = proto.lower()
        if not xray_has_proto(cfg, xproto):
            return f"❌ Inbound {proto} belum ada di XRAY config."
        if xray_user_exists(cfg, xproto, user):
            return "❌ Akun sudah ada."

        value = gen_uuid()  # trojan: random password (uuid)
        xray_add_user_all_inbounds(cfg, xproto, user, value)
        xray_save(cfg)
        exp = add_days_from_today(days)
        expiry_set(proto, user, exp)
        systemctl_restart(SRV_XRAY)
        return build_account_message(proto, user, value, exp)
    except Exception as e:
        return f"❌ Error add: {fmt_err(e)}"


def op_del(proto: str, user: str) -> str:
    if not USERNAME_RE.match(user):
        return "❌ Username tidak valid. Gunakan a-zA-Z0-9_"

    try:
        ico = ICON_PROTO.get(proto, "🔹")
        if proto == "ZIVPN":
            cfg = zivpn_load()
            if not zivpn_exists(cfg, user):
                return "❌ Akun tidak ditemukan."
            zivpn_del_user(cfg, user)
            zivpn_save(cfg)
            expiry_del(TAG_ZIVPN, user)
            systemctl_restart(SRV_ZIVPN)
            return (
                f"✅ 🗑️ {ico} ZIVPN • DELETE OK\n"
                f"{FUTURISTIC_LINE}\n"
                f"👤 User : {user}"
            )

        cfg = xray_load()
        xproto = proto.lower()
        if not xray_has_proto(cfg, xproto):
            return f"❌ Inbound {proto} belum ada."
        if not xray_user_exists(cfg, xproto, user):
            return "❌ Akun tidak ditemukan."
        xray_del_user_all_inbounds(cfg, xproto, user)
        xray_save(cfg)
        expiry_del(proto, user)
        systemctl_restart(SRV_XRAY)
        return (
            f"✅ 🗑️ {ico} {proto} • DELETE OK\n"
            f"{FUTURISTIC_LINE}\n"
            f"👤 User : {user}"
        )

    except Exception as e:
        return f"❌ Error delete: {fmt_err(e)}"


def op_ext(proto: str, user: str, days: int) -> str:
    if not USERNAME_RE.match(user):
        return "❌ Username tidak valid. Gunakan a-zA-Z0-9_"
    if days <= 0:
        return "❌ Jumlah hari harus > 0"

    try:
        ico = ICON_PROTO.get(proto, "🔹")
        if proto == "ZIVPN":
            cfg = zivpn_load()
            if not zivpn_exists(cfg, user):
                return "❌ Akun tidak ditemukan."
            cur = expiry_get(TAG_ZIVPN, user)
            if cur != "-" and is_valid_date_ymd(cur):
                newexp = date_add_days_from(cur, days)
            else:
                newexp = add_days_from_today(days)
            expiry_set(TAG_ZIVPN, user, newexp)
            return (
                f"✅ ⏳ {ico} ZIVPN • EXTEND OK\n"
                f"{FUTURISTIC_LINE}\n"
                f"👤 User : {user}\n"
                f"📆 Exp  : {newexp}"
            )

        cfg = xray_load()
        xproto = proto.lower()
        if not xray_has_proto(cfg, xproto):
            return f"❌ Inbound {proto} belum ada."
        if not xray_user_exists(cfg, xproto, user):
            return "❌ Akun tidak ditemukan."
        cur = expiry_get(proto, user)
        if cur != "-" and is_valid_date_ymd(cur):
            newexp = date_add_days_from(cur, days)
        else:
            newexp = add_days_from_today(days)
        expiry_set(proto, user, newexp)
        return (
            f"✅ ⏳ {ico} {proto} • EXTEND OK\n"
            f"{FUTURISTIC_LINE}\n"
            f"👤 User : {user}\n"
            f"📆 Exp  : {newexp}"
        )

    except Exception as e:
        return f"❌ Error extend: {fmt_err(e)}"


def op_info_vps() -> str:
    osname = get_os_pretty()
    ram_line = get_ram_usage_line()
    cpu_usage = get_cpu_usage_percent()
    up = get_uptime_pretty()

    dom = read_domain_any()
    ip, isp_raw, city = fetch_ipinfo()
    isp = re.sub(r"^AS\d+\s+", "", (isp_raw or "").strip()).strip() or (isp_raw or "-")

    st_xray = systemctl_status(SRV_XRAY)
    st_zivpn = systemctl_status(SRV_ZIVPN)

    # count accounts
    zivpn_cnt = 0
    try:
        zivpn_cnt = len(zivpn_list_users(zivpn_load()))
    except Exception:
        zivpn_cnt = 0

    vmess_cnt = vless_cnt = trojan_cnt = 0
    try:
        cfg = xray_load()
        vmess_cnt = len(xray_list_clients(cfg, "vmess"))
        vless_cnt = len(xray_list_clients(cfg, "vless"))
        trojan_cnt = len(xray_list_clients(cfg, "trojan"))
    except Exception:
        pass

    return (
        "🖥️ INFO VPS\n"
        "━━━━━━━━━━━━━━━━\n"
        "🧩 Sistem\n"
        f"• OS      : {osname}\n"
        f"• Uptime  : {up}\n"
        f"• CPU     : {cpu_usage}\n"
        f"• RAM     : {ram_line}\n"
        "\n"
        "🌐 Jaringan\n"
        f"• IP      : {ip}\n"
        f"• Domain  : {dom}\n"
        f"• ISP     : {isp}\n"
        f"• City    : {city}\n"
        "\n"
        "🛠️ Status Service\n"
        f"• XRAY    : {st_xray}\n"
        f"• ZIVPN   : {st_zivpn}\n"
        "\n"
        "👥 Jumlah Akun\n"
        f"• ZIVPN   : {zivpn_cnt}\n"
        f"• VMESS   : {vmess_cnt}\n"
        f"• VLESS   : {vless_cnt}\n"
        f"• TROJAN  : {trojan_cnt}\n"
    )


# =========================
# TELEGRAM UI / STATE
# =========================
@dataclass
class PendingAction:
    proto: str
    op: str     # add/del/ext
    step: str   # ask_user / ask_days
    user: Optional[str] = None



# =========================
# DOMAIN / SSL / XRAY MODE HELPERS
# =========================
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")

def domain_get() -> str:
    try:
        if os.path.isfile(DOMAIN_FILE):
            with open(DOMAIN_FILE, "r", encoding="utf-8", errors="ignore") as f:
                return (f.readline() or "").strip()
    except Exception:
        pass
    return ""

def _normalize_domain(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    return s.strip().strip(".")

def domain_set_value(d: str) -> str:
    d = _normalize_domain(d).replace(" ", "")
    if not d:
        raise ValueError("Domain kosong.")
    if not DOMAIN_RE.match(d):
        raise ValueError("Format domain tidak valid.")
    os.makedirs(os.path.dirname(DOMAIN_FILE), exist_ok=True)
    atomic_write(DOMAIN_FILE, d + "\n")
    # mirror like utility.sh
    for p in ("/etc/xray/domain", "/root/domain"):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            atomic_write(p, d + "\n")
        except Exception:
            pass
    return d

def domain_clear() -> None:
    try:
        os.makedirs(os.path.dirname(DOMAIN_FILE), exist_ok=True)
        atomic_write(DOMAIN_FILE, "")
    except Exception:
        pass
    for p in ("/etc/xray/domain", "/root/domain"):
        try:
            atomic_write(p, "")
        except Exception:
            pass

def _run_cmd(cmd: List[str], timeout: int = 600) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def reality_ensure() -> Tuple[str, str, str]:
    """Ensure REALITY keypair + shortid exist. Return (priv, pub, sid)."""
    try:
        if os.path.isfile(REALITY_PRIV_FILE) and os.path.getsize(REALITY_PRIV_FILE) > 0 and \
           os.path.isfile(REALITY_PUB_FILE) and os.path.getsize(REALITY_PUB_FILE) > 0 and \
           os.path.isfile(REALITY_SHORTID_FILE) and os.path.getsize(REALITY_SHORTID_FILE) > 0:
            with open(REALITY_PRIV_FILE, "r", encoding="utf-8", errors="ignore") as f:
                priv = f.read().strip()
            with open(REALITY_PUB_FILE, "r", encoding="utf-8", errors="ignore") as f:
                pub = f.read().strip()
            with open(REALITY_SHORTID_FILE, "r", encoding="utf-8", errors="ignore") as f:
                sid = f.read().strip()
            if priv and pub and sid:
                return priv, pub, sid
    except Exception:
        pass

    xb = "/usr/local/bin/xray"
    if not (os.path.isfile(xb) and os.access(xb, os.X_OK)):
        xb = shutil.which("xray") or ""
    if not xb:
        raise RuntimeError("Binary xray tidak ditemukan untuk generate REALITY key.")

    rc, out, err = _run_cmd([xb, "x25519"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"Gagal generate REALITY key: {err.strip() or out.strip() or 'unknown'}")

    priv = pub = ""
    for line in (out or "").splitlines():
        line = line.strip()
        if line.lower().startswith("privatekey:"):
            priv = line.split(":", 1)[1].strip()
        elif line.lower().startswith("password:"):
            pub = line.split(":", 1)[1].strip()
        elif "Private key" in line:
            priv = line.split(":", 1)[1].strip()
        elif "Public key" in line:
            pub = line.split(":", 1)[1].strip()

    if not (priv and pub):
        raise RuntimeError("Output xray x25519 tidak bisa diparse.")

    sid = secrets.token_hex(4)
    os.makedirs(os.path.dirname(REALITY_PRIV_FILE), exist_ok=True)
    atomic_write(REALITY_PRIV_FILE, priv + "\n")
    atomic_write(REALITY_PUB_FILE, pub + "\n")
    atomic_write(REALITY_SHORTID_FILE, sid + "\n")
    try:
        os.chmod(REALITY_PRIV_FILE, 0o600)
        os.chmod(REALITY_SHORTID_FILE, 0o600)
    except Exception:
        pass
    return priv, pub, sid

def selfsigned_ensure() -> None:
    if os.path.isfile(XRAY_SELFSIGN_CERT) and os.path.getsize(XRAY_SELFSIGN_CERT) > 0 and \
       os.path.isfile(XRAY_SELFSIGN_KEY) and os.path.getsize(XRAY_SELFSIGN_KEY) > 0:
        return
    openssl = shutil.which("openssl") or ""
    if not openssl:
        raise RuntimeError("openssl tidak ditemukan. Install: apt-get install -y openssl")
    os.makedirs(os.path.dirname(XRAY_SELFSIGN_CERT), exist_ok=True)
    cmd = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "3650", "-nodes",
        "-keyout", XRAY_SELFSIGN_KEY, "-out", XRAY_SELFSIGN_CERT, "-subj", "/CN=localhost"
    ]
    rc, out, err = _run_cmd(cmd, timeout=120)
    if rc != 0:
        raise RuntimeError(f"Gagal buat self-signed cert: {err.strip() or out.strip() or 'unknown'}")
    try:
        os.chmod(XRAY_SELFSIGN_KEY, 0o600)
    except Exception:
        pass

def nginx_write_default_with_ws() -> None:
    os.makedirs("/var/www/html", exist_ok=True)
    atomic_write("/var/www/html/index.html", "<!doctype html><html><head><meta charset=\"utf-8\"><title>OK</title></head><body><h3>It works.</h3></body></html>\n")
    if os.path.isdir("/etc/nginx/sites-available"):
        conf = """server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  root /var/www/html;
  index index.html;

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
"""
        atomic_write("/etc/nginx/sites-available/default", conf)
        try:
            os.makedirs("/etc/nginx/sites-enabled", exist_ok=True)
            if os.path.islink("/etc/nginx/sites-enabled/default") or os.path.exists("/etc/nginx/sites-enabled/default"):
                try:
                    os.remove("/etc/nginx/sites-enabled/default")
                except Exception:
                    pass
            os.symlink("/etc/nginx/sites-available/default", "/etc/nginx/sites-enabled/default")
        except Exception:
            pass

def nginx_ensure() -> None:
    if not shutil.which("nginx"):
        apt = shutil.which("apt-get")
        if not apt:
            raise RuntimeError("nginx belum terpasang dan apt-get tidak ditemukan untuk install otomatis.")
        _run_cmd([apt, "update", "-y"], timeout=600)
        rc, out, err = _run_cmd([apt, "install", "-y", "nginx"], timeout=900)
        if rc != 0:
            raise RuntimeError(f"Gagal install nginx: {err.strip() or out.strip() or 'unknown'}")
    nginx_write_default_with_ws()
    _run_cmd(["systemctl", "enable", "--now", SRV_NGINX], timeout=120)
    _run_cmd(["systemctl", "restart", SRV_NGINX], timeout=120)

def acme_issue_ssl() -> Tuple[str, str]:
    d = domain_get()
    if not d:
        raise RuntimeError("Domain belum diset.")
    apt = shutil.which("apt-get")
    if apt:
        _run_cmd([apt, "update", "-y"], timeout=600)
        _run_cmd([apt, "install", "-y", "socat", "openssl", "curl"], timeout=900)
    if not os.path.isdir("/root/.acme.sh"):
        rc, out, err = _run_cmd(["bash", "-lc", "curl -fsSL https://get.acme.sh | sh"], timeout=900)
        if rc != 0:
            raise RuntimeError(f"Gagal install acme.sh: {err.strip() or out.strip() or 'unknown'}")
    _run_cmd(["systemctl", "stop", SRV_NGINX], timeout=120)
    _run_cmd(["bash", "-lc", "/root/.acme.sh/acme.sh --upgrade --auto-upgrade"], timeout=300)
    _run_cmd(["bash", "-lc", "/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt"], timeout=300)
    issue_cmd = f'/root/.acme.sh/acme.sh --issue -d {shlex.quote(d)} --standalone -k ec-256'
    rc, out, err = _run_cmd(["bash", "-lc", issue_cmd], timeout=900)
    if rc != 0:
        _run_cmd(["systemctl", "restart", SRV_NGINX], timeout=120)
        raise RuntimeError("Gagal issue SSL. Pastikan A record domain benar & port 80 terbuka.")
    os.makedirs(os.path.dirname(XRAY_CERT), exist_ok=True)
    install_cmd = (
        f'/root/.acme.sh/acme.sh --installcert -d {shlex.quote(d)} --ecc '
        f'--fullchain-file {shlex.quote(XRAY_CERT)} '
        f'--key-file {shlex.quote(XRAY_KEY)} '
        f'--reloadcmd \"systemctl restart {SRV_XRAY} 2>/dev/null || true\"'
    )
    _run_cmd(["bash", "-lc", install_cmd], timeout=600)
    try:
        os.chmod(XRAY_KEY, 0o600)
    except Exception:
        pass
    _run_cmd(["systemctl", "restart", SRV_NGINX], timeout=120)
    return XRAY_CERT, XRAY_KEY

def xray_extract_clients(cfg: dict) -> Tuple[List[dict], List[dict], List[dict]]:
    vm, vl, tr = [], [], []
    for ib in xray_inbounds(cfg):
        proto = (ib or {}).get("protocol")
        st = (ib or {}).get("settings") or {}
        clients = st.get("clients", [])
        if not isinstance(clients, list):
            continue
        if proto == "vmess":
            vm.extend([c for c in clients if isinstance(c, dict)])
        elif proto == "vless":
            vl.extend([c for c in clients if isinstance(c, dict)])
        elif proto == "trojan":
            tr.extend([c for c in clients if isinstance(c, dict)])

    def uniq(arr: List[dict]) -> List[dict]:
        seen = set()
        out = []
        for c in arr:
            em = (c or {}).get("email")
            if not em or em in seen:
                continue
            seen.add(em)
            out.append(c)
        return out

    return uniq(vm), uniq(vl), uniq(tr)

def xray_template_domain(priv: str, sid: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
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
                        {"path": "/vless", "dest": 2082},
                        {"path": "/vmess", "dest": 2083},
                        {"dest": 8446},
                        {"dest": 80},
                    ],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["h2", "http/1.1"],
                        "certificates": [{"certificateFile": XRAY_CERT, "keyFile": XRAY_KEY}],
                    },
                },
            },
            {
                "tag": "trojan-fallback-in",
                "listen": "127.0.0.1",
                "port": 8446,
                "protocol": "trojan",
                "settings": {"clients": []},
                "streamSettings": {"network": "tcp", "security": "none"},
            },
            {
                "tag": "vless-ws-in",
                "listen": "127.0.0.1",
                "port": 2082,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vless"}},
            },
            {
                "tag": "vmess-ws-in",
                "listen": "127.0.0.1",
                "port": 2083,
                "protocol": "vmess",
                "settings": {"clients": []},
                "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/vmess"}},
            },
            {
                "tag": "vless-reality",
                "listen": "0.0.0.0",
                "port": 8444,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": "www.cloudflare.com:443",
                        "xver": 0,
                        "serverNames": ["www.cloudflare.com", "cloudflare.com"],
                        "privateKey": priv,
                        "shortIds": [sid],
                    },
                },
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
    }

def xray_template_nodomain(priv: str, sid: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "vless-reality-443",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": "www.cloudflare.com:443",
                        "xver": 0,
                        "serverNames": ["www.cloudflare.com", "cloudflare.com"],
                        "privateKey": priv,
                        "shortIds": [sid],
                    },
                },
            },
            {
                "tag": "vmess-legacy",
                "listen": "0.0.0.0",
                "port": 10001,
                "protocol": "vmess",
                "settings": {"clients": []},
                "streamSettings": {"network": "tcp", "security": "none"},
            },
            {
                "tag": "vless-legacy",
                "listen": "0.0.0.0",
                "port": 10002,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "none"},
            },
            {
                "tag": "trojan-legacy-selfsigned",
                "listen": "0.0.0.0",
                "port": 10003,
                "protocol": "trojan",
                "settings": {"clients": []},
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["http/1.1"],
                        "certificates": [{"certificateFile": XRAY_SELFSIGN_CERT, "keyFile": XRAY_SELFSIGN_KEY}],
                    },
                },
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
    }

def xray_inject_clients_by_proto(cfg: dict, vm: List[dict], vl: List[dict], tr: List[dict]) -> dict:
    for ib in cfg.get("inbounds", []) or []:
        proto = (ib or {}).get("protocol")
        st = (ib or {}).setdefault("settings", {})
        if proto == "vmess":
            st["clients"] = vm
        elif proto == "vless":
            st["clients"] = vl
        elif proto == "trojan":
            st["clients"] = tr
    return cfg

def xray_switch_mode_python(mode: str) -> str:
    if mode not in ("domain", "nodomain"):
        raise ValueError("Mode tidak valid.")
    if not os.path.isfile(XRAY_JSON):
        raise RuntimeError(f"Config XRAY tidak ditemukan: {XRAY_JSON}")

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bak = f"{XRAY_JSON}.bak.{ts}"
    try:
        shutil.copy2(XRAY_JSON, bak)
    except Exception:
        pass

    old = read_json(XRAY_JSON)
    vm, vl, tr = xray_extract_clients(old)

    priv, pub, sid = reality_ensure()

    if mode == "domain":
        nginx_ensure()
        acme_issue_ssl()
        newcfg = xray_template_domain(priv, sid)
    else:
        selfsigned_ensure()
        newcfg = xray_template_nodomain(priv, sid)

    xray_inject_clients_by_proto(newcfg, vm, vl, tr)
    atomic_write(XRAY_JSON, json.dumps(newcfg, indent=2) + "\n")
    systemctl_restart(SRV_XRAY)
    _run_cmd(["systemctl", "enable", SRV_XRAY], timeout=60)

    return f"✅ Mode XRAY berhasil diganti ke: {mode.upper()}\n🗄️ Backup config: {bak}"


# =========================
# UI TEXT HELPERS (FUTURISTIC)
# =========================
FUTURISTIC_LINE = "━━━━━━━━━━━━━━━━━━━━━━"

# Icon packs (full iconik UI)
ICON_PROTO = {
    "ZIVPN": "🟣",
    "VMESS": "💠",
    "VLESS": "🔷",
    "TROJAN": "🟠",
    "UTILITY": "🧰",
}

ICON_OP = {
    "list": "📋",
    "view": "👁️",
    "add": "➕",
    "del": "🗑️",
    "ext": "⏳",
}

def _panel(title: str, subtitle: str = "") -> str:
    # Plain text panel (no HTML) for menus
    head = f"⟦ {title} ⟧"
    if subtitle:
        return f"{head}\n{FUTURISTIC_LINE}\n{subtitle}"
    return f"{head}\n{FUTURISTIC_LINE}"








def ui_main_text() -> str:
    osname = get_os_pretty()
    ip, org, _city = fetch_ipinfo()
    isp = re.sub(r"^AS\d+\s+", "", (org or "").strip())
    isp = isp.strip() if isp else "-"
    host = read_domain_any()

    lines = [
        "⟦ XZ MANAGER • CONSOLE ⟧",
        FUTURISTIC_LINE,
        f"🖥️ VPS  : {osname}",
        f"🌐 IP   : {ip}",
        f"🔗 Host : {host}",
        f"🏢 ISP  : {isp}",
        FUTURISTIC_LINE,
        "🧭 Pilih modul di bawah:",
    ]
    return "\n".join(lines)
def ui_proto_text(proto: str) -> str:
    ico = ICON_PROTO.get(proto, "🔹")
    return _panel(f"{ico} {proto} • MODULE", "🧭 Pilih aksi di bawah:")


def ui_utility_text() -> str:
    return _panel("🧰 UTILITY • TOOLKIT", "🧭 Pilih aksi di bawah:")

def ui_expired_text() -> str:
    st = "ON" if cron_expiry_is_enabled() else "OFF"
    return _panel("⏳ EXPIRED AKUN", f"• Auto hapus (cron) : {st}\n\nPilih aksi di bawah:")


def ui_domain_text() -> str:
    d = domain_get()
    return (
        "🌐 <b>DOMAIN / SSL</b>\n\n"
        f"Domain tersimpan: <b>{htmlesc(d) if d else '(belum ada)'}</b>\n\n"
        "Pilih aksi di bawah ini:"
    )

def ui_xray_mode_text() -> str:
    return (
        "🧩 <b>SWITCH XRAY MODE</b>\n\n"
        "Pilih mode XRAY:\n"
        "• DOMAIN+SSL: 443 fallback + WS /vless /vmess (nginx:80) + REALITY 8444\n"
        "• NO DOMAIN : REALITY 443 + legacy 10001/10002/10003\n\n"
        "Catatan: ganti mode akan rewrite config.json tapi client akan dipertahankan."
    )



def ui_op_label(op: str) -> str:
    return {
        "add": "➕ CREATE",
        "view": "👁️ VIEW",
        "del": "🗑️ DELETE",
        "ext": "⏳ EXTEND",
    }.get(op, op.upper())

def ui_prompt_username(proto: str, op: str) -> str:
    ico = ICON_PROTO.get(proto, "🔹")
    opico = ICON_OP.get(op, "⚙️")
    return (
        f"⟦ {ico} {proto} • {opico} {ui_op_label(op)} ⟧\n"
        f"{FUTURISTIC_LINE}\n"
        "👤 Masukkan <b>username</b> (a-zA-Z0-9_):"
    )


def ui_prompt_days(proto: str, op: str) -> str:
    ico = ICON_PROTO.get(proto, "🔹")
    opico = ICON_OP.get(op, "⚙️")
    return (
        f"⟦ {ico} {proto} • {opico} {ui_op_label(op)} ⟧\n"
        f"{FUTURISTIC_LINE}\n"
        "📆 Masukkan durasi aktif (hari) ⟡ <i>default 30</i>"
    )


def kb_main() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🟣 ZIVPN", callback_data="m:zivpn"),
         InlineKeyboardButton("💠 VMESS", callback_data="m:vmess")],
        [InlineKeyboardButton("🔷 VLESS", callback_data="m:vless"),
         InlineKeyboardButton("🟠 TROJAN", callback_data="m:trojan")],
        [InlineKeyboardButton("🧰 UTILITY", callback_data="m:utility")],
    ])

def kb_proto(proto: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📋 LIST", callback_data=f"p:{proto}:list"),
         InlineKeyboardButton("👁️ LIHAT", callback_data=f"p:{proto}:view")],
        [InlineKeyboardButton("➕ BUAT", callback_data=f"p:{proto}:add"),
         InlineKeyboardButton("⏳ PERPANJANG", callback_data=f"p:{proto}:ext")],
        [InlineKeyboardButton("🗑️ HAPUS", callback_data=f"p:{proto}:del")],
        [InlineKeyboardButton("⬅️ MENU UTAMA", callback_data="back:main")],
    ])

def kb_utility() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🖥️ INFO VPS", callback_data="u:info:vps")],
        [InlineKeyboardButton("🔄 RESTART XRAY", callback_data="u:restart:xray"),
         InlineKeyboardButton("🔄 RESTART ZIVPN", callback_data="u:restart:zivpn")],
        [InlineKeyboardButton("📌 STATUS XRAY", callback_data="u:status:xray"),
         InlineKeyboardButton("📌 STATUS ZIVPN", callback_data="u:status:zivpn")],
        [InlineKeyboardButton("💾 BACKUP", callback_data="u:backup:now"),
         InlineKeyboardButton("♻️ RESTORE", callback_data="u:backup:restore_menu")],
        [InlineKeyboardButton("🌐 DOMAIN", callback_data="u:domain:menu"),
         InlineKeyboardButton("🧩 XRAY MODE", callback_data="u:xraymode:menu")],
        [InlineKeyboardButton("⏳ EXPIRED AKUN", callback_data="u:expired:menu")],
        [InlineKeyboardButton("⬅️ MENU UTAMA", callback_data="back:main")],
    ])


def kb_expired_menu() -> InlineKeyboardMarkup:
    enabled = cron_expiry_is_enabled()
    st = "✅ ON" if enabled else "❌ OFF"
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧹 Hapus akun expired sekarang", callback_data="u:expired:cleanup_now")],
        [InlineKeyboardButton(f"⏱️ Auto hapus (cron) : {st}", callback_data="noop")],
        [InlineKeyboardButton("✅ Aktifkan auto hapus", callback_data="u:expired:cron_on"),
         InlineKeyboardButton("🛑 Matikan", callback_data="u:expired:cron_off")],
        [InlineKeyboardButton("⬅️ KEMBALI", callback_data="back:utility")],
    ])

def kb_cancel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton("✖️ BATAL", callback_data="cancel")]])
def kb_domain_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✍️ Set/Ubah Domain", callback_data="u:domain:set")],
        [InlineKeyboardButton("🗑️ Hapus Domain", callback_data="u:domain:clear")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="u:domain:back_utility")],
    ])

def kb_domain_input_cancel() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✖️ BATAL", callback_data="cancel")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="u:domain:menu")],
    ])

def kb_xray_mode_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🌐 DOMAIN+SSL", callback_data="u:xraymode:set:domain")],
        [InlineKeyboardButton("🛰️ NO DOMAIN", callback_data="u:xraymode:set:nodomain")],
        [InlineKeyboardButton("⬅️ Kembali", callback_data="u:xraymode:back_utility")],
    ])



def kb_backup_restore_menu() -> InlineKeyboardMarkup:
    backups = backup_list()
    rows = []
    if not backups:
        rows.append([InlineKeyboardButton("📭 Tidak ada backup", callback_data="noop")])
    else:
        for idx, name in enumerate(backups, start=1):
            rows.append([InlineKeyboardButton(f"📦 {idx}. {name}", callback_data=f"u:backup:pick:{idx}")])
    rows.append([
        InlineKeyboardButton("🔄 Refresh", callback_data="u:backup:restore_menu"),
        InlineKeyboardButton("⬅️ Utility", callback_data="u:backup:back_utility"),
    ])
    return InlineKeyboardMarkup(rows)

def kb_backup_confirm(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Restore", callback_data="u:backup:do_restore"),
         InlineKeyboardButton("❌ Batal", callback_data="u:backup:restore_menu")],
        [InlineKeyboardButton("⬅️ Utility", callback_data="u:backup:back_utility")]
    ])

# =========================
# BOT HANDLERS
# =========================
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_dirs()
    env = load_env(BOT_ENV)
    admins = parse_admin_ids(env.get("BOT_ADMIN_IDS", ""))
    uid = update.effective_user.id if update.effective_user else 0

    if not is_admin(uid, admins):
        await reply_clean(update, context, "Akses ditolak.")
        return

    context.user_data.pop("pending", None)
    context.user_data.pop("restore_pick", None)
    await reply_clean(update, context, ui_main_text(), reply_markup=kb_main())


async def on_cb(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_dirs()
    q = update.callback_query
    await q.answer()
    _track_last_bot_message_from_query(update, context)

    env = load_env(BOT_ENV)
    admins = parse_admin_ids(env.get("BOT_ADMIN_IDS", ""))
    uid = update.effective_user.id if update.effective_user else 0
    if not is_admin(uid, admins):
        await q.edit_message_text("Akses ditolak.")
        return

    data = q.data or ""

    # cancel input flow
    if data == "cancel":
        context.user_data.pop("pending", None)
        context.user_data.pop("util_pending", None)
        await q.edit_message_text("✖️ Dibatalkan.\n\n" + ui_main_text(), reply_markup=kb_main())
        return

    if data == "noop":
        return

    # back
    if data == "back:main":
        context.user_data.pop("pending", None)
        context.user_data.pop("restore_pick", None)
        await q.edit_message_text(ui_main_text(), reply_markup=kb_main())
        return

    if data == "back:utility":
        context.user_data.pop("util_pending", None)
        await q.edit_message_text(ui_utility_text(), reply_markup=kb_utility())
        return

    # MAIN MENU
    if data.startswith("m:"):
        m = data.split(":", 1)[1]
        context.user_data.pop("pending", None)

        if m == "utility":
            await q.edit_message_text(ui_utility_text(), reply_markup=kb_utility())
            return

        proto_map = {"zivpn": "ZIVPN", "vmess": "VMESS", "vless": "VLESS", "trojan": "TROJAN"}
        proto = proto_map.get(m)
        if not proto:
            await q.edit_message_text("Menu tidak dikenal.", reply_markup=kb_main())
            return

        await q.edit_message_text(ui_proto_text(proto), reply_markup=kb_proto(proto))
        return

    # PROTO ACTIONS
    if data.startswith("p:"):
        _, proto, op = data.split(":", 2)

        if op == "list":
            await q.edit_message_text("⌛ Memuat daftar akun…")
            txt = await asyncio.to_thread(op_list, proto)
            await q.edit_message_text(txt, reply_markup=kb_proto(proto))
            return

        if op in ("add", "view", "del", "ext"):
            pending = PendingAction(proto=proto, op=op, step="ask_user")
            context.user_data["pending"] = pending.__dict__
            await q.edit_message_text(ui_prompt_username(proto, op), reply_markup=kb_cancel(), parse_mode=ParseMode.HTML)
            return

        await q.edit_message_text("Aksi tidak dikenal.", reply_markup=kb_main())
        return

    # UTILITY ACTIONS
    if data.startswith("u:"):
        # INFO VPS
        if data == "u:info:vps":
            await q.edit_message_text("⌛ Mengambil info VPS…")
            txt = await asyncio.to_thread(op_info_vps)
            await q.edit_message_text(txt, reply_markup=kb_utility())
            return

        # RESTART
        if data == "u:restart:xray":
            await q.edit_message_text("🔄 Restart XRAY...")
            ok, msg = await asyncio.to_thread(systemctl_restart_checked, SRV_XRAY)
            await q.edit_message_text(msg, reply_markup=kb_utility())
            return

        if data == "u:restart:zivpn":
            await q.edit_message_text("🔄 Restart ZIVPN...")
            ok, msg = await asyncio.to_thread(systemctl_restart_checked, SRV_ZIVPN)
            await q.edit_message_text(msg, reply_markup=kb_utility())
            return

        # STATUS
        if data == "u:status:xray":
            st = systemctl_status(SRV_XRAY)
            await q.edit_message_text(f"📌 Status XRAY: {st}", reply_markup=kb_utility())
            return

        if data == "u:status:zivpn":
            st = systemctl_status(SRV_ZIVPN)
            await q.edit_message_text(f"📌 Status ZIVPN: {st}", reply_markup=kb_utility())
            return

        
        # EXPIRED ACCOUNTS
        if data == "u:expired:menu":
            await q.edit_message_text(ui_expired_text(), reply_markup=kb_expired_menu())
            return

        if data == "u:expired:cleanup_now":
            await q.edit_message_text("🧹 Menghapus akun expired…")
            try:
                removed, users = await asyncio.to_thread(expiry_cleanup_now)
                if removed <= 0:
                    await q.edit_message_text("✅ Tidak ada akun expired.", reply_markup=kb_expired_menu())
                else:
                    sample = ", ".join(users[:10])
                    more = f" (+{len(users)-10} lagi)" if len(users) > 10 else ""
                    await q.edit_message_text(
                        f"✅ Berhasil hapus {removed} akun expired.\n👤 {sample}{more}",
                        reply_markup=kb_expired_menu()
                    )
            except Exception as e:
                await q.edit_message_text(f"❌ Gagal cleanup: {fmt_err(e)}", reply_markup=kb_expired_menu())
            return

        if data == "u:expired:cron_on":
            await q.edit_message_text("⏱️ Mengaktifkan auto hapus (cron)…")
            try:
                await asyncio.to_thread(cron_expiry_enable)
                await q.edit_message_text("✅ Auto hapus diaktifkan (harian 00:15).", reply_markup=kb_expired_menu())
            except Exception as e:
                await q.edit_message_text(f"❌ Gagal aktifkan cron: {fmt_err(e)}", reply_markup=kb_expired_menu())
            return

        if data == "u:expired:cron_off":
            await q.edit_message_text("🛑 Mematikan auto hapus (cron)…")
            try:
                await asyncio.to_thread(cron_expiry_disable)
                await q.edit_message_text("✅ Auto hapus dimatikan.", reply_markup=kb_expired_menu())
            except Exception as e:
                await q.edit_message_text(f"❌ Gagal matikan cron: {fmt_err(e)}", reply_markup=kb_expired_menu())
            return

# BACKUP
        if data == "u:backup:now":
            await q.edit_message_text("💾 Membuat backup...")
            try:
                name = await asyncio.to_thread(backup_make)
                archive = await asyncio.to_thread(backup_pack, name)

                # Send the backup file to chat (Telegram shows a Copy/Download UI for documents)
                chat_id = update.effective_chat.id if update.effective_chat else q.message.chat_id
                with open(archive, "rb") as f:
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=os.path.basename(archive),
                        caption=f"✅ Backup dibuat: <b>{htmlesc(name)}</b>\n\n📦 File backup terlampir.",
                        parse_mode=ParseMode.HTML,
                    )

                await reply_clean(update, context, ui_main_text(), reply_markup=kb_main())
            except Exception as e:
                await q.edit_message_text(f"❌ Gagal membuat backup: {htmlesc(str(e))}", parse_mode=ParseMode.HTML, reply_markup=kb_utility())
            return

        if data == "u:backup:restore_menu":
            context.user_data.pop("restore_pick", None)
            await q.edit_message_text("♻️ RESTORE BACKUP\nPilih file backup:", reply_markup=kb_backup_restore_menu())
            return

        if data == "u:backup:back_utility":
            context.user_data.pop("restore_pick", None)
            await q.edit_message_text(ui_utility_text(), reply_markup=kb_utility())
            return

        if data.startswith("u:backup:pick:"):
            idx = int(data.split(":")[-1])
            backups = backup_list()
            if idx <= 0 or idx > len(backups):
                await q.edit_message_text("Pilihan backup tidak valid.", reply_markup=kb_backup_restore_menu())
                return
            pick = backups[idx - 1]
            context.user_data["restore_pick"] = pick
            await q.edit_message_text(f"Restore backup ini?\n\n{pick}", reply_markup=kb_backup_confirm(pick))
            return

        if data == "u:backup:do_restore":
            pick = context.user_data.get("restore_pick")
            if not pick:
                await q.edit_message_text("Belum memilih backup.", reply_markup=kb_backup_restore_menu())
                return
            await q.edit_message_text("♻️ Restore berjalan...")
            txt = await asyncio.to_thread(backup_restore, pick)
            context.user_data.pop("restore_pick", None)
            await q.edit_message_text(txt, reply_markup=kb_utility())
            return

        
        # DOMAIN / SSL
        if data == "u:domain:menu":
            context.user_data.pop("util_pending", None)
            await q.edit_message_text(ui_domain_text(), reply_markup=kb_domain_menu(), parse_mode=ParseMode.HTML)
            return

        if data == "u:domain:back_utility":
            context.user_data.pop("util_pending", None)
            await q.edit_message_text(ui_utility_text(), reply_markup=kb_utility(), parse_mode=ParseMode.HTML)
            return

        if data == "u:domain:set":
            context.user_data["util_pending"] = {"op": "domain_set"}
            await q.edit_message_text(
                "✍️ Kirim domain (contoh: <b>example.com</b>).\n\nJika ingin batal, kirim pesan kosong (Enter) atau tekan tombol.",
                reply_markup=kb_domain_input_cancel(),
                parse_mode=ParseMode.HTML,
            )
            return

        if data == "u:domain:clear":
            await q.edit_message_text("🗑️ Menghapus domain…")
            await asyncio.to_thread(domain_clear)
            await q.edit_message_text("✅ Domain dihapus.", reply_markup=kb_domain_menu())
            return

        # XRAY MODE
        if data == "u:xraymode:menu":
            await q.edit_message_text(ui_xray_mode_text(), reply_markup=kb_xray_mode_menu(), parse_mode=ParseMode.HTML)
            return

        if data == "u:xraymode:back_utility":
            await q.edit_message_text(ui_utility_text(), reply_markup=kb_utility(), parse_mode=ParseMode.HTML)
            return

        if data.startswith("u:xraymode:set:"):
            mode = data.split(":")[-1]
            await q.edit_message_text("⌛ Mengganti mode XRAY… (bisa agak lama)")
            try:
                txt = await asyncio.to_thread(xray_switch_mode_python, mode)
                await q.edit_message_text(txt, reply_markup=kb_utility())
            except Exception as e:
                await q.edit_message_text(f"❌ Gagal switch mode: {htmlesc(str(e))}", parse_mode=ParseMode.HTML, reply_markup=kb_xray_mode_menu())
            return

        await q.edit_message_text("Utility tidak dikenal.", reply_markup=kb_utility())
        return

    await q.edit_message_text("Perintah tidak dikenal.", reply_markup=kb_main())


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    ensure_dirs()

    env = load_env(BOT_ENV)
    admins = parse_admin_ids(env.get("BOT_ADMIN_IDS", ""))
    uid = update.effective_user.id if update.effective_user else 0
    if not is_admin(uid, admins):
        return

    
    # utility input flow (domain set, dll)
    util_pending = context.user_data.get("util_pending")
    if util_pending and isinstance(util_pending, dict):
        op = util_pending.get("op")
        text = (update.message.text or "").strip()

        # pesan kosong dianggap batal
        if not text:
            context.user_data.pop("util_pending", None)
            await reply_clean(update, context, ui_domain_text(), reply_markup=kb_domain_menu(), parse_mode=ParseMode.HTML)
            return

        if op == "domain_set":
            try:
                d = await asyncio.to_thread(domain_set_value, text)
                context.user_data.pop("util_pending", None)
                await reply_clean(update, context, f"✅ Domain tersimpan: <b>{htmlesc(d)}</b>", reply_markup=kb_domain_menu(), parse_mode=ParseMode.HTML)
            except Exception as e:
                await reply_clean(update, context, f"❌ {htmlesc(str(e))}\n\nCoba kirim domain lagi, atau kirim kosong untuk batal.", reply_markup=kb_domain_input_cancel(), parse_mode=ParseMode.HTML)
            return

    pending_raw = context.user_data.get("pending")
    if not pending_raw:
        await reply_clean(update, context, "Gunakan /start lalu pilih menu di bawah.\n\n" + ui_main_text(), reply_markup=kb_main())
        return

    pending = PendingAction(**pending_raw)
    text = (update.message.text or "").strip()

    # hapus pesan input user bila memungkinkan (agar chat lebih rapi)
    await delete_user_message(update, context)

    if pending.step == "ask_user":
        user = text.replace(" ", "")
        if not USERNAME_RE.match(user):
            await reply_clean(update, context, "❌ Username tidak valid.\nGunakan: a-zA-Z0-9_")
            return
        pending.user = user

        # DELETE: cukup input username saja (tanpa tanya masa aktif)
        if pending.op == "del":
            proto = pending.proto
            res = await asyncio.to_thread(op_del, proto, user)
            context.user_data.pop("pending", None)
            await reply_clean(update, context, res, reply_markup=kb_proto(proto))
            return

        # VIEW: cukup input username saja (kirim detail + link)
        if pending.op == "view":
            proto = pending.proto
            res = await asyncio.to_thread(op_view, proto, user)
            context.user_data.pop("pending", None)
            await reply_clean(update, context, res, reply_markup=kb_proto(proto), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            return

        pending.step = "ask_days"
        context.user_data["pending"] = pending.__dict__
        await reply_clean(update, context, ui_prompt_days(pending.proto, pending.op), reply_markup=kb_cancel(), parse_mode=ParseMode.HTML)
        return

    if pending.step == "ask_days":
        days = 30
        if text.isdigit() and int(text) > 0:
            days = int(text)

        proto = pending.proto
        op = pending.op
        user = pending.user or ""

        # execute
        if op == "add":
            res = await asyncio.to_thread(op_add, proto, user, days)
        elif op == "del":
            # days ignored
            res = await asyncio.to_thread(op_del, proto, user)
        else:
            res = await asyncio.to_thread(op_ext, proto, user, days)

        context.user_data.pop("pending", None)
        if op == "add":
            await reply_clean(update, context, res, reply_markup=kb_proto(proto), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        else:
            await reply_clean(update, context, res, reply_markup=kb_proto(proto))
        return


def main() -> None:
    ensure_dirs()
    env = load_env(BOT_ENV)
    token = env.get("BOT_TOKEN", "").strip()
    if not token:
        raise SystemExit(f"BOT_TOKEN belum diset di {BOT_ENV}")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CallbackQueryHandler(on_cb))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()