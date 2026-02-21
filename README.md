# XZ-Manager (XRAY + ZIVPN + Telegram Bot)

XZ-Manager adalah manager berbasis menu (CLI) untuk mengelola:
- **XRAY core** (VMESS / VLESS / TROJAN)
- **ZIVPN core**
- **Telegram Bot Manager** (`xzbot`) dengan menu yang sama seperti manager

> **Wajib dijalankan di VPS sebagai root.**

> **Mode Domain, WAJIB pointing IP VPS ke domain dahulu.**

---

## 1) Wajib Root

Installer membutuhkan akses root untuk memasang dependency, service, dan menulis konfigurasi.

Cek apakah sudah root:
```bash
whoami
```

Jika **belum root**, aktifkan akses root terlebih dahulu:
```bash
wget -qO- -O aksesroot.sh https://raw.githubusercontent.com/rasi1982/sc-vvip/refs/heads/main/aksesroot.sh && bash aksesroot.sh
```

Lalu masuk root:
```bash
sudo -i
```

---

## 2) Instal XRAY + ZIVPN Core + Manager

Jalankan instalasi:
```bash
wget -O install.sh https://raw.githubusercontent.com/harunkl/xz-manager/main/install.sh
chmod +x install.sh
bash install.sh
```

---

## 3) Masuk ke Manager

Untuk masuk menu manager:
```bash
xz
```

---

## 4) Setting Bot Telegram (Token & Admin ID)

Bot Telegram **diatur lewat manager dari VPS** (bukan di install).

Masuk:
- **MENU UTILITY**
- **Bot Telegram**
  - Set **BOT_TOKEN**
  - Tambahkan **Admin ID**
  - Start/Restart **xzbot**

Cek status bot (opsional):
```bash
systemctl status xzbot --no-pager -l
journalctl -u xzbot -n 50 --no-pager
```

---

## Catatan
- Jalankan semua perintah sebagai **root**.
- Jika bot belum jalan, biasanya karena **BOT_TOKEN** masih kosong (set dulu dari menu Utility).



