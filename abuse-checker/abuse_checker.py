import os
import re
import sys
import sqlite3
import ipaddress
from datetime import datetime

import requests

# API anahtarı koda yazılmaz, ortam değişkeninden okunur.
# export ABUSEIPDB_API_KEY="anahtarin"
API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

# Skor bu değerin üstündeyse IP'yi şüpheli sayıyoruz (0-100)
ESIK = 25

# IP regex'i
ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# İç ağ adresleri (RFC1918), bunları sorgulamıyoruz
IC_AGLAR = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def loglardan_ip_cikar(log_data):
    ips = set()
    for aday in ip_pattern.findall(log_data):
        try:
            ip = ipaddress.ip_address(aday)
        except ValueError:
            # 999.1.1.1 gibi geçersiz değerler
            continue
        # Yerel / özel IP'leri AbuseIPDB'ye sormanın anlamı yok, kotayı boşa harcar
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or any(ip in ag for ag in IC_AGLAR):
            continue
        ips.add(str(ip))
    return sorted(ips)


def ip_sorgula(ip):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    response = requests.get(API_URL, headers=headers, params=params, timeout=10)
    if response.status_code != 200:
        # 401 = anahtar hatalı, 429 = günlük limit doldu
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:200]}")
    return response.json()["data"]


def veritabani_hazirla(yol):
    conn = sqlite3.connect(yol)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS ip_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            is_abusive INTEGER,
            abuse_score INTEGER,
            country TEXT,
            isp TEXT,
            timestamp TEXT
        )
    ''')
    return conn


def main():
    log_dosyasi = sys.argv[1] if len(sys.argv) > 1 else "access.log"
    db_dosyasi = sys.argv[2] if len(sys.argv) > 2 else "abuse.db"

    if not API_KEY:
        print("[!] ABUSEIPDB_API_KEY ortam değişkeni tanımlı değil.")
        print("    Örnek: export ABUSEIPDB_API_KEY=\"anahtarin\"")
        sys.exit(1)

    try:
        with open(log_dosyasi, "r", encoding="utf-8", errors="ignore") as file:
            log_data = file.read()
    except FileNotFoundError:
        print(f"[!] Log dosyası bulunamadı: {log_dosyasi}")
        sys.exit(1)

    ips = loglardan_ip_cikar(log_data)
    print(f"[+] {len(ips)} adet public IP bulundu.")

    conn = veritabani_hazirla(db_dosyasi)
    cursor = conn.cursor()
    supheli = 0

    for ip in ips:
        print(f"[+] Sorgulanıyor: {ip}")
        try:
            data = ip_sorgula(ip)
        except Exception as e:
            print(f"[!] Hata: {ip} için API sorgusu başarısız oldu. Sebep: {e}")
            continue

        skor = data.get("abuseConfidenceScore", 0)
        is_abusive = 1 if skor >= ESIK else 0
        supheli += is_abusive

        cursor.execute('''
            INSERT INTO ip_reports (ip, is_abusive, abuse_score, country, isp, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            ip,
            is_abusive,
            skor,
            data.get("countryCode") or "N/A",
            data.get("isp") or "N/A",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        conn.commit()
        print(f"    skor: {skor}  ülke: {data.get('countryCode')}  isp: {data.get('isp')}")

    conn.close()
    print(f"[OK] Tüm IP'ler işlendi. Şüpheli (skor >= {ESIK}): {supheli}")


if __name__ == "__main__":
    main()
