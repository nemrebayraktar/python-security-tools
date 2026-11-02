# Abuse Checker

Türkçe | [English](#english)

Web sunucusu log dosyasındaki (access.log) IP adreslerini bulup [AbuseIPDB](https://www.abuseipdb.com/) üzerinden itibar skorlarını sorgulayan küçük bir script. Sonuçlar `abuse.db` adlı SQLite veritabanına kaydedilir.

Neden yazdım: Log incelemesinde hangi IP'lerin daha önce kötü niyetli olarak raporlandığını tek tek elle bakmadan görmek için.

## Kurulum

```bash
pip install -r requirements.txt
export ABUSEIPDB_API_KEY="kendi_anahtarin"   # Windows: set ABUSEIPDB_API_KEY=...
```

API anahtarı AbuseIPDB hesabından ücretsiz alınabilir. Anahtar koda yazılmaz.

## Kullanım

```bash
python abuse_checker.py                      # varsayılan: access.log -> abuse.db
python abuse_checker.py access_sample.log    # örnek log ile
python abuse_checker.py sunucu.log sonuc.db  # log ve veritabanı yolu vererek
```

Script şunları yapar:
1. Logdaki IPv4 adreslerini bulur, geçersiz olanları (ör. 999.1.1.1) atar.
2. İç ağ ve loopback adreslerini (10.x, 172.16-31.x, 192.168.x, 127.x) sorgulamaz, kotayı boşa harcamaz.
3. Her IP için AbuseIPDB'den son 90 günün skorunu alır.
4. Skoru 25 ve üstü olanları şüpheli (`is_abusive = 1`) olarak işaretler.
5. API hata dönerse (ör. 401 yanlış anahtar, 429 limit doldu) o IP'yi atlayıp devam eder.

Veritabanı tablosu: `ip_reports (ip, is_abusive, abuse_score, country, isp, timestamp)`

`access_sample.log` sadece dokümantasyon IP blokları içerir. Gerçek log ve `abuse.db` dosyaları repoya eklenmez.

---

## English

A small script that extracts IP addresses from a web server log (access.log) and checks their reputation on [AbuseIPDB](https://www.abuseipdb.com/). Results are stored in a SQLite database (`abuse.db`).

Why: to quickly see which IPs in a log have already been reported as malicious, without looking them up one by one.

## Setup

```bash
pip install -r requirements.txt
export ABUSEIPDB_API_KEY="your_key"
```

## Usage

```bash
python abuse_checker.py                      # default: access.log -> abuse.db
python abuse_checker.py access_sample.log
python abuse_checker.py server.log result.db
```

The script validates IPs, skips private and loopback addresses, queries the last 90 days on AbuseIPDB, flags scores of 25 or more as suspicious and keeps going if the API returns an error (401, 429 etc.).

`access_sample.log` contains documentation IP ranges only. Real logs and `abuse.db` are not committed.
