# Abuse Checker

Türkçe | [English](#english)

Web sunucusu log dosyasındaki (access.log) IP adreslerini bulup [AbuseIPDB](https://www.abuseipdb.com/) üzerinden itibar skorlarını sorgulayan küçük bir script. Sonuçlar `abuse.db` adlı SQLite veritabanına kaydedilir.

Neden yazdım: Log incelemesinde hangi IP'lerin daha önce kötü niyetli olarak raporlandığını tek tek elle bakmadan görmek için.

## Gereksinimler

- Python 3.9 veya üstü
- `requests` paketi
- AbuseIPDB API anahtarı (abuseipdb.com üzerinde ücretsiz hesap açılarak alınır)

## Kurulum ve çalıştırma (macOS)

1. Repoyu indirip klasöre girin:

   ```bash
   git clone https://github.com/nemrebayraktar/python-security-tools.git
   cd python-security-tools/abuse-checker
   ```

2. Sanal ortam kurup bağımlılığı yükleyin. Homebrew Python sistem geneline `pip install` yapılmasına izin vermediği için sanal ortam kullanıyorum:

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

3. API anahtarını ortam değişkeni olarak verin. Anahtar koda yazılmaz:

   ```bash
   export ABUSEIPDB_API_KEY="kendi_anahtarin"
   ```

4. Örnek log ile çalıştırın:

   ```bash
   .venv/bin/python abuse_checker.py access_sample.log
   ```

Linux'ta adımlar aynı. Windows'ta sanal ortam `py -m venv .venv` ile kurulur, paket `.venv\Scripts\pip install -r requirements.txt` ile yüklenir, anahtar `set ABUSEIPDB_API_KEY=...` ile verilir ve script `.venv\Scripts\python abuse_checker.py access_sample.log` ile çalışır.

Diğer kullanımlar:

```bash
.venv/bin/python abuse_checker.py                      # varsayılan: access.log -> abuse.db
.venv/bin/python abuse_checker.py sunucu.log sonuc.db  # log ve veritabanı yolu vererek
```

Anahtar tanımlı değilse script uyarı verip durur. Anahtar yanlışsa her IP için 401 hatası yazılır ve devam edilir.

Script şunları yapar:
1. Logdaki IPv4 adreslerini bulur, geçersiz olanları (ör. 999.1.1.1) atar.
2. İç ağ ve loopback adreslerini (10.x, 172.16-31.x, 192.168.x, 127.x) sorgulamaz, kotayı boşa harcamaz.
3. Her IP için AbuseIPDB'den son 90 günün skorunu alır.
4. Skoru 25 ve üstü olanları şüpheli (`is_abusive = 1`) olarak işaretler.
5. API hata dönerse (ör. 401 yanlış anahtar, 429 limit doldu) o IP'yi atlayıp devam eder.

## Sonuçlar nereye kaydedilir

Sonuçlar çalıştırılan klasördeki `abuse.db` dosyasına (veya verilen veritabanı yoluna) yazılır. Tablo: `ip_reports (ip, is_abusive, abuse_score, country, isp, timestamp)`. Şüpheli olanları görmek için:

```bash
sqlite3 abuse.db "SELECT ip, abuse_score, country FROM ip_reports WHERE is_abusive = 1;"
```

`access_sample.log` sadece dokümantasyon IP blokları içerir. Gerçek log ve `abuse.db` dosyaları repoya eklenmez.

---

## English

A small script that extracts IP addresses from a web server log (access.log) and checks their reputation on [AbuseIPDB](https://www.abuseipdb.com/). Results are stored in a SQLite database (`abuse.db`).

Why: to quickly see which IPs in a log have already been reported as malicious, without looking them up one by one.

Requirements: Python 3.9+, `requests` and a free AbuseIPDB API key.

Setup and run (macOS, Linux is the same):

1. Get the code:

   ```bash
   git clone https://github.com/nemrebayraktar/python-security-tools.git
   cd python-security-tools/abuse-checker
   ```

2. Create a virtual environment and install the dependency (Homebrew Python blocks system-wide `pip install`):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

3. Set your API key as an environment variable: `export ABUSEIPDB_API_KEY="your_key"`
4. Run it with the sample log: `.venv/bin/python abuse_checker.py access_sample.log`

Other usage: `.venv/bin/python abuse_checker.py` (default `access.log` -> `abuse.db`) or `.venv/bin/python abuse_checker.py server.log result.db`. If the key is missing the script stops with a message; if it is wrong each IP gets a 401 error and the script keeps going.

The script validates IPs, skips private and loopback addresses, queries the last 90 days on AbuseIPDB, flags scores of 25 or more as suspicious and keeps going if the API returns an error (401, 429 etc.). Results go to `abuse.db` (table `ip_reports`); to list suspicious ones: `sqlite3 abuse.db "SELECT ip, abuse_score, country FROM ip_reports WHERE is_abusive = 1;"`

`access_sample.log` contains documentation IP ranges only. Real logs and `abuse.db` are not committed.
