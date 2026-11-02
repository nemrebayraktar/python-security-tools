# Port Scanner (MrP's Eye)

Türkçe | [English](#english)

Tkinter arayüzlü basit bir TCP port tarayıcı. Hedef IP veya alan adı ve port aralığı girilir, açık portlar listelenir ve bilinen portlar için olası güvenlik riskleri gösterilir (FTP, Telnet, SMB, RDP vb.). Açık portlar `port_sonuclari.db` dosyasına kaydedilir.

## Kullanım

```bash
python portscanner.py
```

Ek paket gerekmez (tkinter, socket, sqlite3 standart kütüphanede). Linux'ta tkinter yoksa: `sudo apt install python3-tk`.

- Tarama başlamadan önce yasal uyarı çıkar, onay verilmeden tarama yapılmaz.
- Varsayılan hedef `127.0.0.1`. Kendi makineniz dışında yalnızca izinli hedefleri tarayın (ör. Nmap'in test için izin verdiği `scanme.nmap.org`).
- Tarama TCP connect yöntemiyle ve 100 paralel bağlantıyla yapılır, port başına bekleme süresi 0.5 sn.

Veritabanı tablosu: `ports (ip_address, port, service, risk_summary, scan_time)`. `.db` dosyaları repoya eklenmez.

---

## English

A simple TCP port scanner with a Tkinter GUI. Enter a target IP or hostname and a port range; it lists open ports, shows possible risks for well-known ones and saves the results to `port_sonuclari.db`.

```bash
python portscanner.py
```

No extra packages needed (on Linux you may need `python3-tk`). A legal warning has to be accepted before each scan. The default target is `127.0.0.1`; only scan hosts you are allowed to (for example `scanme.nmap.org`). Scans use TCP connect with 100 parallel connections and a 0.5 s timeout per port.
