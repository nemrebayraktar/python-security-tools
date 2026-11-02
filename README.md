# Python Security Tools

Türkçe | [English](#english)

Denetim ve güvenlik çalışmalarım sırasında öğrenmek ve işimi kolaylaştırmak için yazdığım küçük Python araçları. Hepsi eğitim amaçlıdır ve yalnızca sahibi olduğunuz ya da yazılı izin aldığınız sistemlerde kullanılmalıdır.

| Klasör | Ne yapar |
|---|---|
| [abuse-checker](abuse-checker/) | Web sunucusu access.log dosyasındaki IP'leri çıkarır, AbuseIPDB'de sorgular ve sonucu SQLite'a yazar. |
| [port-scanner](port-scanner/) | Tkinter arayüzlü TCP port tarayıcı. Açık portları ve olası risklerini gösterir, sonuçları SQLite'a kaydeder. |
| [wifi-auditor](wifi-auditor/) | Bağlı olunan Wi-Fi ağını kontrol eden Flask tabanlı araç: şifreleme türü, cihaz keşfi, yaygın portlar, DHCP/ARP/DNS kontrolleri ve HTML rapor. |

Her klasörün kendi README dosyasında adım adım kurulum ve çalıştırma anlatılıyor, port-scanner ve wifi-auditor için ekran görüntüleri de var. Kodu indirmek için:

```bash
git clone https://github.com/nemrebayraktar/python-security-tools.git
```

Notlar:
- API anahtarı gibi gizli bilgiler koda yazılmaz, ortam değişkeninden okunur.
- `.db` dosyaları ve gerçek log dosyaları repoya eklenmez (`.gitignore`). Örnek log olarak yalnızca dokümantasyon için ayrılmış IP blokları (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) kullanıldı.
- İzinsiz tarama yapmak suçtur (TCK 243-245). Bu araçları kullanırken tüm sorumluluk kullanıcıya aittir.
- Lisans: MIT ([LICENSE](LICENSE)).

---

## English

Small Python tools I wrote while learning and doing audit/security work. They are for education only and should be used only on systems you own or have written permission to test.

| Folder | What it does |
|---|---|
| [abuse-checker](abuse-checker/) | Extracts IPs from a web server access.log, checks them on AbuseIPDB and stores the results in SQLite. |
| [port-scanner](port-scanner/) | TCP port scanner with a Tkinter GUI. Shows open ports with possible risks and saves results to SQLite. |
| [wifi-auditor](wifi-auditor/) | Flask-based tool that checks the Wi-Fi network you are connected to: encryption type, host discovery, common ports, DHCP/ARP/DNS checks and an HTML report. |

Each folder has its own README with step-by-step setup and run instructions; port-scanner and wifi-auditor also have screenshots. To get the code:

```bash
git clone https://github.com/nemrebayraktar/python-security-tools.git
```

Notes:
- Secrets such as API keys are never hard-coded; they are read from environment variables.
- `.db` files and real log files are not committed (`.gitignore`). The sample log only uses documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Unauthorised scanning is illegal. You are responsible for how you use these tools.
- License: MIT ([LICENSE](LICENSE)).
