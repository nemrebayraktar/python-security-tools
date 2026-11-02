# WiFi Auditor

Türkçe | [English](#english)

Bağlı olduğum Wi-Fi ağının temel güvenlik durumunu hızlıca görmek için yazdığım Flask tabanlı araç. Masaüstü penceresinde (PyWebView) veya tarayıcıda çalışır, sonunda HTML rapor üretir. Kablosuz ağ farkındalık çalışmamda gördüğüm konuları (açık ağlar, eski şifreleme, HTTP üzerinden yönetim paneli gibi) kendi ağımda kontrol edebilmek için hazırladım.

## Ne kontrol eder

1. Bağlı ağ bilgisi: SSID, şifreleme türü, kanal, gateway, DNS, subnet
2. Çevredeki görünür Wi-Fi ağları ve şifreleme türleri (açık, WEP, WPA, WPA2, WPA3)
3. Cihaz keşfi: ARP tablosu, gerekirse /24 ağda ping taraması
4. Gateway ve bulunan ilk 20 cihazda 26 yaygın TCP port
5. 443 açıksa TLS sürümü ve sertifika doğrulaması
6. Birden fazla DHCP sunucusu (rogue DHCP) ve ARP tablosunda aynı MAC'i paylaşan IP'ler
7. DNS sunucularının bilinen sağlayıcı / ağ içi olup olmadığı
8. Sonuçlara göre NIST SP 800-153 ve CIS Controls referanslı bulgu listesi ve risk puanı

## Ne toplar, ne toplamaz

- Toplar: ağ adı (SSID), BSSID, yerel IP, gateway, DNS, ağdaki cihazların IP / MAC / hostname bilgisi, açık port numaraları. Bunlar yalnızca bellekte tutulur ve "Rapor Oluştur" denirse `~/wifi_audit_reports/` altına HTML olarak kaydedilir. Hiçbir yere gönderilmez.
- Toplamaz: parola, kimlik bilgisi, Wi-Fi anahtarı, trafik içeriği. Captive portal / sahte giriş sayfası değildir, kimseden bilgi istemez.
- Raporlar ağdaki cihazları içerdiği için paylaşmadan önce gözden geçirin, repoya eklemeyin.

## Etik kullanım

Araç tamamen pasif değildir: ping taraması ve port taraması yapar. Bu yüzden yalnızca kendi ağınızda veya ağ sahibinden açık (tercihen yazılı) izin aldığınız ağlarda kullanın. Ortak kullanılan ağlarda (yurt, ofis, kafe) ağ yöneticisinin izni olmadan çalıştırmayın. İzinsiz tarama TCK 243-245 kapsamında suçtur. Uygulama açılışta bu koşulların kabul edilmesini ister.

## Kurulum ve çalıştırma

Python 3.9 veya üstü gerekir. Tek zorunlu bağımlılık Flask; pywebview isteğe bağlıdır, kurulu değilse uygulama tarayıcıda açılır.

macOS / Linux:

```bash
cd wifi-auditor
chmod +x setup.sh
./setup.sh          # .venv sanal ortamını kurar, run.sh ve run_browser.sh oluşturur
./run_browser.sh    # tarayıcıda http://127.0.0.1:5050 adresini açın
./run.sh            # pywebview kuruluysa ayrı pencerede açılır
```

Windows (PowerShell):

```powershell
cd wifi-auditor
py -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py --browser
```

Elle kurulum (her sistemde): `python3 -m venv .venv`, `.venv/bin/pip install -r requirements.txt`, `.venv/bin/python app.py --browser`.

Varsayılan port 5050'dir (macOS'ta 5000 portunu AirPlay Alıcısı kullandığı için değiştirildi). Port doluysa uygulama boş bir port seçer ve adresi terminale yazar; istenirse `--port 8000` ile değiştirilebilir. Sunucu yalnızca 127.0.0.1 üzerinde dinler; başka bir sitenin arka planda tarama başlatması engellenmiştir.

## Kullandığı sistem komutları

Araç ağ bilgilerini işletim sisteminin kendi komutlarından okur. Bir komut yoksa o bilgi "Bilinmiyor" olarak gelir, uygulama çalışmaya devam eder.

| Bilgi | macOS | Linux | Windows |
|---|---|---|---|
| SSID, şifreleme, kanal | `networksetup`, `airport -I` | `nmcli`, yoksa `iwgetid` / `iwconfig` | `netsh wlan show interfaces` |
| Gateway, DNS, subnet | `route -n get default`, `scutil --dns`, `ifconfig` | `ip route`, `ip addr`, `/etc/resolv.conf` | `ipconfig /all` |
| Çevredeki ağlar | `airport -s` | `nmcli dev wifi list` | `netsh wlan show networks mode=bssid` |
| Cihaz keşfi | `arp -a`, `ping` | `arp -a` veya `ip neigh`, `ping` | `arp -a`, `ping` |
| DHCP sunucusu | `ipconfig getpacket en0` | - | - |

Bilinen kısıtlar:
- macOS 14.4 ve sonrasında Apple `airport` komutunu kaldırdı. Bu sürümlerde çevredeki ağ listesi ve bazı Wi-Fi detayları boş gelebilir.
- macOS tarafında arayüz adı `en0` olarak varsayılır.
- Cihaz keşfi ağın /24 olduğunu varsayar. Rogue DHCP kontrolü yalnızca macOS'ta çalışır.
- Windows'ta `netsh` çıktısı dil ayarına göre değişebilir; İngilizce ve Türkçe başlıklar okunur.

---

## English

A Flask-based tool I wrote to quickly check the basic security posture of the Wi-Fi network I am connected to. It runs in a desktop window (PyWebView) or in the browser and produces an HTML report. I built it to check, on my own network, the issues I saw in my wireless awareness study (open networks, legacy encryption, HTTP-only admin panels and so on).

What it checks: connected network details, visible networks and their encryption, host discovery (ARP, ping sweep on a /24), 26 common TCP ports on the gateway and up to 20 hosts, TLS version and certificate validation on 443, rogue DHCP and duplicate MAC (ARP spoofing signs), DNS servers, and a findings list with a risk score referencing NIST SP 800-153 and CIS Controls.

What it collects: SSID, BSSID, local IP, gateway, DNS, IP / MAC / hostname of devices on the network and open port numbers. Kept in memory and saved as an HTML report under `~/wifi_audit_reports/` only when you click "generate report". Nothing is sent anywhere. It does not collect passwords, credentials, Wi-Fi keys or traffic content, and it is not a captive portal.

Ethical use: the tool is not purely passive (it does a ping sweep and a port scan). Use it only on your own network or with explicit, preferably written, permission from the network owner. Do not run it on shared networks (dorms, offices, cafés) without the administrator's permission. The app asks you to accept these terms on start.

Setup: Python 3.9+. Flask is the only required dependency; pywebview is optional and the app falls back to the browser without it. On macOS / Linux run `./setup.sh` (creates a `.venv`), then `./run_browser.sh` and open http://127.0.0.1:5050. On Windows: `py -m venv .venv`, `.venv\Scripts\pip install -r requirements.txt`, `.venv\Scripts\python app.py --browser`. The default port is 5050 because macOS uses 5000 for AirPlay Receiver; if the port is busy the app picks a free one and prints it. The server only listens on 127.0.0.1 and blocks cross-site requests that try to start a scan.

System commands used: macOS `networksetup`, `airport`, `route`, `scutil`, `ifconfig`, `ipconfig getpacket`; Linux `nmcli` (or `iwgetid` / `iwconfig`), `ip route`, `ip addr`, `ip neigh`, `/etc/resolv.conf`; Windows `netsh wlan`, `ipconfig /all`; all systems `arp -a` and `ping`. If a command is missing the field shows as unknown and the scan continues.

Known limits: Apple removed the `airport` tool in macOS 14.4+, so the nearby network list may be empty there; macOS assumes the `en0` interface; host discovery assumes a /24; the rogue DHCP check works only on macOS.
