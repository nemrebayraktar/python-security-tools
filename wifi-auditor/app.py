#!/usr/bin/env python3
"""
WiFi Güvenlik Denetim Aracı v2 (WiFi Security Audit Tool)
==========================================================
Kendi ağımı (veya izin aldığım ağları) hızlıca kontrol etmek için yazdığım araç.
Not: Tamamen pasif değildir. Ping taraması ve TCP connect port taraması yapar,
bu yüzden yalnızca izinli ağlarda kullanılmalıdır.

Hiçbir parola, kimlik bilgisi veya trafik içeriği toplanmaz/saklanmaz.

MODÜLLER:
  1. Ağ Bilgi Toplama (SSID, Gateway, DNS, Subnet)
  2. Cihaz Keşfi (ARP + Ping)
  3. Port Taraması (26 yaygın port)
  4. SSL/TLS Sertifika Kontrolü
  5. Rogue DHCP Sunucu Tespiti
  6. ARP Spoofing Belirtisi Kontrolü
  7. DNS Güvenlik Analizi (DoH/DoT)
  8. Gateway Güvenlik Denetimi
  9. Wi-Fi Şifreleme Derinlemesine Analiz
  10. NIST / CIS referanslı zafiyet raporu (HTML)
"""

import os, socket, subprocess, threading, platform
import ipaddress, ssl, re
from html import escape
from datetime import datetime
from flask import Flask, render_template, jsonify, request, abort

# templates klasörünü script'in yanından alıyoruz; başka dizinden
# çalıştırınca "TemplateNotFound" hatası vermesin diye
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

scan_results = {}
scan_in_progress = False
scan_progress = {"current": 0, "total": 0, "status": "idle", "message": ""}


@app.before_request
def sadece_yerel():
    # Uygulama sadece bu bilgisayardan kullanılsın. Başka bir sitenin
    # arka planda /api/scan/start çağırmasını da (CSRF / DNS rebinding) engelliyoruz.
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)
    if request.method == "POST" and request.headers.get("X-Requested-With") != "wifi-auditor":
        abort(403)


# ============================================================
# YARDIMCI FONKSİYONLAR
# ============================================================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Bilinmiyor"


def get_network_info():
    info = {
        "local_ip": get_local_ip(), "hostname": socket.gethostname(),
        "platform": platform.system(), "ssid": "Bilinmiyor", "bssid": "Bilinmiyor",
        "security": "Bilinmiyor", "channel": "Bilinmiyor", "gateway": "Bilinmiyor",
        "dns_servers": [], "subnet_mask": "Bilinmiyor", "network_prefix": "Bilinmiyor",
    }
    try:
        if platform.system() == "Darwin":
            try:
                r = subprocess.run(["networksetup", "-getairportnetwork", "en0"],
                                   capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and "Current Wi-Fi Network" in r.stdout:
                    info["ssid"] = r.stdout.split(": ", 1)[-1].strip()
            except Exception: pass
            try:
                ap = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
                if os.path.exists(ap):
                    r = subprocess.run([ap, "-I"], capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        for line in r.stdout.splitlines():
                            l = line.strip()
                            if l.startswith("SSID:"): info["ssid"] = l.split(":", 1)[-1].strip()
                            elif l.startswith("BSSID:"): info["bssid"] = l.split(":", 1)[-1].strip()
                            elif l.startswith("link auth:"): info["security"] = l.split(":", 1)[-1].strip()
                            elif l.startswith("channel:"): info["channel"] = l.split(":", 1)[-1].strip()
            except Exception: pass
            try:
                r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if "gateway:" in line: info["gateway"] = line.split(":")[-1].strip()
            except Exception: pass
            try:
                r = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=5)
                dns = set()
                for line in r.stdout.splitlines():
                    if "nameserver[" in line: dns.add(line.split(":", 1)[-1].strip())
                info["dns_servers"] = list(dns)[:4]
            except Exception: pass
            try:
                r = subprocess.run(["ifconfig", "en0"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if "netmask" in line and "inet " in line:
                        parts = line.strip().split()
                        for i, p in enumerate(parts):
                            if p == "netmask":
                                m = int(parts[i+1], 16)
                                info["subnet_mask"] = ".".join(str((m >> s) & 0xFF) for s in [24,16,8,0])
            except Exception: pass
        elif platform.system() == "Linux":
            # SSID: önce nmcli, yoksa iwgetid / iwconfig (dağıtıma göre hangisi kuruluysa)
            try:
                r = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SECURITY", "dev", "wifi"],
                                   capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    if line.startswith("yes:"):
                        # nmcli -t çıktısında BSSID içindeki ':' karakterleri '\:' olarak geliyor
                        p = re.split(r'(?<!\\):', line)
                        if len(p) >= 5:
                            info["ssid"] = p[1] or "Bilinmiyor"
                            info["bssid"] = p[2].replace("\\:", ":").lower()
                            info["channel"] = p[3]
                            info["security"] = p[4] or "OPEN"
                        break
            except Exception: pass
            if info["ssid"] == "Bilinmiyor":
                for cmd in (["iwgetid", "-r"], ["iwconfig"]):
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if cmd[0] == "iwgetid" and r.stdout.strip():
                            info["ssid"] = r.stdout.strip(); break
                        for line in r.stdout.splitlines():
                            if 'ESSID:"' in line:
                                info["ssid"] = line.split('ESSID:"')[-1].rstrip('" '); break
                    except Exception: pass
                    if info["ssid"] != "Bilinmiyor": break
            try:
                r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
                if r.stdout:
                    parts = r.stdout.split()
                    if "via" in parts: info["gateway"] = parts[parts.index("via") + 1]
            except Exception: pass
            try:
                r = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"], capture_output=True, text=True, timeout=5)
                for line in r.stdout.splitlines():
                    m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if m and m.group(1) == info["local_ip"]:
                        info["subnet_mask"] = str(ipaddress.IPv4Network(f"0.0.0.0/{m.group(2)}").netmask)
            except Exception: pass
            try:
                with open("/etc/resolv.conf") as f:
                    info["dns_servers"] = [l.split()[1] for l in f if l.startswith("nameserver") and len(l.split()) > 1][:4]
            except Exception: pass
        elif platform.system() == "Windows":
            # netsh çıktısı Windows diline göre değişebiliyor, o yüzden satırları
            # anahtar kelimeye değil biçime göre yakalamaya çalışıyoruz
            try:
                r = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True,
                                   text=True, timeout=5, errors="ignore")
                for line in r.stdout.splitlines():
                    if ":" not in line: continue
                    k, v = [x.strip() for x in line.split(":", 1)]
                    kl = k.lower()
                    if kl == "ssid": info["ssid"] = v
                    elif kl in ("bssid", "ap bssid"): info["bssid"] = v.lower()
                    elif kl in ("authentication", "kimlik doğrulama"): info["security"] = v
                    elif kl in ("channel", "kanal"): info["channel"] = v
            except Exception: pass
            try:
                r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10, errors="ignore")
                lines = r.stdout.splitlines(); dns = []; in_dns = False
                for line in lines:
                    ips = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
                    low = line.lower()
                    if "dns" in low and ips and ":" in line:
                        dns.extend(ips); in_dns = True; continue
                    if in_dns and ips and ":" not in line.split(ips[0])[0]:
                        dns.extend(ips); continue
                    in_dns = False
                    if ("gateway" in low or "geçidi" in low) and ips: info["gateway"] = ips[0]
                    if ("subnet" in low or "alt ağ" in low) and ips: info["subnet_mask"] = ips[0]
                info["dns_servers"] = list(dict.fromkeys(dns))[:4]
            except Exception: pass
    except Exception as e:
        info["error"] = str(e)
    try:
        if info["local_ip"] != "Bilinmiyor":
            p = info["local_ip"].split(".")
            info["network_prefix"] = f"{p[0]}.{p[1]}.{p[2]}"
    except Exception: pass
    return info


def scan_port(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def get_service_name(port):
    m = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
         135:"MS-RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",
         995:"POP3S",1433:"MSSQL",1521:"Oracle",3306:"MySQL",3389:"RDP",
         5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-Proxy",
         8443:"HTTPS-Alt",8888:"HTTP-Alt",9090:"WebUI",27017:"MongoDB"}
    return m.get(port, f"Port-{port}")


def check_ssl_cert(ip, port=443, timeout=3.0):
    result = {"valid": False, "issuer": "Bilinmiyor", "expires": "Bilinmiyor",
              "protocol": "Bilinmiyor", "issues": []}
    # CERT_NONE ile getpeercert() boş döner, o yüzden önce doğrulamalı deniyoruz.
    # Doğrulanamazsa (self-signed, süresi dolmuş vb.) bunu bulgu olarak yazıp
    # doğrulamasız bağlanarak sadece protokolü alıyoruz.
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                cert = ss.getpeercert()
                result["protocol"] = ss.version()
                if cert:
                    result["valid"] = True
                    if "issuer" in cert:
                        parts = []
                        for item in cert["issuer"]:
                            for k, v in item:
                                if k == "organizationName": parts.append(v)
                        result["issuer"] = ", ".join(parts) if parts else "Bilinmiyor"
                    if "notAfter" in cert: result["expires"] = cert["notAfter"]
                if result["protocol"] in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    result["issues"].append(f"Eski protokol: {result['protocol']}")
    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"Sertifika doğrulanamadı: {e.verify_message}")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                    result["protocol"] = ss.version()
        except Exception:
            pass
    except ssl.SSLError as e:
        result["issues"].append(f"SSL Hatası: {str(e)[:100]}")
    except Exception as e:
        result["issues"].append(f"Bağlantı hatası: {str(e)[:100]}")
    return result


def discover_hosts(network_prefix):
    hosts = []
    # ARP tablosu: macOS/Linux "arp -a" -> "? (192.168.1.1) at 0:1a:2b:..",
    # Windows "arp -a" -> "192.168.1.1   00-1a-2b-..   dynamic",
    # arp kurulu olmayan Linux'ta "ip neigh" -> "192.168.1.1 dev wlan0 lladdr 00:1a:.."
    out = ""
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, errors="ignore")
            if r.returncode == 0 and r.stdout.strip():
                out = r.stdout; break
        except Exception: pass
    prefix = network_prefix + "."
    for line in out.splitlines():
        m = re.search(r'\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
        if not m: continue
        ip = m.group(1)
        if not ip.startswith(prefix) or ip in [h["ip"] for h in hosts]: continue
        # macOS baştaki sıfırları yazmıyor (0:1a:2b...), o yüzden 1-2 hane kabul edip tamamlıyoruz
        mac_m = re.search(r'\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b', line)
        if not mac_m: continue
        mac = ":".join(x.zfill(2) for x in re.split(r'[:-]', mac_m.group(1).lower()))
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"): continue
        try: hn = socket.gethostbyaddr(ip)[0]
        except Exception: hn = ""
        hosts.append({"ip": ip, "mac": mac, "hostname": hn})
    if len(hosts) < 3:
        lock = threading.Lock()
        # ping parametreleri işletim sistemine göre değişiyor
        # (macOS'ta -W milisaniye, Linux'ta saniye)
        if platform.system() == "Windows": opts = ["-n", "1", "-w", "1000"]
        elif platform.system() == "Darwin": opts = ["-c", "1", "-t", "1"]
        else: opts = ["-c", "1", "-W", "1"]
        def ping_host(ip_str):
            try:
                r = subprocess.run(["ping"] + opts + [ip_str], capture_output=True, timeout=3)
                if r.returncode == 0:
                    try: hn = socket.gethostbyaddr(ip_str)[0]
                    except Exception: hn = ""
                    with lock:
                        if ip_str not in [h["ip"] for h in hosts]:
                            hosts.append({"ip": ip_str, "mac": "Bilinmiyor", "hostname": hn})
            except Exception: pass
        threads = []
        for i in range(1, 255):
            t = threading.Thread(target=ping_host, args=(f"{network_prefix}.{i}",))
            threads.append(t); t.start()
            if len(threads) >= 50:
                for t in threads: t.join(timeout=2)
                threads = []
        for t in threads: t.join(timeout=2)
    return hosts


def scan_visible_wifi():
    nets = []
    try:
        if platform.system() == "Darwin":
            ap = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if os.path.exists(ap):
                r = subprocess.run([ap, "-s"], capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    lines = r.stdout.strip().splitlines()
                    if len(lines) > 1:
                        for line in lines[1:]:
                            # SSID içinde boşluk olabilir, BSSID'yi referans alıp bölüyoruz
                            m = re.match(r'\s*(.*?)\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\s+(-?\d+)\s+\S+\s+\S+\s+\S+\s+(.*)$', line)
                            if m:
                                nets.append({"ssid": m.group(1), "rssi": m.group(3), "security": m.group(4).strip()})
        elif platform.system() == "Linux":
            r = subprocess.run(["nmcli","-t","-f","SSID,SIGNAL,SECURITY","dev","wifi","list"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                for line in r.stdout.strip().splitlines():
                    p = line.split(":")
                    if len(p) >= 3:
                        nets.append({"ssid": p[0], "rssi": p[1], "security": p[2] or "OPEN"})
        elif platform.system() == "Windows":
            r = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                               capture_output=True, text=True, timeout=15, errors="ignore")
            cur = None
            for line in r.stdout.splitlines():
                m = re.match(r'^SSID \d+\s*:\s*(.*)$', line.strip())
                if m:
                    cur = {"ssid": m.group(1), "rssi": "", "security": ""}; nets.append(cur); continue
                if cur is None or ":" not in line: continue
                k, v = [x.strip() for x in line.split(":", 1)]
                kl = k.lower()
                if kl in ("authentication", "kimlik doğrulama") and not cur["security"]:
                    cur["security"] = "OPEN" if v.lower() in ("open", "açık") else v
                elif kl in ("signal", "sinyal") and not cur["rssi"]:
                    cur["rssi"] = v
    except Exception: pass
    return nets


# ============================================================
# YENİ MODÜLLER (v2)
# ============================================================

def detect_rogue_dhcp(network_prefix, gateway_ip):
    findings = []; servers = []
    try:
        if platform.system() == "Darwin":
            r = subprocess.run(["ipconfig", "getpacket", "en0"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if "server_identifier" in line:
                        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if m: servers.append(m.group(1))
                    elif "lease_time" in line:
                        findings.append({"type": "info", "detail": f"DHCP Lease: {line.split(':')[-1].strip()}"})
    except Exception: pass
    servers = list(set(servers))
    if len(servers) > 1:
        findings.append({"type": "critical", "detail": f"Birden fazla DHCP sunucu: {', '.join(servers)}. Rogue DHCP!"})
    elif len(servers) == 1:
        if servers[0] == gateway_ip:
            findings.append({"type": "ok", "detail": f"DHCP sunucu ({servers[0]}) = gateway — normal."})
        else:
            findings.append({"type": "warning", "detail": f"DHCP ({servers[0]}) ≠ gateway ({gateway_ip}) — kontrol edin."})
    return {"dhcp_servers": servers, "findings": findings}


def detect_arp_spoofing(hosts, gateway_ip):
    findings = []; mac_map = {}
    for h in hosts:
        mac = h.get("mac", "Bilinmiyor")
        if mac != "Bilinmiyor":
            mac_map.setdefault(mac, []).append(h["ip"])
    for mac, ips in mac_map.items():
        if len(ips) > 1:
            if gateway_ip in ips:
                findings.append({"type": "critical",
                    "detail": f"Gateway ({gateway_ip}) MAC'i başka IP ile paylaşılıyor ({mac}): {', '.join(ips)}. ARP Spoofing!"})
            else:
                findings.append({"type": "warning",
                    "detail": f"MAC {mac} birden fazla IP'de: {', '.join(ips)}. ARP anomalisi."})
    for h in hosts:
        if h.get("mac", "").lower().startswith("ff:ff:ff"):
            findings.append({"type": "warning", "detail": f"{h['ip']} broadcast MAC — anormal."})
    if not findings:
        findings.append({"type": "ok", "detail": "ARP tablosunda spoofing belirtisi yok."})
    return {"mac_map": mac_map, "findings": findings}


def _ozel_ip_mi(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def analyze_dns_security(dns_servers):
    findings = []
    secure = {
        "1.1.1.1": ("Cloudflare", True, True, True), "1.0.0.1": ("Cloudflare", True, True, True),
        "8.8.8.8": ("Google", True, True, True), "8.8.4.4": ("Google", True, True, True),
        "9.9.9.9": ("Quad9", True, True, True), "149.112.112.112": ("Quad9", True, True, True),
        "208.67.222.222": ("OpenDNS", True, False, True), "208.67.220.220": ("OpenDNS", True, False, True),
    }
    analyzed = []
    for dns in dns_servers:
        info = {"ip": dns, "provider": "Bilinmiyor", "is_known_secure": False}
        if dns in secure:
            prov, doh, dot, dnssec = secure[dns]
            info.update({"provider": prov, "is_known_secure": True})
            findings.append({"type": "ok",
                "detail": f"DNS {dns} ({prov}) — güvenilir. DoH:{'var' if doh else 'yok'} DoT:{'var' if dot else 'yok'} DNSSEC:{'var' if dnssec else 'yok'}"})
        elif dns.startswith("127.") or dns.startswith("::1"):
            findings.append({"type": "info", "detail": f"DNS {dns} — yerel resolver."})
        elif _ozel_ip_mi(dns):
            findings.append({"type": "warning", "detail": f"DNS {dns} — ağ içi. DNS spoofing riski."})
        else:
            findings.append({"type": "warning", "detail": f"DNS {dns} — bilinmeyen. Güvenilirlik doğrulanmalı."})
        analyzed.append(info)
    if not dns_servers:
        findings.append({"type": "warning", "detail": "DNS bilgisi alınamadı."})
    return {"dns_details": analyzed, "findings": findings}


def audit_gateway(gateway_ip, port_results):
    findings = []; gw_ports = port_results.get(gateway_ip, [])
    if not gw_ports:
        findings.append({"type": "info", "detail": "Gateway'de açık port yok (firewall aktif olabilir)."})
        return {"gateway_ip": gateway_ip, "findings": findings}
    if 80 in gw_ports:
        if 443 in gw_ports:
            findings.append({"type": "warning", "detail": "Gateway: HTTP(80) + HTTPS(443) açık. HTTP kapatılmalı."})
        else:
            findings.append({"type": "critical", "detail": "Gateway yalnızca HTTP(80) — şifresiz yönetim paneli!"})
    if 443 in gw_ports and 80 not in gw_ports:
        findings.append({"type": "ok", "detail": "Gateway yalnızca HTTPS — iyi."})
    danger = {21:"FTP",23:"Telnet",135:"MS-RPC",445:"SMB",3389:"RDP",5900:"VNC",8080:"HTTP-Proxy"}
    for p, name in danger.items():
        if p in gw_ports:
            sev = "critical" if p in [23, 21, 445, 3389] else "warning"
            findings.append({"type": sev, "detail": f"Gateway port {p} ({name}) açık — kapatılmalı."})
    if 22 in gw_ports:
        findings.append({"type": "info", "detail": "Gateway SSH(22) açık — güçlü auth kullanın."})
    if 53 in gw_ports:
        findings.append({"type": "info", "detail": "Gateway DNS(53) sunuyor — yerel resolver."})
    return {"gateway_ip": gateway_ip, "findings": findings}


def analyze_wifi_deep(visible):
    findings = []
    cats = {"open":[],"wep":[],"wpa1":[],"wpa2":[],"wpa2e":[],"wpa3":[],"unknown":[]}
    for n in visible:
        sec = n.get("security","").upper(); ssid = n.get("ssid","?")
        if not sec or "OPEN" in sec or "NONE" in sec: cats["open"].append(ssid)
        elif "WEP" in sec: cats["wep"].append(ssid)
        elif "WPA3" in sec: cats["wpa3"].append(ssid)
        elif "WPA2" in sec and "ENTERPRISE" in sec: cats["wpa2e"].append(ssid)
        elif "WPA2" in sec: cats["wpa2"].append(ssid)
        elif "WPA" in sec: cats["wpa1"].append(ssid)
        else: cats["unknown"].append(ssid)
    if cats["open"]:
        findings.append({"type":"critical","detail":f"{len(cats['open'])} açık ağ: {', '.join(cats['open'][:5])}"})
    if cats["wep"]:
        findings.append({"type":"critical","detail":f"{len(cats['wep'])} WEP ağ (kırılabilir): {', '.join(cats['wep'][:5])}"})
    if cats["wpa1"]:
        findings.append({"type":"warning","detail":f"{len(cats['wpa1'])} WPA1 ağ (zayıf): {', '.join(cats['wpa1'][:5])}"})
    if cats["wpa3"]:
        findings.append({"type":"ok","detail":f"{len(cats['wpa3'])} WPA3 ağ — güçlü şifreleme."})
    if cats["wpa2e"]:
        findings.append({"type":"ok","detail":f"{len(cats['wpa2e'])} WPA2-Enterprise — kurumsal güvenlik."})
    return {"breakdown": cats, "findings": findings}


# ============================================================
# ZAFİYET ANALİZİ
# ============================================================

def analyze_all(net_info, hosts, port_results, modules):
    vulns = []
    sec = net_info.get("security","").lower()
    if sec and sec != "bilinmiyor":
        if "wep" in sec:
            vulns.append({"severity":"KRİTİK","category":"Şifreleme","title":"WEP Şifreleme",
                "description":"WEP kırılabilir.","recommendation":"WPA2/WPA3'e yükseltin.","cisa_ref":"NIST SP 800-153"})
        elif "wpa" in sec and "wpa2" not in sec and "wpa3" not in sec:
            vulns.append({"severity":"YÜKSEK","category":"Şifreleme","title":"WPA1 Şifreleme",
                "description":"WPA1 zafiyetlere sahip.","recommendation":"WPA2/WPA3'e geçin.","cisa_ref":"NIST SP 800-153"})
        elif "open" in sec or "none" in sec:
            vulns.append({"severity":"KRİTİK","category":"Şifreleme","title":"Açık (Şifresiz) Ağ",
                "description":"Trafik şifresiz. MITM riski yüksek.","recommendation":"VPN+WPA2/WPA3 zorunlu.","cisa_ref":"NIST SP 800-153"})

    risky = {21:("FTP","KRİTİK"),23:("Telnet","KRİTİK"),135:("MS-RPC","YÜKSEK"),139:("NetBIOS","YÜKSEK"),
             445:("SMB","YÜKSEK"),3389:("RDP","YÜKSEK"),5900:("VNC","YÜKSEK"),6379:("Redis","KRİTİK"),27017:("MongoDB","KRİTİK")}
    for ip, ports in port_results.items():
        for p in ports:
            if p in risky:
                svc, sev = risky[p]
                vulns.append({"severity":sev,"category":"Açık Port","title":f"{svc} Açık ({ip}:{p})",
                    "description":f"{svc} servisi açık.","recommendation":f"Port {p} kapatılmalı.","cisa_ref":"NIST SP 800-123"})
        if len(ports) > 10:
            vulns.append({"severity":"ORTA","category":"Yapılandırma","title":f"Geniş Saldırı Yüzeyi ({ip})",
                "description":f"{len(ports)} açık port.","recommendation":"Gereksiz servisleri kapatın.","cisa_ref":"CIS Controls v8"})

    mod_vuln_map = {
        "rogue_dhcp": {"critical":("KRİTİK","DHCP","Rogue DHCP","Port security uygulayın.","CIS Controls v8"),
                       "warning":("ORTA","DHCP","DHCP Anomalisi","DHCP yapılandırmasını doğrulayın.","NIST SP 800-153")},
        "arp_spoofing": {"critical":("KRİTİK","ARP","ARP Spoofing","DAI etkinleştirin.","NIST SP 800-153"),
                         "warning":("YÜKSEK","ARP","ARP Anomalisi","ARP tablosunu kontrol edin.","NIST SP 800-153")},
        "dns_security": {"warning":("ORTA","DNS","DNS Güvenlik Uyarısı","DoH/DoT kullanın.","NIST SP 800-81-2")},
        "gateway_audit": {"critical":("KRİTİK","Gateway","Gateway Güvenlik İhlali","Yönetim panelini HTTPS yapın.","CISA TA18-106A"),
                          "warning":("ORTA","Gateway","Gateway Uyarısı","Yapılandırmayı gözden geçirin.","CIS Controls v8")},
        "wifi_encryption": {"critical":("YÜKSEK","Wi-Fi Ortamı","Güvensiz Ağlar","Evil Twin riski — uyarı verin.","NIST SP 800-153")}
    }
    for mod_key, mapping in mod_vuln_map.items():
        mod_data = modules.get(mod_key, {})
        for finding in mod_data.get("findings", []):
            ft = finding["type"]
            if ft in mapping:
                sev, cat, title, rec, ref = mapping[ft]
                vulns.append({"severity":sev,"category":cat,"title":title,
                    "description":finding["detail"],"recommendation":rec,"cisa_ref":ref})

    order = {"KRİTİK":0,"YÜKSEK":1,"ORTA":2,"DÜŞÜK":3,"BİLGİ":4}
    vulns.sort(key=lambda x: order.get(x["severity"], 5))
    return vulns


def calc_risk(vulns):
    if not vulns: return 0
    w = {"KRİTİK":25,"YÜKSEK":15,"ORTA":8,"DÜŞÜK":3}
    return min(sum(w.get(v.get("severity",""),0) for v in vulns), 100)


# ============================================================
# FLASK ROTALARI
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/network-info")
def api_network_info():
    return jsonify(get_network_info())

@app.route("/api/visible-networks")
def api_visible_networks():
    return jsonify(scan_visible_wifi())

@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    global scan_results, scan_in_progress, scan_progress
    if scan_in_progress: return jsonify({"error":"Tarama devam ediyor"}), 400
    scan_in_progress = True
    scan_progress = {"current":0,"total":100,"status":"running","message":"Başlatılıyor..."}

    def run():
        global scan_results, scan_in_progress, scan_progress
        try:
            R = {"timestamp":datetime.now().isoformat(),"network_info":{},"hosts":[],"port_results":{},
                 "ssl_results":{},"vulnerabilities":[],"visible_networks":[],"modules":{},"summary":{}}

            scan_progress.update({"message":"Ağ bilgileri...","current":5})
            R["network_info"] = get_network_info()

            scan_progress.update({"message":"Wi-Fi tarama...","current":10})
            R["visible_networks"] = scan_visible_wifi()

            scan_progress.update({"message":"Wi-Fi şifreleme analizi...","current":15})
            R["modules"]["wifi_encryption"] = analyze_wifi_deep(R["visible_networks"])

            prefix = R["network_info"].get("network_prefix","")
            if prefix and prefix != "Bilinmiyor":
                scan_progress.update({"message":"Cihaz keşfi...","current":20})
                R["hosts"] = discover_hosts(prefix)

            gw = R["network_info"].get("gateway","Bilinmiyor")
            scan_progress.update({"message":"DHCP kontrolü...","current":28})
            R["modules"]["rogue_dhcp"] = detect_rogue_dhcp(prefix, gw)

            scan_progress.update({"message":"ARP spoofing kontrolü...","current":33})
            R["modules"]["arp_spoofing"] = detect_arp_spoofing(R["hosts"], gw)

            ports_to_scan = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
                             1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9090,27017]
            targets = []
            if gw and gw != "Bilinmiyor": targets.append(gw)
            for h in R["hosts"][:20]:
                if h["ip"] not in targets: targets.append(h["ip"])
            total = len(targets) * len(ports_to_scan); done = 0
            for tip in targets:
                scan_progress["message"] = f"Port tarama: {tip}"
                op = []
                for p in ports_to_scan:
                    if scan_port(tip, p, 0.8): op.append(p)
                    done += 1
                    if total > 0: scan_progress["current"] = 35 + int((done/total)*40)
                if op: R["port_results"][tip] = op

            scan_progress.update({"message":"SSL kontrolü...","current":78})
            for ip, ports in R["port_results"].items():
                if 443 in ports: R["ssl_results"][ip] = check_ssl_cert(ip)

            scan_progress.update({"message":"DNS güvenlik analizi...","current":83})
            R["modules"]["dns_security"] = analyze_dns_security(R["network_info"].get("dns_servers",[]))

            scan_progress.update({"message":"Gateway denetimi...","current":88})
            R["modules"]["gateway_audit"] = audit_gateway(gw, R["port_results"])

            scan_progress.update({"message":"Zafiyet analizi...","current":93})
            R["vulnerabilities"] = analyze_all(R["network_info"], R["hosts"], R["port_results"], R["modules"])

            sc = {"KRİTİK":0,"YÜKSEK":0,"ORTA":0,"DÜŞÜK":0}
            for v in R["vulnerabilities"]:
                s = v.get("severity","")
                if s in sc: sc[s] += 1
            R["summary"] = {"total_hosts":len(R["hosts"]),
                "total_open_ports":sum(len(p) for p in R["port_results"].values()),
                "total_vulnerabilities":len(R["vulnerabilities"]),
                "severity_counts":sc, "risk_score":calc_risk(R["vulnerabilities"]),
                "modules_run":list(R["modules"].keys())}

            scan_progress.update({"current":100,"message":"Tamamlandı!","status":"completed"})
            scan_results = R
        except Exception as e:
            scan_progress.update({"status":"error","message":str(e)})
        finally:
            scan_in_progress = False

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/scan/progress")
def api_scan_progress():
    return jsonify(scan_progress)

@app.route("/api/scan/results")
def api_scan_results():
    return jsonify(scan_results)

@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    if not scan_results: return jsonify({"error":"Önce tarama yapın"}), 400
    html = generate_report(scan_results)
    d = os.path.expanduser("~/wifi_audit_reports"); os.makedirs(d, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ssid = re.sub(r'[^\w\-]','_', scan_results.get("network_info",{}).get("ssid","unknown"))
    fn = f"wifi_audit_{ssid}_{ts}.html"
    fp = os.path.join(d, fn)
    with open(fp, "w", encoding="utf-8") as f: f.write(html)
    return jsonify({"status":"success","filepath":fp,"filename":fn})


def generate_report(R):
    net=R.get("network_info",{}); vulns=R.get("vulnerabilities",[]); summary=R.get("summary",{})
    modules=R.get("modules",{}); ts=R.get("timestamp",datetime.now().isoformat())
    sc={"KRİTİK":"#dc2626","YÜKSEK":"#ea580c","ORTA":"#d97706","DÜŞÜK":"#2563eb"}
    vr=""
    # SSID, hostname gibi alanlar dışarıdan gelir (komşu ağın adı bile olabilir),
    # rapora basmadan önce escape ediyoruz. Yoksa SSID'ye yazılan <script> raporda çalışır.
    e=lambda x: escape(str(x))
    for i,v in enumerate(vulns,1):
        c=sc.get(v["severity"],"#6b7280")
        vr+=f'<tr><td>{i}</td><td><span style="background:{c};color:#fff;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600">{e(v["severity"])}</span></td><td>{e(v["category"])}</td><td><b>{e(v["title"])}</b><br><small style="color:#666">{e(v["description"])}</small></td><td><small>{e(v["recommendation"])}</small></td><td><small style="color:#999">{e(v.get("cisa_ref",""))}</small></td></tr>'
    mn={"rogue_dhcp":"DHCP Tespiti","arp_spoofing":"ARP Kontrolü","dns_security":"DNS Analizi","gateway_audit":"Gateway Denetimi","wifi_encryption":"Wi-Fi Şifreleme"}
    ti={"ok":"OK","warning":"Uyarı","critical":"Kritik","info":"Bilgi"}
    ms=""
    for k,d in modules.items():
        fs=d.get("findings",[])
        if fs:
            rows="".join(f'<tr><td>{ti.get(f["type"],"")}</td><td>{e(f["detail"])}</td></tr>' for f in fs)
            ms+=f'<div style="background:#fff;border-radius:10px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)"><h3 style="margin-bottom:12px;font-size:16px">{mn.get(k,k)}</h3><table style="width:100%;font-size:14px;border-collapse:collapse"><tbody>{rows}</tbody></table></div>'
    sev=summary.get("severity_counts",{}); risk=summary.get("risk_score",0)
    rc="#22c55e" if risk<25 else "#d97706" if risk<50 else "#dc2626"
    return f'''<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>WiFi Denetim — {e(net.get("ssid","?"))}</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:system-ui,sans-serif;color:#1e293b;padding:40px;max-width:1100px;margin:0 auto;background:#f8fafc;line-height:1.6}}
.h{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:40px;border-radius:12px;margin-bottom:30px}}.h h1{{font-size:24px}}.h p{{opacity:.7;font-size:14px;margin-top:6px}}
.g{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}.c{{background:#fff;border-radius:10px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.1)}}.c .n{{font-size:36px;font-weight:700}}.c .l{{font-size:12px;color:#64748b}}
table{{width:100%;border-collapse:collapse;font-size:14px}}th{{background:#f1f5f9;padding:10px 12px;text-align:left;font-size:12px;font-weight:600}}td{{padding:10px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
.d{{background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;padding:16px;margin-top:24px;font-size:13px;color:#92400e}}.f{{text-align:center;margin-top:24px;font-size:12px;color:#94a3b8}}</style></head>
<body><div class="h"><h1>Wi-Fi Güvenlik Denetim Raporu v2</h1><p>{e(net.get("ssid","—"))} • {datetime.fromisoformat(ts).strftime("%d/%m/%Y %H:%M")} • Gateway: {e(net.get("gateway","—"))}</p></div>
<div class="g"><div class="c"><div class="n" style="color:{rc}">{risk}</div><div class="l">Risk Puanı</div></div><div class="c"><div class="n" style="color:#dc2626">{sev.get("KRİTİK",0)}</div><div class="l">Kritik</div></div><div class="c"><div class="n" style="color:#ea580c">{sev.get("YÜKSEK",0)}</div><div class="l">Yüksek</div></div><div class="c"><div class="n" style="color:#d97706">{sev.get("ORTA",0)}</div><div class="l">Orta</div></div></div>
<div style="background:#fff;border-radius:10px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)"><h3 style="margin-bottom:12px">Zafiyetler ({len(vulns)})</h3>
{"<p style='color:#22c55e;font-weight:600'>Zafiyet yok.</p>" if not vulns else f"<table><thead><tr><th>#</th><th>Önem</th><th>Kategori</th><th>Zafiyet</th><th>Öneri</th><th>Ref</th></tr></thead><tbody>{vr}</tbody></table>"}</div>
{ms}
<div class="d"><b>Not:</b> Bu rapor yalnızca yetkili denetim amacıyla oluşturulmuştur. İzinsiz tarama yasalara aykırıdır.</div>
<div class="f">WiFi Güvenlik Denetim Aracı v2 — {datetime.now().strftime("%d/%m/%Y %H:%M")}</div></body></html>'''


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", action="store_true")
    # macOS 12+ sürümlerinde 5000 portunu AirPlay Alıcısı kullanıyor,
    # bu yüzden varsayılanı 5050 yaptım; doluysa boş bir port seçiliyor
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()
    try:
        with socket.socket() as s_:
            s_.bind(("127.0.0.1", args.port))
    except OSError:
        with socket.socket() as s_:
            s_.bind(("127.0.0.1", 0)); yeni = s_.getsockname()[1]
        print(f"{args.port} portu kullanımda, {yeni} portu kullanılacak.")
        args.port = yeni
    print(f"Adres: http://127.0.0.1:{args.port}  (kapatmak için Ctrl+C)")
    # debug=True kullanmıyoruz: Werkzeug debugger kod çalıştırmaya izin veriyor
    webview = None
    if not args.browser:
        try:
            import webview
        except ImportError:
            print("PyWebView kurulu değil, tarayıcı modunda açılıyor. Adresi tarayıcıda açın.")
    if webview is None:
        app.run(host="127.0.0.1", port=args.port, debug=False)
    else:
        def sf(): app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
        th = threading.Thread(target=sf, daemon=True); th.start()
        import time; time.sleep(1.5)
        try:
            webview.create_window("WiFi Denetim v2", f"http://127.0.0.1:{args.port}",
                                  width=1280, height=860, resizable=True, min_size=(900, 600))
            webview.start()
        except Exception as ex:
            # Linux'ta GTK/Qt yoksa pencere açılamıyor; sunucu çalışmaya devam etsin
            print(f"Pencere açılamadı ({ex}). Tarayıcıdan http://127.0.0.1:{args.port} adresini açın.")
            try: th.join()
            except KeyboardInterrupt: pass
