import os
import socket
import sqlite3
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Sonuçlar script'in yanındaki veritabanına yazılır
DB_YOLU = os.path.join(os.path.dirname(os.path.abspath(__file__)), "port_sonuclari.db")

# Açık port risk açıklamaları
port_riskleri = {
    21: "FTP - Anonymous login açık olabilir, dosya sızdırılabilir.",
    22: "SSH - Zayıf parola veya brute-force saldırılarına açık olabilir.",
    23: "Telnet - Şifrelenmemiş bağlantı, şifreler ağda açık gider.",
    25: "SMTP - Spam gönderimi, açık relay riski taşır.",
    53: "DNS - DNS cache poisoning, amplification saldırıları.",
    80: "HTTP - XSS, SQL injection, açık web sayfaları.",
    110: "POP3 - Düz metinle şifre gönderimi, oturum çalma.",
    139: "NetBIOS - Dosya paylaşımı açıklıkları, SMB zafiyetleri.",
    143: "IMAP - E-posta sızdırma, brute-force.",
    443: "HTTPS - Zayıf SSL/TLS yapılandırmaları.",
    445: "SMB - EternalBlue, WannaCry gibi saldırılara açık.",
    3306: "MySQL - Yetkisiz erişim, zayıf parola.",
    3389: "RDP - Brute-force, BlueKeep zafiyeti."
}
VARSAYILAN_RISK = "Bu port için özel bir açıklama yok, servisin gerekli olup olmadığı kontrol edilmeli."

# getservbyport bazı sistemlerde (özellikle yüksek portlarda) isim döndürmüyor,
# o zaman bu listeye bakıyoruz
bilinen_portlar = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 2375: "docker", 3000: "http-dev",
    3306: "mysql", 3389: "rdp", 5000: "http-flask/airplay", 5432: "postgresql",
    5900: "vnc", 5901: "vnc-1", 6080: "novnc", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"
}


def port_acik_mi(ip, port, timeout=0.5):
    # with kullanınca hata olsa bile soket kapanıyor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as soket:
        soket.settimeout(timeout)
        return soket.connect_ex((ip, port)) == 0


def servis_adi(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return bilinen_portlar.get(port, "Bilinmiyor")


def tara(hedef_ip, baslangic, bitis, timeout=0.5):
    # Portları tek tek beklemek yerine 100 thread ile paralel tarıyoruz
    portlar = range(baslangic, bitis + 1)
    with ThreadPoolExecutor(max_workers=100) as havuz:
        sonuclar = havuz.map(lambda p: (p, port_acik_mi(hedef_ip, p, timeout)), portlar)
        return [p for p, acik in sonuclar if acik]


def sonuclari_kaydet(hedef_ip, acik_portlar, db_yolu=DB_YOLU):
    conn = sqlite3.connect(db_yolu)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            port INTEGER,
            service TEXT,
            risk_summary TEXT,
            scan_time TEXT
        )
    ''')
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for port in acik_portlar:
        cursor.execute(
            "INSERT INTO ports (ip_address, port, service, risk_summary, scan_time) VALUES (?, ?, ?, ?, ?)",
            (hedef_ip, port, servis_adi(port), port_riskleri.get(port, VARSAYILAN_RISK), scan_time)
        )
    conn.commit()
    conn.close()


# --- Arayüz ---
# Not: tkinter thread-safe değil. Tarama ayrı thread'de çalışıyor,
# ekrana yazma işlerini pencere.after ile ana thread'e bırakıyoruz.

def yaz(metin):
    pencere.after(0, lambda: sonuc_ekrani.insert(tk.END, metin))


def baslat_tarama_thread():
    hedef = entry_hedef.get().strip()
    if not hedef:
        messagebox.showerror("Hata", "Lütfen bir hedef IP veya alan adı girin.")
        return

    try:
        baslangic = int(entry_baslangic.get().strip())
        bitis = int(entry_bitis.get().strip())
    except ValueError:
        messagebox.showerror("Hata", "Port numaraları sayı olmalıdır.")
        return
    if not (1 <= baslangic <= bitis <= 65535):
        messagebox.showerror("Hata", "Geçersiz port aralığı. Portlar 1-65535 arasında olmalı ve başlangıç bitişten büyük olmamalıdır.")
        return

    try:
        hedef_ip = socket.gethostbyname(hedef)
    except socket.gaierror:
        messagebox.showerror("Hata", "Hedef adres çözümlenemedi. Geçerli bir IP veya alan adı girin.")
        return

    # Yasal uyarı mesajını göster
    onay = messagebox.askyesno(
        "Yasal Uyarı",
        "Lütfen dikkat!\n\n"
        "Port taraması yapacağınız alan adının veya IP adresinin sahibinden YAZILI İZİN almanız GEREKMEKTEDİR. "
        "İzinsiz tarama yapmak, yasal sonuçlar doğurabilir ve ciddi hukuki yaptırımlara yol açabilir.\n\n"
        "Bu aracı kullanarak yapacağınız tüm işlemlerden tamamen siz sorumlusunuzdur. "
        "Devam etmek istiyor musunuz?"
    )
    if not onay:
        messagebox.showinfo("İptal Edildi", "Tarama işlemi iptal edildi.")
        return

    btn_tara.config(state=tk.DISABLED)
    sonuc_ekrani.delete(1.0, tk.END)
    sonuc_ekrani.insert(tk.END, f"Taranıyor: {hedef} ({hedef_ip}) port {baslangic}-{bitis}\n\n")
    sonuc_ekrani.insert(tk.END, "Lütfen bekleyin, tarama devam ediyor...\n\n")
    threading.Thread(target=port_tara, args=(hedef_ip, baslangic, bitis), daemon=True).start()


def port_tara(hedef_ip, baslangic, bitis):
    try:
        acik_portlar = tara(hedef_ip, baslangic, bitis)
        for port in acik_portlar:
            yaz(f"[AÇIK] {port} | Servis: {servis_adi(port)}\n")
        yaz("\nTarama tamamlandı.\n\n")

        if acik_portlar:
            yaz("Açık portlara ait olası güvenlik riskleri:\n")
            for port in acik_portlar:
                yaz(f"- Port {port}: {port_riskleri.get(port, VARSAYILAN_RISK)}\n")
            sonuclari_kaydet(hedef_ip, acik_portlar)
            yaz(f"\nSonuçlar kaydedildi: {DB_YOLU}\n")
        else:
            yaz("Hiçbir port açık değil ya da hedef erişilemiyor / portlar filtrelenmiş.\n")
    except Exception as e:
        yaz(f"\nTarama sırasında hata oluştu: {e}\n")
    finally:
        pencere.after(0, lambda: btn_tara.config(state=tk.NORMAL))


if __name__ == "__main__":
    pencere = tk.Tk()
    pencere.title("MrP's Eye")
    pencere.geometry("700x550")
    pencere.resizable(False, False)

    font_label = ("Arial", 10, "bold")
    font_button = ("Arial", 10, "bold")

    tk.Label(pencere, text="Hedef IP / Alan Adı:", font=font_label).pack(pady=(10, 0))
    entry_hedef = tk.Entry(pencere, width=50, bd=2, relief="groove")
    entry_hedef.pack(pady=5)
    entry_hedef.insert(0, "127.0.0.1")  # sadece izinli hedefler (ör. kendi makinen, scanme.nmap.org)

    tk.Label(pencere, text="Başlangıç Portu:", font=font_label).pack(pady=(5, 0))
    entry_baslangic = tk.Entry(pencere, width=20, bd=2, relief="groove")
    entry_baslangic.pack(pady=5)
    entry_baslangic.insert(0, "1")

    tk.Label(pencere, text="Bitiş Portu:", font=font_label).pack(pady=(5, 0))
    entry_bitis = tk.Entry(pencere, width=20, bd=2, relief="groove")
    entry_bitis.pack(pady=5)
    entry_bitis.insert(0, "1024")

    btn_tara = tk.Button(pencere, text="Taramayı Başlat", command=baslat_tarama_thread, bg="#4CAF50", fg="black",
                         font=font_button, padx=15, pady=8, relief="raised", bd=3)
    btn_tara.pack(pady=15)

    sonuc_ekrani = scrolledtext.ScrolledText(pencere, width=80, height=20, bd=2, relief="sunken",
                                             font=("Consolas", 9), wrap=tk.WORD)
    sonuc_ekrani.pack(padx=10, pady=10)

    pencere.mainloop()
