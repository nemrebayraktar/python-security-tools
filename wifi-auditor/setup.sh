#!/bin/bash
# WiFi Güvenlik Denetim Aracı - kurulum (macOS / Linux)
# Proje klasöründe bir sanal ortam (.venv) kurar, bağımlılıkları yükler
# ve run.sh / run_browser.sh scriptlerini oluşturur.
# Homebrew Python'da sistem geneline pip install engellendiği için
# (externally-managed-environment hatası) sanal ortam kullanıyoruz.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[1/4] Python kontrol ediliyor..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "  python3 bulunamadı. macOS: brew install python3, Linux: sudo apt install python3 python3-venv"
    exit 1
fi
python3 --version

echo "[2/4] Sanal ortam oluşturuluyor (.venv)..."
if [ ! -d .venv ]; then
    python3 -m venv .venv || { echo "  venv oluşturulamadı. Linux'ta: sudo apt install python3-venv"; exit 1; }
fi
.venv/bin/python -m pip install --upgrade pip --quiet || true

echo "[3/4] Bağımlılıklar kuruluyor..."
.venv/bin/python -m pip install -r requirements.txt --quiet
echo "  Flask kuruldu"
# pywebview zorunlu değil; kurulamazsa uygulama tarayıcıda açılır
if .venv/bin/python -m pip install -r requirements-desktop.txt --quiet 2>/dev/null; then
    echo "  pywebview kuruldu (pencere modu)"
else
    echo "  pywebview kurulamadı, sorun değil: uygulama tarayıcı modunda çalışacak"
fi

echo "[4/4] Çalıştırma scriptleri oluşturuluyor..."
cat > run.sh <<'RUNEOF'
#!/bin/bash
cd "$(dirname "$0")"
.venv/bin/python app.py "$@"
RUNEOF
cat > run_browser.sh <<'RUNEOF'
#!/bin/bash
cd "$(dirname "$0")"
.venv/bin/python app.py --browser "$@"
RUNEOF
chmod +x run.sh run_browser.sh

echo ""
echo "Kurulum tamamlandı."
echo "  ./run.sh            pencere modunda (pywebview kuruluysa)"
echo "  ./run_browser.sh    tarayıcı modunda, http://127.0.0.1:5050"
echo "Raporlar: ~/wifi_audit_reports/"
echo "Bu aracı yalnızca kendi ağınızda veya izinli ağlarda kullanın."
