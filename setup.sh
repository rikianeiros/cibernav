#!/bin/bash
set -e
echo "============================================="
echo " CIBERNAV — Instalación del entorno"
echo "============================================="

if ! command -v apt &> /dev/null; then
    echo "[!] Aviso: pensado para Kali/Debian (apt). En otros sistemas instala las dependencias a mano."
else
    echo "[*] Instalando dependencias del sistema (requiere sudo)..."
    sudo apt update -qq
    # Herramientas de auditoría (opcionales pero recomendadas) + libs de WeasyPrint
    sudo apt install -y nmap aircrack-ng hcxdumptool bettercap \
        python3-venv python3-dev python3-cffi libcairo2 libpango-1.0-0 \
        libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev || true
fi

echo "[*] Creando entorno virtual e instalando librerías Python..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip -q
./venv/bin/pip install -r requirements.txt

[ -f .env ] || cp .env.example .env

echo ""
echo "  Instalación completada. Arranca con:  ./run.sh"
echo "  (Revisa y ajusta el archivo .env antes de exponer el panel)"
