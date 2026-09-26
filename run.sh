#!/bin/bash
cd "$(dirname "$0")"

echo "[CIBERNAV] Comprobando herramientas del sistema (opcionales)..."
for tool in airodump-ng aireplay-ng aircrack-ng nmap bettercap hcxdumptool hashcat; do
    if ! command -v "$tool" &> /dev/null; then
        echo "  [aviso] $tool no encontrado — las funciones que lo usan quedarán desactivadas."
    fi
done

if [ ! -d "venv" ]; then
    echo "[CIBERNAV] Creando entorno virtual e instalando dependencias..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q
    ./venv/bin/pip install -r requirements.txt
fi

# Carga variables de .env si existe
[ -f .env ] && export $(grep -v '^#' .env | xargs)

echo "[CIBERNAV] Servidor en http://127.0.0.1:8080"
./venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8080 --reload
