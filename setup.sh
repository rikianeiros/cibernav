#!/bin/bash
set -e  # Salir inmediatamente si cualquier comando falla

echo "============================================="
echo " CIBERNAV - Instalación del Entorno"
echo "============================================="

# 1. Comprobar que estamos en Kali Linux
if ! command -v apt &> /dev/null; then
    echo "[!] ADVERTENCIA: Este script está diseñado para Kali Linux (apt)."
fi

# 2. Instalar dependencias del sistema (nmap + librerías para WeasyPrint)
echo "[*] Instalando dependencias del sistema con apt..."
sudo apt update -qq
sudo apt install -y nmap python3-cffi libcairo2 libpango-1.0-0 \
    libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev python3-dev

# 3. Crear la carpeta de base de datos si no existe
echo "[*] Creando estructura de carpetas..."
mkdir -p db

# 4. Crear el entorno virtual de Python
echo "[*] Creando entorno virtual nativo..."
python3 -m venv venv

# 5. Activar e instalar librerías Python
echo "[*] Instalando librerías Python..."
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt

echo ""
echo "============================================="
echo " ¡Instalación completada con éxito!"
echo "============================================="
echo ""
echo " Para arrancar CIBERNAV:"
echo "   source venv/bin/activate"
echo "   sudo python3 app.py"
echo ""
echo " Luego abre el navegador en: http://localhost:5000"
