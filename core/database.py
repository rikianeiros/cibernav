import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'db', 'cibernav.db')

def get_connection():
    """Establece conexión con la base de datos local SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Habilitar integridad referencial (desactivada por defecto en SQLite)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Inicializa la estructura de la base de datos."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS buques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL UNIQUE,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS escaneos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                buque_id INTEGER,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tipo_escaneo TEXT,
                FOREIGN KEY(buque_id) REFERENCES buques(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS dispositivos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL UNIQUE,
                fabricante TEXT,
                tipo_dispositivo TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS avistamientos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                escaneo_id INTEGER,
                dispositivo_id INTEGER,
                ip TEXT,
                hostname TEXT,
                os_detectado TEXT,
                FOREIGN KEY(escaneo_id) REFERENCES escaneos(id),
                FOREIGN KEY(dispositivo_id) REFERENCES dispositivos(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS servicios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                avistamiento_id INTEGER,
                puerto INTEGER,
                protocolo TEXT,
                servicio TEXT,
                version TEXT,
                FOREIGN KEY(avistamiento_id) REFERENCES avistamientos(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilidades_offline (
                cve_id TEXT PRIMARY KEY,
                descripcion TEXT,
                severidad TEXT
            )
        ''')

if __name__ == '__main__':
    print("[*] Inicializando Base de Datos...")
    init_db()
    print("[*] Base de Datos creada en:", DB_PATH)
