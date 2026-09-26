"""
Pruebas a nivel de código de los módulos de CIBERNAV.

No requieren las herramientas de Kali: comprueban la lógica pura (base de
conocimiento, parser de airodump, persistencia, informes, NMEA, alertas y el
gestor de ataques con subprocess simulado).

Ejecutar desde la raíz del proyecto:

    python -m pytest tests/            # si tienes pytest
    python tests/test_modules.py       # sin dependencias extra
"""
import os
import sys
import asyncio
import types
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("CIBERNAV_USER", "admin")
os.environ.setdefault("CIBERNAV_PASS", "test")
_tmp = tempfile.mkdtemp(prefix="cibernav_test_")
os.environ["CIBERNAV_DATA_DIR"] = _tmp
os.environ["CIBERNAV_DB_PATH"] = os.path.join(_tmp, "test.db")


def test_knowledge():
    from modules import knowledge
    assert knowledge.get_port_knowledge(23)["riesgo"] == "CRÍTICO"
    assert "NMEA" in knowledge.get_port_knowledge(10110)["servicio"]
    assert knowledge.get_port_knowledge(65000)["riesgo"] == "DESCONOCIDO"
    assert knowledge.CIPHER_KNOWLEDGE["OPN"]["riesgo"] == "CRÍTICO"
    assert "Espressif" in knowledge.get_oui_info("40:b4:cd:11:22:33")[0]
    assert knowledge.get_oui_info("ff:ff:ff:00:00:00")[0] == "Desconocido"


def test_system_check():
    from modules import system_check
    caps = system_check.get_capabilities()
    assert "capabilities" in caps and "warnings" in caps
    assert "nmap" in caps["capabilities"] and "report" in caps["capabilities"]


def test_nmea():
    from modules import nmea
    assert nmea._sentence_type("$GPGGA,123") == "GGA"
    res = asyncio.run(nmea.capturar_nmea_async("127.0.0.1", 9, 2, 2))
    assert res["exito"] is False  # puerto cerrado, no debe romper


def test_database_and_report():
    from modules import database, report
    database.init_db()
    hosts = [{"ip": "10.0.0.5", "hostname": "gps", "mac": "AA:BB:CC:DD:EE:FF",
              "vendor": "ACME", "os": "Linux",
              "puertos": [{"puerto": 10110, "protocolo": "tcp", "servicio": "nmea", "version": ""},
                          {"puerto": 23, "protocolo": "tcp", "servicio": "telnet", "version": ""}]}]
    eid = database.db_manager.guardar_hosts("Objetivo Test", hosts, "Inventario")
    assert isinstance(eid, int)
    scan = database.db_manager.obtener_escaneo(eid)
    assert scan["objetivo"] == "Objetivo Test"
    assert len(scan["hosts"]) == 1 and len(scan["hosts"][0]["servicios"]) == 2
    assert database.db_manager.guardar_hosts("Vacio", []) is None
    html = report.render_html(scan)
    assert "Objetivo Test" in html and "CRÍTICO" in html


def test_airodump_parser():
    from modules import scanner
    csv = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, beacons, IV, LAN IP, ID-length, ESSID, Key\r\n"
           "AA:BB:CC:DD:EE:01, 2024, 2024, 6, 130, WPA2, CCMP, PSK, -40, 100, 0, 0.0.0.0, 8, MiRouter, \r\n"
           "AA:BB:CC:DD:EE:02, 2024, 2024, 1, 54, OPN, , , -60, 50, 0, 0.0.0.0, 5, Libre, \r\n"
           "\r\n"
           "Station MAC, First time seen, Last time seen, Power, packets, BSSID, Probed ESSIDs\r\n"
           "11:22:33:44:55:66, 2024, 2024, -50, 20, AA:BB:CC:DD:EE:01, casa\r\n")
    p = os.path.join(_tmp, "scan-01.csv")
    with open(p, "w", newline="") as f:
        f.write(csv)
    nets, clis = scanner.parse_airodump_csv(p)
    assert len(nets) == 2
    assert "OPEN_NETWORK" in nets["AA:BB:CC:DD:EE:02"]["flags"]
    assert "11:22:33:44:55:66" in nets["AA:BB:CC:DD:EE:01"]["clients"]
    assert scanner.parse_airodump_csv("/no/existe.csv") == ({}, {})


def test_alert_engine():
    from modules.alert_engine import alert_engine
    n0 = len(alert_engine.alerts)
    alert_engine.add_alert("INFO", "prueba")
    assert len(alert_engine.alerts) == n0 + 1
    assert "OPEN_NETWORK" in alert_engine.analyze_network({"privacy": "OPN", "bssid": "x"})


def test_attacker_with_fake_subprocess():
    from modules import attacker

    class FakeProc:
        def __init__(self, *a, **k):
            self.stdout = self
            self._lines = ["linea 1\n", "linea 2\n"]

        def readline(self):
            return self._lines.pop(0) if self._lines else ""

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            pass

        def kill(self):
            pass

    attacker.subprocess = types.SimpleNamespace(
        Popen=lambda *a, **k: FakeProc(),
        run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        STDOUT=-2, PIPE=-1,
    )
    got = []

    async def cb(aid, line, finished=False):
        got.append((aid, line, finished))

    async def run():
        aid = await attacker.attack_manager.launch_deauth("wlan0mon", "AA:BB:CC:DD:EE:01", None, 3, cb)
        await asyncio.sleep(0.2)
        return aid

    aid = asyncio.run(run())
    assert aid.startswith("deauth_")
    assert any(f for _, _, f in got)
    assert attacker.attack_manager.stop_attack("inexistente") is False


def test_cracker():
    import shutil as _sh
    from modules import cracker

    # Captura y diccionario de prueba
    cap = os.path.join(_tmp, "handshake-01.cap")
    open(cap, "w").write("fake")
    wl = os.path.join(_tmp, "words.txt")
    open(wl, "w").write("1234\npassword123\n")

    # list_captures encuentra la captura
    caps = cracker.crack_manager.list_captures()
    assert any(c["nombre"] == "handshake-01.cap" for c in caps)

    # subprocess simulado que "encuentra" la clave
    class FakeProc:
        def __init__(self, *a, **k):
            self.stdout = self
            self._lines = ["Reading packets...\n", "KEY FOUND! [ password123 ]\n"]

        def readline(self):
            return self._lines.pop(0) if self._lines else ""

        def wait(self, timeout=None):
            return 0

    cracker.subprocess = types.SimpleNamespace(
        Popen=lambda *a, **k: FakeProc(),
        run=lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
        STDOUT=-2, PIPE=-1,
    )
    cracker.shutil = types.SimpleNamespace(which=lambda t: "/usr/bin/" + t)  # fingir tools presentes

    got = {}

    async def cb(job_id, line, finished=False, key=None):
        if finished:
            got["key"] = key

    async def run():
        r = await cracker.crack_manager.crack_aircrack(cap, "AA:BB:CC:DD:EE:01", wl, cb)
        await asyncio.sleep(0.2)
        return r

    res = asyncio.run(run())
    assert "job_id" in res
    assert got.get("key") == "password123"

    # errores controlados
    err = asyncio.run(cracker.crack_manager.crack_aircrack("/no/existe.cap", None, wl, cb))
    assert "error" in err
    assert cracker.crack_manager.stop("inexistente") is False


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ✔ {fn.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  ✖ {fn.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} pruebas OK")
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
