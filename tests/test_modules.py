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
import json
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
os.environ["CIBERNAV_CVE_FILE"] = os.path.join(_tmp, "cve_rules.json")  # no tocar el JSON del repo


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


def test_diff_escaneos():
    from modules import database
    database.init_db()
    dm = database.db_manager
    base = [{"ip": "10.0.0.1", "mac": "AA:AA:AA:AA:AA:01", "vendor": "X", "os": "", "hostname": "",
             "puertos": [{"puerto": 80, "protocolo": "tcp", "servicio": "http", "version": ""}]}]
    target = [
        {"ip": "10.0.0.1", "mac": "AA:AA:AA:AA:AA:01", "vendor": "X", "os": "", "hostname": "",
         "puertos": [{"puerto": 80, "protocolo": "tcp", "servicio": "http", "version": ""},
                     {"puerto": 23, "protocolo": "tcp", "servicio": "telnet", "version": ""}]},  # abre 23
        {"ip": "10.0.0.9", "mac": "AA:AA:AA:AA:AA:09", "vendor": "Y", "os": "", "hostname": "",
         "puertos": []},  # dispositivo nuevo
    ]
    b_id = dm.guardar_hosts("Diff Test", base, "base")
    t_id = dm.guardar_hosts("Diff Test", target, "target")
    d = dm.comparar_escaneos(b_id, t_id)
    assert len(d["dispositivos_nuevos"]) == 1 and d["dispositivos_nuevos"][0]["ip"] == "10.0.0.9"
    assert d["dispositivos_desaparecidos"] == []
    assert len(d["cambios_puertos"]) == 1
    assert d["cambios_puertos"][0]["puertos_abiertos"][0]["puerto"] == 23
    assert d["sin_cambios"] is False
    # mismo escaneo contra sí mismo -> sin cambios
    igual = dm.comparar_escaneos(b_id, b_id)
    assert igual["sin_cambios"] is True
    # id inexistente -> None
    assert dm.comparar_escaneos(b_id, 99999) is None


def test_vulns_cve():
    from modules import vulns
    # vsftpd 2.3.4 -> backdoor conocido
    r = vulns.match_cves("ftp", "vsftpd 2.3.4")
    assert any("2011-2523" in c["cve"] for c in r)
    # vsftpd 3.0.3 -> no debe casar la regla de 2.3.4
    assert vulns.match_cves("ftp", "vsftpd 3.0.3") == []
    # OpenSSH 7.2 (< 7.7) -> enumeración de usuarios
    r = vulns.match_cves("ssh", "OpenSSH 7.2")
    assert any("2018-15473" in c["cve"] for c in r)
    # OpenSSH 8.0 (>= 7.7) -> sin ese CVE
    assert vulns.match_cves("ssh", "OpenSSH 8.0") == []
    # Apache 2.4.49 -> path traversal
    assert any("2021-41773" in c["cve"] for c in vulns.match_cves("http", "Apache httpd 2.4.49"))
    # Samba en rango vulnerable
    assert any("2017-7494" in c["cve"] for c in vulns.match_cves("netbios-ssn", "Samba smbd 4.3.11"))
    # servicio sin coincidencia
    assert vulns.match_cves("http", "nginx 1.25.0") == []


def test_vulns_update_from_file():
    from modules import vulns
    # feed local con una regla nueva; se actualiza vía file:// y se recarga
    feed = os.path.join(_tmp, "feed.json")
    regla = [{"match": "nginx", "versions": ["1.20.0"], "cve": "CVE-TEST-0001",
              "severidad": "ALTO", "descripcion": "Regla de prueba para nginx 1.20.0."}]
    with open(feed, "w") as f:
        json.dump(regla, f)
    n_antes = vulns.info()["n"]
    res = vulns.update_from_url("file://" + feed, merge=True)
    assert res.get("ok") is True
    assert vulns.info()["n"] >= n_antes  # fusionó sin perder las previas
    # la regla nueva ya casa
    assert any(c["cve"] == "CVE-TEST-0001" for c in vulns.match_cves("http", "nginx 1.20.0"))
    # feed inexistente -> error controlado, sin romper
    assert "error" in vulns.update_from_url("file:///no/existe/x.json")


def test_vulners_parser():
    from modules import vulns
    salida = """
    cpe:/a:openbsd:openssh:7.2p2:
        CVE-2016-6210    7.5     https://vulners.com/cve/CVE-2016-6210
        CVE-2016-10009   9.8     https://vulners.com/cve/CVE-2016-10009
        CVE-2016-6515    7.8     https://vulners.com/cve/CVE-2016-6515
    """
    r = vulns.parse_vulners(salida)
    assert len(r) == 3
    assert r[0]["cvss"] == 9.8 and r[0]["severidad"] == "CRÍTICO"  # ordenado por CVSS desc
    assert vulns.parse_vulners("") == []


def test_wifi_report():
    from modules import report
    networks = [
        {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "MiCasa", "channel": 6, "power": -40,
         "privacy": "WPA2", "flags": [], "clients": ["11:22:33:44:55:66"], "wps": False},
        {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "Libre", "channel": 1, "power": -60,
         "privacy": "OPN", "flags": ["OPEN_NETWORK"], "clients": [], "wps": False},
    ]
    html = report.render_html_wifi(networks, [{"mac": "11:22:33:44:55:66"}])
    assert "INFORME DE AUDITORÍA WI-FI" in html
    assert "MiCasa" in html and "Libre" in html
    assert "Red abierta" in html  # nombre del cifrado OPN desde CIPHER_KNOWLEDGE


def test_wash_parser():
    from modules import scanner
    salida = (
        "BSSID               Ch  dBm  WPS  Lck  ESSID\n"
        "--------------------------------------------\n"
        "AA:BB:CC:DD:EE:01    6  -40  2.0  No   MiRouter\n"
        "11:22:33:44:55:66    1  -60  1.0  No   Vecino\n"
    )
    bssids = scanner.parse_wash_output(salida)
    assert bssids == {"AA:BB:CC:DD:EE:01", "11:22:33:44:55:66"}
    assert scanner.parse_wash_output("sin nada aquí") == set()


def test_recon_domain_validation():
    from modules import recon
    assert recon.valid_domain("faroladigital.es")
    assert recon.valid_domain("blog.faroladigital.es")
    assert not recon.valid_domain("http://faroladigital.es")   # con esquema, no
    assert not recon.valid_domain("faroladigital.es; rm -rf /")  # inyección, no
    assert not recon.valid_domain("localhost")
    assert not recon.valid_domain("")


def test_recon_crtsh_parsing():
    from modules import recon, tor
    payload = json.dumps([
        {"name_value": "faroladigital.es\n*.faroladigital.es"},
        {"name_value": "blog.faroladigital.es"},
        {"name_value": "www.faroladigital.es"},
    ])
    orig = tor.http_get
    tor.http_get = lambda url, timeout=0: payload
    try:
        r = recon.subdomains_crtsh("faroladigital.es")
    finally:
        tor.http_get = orig
    assert "blog.faroladigital.es" in r["subdominios"]
    assert "www.faroladigital.es" in r["subdominios"]
    # sin duplicados y ordenado
    assert len(r["subdominios"]) == len(set(r["subdominios"]))


def test_recon_graceful_without_tools():
    from modules import recon
    import shutil as _sh
    orig = recon.shutil.which
    recon.shutil.which = lambda t: None  # ninguna herramienta instalada
    try:
        r = recon._run(["whatweb", "https://x"], 5)
        assert r["disponible"] is False and "no está instalado" in r["error"]
        gb = recon.gobuster("faroladigital.es")
        assert gb["disponible"] is False
    finally:
        recon.shutil.which = orig


def test_tor():
    from modules import tor
    # con Tor desactivado, torify_cmd no cambia el comando
    tor.state.enabled = False
    assert tor.torify_cmd(["nmap", "-sT", "x"]) == ["nmap", "-sT", "x"]
    # http_get sin Tor usa urllib y funciona con file://
    feed = os.path.join(_tmp, "tor_feed.json")
    with open(feed, "w") as f:
        f.write('{"ok": true}')
    assert '"ok"' in tor.http_get("file://" + feed, 5)
    # status devuelve las claves esperadas
    s = tor.status()
    assert set(["enabled", "socks_ok", "torify", "socks"]).issubset(s.keys())
    # con Tor activo y torsocks presente, antepone el prefijo
    import shutil as _sh
    orig = tor.shutil.which
    tor.shutil.which = lambda t: "/usr/bin/torsocks" if t == "torsocks" else None
    tor.state.enabled = True
    try:
        assert tor.torify_cmd(["nmap", "-sT", "x"])[0] == "torsocks"
    finally:
        tor.shutil.which = orig
        tor.state.enabled = False


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
