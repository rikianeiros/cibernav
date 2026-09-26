"""
Crackeo de handshakes capturados.

Cierra el ciclo de la auditoría Wi-Fi: sobre una captura ya obtenida (handshake
WPA/WPA2 en .cap o PMKID en .pcapng) lanza un ataque de diccionario y, si la
clave está en la lista, la recupera. Dos motores:

  · aircrack-ng  -> handshakes .cap
  · hashcat (modo 22000) -> PMKID .pcapng, convertido antes con hcxpcapngtool

La salida se transmite línea a línea por un callback (WebSocket) y se detecta
la clave encontrada. Todo el trabajo es local y sobre capturas propias.
"""
import asyncio
import os
import re
import time
import glob
import shutil

from config import DEFAULT_WORDLIST, CAPTURES_DIR, FOUND_DIR, DATA_DIR

# import perezoso de subprocess para poder simularlo en pruebas
import subprocess

_KEY_AIRCRACK = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")


class CrackManager:
    def __init__(self):
        self.jobs = {}  # job_id -> proc

    # --- utilidades ---
    def wordlist_ok(self, path: str | None = None) -> bool:
        path = path or DEFAULT_WORDLIST
        return os.path.isfile(path)

    def list_captures(self) -> list[dict]:
        """Capturas disponibles para crackear (.cap y .pcapng)."""
        encontrados = []
        for base in {CAPTURES_DIR, DATA_DIR}:
            for ext in ("*.cap", "*.pcapng"):
                for f in glob.glob(os.path.join(base, ext)):
                    try:
                        size = os.path.getsize(f)
                    except OSError:
                        size = 0
                    encontrados.append({
                        "ruta": f,
                        "nombre": os.path.basename(f),
                        "tipo": "pmkid" if f.endswith(".pcapng") else "handshake",
                        "tamano": size,
                    })
        # sin duplicados por ruta
        vistos, unicos = set(), []
        for c in encontrados:
            if c["ruta"] not in vistos:
                vistos.add(c["ruta"])
                unicos.append(c)
        return unicos

    # --- streaming común ---
    async def _stream(self, job_id, proc, callback, on_line):
        loop = asyncio.get_event_loop()
        found = None
        while True:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if not line:
                break
            line = line.rstrip()
            if on_line:
                k = on_line(line)
                if k:
                    found = k
            if callback and line:
                await callback(job_id, line)
        proc.wait()
        if found:
            self._guardar_clave(job_id, found)
        if callback:
            msg = f"[*] Finalizado. CLAVE ENCONTRADA: {found}" if found else "[*] Finalizado. La clave no está en el diccionario."
            await callback(job_id, msg, finished=True, key=found)
        self.jobs.pop(job_id, None)
        return found

    def _guardar_clave(self, job_id, key):
        try:
            os.makedirs(FOUND_DIR, exist_ok=True)
            with open(os.path.join(FOUND_DIR, f"{job_id}.key"), "w") as f:
                f.write(key + "\n")
        except OSError:
            pass

    # --- motores ---
    async def crack_aircrack(self, capture: str, bssid: str | None = None,
                             wordlist: str | None = None, callback=None) -> dict:
        wordlist = wordlist or DEFAULT_WORDLIST
        if not shutil.which("aircrack-ng"):
            return {"error": "aircrack-ng no está instalado."}
        if not os.path.isfile(capture):
            return {"error": f"No existe la captura: {capture}"}
        if not self.wordlist_ok(wordlist):
            return {"error": f"No existe el diccionario: {wordlist}"}

        job_id = f"crack_{int(time.time())}"
        cmd = ["aircrack-ng", "-w", wordlist]
        if bssid:
            cmd += ["-b", bssid]
        cmd.append(capture)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.jobs[job_id] = proc

        def on_line(l):
            m = _KEY_AIRCRACK.search(l)
            return m.group(1) if m else None

        asyncio.create_task(self._stream(job_id, proc, callback, on_line))
        return {"job_id": job_id, "motor": "aircrack-ng", "wordlist": wordlist}

    async def crack_hashcat(self, pcapng: str, wordlist: str | None = None, callback=None) -> dict:
        wordlist = wordlist or DEFAULT_WORDLIST
        if not shutil.which("hashcat") or not shutil.which("hcxpcapngtool"):
            return {"error": "Se requieren hashcat y hcxpcapngtool."}
        if not os.path.isfile(pcapng):
            return {"error": f"No existe la captura: {pcapng}"}
        if not self.wordlist_ok(wordlist):
            return {"error": f"No existe el diccionario: {wordlist}"}

        # 1) convertir pcapng -> hc22000
        hash_file = pcapng.replace(".pcapng", ".hc22000")
        loop = asyncio.get_event_loop()
        conv = await loop.run_in_executor(
            None, lambda: subprocess.run(["hcxpcapngtool", "-o", hash_file, pcapng],
                                         capture_output=True, text=True))
        if not os.path.isfile(hash_file) or os.path.getsize(hash_file) == 0:
            return {"error": "hcxpcapngtool no extrajo ningún hash de la captura."}

        # 2) lanzar hashcat
        job_id = f"hashcat_{int(time.time())}"
        potfile = os.path.join(FOUND_DIR, f"{job_id}.pot")
        cmd = ["hashcat", "-m", "22000", "-a", "0", "--potfile-path", potfile,
               "--status", "--status-timer", "5", hash_file, wordlist]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.jobs[job_id] = proc

        def on_line(l):
            # la clave crackeada aparece en el potfile como hash:...:essid:password
            if "Cracked" in l and os.path.isfile(potfile):
                try:
                    last = open(potfile).read().strip().splitlines()[-1]
                    return last.split(":")[-1]
                except Exception:
                    return None
            return None

        asyncio.create_task(self._stream(job_id, proc, callback, on_line))
        return {"job_id": job_id, "motor": "hashcat", "wordlist": wordlist}

    def stop(self, job_id: str) -> bool:
        proc = self.jobs.get(job_id)
        if not proc:
            return False
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        self.jobs.pop(job_id, None)
        return True


crack_manager = CrackManager()
