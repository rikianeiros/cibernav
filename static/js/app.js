// CIBERNAV — lógica de la interfaz (SPA sin dependencias)
const app = (() => {
  const $ = (id) => document.getElementById(id);
  const api = async (path, method = "GET") => {
    const r = await fetch(path, { method });
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
    return r.json();
  };
  const qs = (o) => Object.entries(o).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
  const RISK = { "CRÍTICO": "crit", "ALTO": "alto", "MEDIO-ALTO": "alto", "MEDIO": "medio", "BAJO": "bajo", "DESCONOCIDO": "desc" };

  // --- Pestañas ---
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      $(t.dataset.tab).classList.add("active");
    })
  );

  // --- Capacidades (degradación elegante) ---
  async function loadCapabilities() {
    let data;
    try { data = await api("/api/capabilities"); }
    catch (e) { return; }
    const banner = $("cap-banner");
    if (data.warnings && data.warnings.length) {
      banner.innerHTML = data.warnings.map((w) => `<div>⚠ ${w}</div>`).join("");
      banner.classList.remove("hidden");
    } else { banner.classList.add("hidden"); }

    const names = {
      wifi_scan: "Escaneo Wi-Fi", wifi_attack: "Ataques Wi-Fi", pmkid: "Ataque PMKID",
      nmap: "Escaneo de puertos (nmap)", bettercap: "Bettercap", cracking: "Cracking (aircrack/hashcat)",
      report: "Informes PDF",
    };
    $("caps").innerHTML = Object.entries(data.capabilities).map(([k, v]) =>
      `<span class="cap ${v.available ? "ok" : "no"}">${v.available ? "✔" : "✖"} ${names[k] || k}</span>`
    ).join("");

    // Rellenar interfaces Wi-Fi
    const ifaces = (data.capabilities.wifi_scan || {}).interfaces || [];
    $("iface").innerHTML = ifaces.length
      ? ifaces.map((i) => `<option>${i}</option>`).join("")
      : `<option value="">(sin interfaz inalámbrica)</option>`;
  }

  // --- WebSocket (tiempo real) ---
  function connectWS() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => setWs(true);
    ws.onclose = () => { setWs(false); setTimeout(connectWS, 3000); };
    ws.onmessage = (ev) => handle(JSON.parse(ev.data));
  }
  const setWs = (on) => {
    const el = $("ws-status");
    el.className = "ws-status " + (on ? "on" : "off");
    el.textContent = on ? "● en vivo" : "● desconectado";
  };

  function handle(msg) {
    if (msg.type === "scan_update") {
      $("s-net").textContent = msg.stats.total_networks;
      $("s-cli").textContent = msg.stats.total_clients;
      $("s-open").textContent = msg.stats.open_networks;
      $("s-wps").textContent = msg.stats.wps_networks;
      renderNetworks(msg.networks);
      renderAlerts(msg.alerts);
    } else if (msg.type === "attack_output") {
      $("attack-out").textContent += `[${msg.id.slice(0, 6)}] ${msg.line}\n`;
    } else if (msg.type === "attack_finished") {
      $("attack-out").textContent += `[${msg.id.slice(0, 6)}] — finalizado —\n`;
    } else if (msg.type === "nmap_finished") {
      renderNmap(msg.target, msg.results);
    } else if (msg.type === "crack_output") {
      $("crack-out").textContent += msg.line + "\n";
      $("crack-out").scrollTop = $("crack-out").scrollHeight;
    } else if (msg.type === "crack_finished") {
      $("crack-out").textContent += msg.line + "\n";
      if (msg.key) {
        $("crack-key").innerHTML = `<div class="finding r-crit"><div class="fh"><b>🔑 Clave encontrada</b>
          <span class="badge crit">CRÍTICO</span></div><p class="mono" style="font-size:16px">${msg.key}</p></div>`;
      } else {
        $("crack-key").innerHTML = `<div class="finding r-bajo"><p>La clave no estaba en el diccionario.</p></div>`;
      }
    }
  }

  function renderAlerts(alerts) {
    if (!alerts) return;
    $("alerts").innerHTML = alerts.slice().reverse().map((a) =>
      `<li class="lvl-${(a.level || "INFO").toLowerCase()}"><b>${a.level}</b> ${a.message} <small>${a.source || ""}</small></li>`
    ).join("");
  }

  function renderNetworks(nets) {
    $("net-rows").innerHTML = (nets || []).map((n) => {
      const enc = n.privacy || (n.flags && n.flags.includes("OPEN_NETWORK") ? "OPN" : "?");
      const flags = (n.flags || []).filter((f) => f !== "STRONG_SIGNAL")
        .map((f) => `<span class="badge alto">${f}</span>`).join(" ");
      return `<tr>
        <td class="mono">${n.bssid || ""}</td>
        <td>${n.ssid || "&lt;oculta&gt;"} ${flags}</td>
        <td>${n.channel || ""}</td>
        <td>${enc}</td>
        <td>${n.power || ""}</td>
        <td><button class="mini" onclick="app.deauth('${n.bssid}')">deauth</button></td>
      </tr>`;
    }).join("");
  }

  function renderNmap(target, results) {
    const box = $("nmap-results");
    if (results && results[0] && results[0].error) {
      box.innerHTML = `<p class="err">Error: ${results[0].error}</p>`; return;
    }
    if (!results || !results.length) { box.innerHTML = `<p class="hint">Sin puertos abiertos en ${target}.</p>`; return; }
    box.innerHTML = `<h3>${target}</h3>` + results.map((r) => {
      const k = r.knowledge || {};
      return `<div class="finding r-${RISK[k.riesgo] || "desc"}">
        <div class="fh"><b>${k.servicio || r.service}</b> <span class="port">${r.port}/tcp</span>
          <span class="badge ${RISK[k.riesgo] || "desc"}">${k.riesgo || "?"}</span></div>
        <p>${k.descripcion || ""}</p>
        <p class="rec">→ ${k.recomendacion || ""}</p>
      </div>`;
    }).join("");
  }

  // --- Acciones ---
  const act = async (fn) => { try { return await fn(); } catch (e) { alert(e.message); } };

  return {
    init() { loadCapabilities(); connectWS(); this.loadScans(); this.loadCaptures(); setInterval(loadCapabilities, 15000); },
    async loadCaptures() {
      try {
        const r = await api("/api/captures");
        const fmt = (b) => b > 1024 ? (b / 1024).toFixed(0) + " KB" : b + " B";
        $("capture-rows").innerHTML = (r.captures || []).map((c) => {
          const engine = c.tipo === "pmkid" ? "hashcat" : "aircrack";
          return `<tr>
            <td class="mono">${c.nombre}</td><td>${c.tipo}</td><td>${fmt(c.tamano)}</td>
            <td><input class="bssid-in" data-cap="${c.ruta}" placeholder="AA:BB:.." style="min-width:120px"></td>
            <td><button class="mini" onclick="app.crack('${c.ruta.replace(/'/g, "")}','${engine}')">crackear</button></td>
          </tr>`;
        }).join("") || `<tr><td colspan="5" class="hint">No hay capturas todavía. Captura un handshake o PMKID en la pestaña Wi-Fi.</td></tr>`;
        if (!r.wordlist_ok) $("wordlist").placeholder = "⚠ diccionario por defecto no encontrado — indica una ruta";
      } catch (e) {}
    },
    crack(ruta, engine) {
      const wl = $("wordlist").value.trim();
      const bssidInput = document.querySelector(`.bssid-in[data-cap="${ruta}"]`);
      const bssid = bssidInput ? bssidInput.value.trim() : "";
      $("crack-out").textContent = ""; $("crack-key").innerHTML = "";
      const params = { capture: ruta };
      if (wl) params.wordlist = wl;
      const path = engine === "hashcat" ? "/api/crack/hashcat" : "/api/crack/aircrack";
      if (engine === "aircrack" && bssid) params.bssid = bssid;
      act(async () => {
        const r = await api(`${path}?${qs(params)}`, "POST");
        if (r.error) { $("crack-out").textContent = "Error: " + r.error; return; }
        $("crack-out").textContent = `[*] ${r.motor} en marcha con ${r.wordlist}\n`;
      });
    },
    startMonitor() { const i = $("iface").value; if (!i) return alert("No hay interfaz inalámbrica."); act(() => api(`/api/monitor/start?interface=${i}`, "POST")); },
    stopMonitor() { act(() => api("/api/monitor/stop", "POST")); },
    startScan() { act(() => api("/api/scan/start", "POST")); },
    stopScan() { act(() => api("/api/scan/stop", "POST")); },
    deauth(bssid) { if (!bssid) return; act(() => api(`/api/attack/deauth?${qs({ bssid })}`, "POST")); },
    scanPorts() { const ip = $("nmap-ip").value.trim(); if (!ip) return; $("nmap-results").innerHTML = `<p class="hint">Escaneando ${ip}…</p>`; act(() => api(`/api/ports/scan?${qs({ target_ip: ip, profile: $("nmap-profile").value })}`, "POST")); },
    async inventoryScan() {
      const target = $("inv-target").value.trim(), objetivo = $("inv-name").value.trim();
      if (!target || !objetivo) return alert("Indica red/host y nombre del objetivo.");
      const withOs = $("inv-os").checked;
      await act(async () => {
        const r = await api(`/api/inventory/scan?${qs({ target, objetivo, with_os: withOs })}`, "POST");
        if (r.error) return alert("Error: " + r.error);
        alert(`Inventario guardado (${r.dispositivos} dispositivos). Escaneo #${r.escaneo_id}.`);
        this.loadScans();
      });
    },
    async loadScans() {
      try {
        const r = await api("/api/scans");
        $("scan-rows").innerHTML = (r.scans || []).map((s) =>
          `<tr><td>${s.id}</td><td>${s.objetivo}</td><td>${s.tipo_escaneo}</td><td>${s.fecha}</td>
           <td><a class="mini" href="/api/report/${s.id}" target="_blank">ver informe</a></td></tr>`
        ).join("") || `<tr><td colspan="5" class="hint">Aún no hay escaneos.</td></tr>`;
      } catch (e) {}
    },
    async nmea() {
      const ip = $("nmea-ip").value.trim(), puerto = $("nmea-port").value || 10110;
      if (!ip) return; $("nmea-result").innerHTML = `<p class="hint">Conectando a ${ip}:${puerto}…</p>`;
      await act(async () => renderNmea([await api(`/api/naval/nmea?${qs({ ip, puerto })}`, "POST")]));
    },
    async nmeaAuto() {
      const ip = $("nmea-ip").value.trim(); if (!ip) return;
      $("nmea-result").innerHTML = `<p class="hint">Probando puertos NMEA en ${ip}…</p>`;
      await act(async () => { const r = await api(`/api/naval/nmea/auto?${qs({ ip })}`, "POST"); renderNmea(r.resultados); });
    },
  };

  function renderNmea(list) {
    $("nmea-result").innerHTML = list.map((res) => {
      const cls = res.exito ? "r-crit" : "";
      const sent = (res.sentencias || []).map((s) =>
        `<li><span class="mono">${s.raw}</span> — <small>${s.tipo}: ${s.descripcion}</small></li>`).join("");
      return `<div class="finding ${cls}">
        <div class="fh"><b>Puerto ${res.puerto}</b>
          <span class="badge ${res.exito ? "crit" : "bajo"}">${res.exito ? "DATOS EN CLARO" : "sin datos"}</span></div>
        <p>${res.mensaje}</p>
        ${sent ? `<ul class="nmea">${sent}</ul>` : ""}
        ${res.exito ? `<p class="rec">→ ${res.recomendacion}</p>` : ""}
      </div>`;
    }).join("");
  }
})();
document.addEventListener("DOMContentLoaded", () => app.init());
