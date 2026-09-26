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
    const warns = (data.warnings || []).slice();
    if (data.passive) { warns.unshift("🔒 Modo pasivo activo: ataques y crackeo deshabilitados."); }
    if ($("passive-chk")) $("passive-chk").checked = !!data.passive;
    if (warns.length) {
      banner.innerHTML = warns.map((w) => `<div>${w.startsWith("🔒") ? w : "⚠ " + w}</div>`).join("");
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
      const cves = (r.cves || []).map((c) =>
        `<p class="cve">⚠ <b>${c.cve}</b> [${c.severidad}] — ${c.descripcion}</p>`).join("");
      const vuln = (r.vulners || []).slice(0, 12).map((c) =>
        `<p class="cve">◆ <b>${c.cve}</b> CVSS ${c.cvss} [${c.severidad}]</p>`).join("")
        + ((r.vulners || []).length > 12 ? `<p class="hint">… y ${r.vulners.length - 12} más (vulners)</p>` : "");
      return `<div class="finding r-${RISK[k.riesgo] || "desc"}">
        <div class="fh"><b>${k.servicio || r.service}</b> <span class="port">${r.port}/tcp ${r.version || ""}</span>
          <span class="badge ${RISK[k.riesgo] || "desc"}">${k.riesgo || "?"}</span></div>
        <p>${k.descripcion || ""}</p>
        <p class="rec">→ ${k.recomendacion || ""}</p>
        ${cves}${vuln}
      </div>`;
    }).join("");
  }

  // --- Acciones ---
  const act = async (fn) => { try { return await fn(); } catch (e) { alert(e.message); } };

  return {
    init() { loadCapabilities(); connectWS(); this.loadScans(); this.loadCaptures(); this.loadCveInfo(); setInterval(loadCapabilities, 15000); },
    async loadCveInfo() {
      try {
        const i = await api("/api/vulns");
        if ($("cve-info")) $("cve-info").textContent = `Base de CVEs: ${i.n} reglas · actualizado ${i.actualizado || "—"}`;
      } catch (e) {}
    },
    updateCves() {
      const url = $("cve-url").value.trim();
      act(async () => {
        const r = await api(`/api/vulns/update?${qs(url ? { url } : {})}`, "POST");
        if (r.error) return alert(r.error);
        alert(`Base de CVEs actualizada: ${r.reglas} reglas (${r.nuevas} del feed).`);
        this.loadCveInfo();
      });
    },
    reloadCves() { act(async () => { await api("/api/vulns/reload", "POST"); this.loadCveInfo(); }); },
    reconPasivo() {
      const d = $("recon-domain").value.trim(); if (!d) return;
      $("recon-result").innerHTML = `<p class="hint">Recon pasivo sobre ${d}…</p>`;
      act(async () => renderRecon(await api(`/api/recon/passive?${qs({ domain: d })}`, "POST"), "pasiva"));
    },
    reconActivo() {
      const d = $("recon-domain").value.trim(); if (!d) return;
      if (!confirm(`Vas a lanzar un escaneo ACTIVO contra ${d}. Solo debes hacerlo sobre dominios propios o autorizados. ¿Continuar?`)) return;
      $("recon-result").innerHTML = `<p class="hint">Recon activo sobre ${d} (puede tardar unos minutos)…</p>`;
      act(async () => renderRecon(await api(`/api/recon/active?${qs({ domain: d, wpscan: $("recon-wpscan").checked })}`, "POST"), "activa"));
    },
    searchsploit() {
      const t = $("recon-sploit").value.trim(); if (!t) return;
      act(async () => {
        const r = await api(`/api/recon/searchsploit?${qs({ termino: t })}`, "POST");
        $("recon-result").innerHTML = `<h3>searchsploit: ${t}</h3>` + reconBlock("searchsploit", r);
      });
    },
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
    wpsScan() { act(async () => { const r = await api("/api/wps/scan", "POST"); if (r.error) return alert(r.error); alert(`WPS detectado en ${r.wps_bssids.length} red(es).`); }); },
    deauth(bssid) { if (!bssid) return; act(() => api(`/api/attack/deauth?${qs({ bssid })}`, "POST")); },
    scanPorts() { const ip = $("nmap-ip").value.trim(); if (!ip) return; const v = $("nmap-vulners") && $("nmap-vulners").checked; $("nmap-results").innerHTML = `<p class="hint">Escaneando ${ip}${v ? " con vulners (puede tardar)" : ""}…</p>`; act(() => api(`/api/ports/scan?${qs({ target_ip: ip, profile: $("nmap-profile").value, vulners: !!v })}`, "POST")); },
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
        const scans = r.scans || [];
        $("scan-rows").innerHTML = scans.map((s) =>
          `<tr><td>${s.id}</td><td>${s.objetivo}</td><td>${s.tipo_escaneo}</td><td>${s.fecha}</td>
           <td><a class="mini" href="/api/report/${s.id}" target="_blank">ver informe</a></td></tr>`
        ).join("") || `<tr><td colspan="5" class="hint">Aún no hay escaneos.</td></tr>`;
        const opts = scans.map((s) => `<option value="${s.id}">#${s.id} · ${s.objetivo} · ${s.fecha}</option>`).join("");
        if ($("diff-base")) $("diff-base").innerHTML = opts;
        if ($("diff-target")) $("diff-target").innerHTML = opts;
      } catch (e) {}
    },
    setPassive(on) {
      act(async () => { await api(`/api/mode?passive=${on}`, "POST"); loadCapabilities(); });
    },
    async diff() {
      const b = $("diff-base").value, t = $("diff-target").value;
      if (!b || !t) return alert("Necesitas dos escaneos guardados.");
      if (b === t) return alert("Elige dos escaneos distintos.");
      await act(async () => renderDiff(await api(`/api/diff?${qs({ base_id: b, target_id: t })}`)));
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

  function reconBlock(nombre, r) {
    if (!r) return "";
    if (r.disponible === false) return `<div class="finding"><div class="fh"><b>${nombre}</b><span class="badge desc">no instalado</span></div><p class="hint">${r.error || ""}</p></div>`;
    const cuerpo = r.salida ? `<pre class="console">${(r.salida || "").replace(/</g, "&lt;")}</pre>` : "";
    return `<div class="finding"><div class="fh"><b>${nombre}</b><span class="badge bajo">${r.resumen || "ok"}</span></div>
      ${r.error ? `<p class="err">${r.error}</p>` : ""}${cuerpo}</div>`;
  }

  function renderRecon(data, fase) {
    const box = $("recon-result");
    let html = `<h3>Recon ${fase} · ${data.dominio}</h3>`;
    if (fase === "pasiva") {
      // subdominios en lista, DNS como tabla, resto en bloques
      const subs = (data.subdominios && data.subdominios.subdominios) || [];
      html += `<div class="finding r-bajo"><div class="fh"><b>Subdominios (crt.sh)</b><span class="badge bajo">${subs.length}</span></div>
        <p class="mono" style="line-height:1.8">${subs.map((s) => s).join("&nbsp;·&nbsp;") || "—"}</p></div>`;
      const dns = (data.dns && data.dns.registros) || {};
      html += `<div class="finding"><div class="fh"><b>DNS</b><span class="badge bajo">${data.dns ? data.dns.resumen : ""}</span></div>`
        + Object.entries(dns).map(([k, v]) => `<p><b>${k}</b>: <span class="mono">${v.join(", ")}</span></p>`).join("") + `</div>`;
      html += reconBlock("whois", data.whois) + reconBlock("whatweb", data.whatweb)
        + reconBlock("WAF (wafw00f)", data.waf) + reconBlock("SSL (sslscan)", data.ssl);
    } else {
      html += reconBlock("nmap web (NSE)", data.nmap_web) + reconBlock("nikto", data.nikto)
        + reconBlock("gobuster", data.gobuster) + (data.wpscan ? reconBlock("wpscan", data.wpscan) : "");
    }
    box.innerHTML = html;
  }

  function renderDiff(d) {
    const box = $("diff-result");
    if (d.sin_cambios) {
      box.innerHTML = `<div class="finding r-bajo"><p>Sin cambios entre el escaneo #${d.base.id} y el #${d.target.id}.</p></div>`;
      return;
    }
    const dev = (h) => `${h.ip} <small class="mono">${h.mac || ""}</small> ${h.fabricante || ""}`;
    const ports = (list) => list.map((p) => `${p.protocolo}/${p.puerto}`).join(", ");
    let html = `<p class="hint">Comparando #${d.base.id} (${d.base.fecha}) → #${d.target.id} (${d.target.fecha})</p>`;
    if (d.dispositivos_nuevos.length)
      html += `<div class="finding r-alto"><div class="fh"><b>🆕 Dispositivos nuevos (${d.dispositivos_nuevos.length})</b></div>`
        + d.dispositivos_nuevos.map((h) => `<p>+ ${dev(h)}</p>`).join("") + `</div>`;
    if (d.dispositivos_desaparecidos.length)
      html += `<div class="finding r-medio"><div class="fh"><b>➖ Desaparecidos (${d.dispositivos_desaparecidos.length})</b></div>`
        + d.dispositivos_desaparecidos.map((h) => `<p>− ${dev(h)}</p>`).join("") + `</div>`;
    d.cambios_puertos.forEach((c) => {
      html += `<div class="finding r-alto"><div class="fh"><b>${dev(c.dispositivo)}</b></div>`;
      if (c.puertos_abiertos.length) html += `<p class="rec">▲ Puertos abiertos: ${ports(c.puertos_abiertos)}</p>`;
      if (c.puertos_cerrados.length) html += `<p>▼ Puertos cerrados: ${ports(c.puertos_cerrados)}</p>`;
      html += `</div>`;
    });
    box.innerHTML = html;
  }

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
