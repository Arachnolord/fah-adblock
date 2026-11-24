// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// FAH-Adblock – Oberfläche (ohne Fremdbibliotheken).
'use strict';
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const zahl = (n) => Number(n || 0).toLocaleString('de-DE');
  const uhr = (ts) => new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const vor = (ts) => { if (!ts) return 'nie'; const s = Math.round((Date.now() - ts) / 1000); return s < 60 ? 'gerade eben' : s < 3600 ? `vor ${Math.round(s / 60)} min` : s < 86400 ? `vor ${Math.round(s / 3600)} h` : `vor ${Math.round(s / 86400)} T`; };
  const bytes = (b) => b > 1073741824 ? `${(b / 1073741824).toFixed(1)} GB` : b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.round((b || 0) / 1024)} kB`;
  const info = (text) => `<small class="info">${text}</small>`;
  const wenigBewegung = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const SCHILD = '<svg viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#40e0a0"/><stop offset="1" stop-color="#5cc8ff"/></linearGradient></defs><path d="M32 4 54 12v18c0 14-9.4 24.6-22 30C19.4 54.6 10 44 10 30V12Z" fill="none" stroke="url(#sg)" stroke-width="4" stroke-linejoin="round"/><path d="m22 32 7 7 13-15" fill="none" stroke="url(#sg)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const ANSICHTEN = [
    { id: 'schild', name: 'Schutzschild', kurz: 'Schild', symbol: '🛡️' }, { id: 'geraete', name: 'Geräte', kurz: 'Geräte', symbol: '💻' }, { id: 'protokoll', name: 'Protokoll', kurz: 'Protok.', symbol: '📜' },
    { id: 'listen', name: 'Listen & Regeln', kurz: 'Listen', symbol: '🧱' }, { id: 'dienste', name: 'Dienste', kurz: 'Dienste', symbol: '📺' }, { id: 'profile', name: 'Profile', kurz: 'Profile', symbol: '👪' }, { id: 'kinderschutz', name: 'Kinderschutz', kurz: 'Kinder', symbol: '🧒' },
    { id: 'statistik', name: 'Statistik', kurz: 'Statistik', symbol: '📊' }, { id: 'einstellungen', name: 'Einstellungen', kurz: 'Einst.', symbol: '⚙️' },
  ];
  const ZEITRAEUME = [[24, '24 h'], [168, '7 Tage'], [720, '1 Monat']];
  const schildStundenGemerkt = () => { try { const v = +localStorage.getItem('schildStunden'); return ZEITRAEUME.some(([h]) => h === v) ? v : 24; } catch (e) { return 24; } };
  const S = { schildStunden: schildStundenGemerkt(), ich: null, ansicht: 'schild', uebersicht: null, geraete: null, profile: [], live: [], quelle: null, timer: [], liveAn: true };

  // ── Grundlagen ─────────────────────────────────────────────────────────────
  async function api(pfad, { methode = 'GET', daten } = {}) {
    const r = await fetch(pfad, { method: methode, credentials: 'same-origin', headers: { ...(daten !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(S.ich?.csrf ? { 'x-csrf': S.ich.csrf } : {}) }, body: daten !== undefined ? JSON.stringify(daten) : undefined });
    if (r.status === 401 && !pfad.includes('/anmelden')) { S.ich = null; zeigeAnmeldung(); throw new Error('Bitte anmelden'); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.fehler || `Fehler ${r.status}`);
    return j;
  }
  function toast(text, art = 'ok') {
    $$('.toast').forEach((t) => t.remove());
    const t = document.createElement('div'); t.className = `toast ${art}`; t.textContent = text; document.body.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }
  const theme = () => { try { return localStorage.getItem('fah-adblock-theme') || 'dunkel'; } catch (e) { return 'dunkel'; } };
  const setzeTheme = (t) => { document.documentElement.dataset.theme = t; try { localStorage.setItem('fah-adblock-theme', t); } catch (e) {} };
  setzeTheme(theme());
  function waehle(titel, optionen) {
    return new Promise((ok) => {
      const schleier = document.createElement('div'); schleier.className = 'schleier';
      const box = document.createElement('div'); box.className = 'karte'; box.setAttribute('role', 'dialog');
      box.style.cssText = 'position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:45;width:min(420px,calc(100vw - 32px));padding:18px';
      box.innerHTML = `<h3 style="margin:0 0 12px;font-size:16px">${esc(titel)}</h3><div style="display:flex;flex-direction:column;gap:8px">${optionen.map((o, i) => `<button class="knopf ${o.art || ''}" data-i="${i}" style="justify-content:flex-start">${esc(o.text)}</button>`).join('')}<button class="knopf leise" data-i="-1">Abbrechen</button></div>`;
      const zu = (wert) => { schleier.remove(); box.remove(); ok(wert); };
      schleier.onclick = () => zu(null);
      box.onclick = (e) => { const b = e.target.closest('button'); if (b) zu(+b.dataset.i >= 0 ? optionen[+b.dataset.i].wert : null); };
      document.body.append(schleier, box); box.querySelector('button')?.focus();
    });
  }

  // Hinweisfenster mit eigenem Inhalt (Text bricht um) und Knöpfen [{text, art, fn}]
  function hinweisDialog(titel, html, knoepfe = []) {
    const schleier = document.createElement('div'); schleier.className = 'schleier';
    const box = document.createElement('div'); box.className = 'karte hinweisdialog'; box.setAttribute('role', 'dialog'); box.setAttribute('aria-label', titel);
    box.innerHTML = `<h3>${esc(titel)}</h3><div class="dialoginhalt">${html}</div><div class="dialogknoepfe">${knoepfe.map((k, i) => `<button class="knopf ${k.art || ''}" data-i="${i}">${esc(k.text)}</button>`).join('')}<button class="knopf leise" data-i="-1">Schließen</button></div>`;
    const zu = () => { schleier.remove(); box.remove(); };
    schleier.onclick = zu;
    box.onclick = (e) => { const b = e.target.closest('button[data-i]'); if (!b) return; const k = knoepfe[+b.dataset.i]; if (k) k.fn?.(); zu(); };
    document.body.append(schleier, box); box.querySelector('button')?.focus();
  }

  // ── Anmeldung ──────────────────────────────────────────────────────────────
  function zeigeAnmeldung(fehler = '') {
    stoppeAlles();
    $('#app').innerHTML = `<div class="anmeldung"><div class="karte anmeldekarte">${SCHILD}<h1>FAH-Adblock</h1><p>Netzweiter Schutz vor Werbung und Trackern</p>
      <form id="anmeldeform"><div class="feld"><label for="an-name">Name</label><input id="an-name" type="text" autocomplete="username" value="admin" required></div>
      <div class="feld"><label for="an-pw">Passwort</label><input id="an-pw" type="password" autocomplete="current-password" required></div>
      ${fehler ? `<div class="fehlertext">${esc(fehler)}</div>` : ''}<button class="knopf gruen" type="submit">Anmelden</button></form></div></div>`;
    $('#an-pw').focus();
    $('#anmeldeform').onsubmit = async (e) => {
      e.preventDefault();
      try { await api('/api/anmelden', { methode: 'POST', daten: { name: $('#an-name').value, passwort: $('#an-pw').value } }); await start(); }
      catch (err) { zeigeAnmeldung(err.message); }
    };
  }

  // ── Rahmen ─────────────────────────────────────────────────────────────────
  function rahmen() {
    $('#app').innerHTML = `
      <header class="kopf">
        <div class="marke">${SCHILD}<div>FAH-Adblock<br><small>DNS-Schutzschild</small></div></div>
        <nav class="navi" aria-label="Bereiche">${ANSICHTEN.map((a) => `<button data-ansicht="${a.id}">${a.name}</button>`).join('')}</nav>
        <div class="kopfrechts">
          <div class="statuspille" id="statuspille" title="Zustand des DNS-Dienstes"><i></i><span>verbinde …</span></div>
          <div class="pausemenue"><button class="knopf" id="pauseknopf" aria-haspopup="true">⏸ Pause</button><div class="aufklapp versteckt" id="pauseaufklapp">
            <button data-pause="5">5 Minuten pausieren</button><button data-pause="15">15 Minuten pausieren</button><button data-pause="60">1 Stunde pausieren</button><button data-pause="0">Schutz wieder einschalten</button>${info('Alle Geräte ungefiltert – danach schaltet sich der Schutz von selbst wieder ein. Nur ein Gerät pausieren: unter Geräte.')}</div></div>
          <button class="knopf leise klein" id="themeknopf" title="Hell/Dunkel">◐</button>
        </div>
      </header>
      <main id="haupt"></main>
      <nav class="untennavi" aria-label="Bereiche">${ANSICHTEN.filter((a) => a.id !== 'statistik').map((a) => `<button data-ansicht="${a.id}"><span>${a.symbol}</span>${a.kurz || a.name}</button>`).join('')}</nav>`;
    if (!rahmen.verdrahtet) { document.addEventListener('click', klickVerteiler); rahmen.verdrahtet = true; }
    $('#themeknopf').onclick = () => { setzeTheme(theme() === 'dunkel' ? 'hell' : 'dunkel'); Buehne.farben(); };
    $('#pauseknopf').onclick = (e) => { e.stopPropagation(); $('#pauseaufklapp').classList.toggle('versteckt'); };
  }
  async function klickVerteiler(e) {
    const a = e.target.closest('[data-ansicht]'); if (a) { location.hash = a.dataset.ansicht; return; }
    if (!e.target.closest('.pausemenue')) $('#pauseaufklapp')?.classList.add('versteckt');
    const p = e.target.closest('[data-pause]');
    if (p) { $('#pauseaufklapp').classList.add('versteckt'); await pause('', +p.dataset.pause); return; }
  }
  async function pause(geraet, minuten) {
    try { await api('/api/pause', { methode: 'POST', daten: { geraet: geraet || undefined, minuten } }); toast(minuten ? `${geraet ? 'Gerät' : 'Schutz'} für ${minuten} min pausiert` : 'Schutz wieder aktiv'); ladeUebersicht(); if (S.ansicht === 'geraete') zeigeGeraete(); }
    catch (err) { toast(err.message, 'fehler'); }
  }
  function kopfAktualisieren() {
    const u = S.uebersicht; if (!u) return;
    const pille = $('#statuspille'), knopf = $('#pauseknopf');
    const ms = u.upstream.anbieter.find((a) => a.ms != null);
    const pauseBis = u.pause.global;
    pille.className = 'statuspille' + (!u.dns.laeuft ? ' fehler' : pauseBis ? ' pause' : '');
    pille.querySelector('span').textContent = !u.dns.laeuft ? 'DNS gestoppt' : pauseBis ? `pausiert bis ${new Date(pauseBis).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}` : `Schutz aktiv${ms ? ` · ${ms.name} ${ms.ms} ms` : ''}`;
    knopf.classList.toggle('pausiert', !!pauseBis);
    knopf.textContent = pauseBis ? `▶ Pause · noch ${Math.max(1, Math.ceil((pauseBis - Date.now()) / 60000))} min` : '⏸ Pause';
  }
  async function ladeUebersicht() {
    try {
      S.uebersicht = await api(`/api/uebersicht?stunden=${S.schildStunden}`); kopfAktualisieren(); if (S.ansicht === 'schild') schildZahlen();
      // Neue Version auf dem NAS: Oberfläche neu laden (nicht mitten in einer Eingabe oder einem Dialog)
      S.version = S.version || S.uebersicht.version;
      if (S.uebersicht.version && S.version !== S.uebersicht.version && !S.neuLaden) {
        S.neuLaden = true; toast('Neue Version – Oberfläche wird neu geladen');
        const versuch = () => { const aktiv = document.activeElement; if ((aktiv && /INPUT|TEXTAREA|SELECT/.test(aktiv.tagName)) || document.querySelector('[role="dialog"]')) return setTimeout(versuch, 3000); location.reload(); };
        setTimeout(versuch, 1500);
      }
    } catch (e) {}
  }
  function stoppeAlles() { S.timer.forEach(clearInterval); S.timer = []; S.quelle?.close(); S.quelle = null; Buehne.stopp(); }

  // ── Livestrom ──────────────────────────────────────────────────────────────
  function liveVerbinden() {
    S.quelle?.close();
    const q = new EventSource('/api/live');
    q.addEventListener('start', (e) => { S.live = JSON.parse(e.data); if (S.ansicht === 'schild') geblocktListe(); });
    q.addEventListener('anfragen', (e) => {
      const { e: liste, extra } = JSON.parse(e.data);
      S.live.push(...liste); if (S.live.length > 400) S.live.splice(0, S.live.length - 400);
      Buehne.ereignisse(liste, extra);
      if (S.ansicht === 'schild') geblocktListe(liste);
      if (S.ansicht === 'protokoll') protokollLive(liste);
    });
    S.quelle = q;
  }

  // ── Router ─────────────────────────────────────────────────────────────────
  function route() {
    const id = (location.hash || '#schild').slice(1);
    S.ansicht = ANSICHTEN.some((a) => a.id === id) ? id : 'schild';
    $$('[data-ansicht]').forEach((b) => b.setAttribute('aria-current', b.dataset.ansicht === S.ansicht ? 'page' : 'false'));
    Buehne.stopp();
    ({ schild: zeigeSchild, geraete: zeigeGeraete, protokoll: zeigeProtokoll, listen: zeigeListen, dienste: zeigeDienste, profile: zeigeProfile, kinderschutz: zeigeKinderschutz, statistik: zeigeStatistik, einstellungen: zeigeEinstellungen })[S.ansicht]();
    window.scrollTo({ top: 0 });
  }
  function hinweisband() {
    const sp = S.ich?.spiegel;
    const ersatz = sp?.rolle === 'ersatz' ? `<div class="hinweisband"><span>🔁 <b>Ersatz-Instanz</b> – Listen, Profile, Geräte und Regeln kommen alle 2 Minuten vom Haupt. Ändern bitte dort.</span><a class="knopf klein" href="${esc(sp.haupt_url || '#')}" target="_blank" rel="noopener">Zum Haupt</a></div>` : '';
    return ersatz + (S.ich?.standardPasswort ? `<div class="hinweisband"><span>🔑 Es gilt noch das Startpasswort <b>admin / admin</b> – bitte in den Einstellungen ändern.</span><a class="knopf klein" href="#einstellungen">Passwort ändern</a></div>` : '');
  }

  // ── Schutzschild ───────────────────────────────────────────────────────────
  function zeigeSchild() {
    const zt = ZEITRAEUME.find(([h]) => h === S.schildStunden)?.[1] || '24 h';
    $('#haupt').innerHTML = `${hinweisband()}
      <div class="zeitwahl"><span>Zeitraum</span>${ZEITRAEUME.map(([h, t]) => `<button class="knopf klein ${h === S.schildStunden ? '' : 'leise'}" data-schildstunden="${h}" aria-pressed="${h === S.schildStunden}">${t}</button>`).join('')}</div>
      ${info('Gilt für die Zahlen oben und die Liste „Meistgeblockt". <b>24 h</b>, <b>7 Tage</b> und <b>1 Monat</b> zählen gleitend ab jetzt. Die Stundenstatistik wird 35 Tage vorgehalten; die Domain-Liste reicht nur so weit, wie das Protokoll aufbewahrt wird (Einstellungen → Protokoll).')}
      <section class="kennzahlen" id="kennzahlen"></section>
      <section class="karte"><div class="schildbuehne" id="buehne"><canvas id="buehnencanvas" aria-label="Live-Ansicht: Anfragen der Geräte treffen auf die Schutzwand zwischen Heimnetz und Internet"></canvas>
        <div class="buehnenzahl"><b id="rate">–</b><span>Anfragen / min</span></div>
        <div class="buehnenlegende"><span><i style="background:var(--ich)"></i>deine Geräte</span><span><i style="background:var(--neutral)"></i>erlaubt</span><span><i style="background:var(--block)"></i>geblockt</span></div></div></section>
      <div class="zweispaltig">
        <section class="karte"><div class="kartekopf">⛔ Gerade geblockt<span class="rechts"><span class="chip rot" id="geblocktzahl">0</span></span></div><div class="zeilen" id="geblocktliste"><div class="leer">Warte auf Anfragen …</div></div></section>
        <section class="karte"><div class="kartekopf">🏆 Meistgeblockt · <span id="topzeitraum">${zt}</span></div><div id="topgeblockthinweis"></div><div id="topgeblockt"><div class="leer">wird geladen …</div></div></section>
      </div>`;
    $$('[data-schildstunden]').forEach((b) => { b.onclick = () => zeitraumWaehlen(+b.dataset.schildstunden); });
    schildZahlen(); geblocktListe(); topGeblockt();
    Buehne.start($('#buehnencanvas'));
  }
  function zeitraumWaehlen(h) {
    S.schildStunden = h; try { localStorage.setItem('schildStunden', String(h)); } catch (e) {}
    const zt = ZEITRAEUME.find(([x]) => x === h)?.[1] || '24 h';
    $$('[data-schildstunden]').forEach((b) => { const an = +b.dataset.schildstunden === h; b.setAttribute('aria-pressed', String(an)); b.classList.toggle('leise', !an); });
    const tz = $('#topzeitraum'); if (tz) tz.textContent = zt;
    ladeUebersicht(); topGeblockt();
  }
  function schildZahlen() {
    const u = S.uebersicht, el = $('#kennzahlen'); if (!u || !el) return;
    const k = u.kennzahlen, cache = u.upstream.cache.trefferquote, ms = u.upstream.anbieter.find((a) => a.ms != null);
    // Zahlen für den gewählten Zeitraum; ältere Server ohne „zeitraum" liefern „heute"
    const z = k.zeitraum && k.zeitraum.stunden === S.schildStunden ? k.zeitraum : k.heute;
    const zt = k.zeitraum && k.zeitraum.stunden === S.schildStunden ? (ZEITRAEUME.find(([x]) => x === S.schildStunden)?.[1] || '24 h') : 'heute';
    const karten = [
      ['', zahl(z.anfragen), `Anfragen · ${zt}`, `${zahl(u.dns.zaehler.anfragen)} seit Start`],
      ['rot', zahl(z.geblockt), `Geblockt · ${zt}`, `${String(z.quote).replace('.', ',')} % aller Anfragen`],
      ['gruen', zahl(k.aktiveGeraete), 'Aktive Geräte', 'letzte 10 Minuten'],
      ['', cache == null ? '–' : `${cache} %`, 'Aus dem Speicher', `${zahl(u.upstream.cache.eintraege)} Einträge`],
      ['', ms ? `${ms.ms} ms` : '–', 'Antwortzeit', ms ? `verschlüsselt über ${esc(ms.name)}` : 'noch keine Anfrage'],
      [u.sperrseite?.an ? 'gruen' : '', u.sperrseite?.an ? 'an' : 'aus', 'Sperrseite', `${zahl(u.sperrseite?.aufrufe || 0)} Aufrufe seit Start`],
    ];
    const ks = u.kinderschutz;
    if (ks) karten.push(
      [ks.meldungen.heute ? 'rot' : '', ks.meldungen.an ? zahl(ks.meldungen.heute) : 'aus', 'Kinderschutz-Meldungen', ks.meldungen.letzte ? `zuletzt ${vor(ks.meldungen.letzte.ts)}` : ks.meldungen.an ? 'heute keine' : 'unter Kinderschutz einschalten', 'kinderschutz'],
      [ks.zeitkonten.aufgebraucht ? 'rot' : '', ks.zeitkonten.geraete ? zahl(ks.zeitkonten.aufgebraucht) : '–', 'Zeitlimits erreicht', ks.zeitkonten.geraete ? `${zahl(ks.zeitkonten.geraete)} ${ks.zeitkonten.geraete === 1 ? 'Gerät' : 'Geräte'} mit Limit` : 'keine Limits festgelegt', 'kinderschutz'],
      [ks.unterwegs?.an ? 'gruen' : '', ks.unterwegs?.an ? zahl(ks.unterwegs.aktiv) : 'aus', 'Unterwegs geschützt', ks.unterwegs?.an ? `${zahl(ks.unterwegs.geraete)} eingerichtet · letzte Stunde` : 'Mobilfunk-Schutz aus', 'kinderschutz'],
    );
    for (const k of u.erweiterungen || []) if (Array.isArray(k) && k.length >= 4) karten.push([['rot', 'gruen'].includes(k[0]) ? k[0] : '', esc(k[1]), esc(k[2]), esc(k[3]), /^[a-z]+$/.test(String(k[4] || '')) ? k[4] : '']);
    el.innerHTML = karten.map(([art, wert, name, unter, ziel]) => `<div class="karte kz ${art}" ${ziel ? `data-ansicht="${ziel}" role="link" tabindex="0" style="cursor:pointer"` : ''}><div class="wert">${wert}</div><div class="name">${name}</div><div class="unter">${unter}</div></div>`).join('');
    const rate = $('#rate'); if (rate) { const minute = S.live.filter((e) => e.t > Date.now() - 60000).length; rate.textContent = zahl(minute); }
  }
  function geblocktListe(neu) {
    const el = $('#geblocktliste'); if (!el) return;
    const rate = $('#rate'); if (rate) rate.textContent = zahl(S.live.filter((e) => e.t > Date.now() - 60000).length);
    const geblockt = S.live.filter((e) => e.a === 'geblockt').slice(-14).reverse();
    $('#geblocktzahl').textContent = zahl(S.live.filter((e) => e.a === 'geblockt').length);
    if (!geblockt.length) { el.innerHTML = '<div class="leer">In den letzten Minuten nichts geblockt.</div>'; return; }
    const neueSchluessel = new Set((neu || []).filter((e) => e.a === 'geblockt').map((e) => `${e.t}|${e.d}`));
    el.innerHTML = geblockt.map((e) => `<div class="zeile ${neueSchluessel.has(`${e.t}|${e.d}`) ? 'neu' : ''}"><i class="punkt rot"></i><div class="haupt"><b class="mono">${esc(e.d)}</b>${dinfo(e.d, { kurz: true })}<small>${esc(e.n || e.g)} · ${uhr(e.t)} · ${esc(grundText(e))}</small></div>
      <button class="knopf klein" data-freigeben="${esc(e.d)}" data-geraet="${esc(e.g)}" data-name="${esc(e.n || e.g)}">Freigeben</button></div>`).join('');
  }
  // Was ist diese Domain? (public/domaininfo.js) – kurz: Unbekanntes ohne Nachschlage-Link (Tabellen)
  function dinfo(domain, { kurz = false } = {}) {
    const i = window.DomainInfo?.beschreibe(domain);
    if (!i) return kurz ? '' : `<small class="dinfo unbekannt">keine Beschreibung bekannt · <a href="https://duckduckgo.com/?q=%22${encodeURIComponent(domain)}%22" target="_blank" rel="noopener noreferrer">im Web nachschlagen ↗</a></small>`;
    const rest = i.anbieter ? i.text.slice(i.anbieter.length) : i.text;
    return `<small class="dinfo">${i.anbieter ? `<b>${esc(i.anbieter)}</b>` : ''}${esc(rest)}${i.hinweis ? `<span class="dhinweis">⚠ ${esc(i.hinweis)}</span>` : ''}</small>`;
  }
  const grundText = (e) => e.r === 'Liste' ? (e.l || 'Blockliste') : e.r === 'CNAME-Tarnung' ? `getarnter Tracker (${e.l})` : e.r === 'Dienst gesperrt' ? `Dienst gesperrt (${e.l})` : e.r || '';
  async function topGeblockt() {
    const el = $('#topgeblockt'); if (!el) return;
    try {
      const top = await api(`/api/top?aktion=geblockt&stunden=${S.schildStunden}&limit=10`);
      const hinweis = $('#topgeblockthinweis'), tage = S.uebersicht?.protokoll?.tage;
      if (hinweis) hinweis.innerHTML = tage && S.schildStunden / 24 > tage ? `<div class="leer" style="padding:8px 20px">Das Protokoll wird ${tage} Tage aufbewahrt – die Liste umfasst nur diese ${tage} Tage. Länger aufheben: Einstellungen → Protokoll.</div>` : '';
      if (!top.length) { el.innerHTML = '<div class="leer">Noch nichts geblockt.</div>'; return; }
      const max = top[0].n;
      el.innerHTML = top.map((t) => `<div class="balkenzeile"><span class="mono">${esc(t.domain)}</span><b class="mono">${zahl(t.n)}</b>${dinfo(t.domain)}<div class="balken"><i style="width:${Math.max(2, t.n / max * 100)}%"></i></div></div>`).join('');
    } catch (e) {}
  }
  document.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-freigeben]'); if (!b) return;
    await freigabeDialog(b.dataset.freigeben, b.dataset.geraet, b.dataset.name);
  });
  async function freigabeDialog(domain, geraet, name) {
    const wahl = await waehle(`${domain} freigeben`, [
      { text: `Nur für ${name} · 1 Stunde`, wert: { geltung: `geraet:${geraet}`, minuten: 60 }, art: 'gruen' },
      { text: `Nur für ${name} · dauerhaft`, wert: { geltung: `geraet:${geraet}`, minuten: 0 } },
      { text: 'Für alle Geräte · dauerhaft', wert: { geltung: 'alle', minuten: 0 } },
    ]);
    if (!wahl) return false;
    try { await api('/api/regeln', { methode: 'POST', daten: { typ: 'erlauben', muster: domain, ...wahl, notiz: 'Rettung' } }); toast(`✓ ${domain} freigegeben – Seite/App neu laden`); return true; }
    catch (err) { toast(err.message, 'fehler'); return false; }
  }

  // Bühne: Heimnetz links, eine Wand in der Mitte trennt es vom Internet rechts. Jede Anfrage (gebündelt) fliegt
  // als Lichtpunkt zur Wand: geblockte prallen ab (Funken, Steine glühen rot), erlaubte gehen durch einen Spalt.
  const Buehne = (() => {
    let cv = null, ctx = null, W = 0, H = 0, dpr = 1, laeuft = false, sichtbar = true, beobachter = null, raf = 0, letzteZeit = 0;
    const teilchen = [], funken = [], geraete = new Map(), domains = [], spalte = [], symbole = new Map();
    const symbolBild = (id) => { if (!id) return null; let b = symbole.get(id); if (!b) { b = new Image(); b.src = `/api/symbol/${id}`; symbole.set(id, b); } return b.complete && b.naturalWidth ? b : null; };
    let hitze = [], zeitGesamt = 0, farbe = {}, pflege = 0;
    const farben = () => { const s = getComputedStyle(document.documentElement), v = (n) => s.getPropertyValue(n).trim(); farbe = { ich: v('--ich'), block: v('--block'), neutral: v('--neutral'), akzent: v('--akzent'), text: v('--text'), muted: v('--muted'), rand: v('--rand2'), bg: v('--bg'), bg2: v('--bg2'), karte: v('--karte2') }; };
    const STEIN_H = 20;
    function groesse() { if (!cv) return; const r = cv.getBoundingClientRect(); dpr = Math.min(2, devicePixelRatio || 1); W = r.width; H = r.height; cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); hitze = new Array(Math.ceil(H / STEIN_H) + 1).fill(0); ordneGeraete(); }
    // Wand: Mitte, Breite, Plakette mit dem Zähler
    const wand = () => {
      const breite = Math.max(40, Math.min(92, W * 0.065)), x = W < 600 ? W * 0.54 : W * 0.5;
      const pb = Math.max(118, Math.min(210, W * 0.15)), ph = Math.max(64, Math.min(96, H * 0.18));
      return { x, links: x - breite / 2, rechts: x + breite / 2, breite, platte: { x: x - pb / 2, y: H / 2 - ph / 2, b: pb, h: ph } };
    };
    // Alle aktiven Geräte (letzte 10 min, wie die Kachel „Aktive Geräte“) – bei vielen in mehreren Spalten
    const AKTIV_MS = 600000;
    let spaltenBreite = 0, spaltenZahl = 1, symbolR = 12;
    function ordneGeraete() {
      const liste = [...geraete.values()].sort((a, b) => a.name.localeCompare(b.name, 'de')), n = liste.length;
      const breit = W >= 480, oben = Math.max(H * 0.13, 44), hoehe = H * 0.86 - oben, abstand = breit ? 32 : 18;
      const spalten = Math.max(1, Math.min(4, Math.ceil(n * abstand / Math.max(1, hoehe))));
      const jeSpalte = Math.ceil(n / spalten), links = breit ? W * 0.06 : 12, wandLinks = wand().links;
      const schritt = jeSpalte > 1 ? hoehe / (jeSpalte - 1) : hoehe;
      symbolR = Math.max(7, Math.min(breit ? 13 : 10, schritt * 0.38));
      spaltenBreite = Math.min(breit ? 260 : 200, (wandLinks - 16 - links) / spalten); spaltenZahl = spalten;
      liste.forEach((g, i) => {
        const sp = Math.floor(i / jeSpalte), zeile = i % jeSpalte, zeilen = Math.min(jeSpalte, n - sp * jeSpalte);
        g.zx = links + symbolR + 2 + sp * spaltenBreite;
        g.zy = zeilen === 1 ? H * 0.5 : oben + hoehe * zeile / (zeilen - 1);
        if (g.x == null) { g.x = g.zx - 40; g.y = g.zy; }
      });
    }
    function geraetVon(id, name, zuletzt = Date.now()) {
      let g = geraete.get(id), neu = false;
      if (!g) { g = { id, name: name || id, zuletzt, puls: 0 }; geraete.set(id, g); neu = true; }
      g.zuletzt = Math.max(g.zuletzt, zuletzt);
      if (name && name !== g.name) { g.name = name; neu = true; }
      if (neu) ordneGeraete();
      return g;
    }
    function aufraeumen() {
      const grenze = Date.now() - AKTIV_MS; let weg = false;
      for (const g of geraete.values()) if (g.zuletzt < grenze) { geraete.delete(g.id); weg = true; }
      if (weg) ordneGeraete();
    }
    function abgleichen(canvas) {
      api('/api/geraete').then((d) => {
        if (cv !== canvas) return;
        const jetzt = Date.now();
        for (const g of d.geraete) if (jetzt - g.zuletzt < AKTIV_MS) geraetVon(g.id, g.name, g.zuletzt).icon = g.icon || null;
        const ids = new Set(d.geraete.map((g) => g.id));
        for (const g of geraete.values()) if (g.id.startsWith('ip:') && !ids.has(g.id) && jetzt - g.zuletzt > 30000) geraete.delete(g.id);   // inzwischen dem Gerät (MAC) zugeordnet
        aufraeumen(); ordneGeraete();
      }).catch(() => {});
    }
    // Nicht sichtbar (anderer Tab, weggescrollt): keine Punkte ansammeln – sonst holt die Bühne beim Zurückkehren
    // alles auf einmal nach. Sie zeigt immer nur, was gerade passiert.
    const unsichtbar = () => document.hidden || !sichtbar;
    function ereignisse(liste) {
      if (!cv || !laeuft) return;
      if (wenigBewegung() || unsichtbar()) { for (const e of liste) geraetVon(e.g, e.n, e.t); return; }
      const geblockt = liste.filter((e) => e.a === 'geblockt'), erlaubt = liste.filter((e) => e.a === 'erlaubt' || e.a === 'lokal');
      const auswahl = [...geblockt.slice(-14), ...erlaubt.slice(-(22 - Math.min(14, geblockt.length)))];
      auswahl.forEach((e, i) => { const warte = i * (280 / Math.max(1, auswahl.length)), soll = performance.now() + warte; setTimeout(() => { if (!unsichtbar() && performance.now() - soll < 400) neuesTeilchen(e); }, warte); });
    }
    // Auftreffhöhe an der Wand – nicht dort, wo die Plakette sitzt
    function trefferHoehe(w) {
      for (let i = 0; i < 6; i++) { const y = H * (0.08 + Math.random() * 0.84); if (y < w.platte.y - 8 || y > w.platte.y + w.platte.h + 8) return y; }
      return Math.random() < 0.5 ? w.platte.y - 20 : w.platte.y + w.platte.h + 20;
    }
    function neuesTeilchen(e) {
      if (teilchen.length > 160) return;
      const g = geraetVon(e.g, e.n, e.t), w = wand(), blockiert = e.a === 'geblockt';
      g.puls = 1;
      const zy = trefferHoehe(w);
      const aus = { x: W * (0.8 + Math.random() * 0.12), y: Math.max(66, Math.min(H - 40, H * (0.14 + Math.random() * 0.72))) };
      teilchen.push({ g, x0: g.x + symbolR, y0: g.y, ziel: { x: w.links - 2, y: zy }, aus, t: 0, dauer: 750 + Math.random() * 350, blockiert, domain: e.d, phase: 0, geboren: performance.now() });
    }
    function aufprall(x, y) {
      const reihe = Math.floor(y / STEIN_H);
      for (let d = -1; d <= 1; d++) if (hitze[reihe + d] != null) hitze[reihe + d] = Math.min(1, hitze[reihe + d] + (d ? 0.45 : 0.9));
      for (let i = 0; i < 12; i++) { const w = Math.PI / 2 + Math.random() * Math.PI, v = 50 + Math.random() * 150; funken.push({ x, y, vx: Math.cos(w) * v, vy: Math.sin(w) * v * 0.8, leben: 1, groesse: 1 + Math.random() * 2.2 }); }
      funken.push({ ring: true, x, y, leben: 1 });
    }
    function zeichneWand(w) {
      // Steine im Verband
      const halb = w.breite / 2;
      for (let r = 0, y = 0; y < H; r++, y += STEIN_H) {
        const h = hitze[r] || 0, versatz = r % 2 ? halb / 2 : 0;
        for (let x = w.links - versatz; x < w.rechts; x += halb) {
          const x1 = Math.max(w.links, x + 1.5), x2 = Math.min(w.rechts, x + halb - 1.5);
          if (x2 - x1 < 3) continue;
          ctx.fillStyle = farbe.karte; ctx.fillRect(x1, y + 1.5, x2 - x1, STEIN_H - 3);
          ctx.globalAlpha = 0.9; ctx.strokeStyle = farbe.rand; ctx.lineWidth = 1; ctx.strokeRect(x1 + 0.5, y + 2, x2 - x1 - 1, STEIN_H - 4);
          ctx.globalAlpha = 0.5; ctx.fillStyle = farbe.rand; ctx.fillRect(x1 + 1, y + 2, x2 - x1 - 2, 1.5); ctx.globalAlpha = 1;   // Lichtkante oben
          if (h > 0.02) { ctx.globalAlpha = h * 0.8; ctx.fillStyle = farbe.block; ctx.fillRect(x1, y + 1.5, x2 - x1, STEIN_H - 3); ctx.globalAlpha = 1; }
        }
      }
      // Tiefe: zum Internet hin dunkler
      const tiefe = ctx.createLinearGradient(w.links, 0, w.rechts, 0); tiefe.addColorStop(0, 'transparent'); tiefe.addColorStop(1, farbe.bg);
      ctx.globalAlpha = 0.35; ctx.fillStyle = tiefe; ctx.fillRect(w.links, 0, w.breite, H); ctx.globalAlpha = 1;
      // Energiekante zum Heimnetz
      const puls = 0.65 + Math.sin(zeitGesamt * 2.2) * 0.15;
      ctx.beginPath(); ctx.moveTo(w.links, 0); ctx.lineTo(w.links, H); ctx.strokeStyle = farbe.ich; ctx.lineWidth = 2.5; ctx.globalAlpha = puls; ctx.shadowColor = farbe.ich; ctx.shadowBlur = 16; ctx.stroke(); ctx.shadowBlur = 0; ctx.globalAlpha = 1;
      for (let r = 0; r < hitze.length; r++) if (hitze[r] > 0.05) { ctx.beginPath(); ctx.moveTo(w.links, r * STEIN_H); ctx.lineTo(w.links, (r + 1) * STEIN_H); ctx.strokeStyle = farbe.block; ctx.lineWidth = 3.5; ctx.globalAlpha = hitze[r]; ctx.stroke(); ctx.globalAlpha = 1; }
      // Wand oben/unten weich ausblenden – sie geht „endlos“ weiter
      ctx.save(); ctx.globalCompositeOperation = 'destination-out';
      for (const [y0, y1] of [[0, 40], [H, H - 40]]) { const g = ctx.createLinearGradient(0, y0, 0, y1); g.addColorStop(0, 'rgba(0,0,0,1)'); g.addColorStop(1, 'rgba(0,0,0,0)'); ctx.fillStyle = g; ctx.fillRect(w.links - 24, Math.min(y0, y1), w.breite + 26, 40); }
      ctx.restore();
      // Heimnetz leicht grün getönt, Internet mit Punktraster
      const tint = ctx.createLinearGradient(0, 0, w.links, 0); tint.addColorStop(0, 'transparent'); tint.addColorStop(1, farbe.ich);
      ctx.globalAlpha = 0.05; ctx.fillStyle = tint; ctx.fillRect(0, 0, w.links, H); ctx.globalAlpha = 1;
      ctx.fillStyle = farbe.rand; ctx.globalAlpha = 0.55;
      for (let y = 14; y < H; y += 22) for (let x = w.rechts + 18 + ((y / 22) % 2) * 11; x < W; x += 22) ctx.fillRect(x, y, 1.4, 1.4);
      ctx.globalAlpha = 1;
      // Durchlässe erlaubter Anfragen
      for (const s of spalte) { const g = ctx.createLinearGradient(w.links, 0, w.rechts, 0); g.addColorStop(0, farbe.ich); g.addColorStop(1, farbe.neutral); ctx.globalAlpha = s.leben * 0.8; ctx.fillStyle = g; ctx.fillRect(w.links, s.y - 1.5, w.breite, 3); ctx.globalAlpha = 1; }
    }
    function zeichnePlatte(w) {
      const p = w.platte, k = S.uebersicht?.kennzahlen, r = 12;
      ctx.beginPath(); ctx.roundRect ? ctx.roundRect(p.x, p.y, p.b, p.h, r) : ctx.rect(p.x, p.y, p.b, p.h);
      ctx.fillStyle = farbe.bg2; ctx.fill();
      const glut = Math.max(0, ...hitze.slice(Math.floor(p.y / STEIN_H) - 3, Math.ceil((p.y + p.h) / STEIN_H) + 3)) || 0;
      ctx.lineWidth = 2; ctx.strokeStyle = glut > 0.3 ? farbe.block : farbe.ich; ctx.shadowColor = ctx.strokeStyle; ctx.shadowBlur = 16; ctx.stroke(); ctx.shadowBlur = 0;
      ctx.textAlign = 'center'; ctx.fillStyle = farbe.text;
      // Plakette folgt dem gewählten Zeitraum (wie die Kennzahlen oben); ältere Server liefern nur „heute"
      const zr = k && k.zeitraum && k.zeitraum.stunden === S.schildStunden ? k.zeitraum : k?.heute;
      const plakette = k && k.zeitraum && k.zeitraum.stunden === S.schildStunden ? `GEBLOCKT · ${(ZEITRAEUME.find(([x]) => x === S.schildStunden)?.[1] || '24 h').toUpperCase()}` : 'GEBLOCKT HEUTE';
      const zahlText = zr ? zahl(zr.geblockt) : '–', breite = p.b - 20;
      let gz = Math.round(p.h * 0.46); ctx.font = `800 ${gz}px "JetBrains Mono", monospace`; while (gz > 10 && ctx.measureText(zahlText).width > breite) { gz--; ctx.font = `800 ${gz}px "JetBrains Mono", monospace`; }
      ctx.fillText(zahlText, w.x, p.y + p.h * 0.56);
      let lz = Math.max(8, Math.round(p.h * 0.13)); ctx.font = `700 ${lz}px Inter, system-ui, sans-serif`; while (lz > 7 && ctx.measureText(plakette).width > breite) { lz--; ctx.font = `700 ${lz}px Inter, system-ui, sans-serif`; }
      ctx.fillStyle = farbe.muted; ctx.fillText(plakette, w.x, p.y + p.h * 0.82);
    }
    function zeichne(zeit) {
      if (!laeuft) return;
      raf = requestAnimationFrame(zeichne);
      if (unsichtbar()) { letzteZeit = zeit; teilchen.length = 0; funken.length = 0; spalte.length = 0; return; }
      const dt = Math.min(0.05, (zeit - (letzteZeit || zeit)) / 1000); letzteZeit = zeit;
      const ruhig = !teilchen.length && !funken.length && !spalte.length && !hitze.some((h) => h > 0.01);
      if (ruhig && (zeichne.zaehler = (zeichne.zaehler || 0) + 1) % 3) return;   // im Leerlauf nur jedes 3. Bild
      zeitGesamt += ruhig ? dt * 3 : dt;
      ctx.clearRect(0, 0, W, H);
      const w = wand();
      for (let r = 0; r < hitze.length; r++) hitze[r] = Math.max(0, hitze[r] - dt * 1.6);
      for (let i = spalte.length - 1; i >= 0; i--) { spalte[i].leben -= dt * 3; if (spalte[i].leben <= 0) spalte.splice(i, 1); }
      zeichneWand(w);
      // Beschriftungen
      ctx.font = '700 10px Inter, system-ui, sans-serif'; ctx.fillStyle = farbe.text; ctx.globalAlpha = 0.5;
      ctx.textAlign = 'left'; ctx.fillText('HEIMNETZ', 14, 20);
      ctx.textAlign = 'right'; ctx.fillText('INTERNET  →', W - 14, H - 16); ctx.globalAlpha = 1;
      ctx.font = '600 11px Inter, system-ui, sans-serif';
      for (let i = domains.length - 1; i >= 0; i--) { const d = domains[i]; d.leben -= dt * 0.35; if (d.leben <= 0) { domains.splice(i, 1); continue; } ctx.globalAlpha = Math.min(1, d.leben) * 0.75; ctx.fillStyle = farbe.muted; ctx.fillText(d.text, W - 14, d.y); }
      ctx.globalAlpha = 1;
      // Geräte links
      ctx.textAlign = 'left';
      for (const g of geraete.values()) {
        g.x += (g.zx - g.x) * Math.min(1, dt * 4); g.y += (g.zy - g.y) * Math.min(1, dt * 4); g.puls = Math.max(0, g.puls - dt * 2.2);
        const breit = W >= 480, bild = symbolBild(g.icon), r = bild ? symbolR : 5;
        ctx.beginPath(); ctx.arc(g.x, g.y, r + 1 + g.puls * 6, 0, Math.PI * 2); ctx.fillStyle = farbe.ich; ctx.globalAlpha = 0.18 + g.puls * 0.3; ctx.fill(); ctx.globalAlpha = 1;
        if (bild) {
          ctx.beginPath(); ctx.arc(g.x, g.y, r, 0, Math.PI * 2); ctx.fillStyle = farbe.bg2; ctx.fill();
          ctx.lineWidth = 1.5; ctx.strokeStyle = farbe.ich; ctx.shadowColor = farbe.ich; ctx.shadowBlur = 8 + g.puls * 8; ctx.stroke(); ctx.shadowBlur = 0;
          const k = r * 1.45; ctx.drawImage(bild, g.x - k / 2, g.y - k / 2, k, k);
        } else { ctx.beginPath(); ctx.arc(g.x, g.y, 5, 0, Math.PI * 2); ctx.fillStyle = farbe.ich; ctx.shadowColor = farbe.ich; ctx.shadowBlur = 12; ctx.fill(); ctx.shadowBlur = 0; }
        // Name rechts neben dem Symbol – gekürzt auf den Platz bis zur Wand bzw. zur nächsten Spalte
        const schrift = breit ? 12 : spaltenZahl > 1 ? 9 : 10, lx = g.x + Math.max(r, 5) + 7;
        const vorPlatte = g.y > w.platte.y - 10 && g.y < w.platte.y + w.platte.h + 10 ? w.platte.x - 10 : w.links - 14;   // nicht unter die Zähler-Plakette
        const rechts = Math.min(vorPlatte, spaltenZahl === 1 ? w.links - 14 : g.x - symbolR - 2 + spaltenBreite - 6);
        const platz = Math.max(20, rechts - lx);
        ctx.font = `600 ${schrift}px Inter, system-ui, sans-serif`;
        const schluessel = `${g.name}|${Math.round(platz)}|${schrift}`;
        if (g.labelFuer !== schluessel) { let t = g.name; if (ctx.measureText(t).width > platz) { while (t.length > 1 && ctx.measureText(t + '…').width > platz) t = t.slice(0, -1); t += '…'; } g.label = t; g.labelFuer = schluessel; }
        ctx.fillStyle = farbe.text; ctx.globalAlpha = 0.9; ctx.fillText(g.label, lx, g.y + schrift * 0.36); ctx.globalAlpha = 1;
      }
      // Teilchen: Phase 0 zur Wand, Phase 1 durch die Wand, Phase 2 ins Internet
      for (let i = teilchen.length - 1; i >= 0; i--) {
        const p = teilchen[i]; p.t += dt * 1000;
        if (zeit - p.geboren > 4000) { teilchen.splice(i, 1); continue; }   // Nachzügler nach einer Pause verwerfen
        let x, y, fertig = false;
        if (p.phase === 0) {
          const u = Math.min(1, p.t / p.dauer), e = u < 0.5 ? 2 * u * u : 1 - Math.pow(-2 * u + 2, 2) / 2;
          const mx = (p.x0 + p.ziel.x) / 2, my = (p.y0 + p.ziel.y) / 2 - 30;
          x = (1 - e) * (1 - e) * p.x0 + 2 * (1 - e) * e * mx + e * e * p.ziel.x; y = (1 - e) * (1 - e) * p.y0 + 2 * (1 - e) * e * my + e * e * p.ziel.y;
          if (u >= 1) { if (p.blockiert) { aufprall(p.ziel.x, p.ziel.y); fertig = true; } else { p.phase = 1; p.t = 0; spalte.push({ y: p.ziel.y, leben: 1 }); } }
        } else if (p.phase === 1) {
          const u = Math.min(1, p.t / 160); x = w.links + (w.breite + 4) * u; y = p.ziel.y;
          if (u >= 1) { p.phase = 2; p.t = 0; p.x0 = w.rechts + 2; p.y0 = p.ziel.y; }
        } else {
          const u = Math.min(1, p.t / 700), e = 1 - Math.pow(1 - u, 3);
          x = p.x0 + (p.aus.x - p.x0) * e; y = p.y0 + (p.aus.y - p.y0) * e;
          if (u >= 1) { fertig = true; const text = p.domain.length > 32 ? '…' + p.domain.slice(-31) : p.domain, da = domains.find((d) => d.text === text); if (da) da.leben = 1.6; else if (domains.length < 14 && !domains.some((d) => Math.abs(d.y - p.aus.y) < 14)) domains.push({ text, y: p.aus.y, leben: 1.6 }); }
        }
        const c = p.blockiert ? farbe.block : p.phase === 0 ? farbe.ich : farbe.neutral;
        ctx.beginPath(); ctx.arc(x, y, p.blockiert ? 3.2 : 2.4, 0, Math.PI * 2); ctx.fillStyle = c; ctx.shadowColor = c; ctx.shadowBlur = p.blockiert ? 14 : 8; ctx.fill(); ctx.shadowBlur = 0;
        if (fertig) teilchen.splice(i, 1);
      }
      zeichnePlatte(w);
      // Funken und Aufprallringe (prallen zurück ins Heimnetz)
      for (let i = funken.length - 1; i >= 0; i--) {
        const f = funken[i]; f.leben -= dt * (f.ring ? 2.2 : 1.6);
        if (f.leben <= 0) { funken.splice(i, 1); continue; }
        if (f.ring) { ctx.beginPath(); ctx.arc(f.x, f.y, (1 - f.leben) * 30, Math.PI / 2, Math.PI * 1.5); ctx.strokeStyle = farbe.block; ctx.globalAlpha = f.leben * 0.8; ctx.lineWidth = 2; ctx.stroke(); ctx.globalAlpha = 1; continue; }
        f.x += f.vx * dt; f.y += f.vy * dt; f.vy += 90 * dt;
        ctx.beginPath(); ctx.arc(f.x, f.y, f.groesse * f.leben, 0, Math.PI * 2); ctx.fillStyle = farbe.block; ctx.globalAlpha = f.leben; ctx.fill(); ctx.globalAlpha = 1;
      }
    }
    return {
      farben,
      start(canvas) {
        cv = canvas; ctx = cv.getContext('2d'); farben(); groesse(); laeuft = true; letzteZeit = 0;
        beobachter?.disconnect();
        beobachter = new IntersectionObserver((e) => { sichtbar = e[0].isIntersecting; }); beobachter.observe(cv);
        new ResizeObserver(groesse).observe(cv);
        // Alle Geräte der letzten 10 Minuten sofort zeigen – nicht erst, wenn sie nach einem Neuladen wieder fragen
        geraete.clear();
        for (const e of S.live) if (Date.now() - e.t < AKTIV_MS) geraetVon(e.g, e.n, e.t);
        abgleichen(canvas);
        clearInterval(pflege); let runde = 0; pflege = setInterval(() => { if (cv !== canvas) return clearInterval(pflege); aufraeumen(); if (++runde % 12 === 0) abgleichen(canvas); }, 5000);
        cancelAnimationFrame(raf); raf = requestAnimationFrame(zeichne);
      },
      stopp() { laeuft = false; clearInterval(pflege); cancelAnimationFrame(raf); beobachter?.disconnect(); teilchen.length = 0; funken.length = 0; spalte.length = 0; cv = null; },
      ereignisse,
    };
  })();

  // ── Geräte ─────────────────────────────────────────────────────────────────
  const symbolVon = (name) => /phone|handy|iphone|galaxy|pixel/i.test(name) ? '📱' : /ipad|tab/i.test(name) ? '📱' : /tv|fernseh|chromecast|fire/i.test(name) ? '📺' : /vpn/i.test(name) ? '🔐' : /drucker|printer|brother/i.test(name) ? '🖨️' : /home|echo|sonos/i.test(name) ? '🔊' : /ugreen|nas/i.test(name) ? '🗄️' : '💻';
  // UniFi-Gerätesymbol (zwischengespeichert vom Server), sonst Emoji; lädt das Bild nicht, springt das Emoji ein
  const geraetSymbol = (g) => g.icon ? `<img class="gsymbol" src="/api/symbol/${encodeURIComponent(g.icon)}" alt="" loading="lazy" data-ersatz="${symbolVon(g.name)}">` : symbolVon(g.name);
  document.addEventListener('error', (e) => { const t = e.target; if (t instanceof HTMLImageElement && t.dataset.ersatz) t.replaceWith(document.createTextNode(t.dataset.ersatz)); }, true);
  async function zeigeGeraete() {
    const haupt = $('#haupt');
    if (!$('#geraeteraster')) haupt.innerHTML = `${hinweisband()}<div class="suchleiste"><input type="search" id="geraetsuche" placeholder="Gerät suchen …" style="flex:1;max-width:320px"><span class="chip" id="geraetzahl">–</span><span style="color:var(--muted);font-size:12px">Zahlen: letzte 24 h · Kurve: letzte 12 h</span></div>${info('Hier erscheint jedes Gerät, das FAH-Adblock als DNS-Server nutzt (Namen aus UniFi). <b>Profil</b> = welche Kategorien für das Gerät gesperrt sind. <b>Pause</b> = nur dieses Gerät kurz ungefiltert. <b>Rettung</b> = zuletzt geblockte Domains des Geräts mit Ein-Klick-Freigabe, wenn eine Seite oder App nicht mehr geht.')}<div style="height:12px"></div><div class="geraeteraster" id="geraeteraster"><div class="leer">wird geladen …</div></div>`;
    let d; try { d = await api('/api/geraete'); } catch (e) { return; }
    S.geraete = d; S.profile = d.profile;
    const suche = ($('#geraetsuche')?.value || '').toLowerCase();
    const liste = d.geraete.filter((g) => !suche || `${g.name} ${g.ip} ${g.id}`.toLowerCase().includes(suche));
    $('#geraetzahl').textContent = `${d.geraete.length} ${d.geraete.length === 1 ? 'Gerät' : 'Geräte'}`;
    const raster = $('#geraeteraster');
    if (!liste.length) { raster.innerHTML = `<div class="leer">${d.geraete.length ? 'Kein Gerät passt zur Suche.' : 'Noch hat kein Gerät über FAH-Adblock aufgelöst. Stelle beim Gerät bzw. in UniFi den DNS-Server auf diese NAS-Adresse.'}</div>`; return; }
    const jetzt = Date.now();
    raster.innerHTML = liste.map((g) => {
      const profil = d.profile.find((p) => p.id === g.profil) || d.profile[0];
      const pausiert = g.pauseBis > jetzt;
      return `<article class="karte geraet ${pausiert ? 'pausiert' : ''}" style="--profilfarbe:${esc(profil?.farbe || '#40e0a0')}" data-geraet="${esc(g.id)}">
        <div class="gkopf"><div class="symbol">${geraetSymbol(g)}</div><div class="gname"><b title="${esc(g.id)}">${esc(g.name)}</b><small>${esc(g.ip || g.id)} · ${esc(vor(g.zuletzt))}</small></div><i class="aktiv ${jetzt - g.zuletzt < 600000 ? 'an' : ''}" title="aktiv in den letzten 10 min"></i></div>
        <canvas data-kurve='${esc(JSON.stringify(g.kurve || []))}'></canvas>
        <div class="gzahlen"><span><b>${zahl(g.erlaubt + g.geblockt)}</b> Anfragen</span><span><b style="color:var(--block)">${zahl(g.geblockt)}</b> geblockt</span><span><b>${String(g.quote).replace('.', ',')} %</b></span></div>
        ${pausiert ? `<div class="chip gelb">⏸ pausiert bis ${new Date(g.pauseBis).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}</div>` : ''}
        <div class="gaktionen">
          <select data-profil aria-label="Profil">${d.profile.map((p) => `<option value="${esc(p.id)}" ${p.id === g.profil ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select>
          <button class="knopf klein rot" data-rettung>🛟 Rettung</button>
        </div>
        <div class="gaktionen">
          ${pausiert ? '<button class="knopf klein" data-gpause="0">▶ Schutz an</button>' : '<button class="knopf klein" data-gpause="15">⏸ 15 min</button><button class="knopf klein leise" data-gpause="60">⏸ 1 h</button>'}
          <button class="knopf klein leise" data-umbenennen>✎ Name</button>
          <button class="knopf klein leise" data-gprotokoll>📜 Protokoll</button>
        </div></article>`;
    }).join('');
    $$('canvas[data-kurve]', raster).forEach(kurveZeichnen);
    $('#geraetsuche').oninput = () => zeigeGeraete();
    raster.onchange = async (e) => {
      const s = e.target.closest('[data-profil]'); if (!s) return;
      const id = s.closest('[data-geraet]').dataset.geraet;
      try { await api(`/api/geraete/${encodeURIComponent(id)}`, { methode: 'PUT', daten: { profil: s.value } }); toast('Profil geändert'); zeigeGeraete(); } catch (err) { toast(err.message, 'fehler'); }
    };
    raster.onclick = async (e) => {
      const karte = e.target.closest('[data-geraet]'); if (!karte) return;
      const id = karte.dataset.geraet, g = d.geraete.find((x) => x.id === id);
      if (e.target.closest('[data-rettung]')) return rettung(g);
      if (e.target.closest('[data-gpause]')) return pause(id, +e.target.closest('[data-gpause]').dataset.gpause);
      if (e.target.closest('[data-gprotokoll]')) { S.protokollGeraet = id; location.hash = 'protokoll'; return; }
      if (e.target.closest('[data-umbenennen]')) {
        const name = prompt('Name für dieses Gerät (leer = automatisch)', g.eigenerName ? g.name : '');
        if (name === null) return;
        try { await api(`/api/geraete/${encodeURIComponent(id)}`, { methode: 'PUT', daten: { name } }); zeigeGeraete(); } catch (err) { toast(err.message, 'fehler'); }
      }
    };
  }
  function kurveZeichnen(cv) {
    const daten = JSON.parse(cv.dataset.kurve || '[]'), r = cv.getBoundingClientRect(), dpr = Math.min(2, devicePixelRatio || 1);
    cv.width = r.width * dpr; cv.height = r.height * dpr;
    const c = cv.getContext('2d'); c.scale(dpr, dpr);
    const s = getComputedStyle(document.documentElement), max = Math.max(1, ...daten.map((x) => x[0])), bw = r.width / Math.max(1, daten.length);
    daten.forEach(([n, g], i) => {
      const h = n / max * (r.height - 4), hg = g / max * (r.height - 4);
      c.fillStyle = s.getPropertyValue('--rand2'); c.fillRect(i * bw + 2, r.height - h, bw - 4, h);
      c.fillStyle = s.getPropertyValue('--block'); c.fillRect(i * bw + 2, r.height - hg, bw - 4, hg);
    });
  }
  // Rettung: zuletzt geblockte Domains eines Geräts, ein Klick gibt frei
  async function rettung(g) {
    $$('.schleier,.seitenleiste').forEach((x) => x.remove());
    const schleier = document.createElement('div'); schleier.className = 'schleier';
    const leiste = document.createElement('aside'); leiste.className = 'seitenleiste'; leiste.setAttribute('role', 'dialog'); leiste.setAttribute('aria-label', 'Rettung');
    leiste.innerHTML = `<header><div class="symbol" style="font-size:26px">🛟</div><div style="flex:1;min-width:0"><h3>Rettung</h3><div style="color:var(--muted);font-size:13px">${esc(g.name)} · zuletzt geblockt</div></div><button class="knopf klein leise" data-zu aria-label="Schließen">✕</button></header>
      <div style="padding:12px 20px;border-bottom:1px solid var(--rand);display:flex;gap:8px;flex-wrap:wrap;align-items:center"><select id="rettungzeit"><option value="15">letzte 15 min</option><option value="60">letzte Stunde</option><option value="240">letzte 4 h</option></select>
      <button class="knopf klein" data-rpause>⏸ Gerät 15 min pausieren</button><span style="color:var(--muted);font-size:12px">Tipp: Seite/App danach neu laden</span></div>
      <div class="inhalt" id="rettunginhalt"><div class="leer">wird geladen …</div></div>`;
    const zu = () => { clearInterval(tick); schleier.remove(); leiste.remove(); };
    schleier.onclick = zu; document.body.append(schleier, leiste);
    const laden = async () => {
      const d = await api(`/api/rettung/${encodeURIComponent(g.id)}?minuten=${$('#rettungzeit').value}`).catch(() => null); if (!d) return;
      const el = $('#rettunginhalt'); if (!el) return;
      el.innerHTML = d.eintraege.length ? d.eintraege.map((e) => `<div class="rettungzeile" data-domain="${esc(e.domain)}"><div class="dom">${esc(e.domain)}</div>${dinfo(e.domain)}<div class="meta">${e.n}× · zuletzt ${uhr(e.zuletzt)} · ${esc(e.grund === 'Liste' ? e.detail : e.grund)}</div>
        <div class="akt"><button class="knopf klein gruen" data-frei="60">Freigeben · 1 h</button><button class="knopf klein" data-frei="0">Dauerhaft für ${esc(g.name.slice(0, 20))}</button><button class="knopf klein leise" data-frei="alle">Für alle</button></div></div>`).join('')
        : '<div class="leer">In diesem Zeitraum wurde für dieses Gerät nichts geblockt.<br>Liegt es vielleicht nicht am Blocker?</div>';
    };
    const tick = setInterval(laden, 5000);
    leiste.onclick = async (e) => {
      if (e.target.closest('[data-zu]')) return zu();
      if (e.target.closest('[data-rpause]')) { await pause(g.id, 15); return; }
      const b = e.target.closest('[data-frei]'); if (!b) return;
      const zeile = b.closest('[data-domain]'), wert = b.dataset.frei;
      try {
        await api('/api/regeln', { methode: 'POST', daten: { typ: 'erlauben', muster: zeile.dataset.domain, geltung: wert === 'alle' ? 'alle' : `geraet:${g.id}`, minuten: wert === 'alle' ? 0 : +wert, notiz: 'Rettung' } });
        zeile.style.transition = 'opacity .3s, transform .3s'; zeile.style.opacity = '0'; zeile.style.transform = 'translateX(30px)'; setTimeout(() => zeile.remove(), 300);
        toast(`✓ ${zeile.dataset.domain} freigegeben`);
      } catch (err) { toast(err.message, 'fehler'); }
    };
    $('#rettungzeit').onchange = laden;
    leiste.querySelector('[data-zu]').focus();
    laden();
  }

  // ── Protokoll ──────────────────────────────────────────────────────────────
  async function zeigeProtokoll() {
    if (!S.geraete) S.geraete = await api('/api/geraete').catch(() => ({ geraete: [], profile: [] }));
    $('#haupt').innerHTML = `<section class="karte"><div class="kartekopf">📜 Protokoll<span class="rechts"><label style="display:flex;gap:8px;align-items:center;font-size:12px">Live <span class="schalter"><input type="checkbox" id="liveschalter" ${S.liveAn ? 'checked' : ''}><span></span></span></label></span></div>
      <div class="kartekoerper" style="padding-bottom:6px">${info('Jede DNS-Anfrage deiner Geräte: welche Domain, ob erlaubt oder geblockt und warum. „Live“ zeigt neue Anfragen sofort oben. Aus einer Zeile heraus lässt sich freigeben oder sperren.')}<div class="formzeile">
        <div class="feld"><label for="pgeraet">Gerät</label><select id="pgeraet"><option value="">alle Geräte</option>${S.geraete.geraete.map((g) => `<option value="${esc(g.id)}" ${S.protokollGeraet === g.id ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}</select></div>
        <div class="feld"><label for="psuche">Domain enthält</label><input type="search" id="psuche" placeholder="z. B. google"></div>
        <label style="display:flex;gap:8px;align-items:center;padding-bottom:8px"><span class="schalter"><input type="checkbox" id="pgeblockt"><span></span></span>nur geblockt</label>
      </div></div>
      <div class="tabellenrahmen"><table class="tabelle"><thead><tr><th>Zeit</th><th>Gerät</th><th>Domain</th><th>Typ</th><th>Ergebnis</th><th>ms</th><th></th></tr></thead><tbody id="ptabelle"><tr><td colspan="7" class="leer">wird geladen …</td></tr></tbody></table></div>
      <div style="padding:12px 18px;text-align:center"><button class="knopf klein" id="pmehr">Ältere laden</button></div></section>`;
    const laden = async (anhaengen = false) => {
      const letzte = anhaengen ? S.protokollLetzte : 0;
      const q = new URLSearchParams({ geraet: $('#pgeraet').value, suche: $('#psuche').value, nurGeblockt: $('#pgeblockt').checked ? '1' : '0', limit: '150', ...(letzte ? { vor: String(letzte) } : {}) });
      const zeilen = await api(`/api/protokoll?${q}`).catch(() => []);
      if (zeilen.length) S.protokollLetzte = zeilen.at(-1).ts;
      const html = zeilen.map((z) => protokollZeile({ t: z.ts, g: z.geraet, n: z.name || z.geraet, d: z.domain, y: z.typ, a: z.aktion, r: z.grund, l: z.detail, c: z.cache, m: z.ms })).join('');
      if (anhaengen) $('#ptabelle').insertAdjacentHTML('beforeend', html); else $('#ptabelle').innerHTML = html || '<tr><td colspan="7" class="leer">Keine Einträge.</td></tr>';
    };
    let verzoegert; $('#psuche').oninput = () => { clearTimeout(verzoegert); verzoegert = setTimeout(() => laden(), 300); };
    $('#pgeraet').onchange = () => { S.protokollGeraet = $('#pgeraet').value; laden(); };
    $('#pgeblockt').onchange = () => laden();
    $('#liveschalter').onchange = (e) => { S.liveAn = e.target.checked; };
    $('#pmehr').onclick = () => laden(true);
    $('#ptabelle').onclick = async (e) => {
      const b = e.target.closest('[data-paktion]'); if (!b) return;
      const tr = b.closest('tr'), domain = tr.dataset.domain, geraet = tr.dataset.geraet, name = tr.dataset.name;
      if (b.dataset.paktion === 'frei') return freigabeDialog(domain, geraet, name);
      const wahl = await waehle(`${domain} sperren`, [{ text: `Nur für ${name}`, wert: `geraet:${geraet}`, art: 'rot' }, { text: 'Für alle Geräte', wert: 'alle' }]);
      if (!wahl) return;
      try { await api('/api/regeln', { methode: 'POST', daten: { typ: 'sperren', muster: domain, geltung: wahl, notiz: 'aus dem Protokoll' } }); toast(`⛔ ${domain} gesperrt`); } catch (err) { toast(err.message, 'fehler'); }
    };
    laden();
  }
  function protokollZeile(e) {
    const art = e.a === 'geblockt' ? 'rot' : e.a === 'fehler' || e.a === 'gebremst' ? 'gelb' : e.a === 'lokal' ? '' : 'gruen';
    const text = e.a === 'geblockt' ? `geblockt · ${grundText(e)}` : e.a === 'lokal' ? (e.r === 'Lokaler Eintrag' ? 'lokal (Eintrag)' : 'lokal (Gateway)') : e.a === 'fehler' ? `Fehler · ${e.r}` : e.a === 'gebremst' ? 'gebremst' : e.r === 'Pause' ? 'erlaubt · Pause' : e.r === 'Freigabe' ? 'erlaubt · eigene Freigabe' : e.r === 'Freigabeliste' ? `erlaubt · Freigabeliste (${e.l})` : e.r === 'Geschützter Dienst' ? `erlaubt · geschützt (${e.l})` : `erlaubt${e.c ? ' · Speicher' : ''}`;
    return `<tr data-domain="${esc(e.d)}" data-geraet="${esc(e.g)}" data-name="${esc(e.n || e.g)}"><td class="mono">${uhr(e.t)}</td><td>${esc(e.n || e.g)}</td><td class="domain">${esc(e.d)}${dinfo(e.d, { kurz: true })}</td><td class="mono">${esc(e.y)}</td><td><span class="chip ${art}">${esc(text)}</span></td><td class="mono">${e.m != null ? String(e.m).replace('.', ',') : ''}</td>
      <td>${e.a === 'geblockt' ? '<button class="knopf klein" data-paktion="frei">Freigeben</button>' : e.a === 'erlaubt' ? '<button class="knopf klein leise" data-paktion="sperren">Sperren</button>' : ''}</td></tr>`;
  }
  function protokollLive(liste) {
    if (!S.liveAn) return;
    const tb = $('#ptabelle'); if (!tb) return;
    const g = $('#pgeraet').value, suche = $('#psuche').value.toLowerCase(), nurG = $('#pgeblockt').checked;
    const passend = liste.filter((e) => (!g || e.g === g) && (!suche || e.d.includes(suche)) && (!nurG || e.a === 'geblockt'));
    if (!passend.length) return;
    tb.querySelector('.leer')?.closest('tr')?.remove();
    tb.insertAdjacentHTML('afterbegin', passend.slice().reverse().map(protokollZeile).join(''));
    while (tb.children.length > 400) tb.lastElementChild.remove();
  }

  // ── Listen & Regeln ────────────────────────────────────────────────────────
  async function zeigeListen() {
    const [ls, regeln, geraete] = await Promise.all([api('/api/listen'), api('/api/regeln'), S.geraete ? S.geraete : api('/api/geraete')]);
    S.geraete = geraete;
    const kat = Object.fromEntries(ls.kategorien.map((k) => [k.id, k]));
    const sperrKat = ls.kategorien.filter((k) => k.art !== 'erlauben');
    const geltungText = (gl) => gl === 'alle' ? 'alle Geräte' : gl.startsWith('geraet:') ? (geraete.geraete.find((g) => `geraet:${g.id}` === gl)?.name || gl.slice(7)) : `Profil ${(geraete.profile.find((p) => `profil:${p.id}` === gl) || {}).name || gl.slice(7)}`;
    const listenKarte = (q) => `<div class="listenkarte" data-liste="${esc(q.id)}"><label class="schalter" title="an/aus"><input type="checkbox" data-listean ${q.an ? 'checked' : ''}><span></span></label>
      <div style="min-width:0"><b>${esc(q.name)}</b>${q.kategorie !== 'freigabe' ? ` <span class="chip">${esc(kat[q.kategorie]?.symbol || '')} ${esc(kat[q.kategorie]?.name || q.kategorie)}</span>` : q.id.startsWith('eigen-') ? ' <span class="chip gruen">alle Kategorien</span>' : ' <span class="chip">nur Werbung & Tracker</span>'}
      ${q.beschreibung ? `<span class="beschreibung">${esc(q.beschreibung)}</span>` : ''}
      <small>${q.laedt ? 'wird geladen …' : q.an || q.anzahl ? `${zahl(q.anzahl)} Einträge · geprüft ${vor(q.geprueft)}` : 'aus – wird beim Einschalten geladen'}</small>${q.fehler ? `<div class="fehlertext">⚠ ${esc(q.fehler)}</div>` : ''}</div>
      <div style="display:flex;gap:6px"><button class="knopf klein leise" data-listeneu title="jetzt aktualisieren">↻</button>${q.id.startsWith('eigen-') ? '<button class="knopf klein leise" data-listeweg title="entfernen">✕</button>' : ''}</div></div>`;
    const sperrListen = ls.quellen.filter((q) => q.kategorie !== 'freigabe'), freiListen = ls.quellen.filter((q) => q.kategorie === 'freigabe');
    const summe = (liste) => liste.filter((q) => q.an).reduce((a, q) => a + (q.anzahl || 0), 0);
    const eigeneListe = (kategorien, feld) => `<div class="kartekoerper" style="border-top:1px solid var(--rand)"><form class="formzeile" data-listeform>
      <div class="feld"><label>Eigene Liste (URL)</label><input type="url" data-lurl placeholder="https://…" required></div>
      ${kategorien.length > 1 ? `<div class="feld" style="flex:0 1 170px"><label>Kategorie</label><select data-lkat>${kategorien.map((k) => `<option value="${k.id}">${esc(k.symbol)} ${esc(k.name)}</option>`).join('')}</select></div>` : `<input type="hidden" data-lkat value="${kategorien[0].id}">`}
      <button class="knopf" type="submit">Hinzufügen</button></form>${info(feld)}</div>`;
    $('#haupt').innerHTML = `
      <section class="karte" style="margin-bottom:16px"><div class="kartekopf">🔎 Domain prüfen</div>
        <div class="kartekoerper">${info('Zeigt für eine Domain und ein Gerät, ob sie geblockt würde und warum – ideal, wenn eine Seite oder App nicht funktioniert.')}<form class="formzeile" id="pruefform"><div class="feld"><label for="prdomain">Domain</label><input id="prdomain" type="text" placeholder="z. B. doubleclick.net" required></div>
        <div class="feld"><label for="prgeraet">für Gerät</label><select id="prgeraet"><option value="">unbekanntes Gerät (Standard)</option>${geraete.geraete.map((g) => `<option value="${esc(g.id)}">${esc(g.name)}</option>`).join('')}</select></div>
        <button class="knopf gruen" type="submit">Prüfen</button></form><div id="prergebnis" style="margin-top:12px"></div></div></section>
      <div class="zweispaltig gleich" style="margin-top:0">
      <div class="raster" style="align-content:start">
      <section class="karte"><div class="kartekopf">🧱 Blocklisten<span class="rechts"><span class="chip">${zahl(summe(sperrListen))} Einträge</span><button class="knopf klein" data-alleaktualisieren="sperren">↻ Alle aktualisieren</button></span></div>
        ${info('Sammlungen bekannter Werbe-, Tracker- und Schadsoftware-Domains aus dem Internet, alle 24 h aktualisiert. Ein Eintrag sperrt die Domain samt Subdomains. Ob eine Kategorie auf einem Gerät greift, bestimmt dessen Profil.')}
        <div>${sperrListen.map(listenKarte).join('')}</div>${eigeneListe(sperrKat, 'Eigene Sperrliste im Hosts-, AdBlock- oder Domain-Format (eine Domain je Zeile).')}</section>
      <section class="karte"><div class="kartekopf">✅ Freigabelisten<span class="rechts"><span class="chip gruen">${zahl(summe(freiListen))} Freigaben</span><button class="knopf klein" data-alleaktualisieren="freigabe">↻ Alle aktualisieren</button></span></div>
        ${info('<b>Listen aus dem Internet</b>: geprüfte Sammlungen von Domains, die Werbelisten fälschlich sperren und dadurch Seiten, Apps oder Links kaputt machen. Sie heben <b>nur Sperren der Kategorie Werbung & Tracker</b> auf – Schadsoftware, Jugendschutz, Social Media und Glücksspiel bleiben gesperrt. <b>Selbst hinzugefügte Listen</b> (URL ganz unten) gelten für alle Kategorien. Einzelne Domains gibst du unter <b>Eigene Regeln → erlauben</b> frei.')}
        <div>${freiListen.map(listenKarte).join('')}</div>${eigeneListe(ls.kategorien.filter((k) => k.art === 'erlauben'), 'Eigene Freigabeliste per URL (eine Domain je Zeile oder AdBlock-Ausnahmen „@@||domain^“) – gilt für alle Kategorien.')}</section>
      </div>
      <div class="raster" style="align-content:start">
      <section class="karte" style="align-self:start"><div class="kartekopf">✍️ Eigene Regeln<span class="rechts"><span class="chip">${regeln.length}</span></span></div>
        <div class="kartekoerper">${info('Deine persönlichen Ausnahmen – sie gehen allen Listen vor: <b>erlauben</b> schlägt jede Sperre – für alle Geräte auch Jugendschutz, Social Media, Glücksspiel und Schadsoftware –, <b>sperren</b> gilt zusätzlich zu den Listen. „beispiel.de“ gilt inklusive Subdomains, „*.beispiel.de“ nur für Subdomains. Mit Dauer laufen sie von selbst ab; Freigaben aus der Rettung für ein Gerät landen hier.')}<form class="formzeile" id="regelform">
          <div class="feld" style="flex:0 1 120px"><label for="rtyp">Aktion</label><select id="rtyp"><option value="erlauben">✅ erlauben</option><option value="sperren">⛔ sperren</option></select></div>
          <div class="feld"><label for="rmuster">Domain</label><input id="rmuster" type="text" placeholder="beispiel.de oder *.beispiel.de" required></div>
          <div class="feld" style="flex:0 1 170px"><label for="rgeltung">gilt für</label><select id="rgeltung"><option value="alle">alle Geräte</option>${geraete.profile.map((p) => `<option value="profil:${esc(p.id)}">Profil ${esc(p.name)}</option>`).join('')}${geraete.geraete.map((g) => `<option value="geraet:${esc(g.id)}">${esc(g.name)}</option>`).join('')}</select></div>
          <div class="feld" style="flex:0 1 120px"><label for="rdauer">Dauer</label><select id="rdauer"><option value="0">dauerhaft</option><option value="60">1 Stunde</option><option value="1440">1 Tag</option><option value="10080">1 Woche</option></select></div>
          <button class="knopf gruen" type="submit">Anlegen</button></form></div>
        <div class="zeilen">${regeln.length ? regeln.slice().reverse().map((r) => `<div class="zeile"><i class="punkt ${r.typ === 'sperren' ? 'rot' : 'gruen'}"></i><div class="haupt"><b class="mono">${esc(r.muster)}</b><small>${r.typ === 'sperren' ? 'gesperrt' : 'erlaubt'} für ${esc(geltungText(r.geltung))}${r.bis ? ` · bis ${new Date(r.bis).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}` : ''}${r.notiz ? ` · ${esc(r.notiz)}` : ''}</small></div><button class="knopf klein leise" data-regelweg="${esc(r.id)}">✕</button></div>`).join('') : '<div class="leer">Noch keine eigenen Regeln.</div>'}</div></section>
      </div>
      </div>`;
    $('#pruefform').onsubmit = async (e) => {
      e.preventDefault();
      try {
        const r = await api(`/api/pruefen?domain=${encodeURIComponent($('#prdomain').value)}&geraet=${encodeURIComponent($('#prgeraet').value)}`);
        const name = (id) => ls.quellen.find((q) => q.id === id)?.name || id;
        const sperrend = r.listen.filter((id) => kat[ls.quellen.find((q) => q.id === id)?.kategorie]?.art !== 'erlauben').map(name), freigebend = r.listen.filter((id) => ls.quellen.find((q) => q.id === id)?.kategorie === 'freigabe').map(name);
        const grund = { Liste: 'steht auf einer aktiven Blockliste', Freigabeliste: 'Werbesperre durch Freigabeliste aufgehoben', Freigabe: 'eigene Freigabe', 'Eigene Regel': 'eigene Sperrregel', 'Geschützter Dienst': `geschützter Dienst „${r.dienstName}“ – keine Liste blockt ihn`, 'Dienst gesperrt': `Dienst „${r.dienstName}“ ist von dir gesperrt`, Pause: 'Schutz pausiert', 'Kategorie im Profil aus': 'gelistet, aber die Kategorie ist im Profil nicht gesperrt', 'auf Freigabeliste': 'nur auf einer Freigabeliste', 'nicht gelistet': 'auf keiner Liste' }[r.grund] || r.grund;
        $('#prergebnis').innerHTML = `<div class="zeile" style="padding:10px 0"><i class="punkt ${r.aktion === 'geblockt' ? 'rot' : 'gruen'}"></i><div class="haupt"><b>${esc(r.domain)} wird ${r.aktion === 'geblockt' ? '<span style="color:var(--block)">geblockt</span>' : '<span style="color:var(--ich)">erlaubt</span>'}</b>
          ${dinfo(r.domain)}<small>Grund: ${esc(grund)} · Profil ${esc(r.profil)}${sperrend.length ? ` · steht auf: ${esc(sperrend.join(', '))}` : ''}${freigebend.length ? ` · freigegeben von: ${esc(freigebend.join(', '))}` : ''}</small></div></div>`;
      } catch (err) { toast(err.message, 'fehler'); }
    };
    $('#regelform').onsubmit = async (e) => { e.preventDefault(); try { await api('/api/regeln', { methode: 'POST', daten: { typ: $('#rtyp').value, muster: $('#rmuster').value, geltung: $('#rgeltung').value, minuten: +$('#rdauer').value } }); toast('Regel angelegt'); zeigeListen(); } catch (err) { toast(err.message, 'fehler'); } };
    $$('[data-listeform]').forEach((f) => { f.onsubmit = async (e) => { e.preventDefault(); try { await api('/api/listen', { methode: 'POST', daten: { url: f.querySelector('[data-lurl]').value, kategorie: f.querySelector('[data-lkat]').value } }); toast('Liste hinzugefügt – wird geladen'); setTimeout(zeigeListen, 1500); } catch (err) { toast(err.message, 'fehler'); } }; });
    $('#haupt').onchange = async (e) => {
      const s = e.target.closest('[data-listean]'); if (!s) return;
      const id = s.closest('[data-liste]').dataset.liste;
      try { await api(`/api/listen/${id}`, { methode: 'PUT', daten: { an: s.checked } }); toast(s.checked ? 'Liste eingeschaltet' : 'Liste ausgeschaltet'); setTimeout(zeigeListen, 1200); } catch (err) { toast(err.message, 'fehler'); }
    };
    $('#haupt').onclick = async (e) => {
      if (e.target.closest('[data-alleaktualisieren]')) { const b = e.target.closest('[data-alleaktualisieren]'); b.disabled = true; b.textContent = 'lädt …'; await api('/api/listen/aktualisieren', { methode: 'POST', daten: { gruppe: b.dataset.alleaktualisieren } }).catch((err) => toast(err.message, 'fehler')); return zeigeListen(); }
      const rw = e.target.closest('[data-regelweg]'); if (rw) { await api(`/api/regeln/${rw.dataset.regelweg}`, { methode: 'DELETE' }).catch(() => {}); return zeigeListen(); }
      const karte = e.target.closest('[data-liste]'); if (!karte) return;
      if (e.target.closest('[data-listeneu]')) { e.target.textContent = '…'; await api('/api/listen/aktualisieren', { methode: 'POST', daten: { id: karte.dataset.liste } }).catch((err) => toast(err.message, 'fehler')); return zeigeListen(); }
      if (e.target.closest('[data-listeweg]') && confirm('Liste entfernen?')) { await api(`/api/listen/${karte.dataset.liste}`, { methode: 'DELETE' }).catch(() => {}); zeigeListen(); }
    };
  }

  // ── Dienste (Rubriken wie bei AdGuard) ─────────────────────────────────────
  const dienstStatus = (d, geltungText) => d.fest ? '🔒 immer erreichbar' : d.modus === 'frei' ? '✓ geschützt' : d.modus === 'sperren' ? `⛔ gesperrt · ${geltungText(d.geltung)}` : '○ nach Listen';
  async function zeigeDienste() {
    const [dl, geraete] = await Promise.all([api('/api/dienste'), S.geraete ? S.geraete : api('/api/geraete')]);
    S.geraete = geraete;
    const geltungText = (gl) => gl === 'alle' ? 'alle Geräte' : gl.startsWith('geraet:') ? (geraete.geraete.find((g) => `geraet:${g.id}` === gl)?.name || gl.slice(7)) : `Profil ${(geraete.profile.find((p) => `profil:${p.id}` === gl) || {}).name || gl.slice(7)}`;
    const suche = (S.dienstSuche || '').toLowerCase(), nurArt = S.dienstArt || 'alle';
    const passt = (d) => (!suche || `${d.name} ${d.domains.join(' ')}`.toLowerCase().includes(suche)) && (nurArt === 'alle' || d.modus === nurArt);
    const zahl = { frei: dl.dienste.filter((d) => d.modus === 'frei').length, listen: dl.dienste.filter((d) => d.modus === 'listen').length, sperren: dl.dienste.filter((d) => d.modus === 'sperren').length };
    $('#haupt').innerHTML = `${hinweisband()}
      <section class="karte"><div class="kartekopf">📺 Dienste<span class="rechts"><span class="chip gruen">${zahl.frei} geschützt</span><span class="chip">${zahl.listen} nach Listen</span>${zahl.sperren ? `<span class="chip rot">${zahl.sperren} gesperrt</span>` : ''}</span></div>
        ${info('Hier bestimmst du je Dienst, was gilt. <b>✓ geschützt</b>: keine Blockliste kann ihn sperren – Vorgabe für Fernsehen, Streaming, Musik und Geräte-Grundfunktionen (Betreiber-Vorgabe: Mediendienste laufen immer). Ebenfalls geschützt: Schule &amp; Lernen, Finanzen/Behörden/Gesundheit sowie Smart Home &amp; Geräte – was im Alltag funktionieren muss. <b>○ nach Listen</b>: Blocklisten und Profil entscheiden – Vorgabe für Social Media, Spiele, Shopping, E-Mail, Reisen und Co. Die Rubriken <b>Dating</b> und <b>VPN &amp; Umgehung</b> sind zum Sperren gedacht, z. B. im Profil „Kinder“ (ein VPN umgeht sonst den ganzen Filter). <b>⛔ gesperrt</b>: von dir gesperrt, für alle Geräte oder ein Profil. Eigene Sperrregeln (Listen &amp; Regeln) gehen immer vor.')}
        <div class="kartekoerper" style="padding-bottom:6px"><div class="formzeile">
          <div class="feld"><label for="dsuche">Dienst oder Domain suchen</label><input id="dsuche" type="search" value="${esc(S.dienstSuche || '')}" placeholder="z. B. youtube oder tiktok.com"></div>
          <div class="feld" style="flex:0 1 200px"><label for="dart">Anzeigen</label><select id="dart">${[['alle', 'alle Dienste'], ['frei', 'nur geschützte'], ['listen', 'nur nach Listen'], ['sperren', 'nur gesperrte']].map(([v, t]) => `<option value="${v}" ${nurArt === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
        </div></div>
        ${dl.gruppen.map((gr) => { const liste = dl.dienste.filter((d) => d.gruppe === gr.id && passt(d)); return liste.length ? `<div class="dienstgruppe"><small>${esc(gr.name)} · ${gr.fest ? 'immer erreichbar, nicht sperrbar' : `Vorgabe: ${gr.vorgabe === 'frei' ? 'geschützt' : 'nach Listen'}`}</small><div class="dienstraster">${liste.map((d) => `<button class="dienst ${d.modus === 'sperren' ? 'gesperrt' : d.modus === 'listen' ? 'neutral' : ''}" data-dienst="${esc(d.id)}" title="${esc(d.name + ' – ' + (d.hinweis ? d.hinweis + ' · ' : '') + d.domains.join(', ') + (d.ausser?.length ? ' · nicht geschützt, hier entscheiden weiter die Listen (reine Mess-Adressen): ' + d.ausser.join(', ') : ''))}"><span class="dsymbol">${esc(d.symbol)}</span><span class="dname">${esc(d.name)}</span><span class="dstatus">${esc(dienstStatus(d, geltungText))}</span></button>`).join('')}</div></div>` : ''; }).join('') || '<div class="leer">Kein Dienst passt zur Suche.</div>'}
      </section>`;
    $('#dsuche').oninput = (e) => { S.dienstSuche = e.target.value; clearTimeout(S.dienstUhr); S.dienstUhr = setTimeout(() => { zeigeDienste().then(() => { const f = $('#dsuche'); f.focus(); f.setSelectionRange(f.value.length, f.value.length); }); }, 250); };
    $('#dart').onchange = (e) => { S.dienstArt = e.target.value; zeigeDienste(); };
    $('#haupt').onclick = async (e) => {
      const b = e.target.closest('[data-dienst]'); if (!b) return;
      const d = dl.dienste.find((x) => x.id === b.dataset.dienst);
      if (d.fest) return toast(`${d.name} ist ein Hilfsangebot – immer erreichbar, in keinem Profil sperrbar`);
      const wahl = await waehle(`${d.symbol} ${d.name}`, [
        { text: '✓ Geschützt – keine Liste blockt ihn', wert: { modus: 'frei' }, art: 'gruen' },
        { text: '○ Nach Listen – Blocklisten und Profil entscheiden', wert: { modus: 'listen' } },
        { text: '⛔ Für alle Geräte sperren', wert: { modus: 'sperren', geltung: 'alle' }, art: 'rot' },
        ...geraete.profile.map((pr) => ({ text: `⛔ Nur für Profil „${pr.name}“ sperren`, wert: { modus: 'sperren', geltung: `profil:${pr.id}` } })),
      ]);
      if (!wahl) return;
      try { await api(`/api/dienste/${encodeURIComponent(d.id)}`, { methode: 'PUT', daten: wahl }); toast(`${d.name}: ${wahl.modus === 'frei' ? 'geschützt' : wahl.modus === 'listen' ? 'nach Listen' : 'gesperrt'}`); } catch (err) { toast(err.message, 'fehler'); }
      zeigeDienste();
    };
  }

  // ── Profile ────────────────────────────────────────────────────────────────
  const TAGE = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];
  // Dienste, die in einem Profil einzeln geregelt werden können (Rubriken, die zu Sperrkategorien passen)
  const PROFILRUBRIKEN = ['social', 'messenger', 'video', 'musik', 'spiele', 'shopping', 'ki', 'nachrichten', 'dating', 'vpn', 'mail', 'lernen'];
  const profilDienstHtml = (p, dl) => `<details class="profildienste"><summary>Einzelne Dienste in diesem Profil (${Object.keys(p.dienste || {}).length} Ausnahmen)</summary>
    ${info('Hier legst du für <b>dieses Profil</b> einzelne Dienste fest – unabhängig von den Kategorien oben. Beispiel Kinder: Social Media gesperrt, aber WhatsApp erlaubt und TikTok immer gesperrt. Antippen wechselt: <b>Standard</b> (wie unter Dienste eingestellt) → <b>erlaubt</b> → <b>gesperrt</b>.')}
    ${PROFILRUBRIKEN.map((gid) => dl.gruppen.find((g) => g.id === gid)).filter(Boolean).map((gr) => `<div class="profilgruppe" data-pgruppe="${esc(gr.id)}"><small>${esc(gr.name)}<span class="pgknoepfe"><button type="button" class="knopf klein leise" data-pgalle="sperren">alle sperren</button><button type="button" class="knopf klein leise" data-pgalle="standard">zurücksetzen</button></span></small><div class="dienstchips">${dl.dienste.filter((d) => d.gruppe === gr.id).map((d) => { const w = (p.dienste || {})[d.id] || 'standard'; return `<button type="button" class="dienstchip ${w}" data-pdienst="${esc(d.id)}" data-wert="${w}" title="${esc(d.domains.join(', '))}">${esc(d.symbol)} ${esc(d.name)}<i>${w === 'frei' ? 'erlaubt' : w === 'sperren' ? 'gesperrt' : w === 'listen' ? 'nach Listen' : 'Standard'}</i></button>`; }).join('')}</div></div>`).join('')}
  </details>`;
  async function zeigeProfile() {
    const [pr, geraete, dl, vorlagen] = await Promise.all([api('/api/profile'), api('/api/geraete'), api('/api/dienste'), api('/api/vorlagen')]);
    S.geraete = geraete;
    const karte = (p) => `<section class="karte" data-profilid="${esc(p.id)}" style="border-top:3px solid ${esc(p.farbe)}"><div class="kartekopf"><input type="color" value="${esc(p.farbe)}" data-farbe style="width:28px;height:28px;border:0;background:none;padding:0" aria-label="Farbe">
        <input type="text" value="${esc(p.name)}" data-name style="font-weight:700;text-transform:none;letter-spacing:0;font-size:15px;flex:1;min-width:0" aria-label="Name">
        <span class="rechts">${p.id !== 'standard' ? '<button class="knopf klein leise" data-profilweg>✕</button>' : ''}</span></div>
      <div class="kartekoerper">${pr.kategorien.filter((k) => k.art !== 'erlauben').map((k) => { const kw = p.kategorien[k.id] || { an: false, zeitplan: [] }; return `<div class="kategoriezeile" data-kat="${k.id}">
        <label class="schalter"><input type="checkbox" data-katan ${kw.an ? 'checked' : ''}><span></span></label>
        <div><b>${esc(k.symbol)} ${esc(k.name)}</b> <small style="color:var(--muted)">${kw.an ? (kw.zeitplan.length ? 'nur zu diesen Zeiten gesperrt:' : 'immer gesperrt') : 'erlaubt'}</small>${k.beschreibung ? `<span class="info" style="margin-top:2px">${esc(k.beschreibung)}</span>` : ''}
          <div data-fenster>${(kw.zeitplan || []).map(fensterHtml).join('')}</div>
          ${kw.an ? `<div class="wochenleiste" title="rot = gesperrt (Woche Mo–So)">${wochenleiste(kw.zeitplan)}</div><button class="knopf klein leise" data-fensterneu style="margin-top:6px">+ Zeitfenster</button>` : ''}</div></div>`; }).join('')}
        ${profilDienstHtml(p, dl)}
        ${kinderschutzHtml(p, dl, vorlagen)}
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;gap:10px;flex-wrap:wrap"><small style="color:var(--muted)">${((n) => `${n} ${n === 1 ? 'Gerät' : 'Geräte'}`)(geraete.geraete.filter((g) => g.profil === p.id).length)}</small><button class="knopf gruen klein" data-profilspeichern>Speichern</button></div></div></section>`;
    $('#haupt').innerHTML = `<div class="suchleiste"><b style="font-size:16px">Profile & Zeitpläne</b><button class="knopf klein leise" id="profilvorlage" style="margin-left:auto">+ aus Altersvorlage</button><button class="knopf klein" id="profilneu">+ Profil</button></div>${info('Ein Profil legt fest, welche Kategorien für die zugeordneten Geräte gesperrt sind. <b>Schalter an</b> = Kategorie gesperrt. Ohne Zeitfenster gilt die Sperre immer; mit Zeitfenstern nur in diesen Zeiten (ein Fenster über Mitternacht wie 20:00–07:00 gehört zum Starttag). Neue Geräte bekommen automatisch „Standard“. Änderungen wirken nach „Speichern“ sofort.')}<div style="height:12px"></div>
      <div class="raster" style="grid-template-columns:repeat(auto-fill,minmax(340px,1fr))">${pr.profile.map(karte).join('')}</div>
      <section class="karte" style="margin-top:16px"><div class="kartekopf">💻 Geräte zuordnen</div>${info('Welches Profil für welches Gerät gilt – wirkt sofort, ohne Speichern.')}<div class="zeilen">${geraete.geraete.map((g) => `<div class="zeile" data-geraet="${esc(g.id)}"><span class="zsymbol">${geraetSymbol(g)}</span><div class="haupt"><b>${esc(g.name)}</b><small>${esc(g.ip || g.id)}</small></div><select data-zuordnen>${pr.profile.map((p) => `<option value="${esc(p.id)}" ${p.id === g.profil ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select></div>`).join('') || '<div class="leer">Noch keine Geräte gesehen.</div>'}</div></section>`;
    const haupt = $('#haupt');
    haupt.onclick = async (e) => {
      if (e.target.id === 'profilvorlage') { const v = await waehle('Neues Profil aus Altersvorlage', vorlagen.map((x) => ({ text: `${x.name} – ${x.beschreibung}`, wert: x.id }))); if (!v) return; await api('/api/profile', { methode: 'POST', daten: { vorlage: v } }).then(() => toast('Profil angelegt'), (err) => toast(err.message, 'fehler')); return zeigeProfile(); }
      if (e.target.id === 'profilneu') { const name = prompt('Name des neuen Profils'); if (!name) return; await api('/api/profile', { methode: 'POST', daten: { name } }).catch((err) => toast(err.message, 'fehler')); return zeigeProfile(); }
      const k = e.target.closest('[data-profilid]'); if (!k) return;
      if (e.target.closest('[data-tag]')) { const b = e.target.closest('[data-tag]'); b.setAttribute('aria-pressed', b.getAttribute('aria-pressed') === 'true' ? 'false' : 'true'); return; }
      if (e.target.closest('[data-fensterweg]')) { e.target.closest('.fenster').remove(); return; }
      const pgalle = e.target.closest('[data-pgalle]');
      if (pgalle) {
        const wert = pgalle.dataset.pgalle;
        $$('[data-pdienst]', pgalle.closest('[data-pgruppe]')).forEach((x) => { x.dataset.wert = wert; x.className = `dienstchip ${wert}`; x.querySelector('i').textContent = wert === 'frei' ? 'erlaubt' : wert === 'sperren' ? 'gesperrt' : 'Standard'; });
        const n = $$('[data-pdienst]', k).filter((x) => x.dataset.wert !== 'standard').length;
        k.querySelector('.profildienste > summary').textContent = `Einzelne Dienste in diesem Profil (${n} Ausnahmen, mit „Speichern“ übernehmen)`;
        return;
      }
      const pd = e.target.closest('[data-pdienst]');
      if (pd) {
        const folge = { standard: 'frei', frei: 'sperren', sperren: 'standard', listen: 'standard' };
        const neu = folge[pd.dataset.wert] || 'frei';
        pd.dataset.wert = neu; pd.className = `dienstchip ${neu}`;
        pd.querySelector('i').textContent = neu === 'frei' ? 'erlaubt' : neu === 'sperren' ? 'gesperrt' : 'Standard';
        const zahl = $$('[data-pdienst]', k).filter((x) => x.dataset.wert !== 'standard').length;
        k.querySelector('.profildienste > summary').textContent = `Einzelne Dienste in diesem Profil (${zahl} Ausnahmen, mit „Speichern“ übernehmen)`;
        return;
      }
      if (e.target.closest('[data-ruheneu]')) { const z = e.target.closest('[data-ruhe]'); z.querySelector('[data-fenster]').insertAdjacentHTML('beforeend', fensterHtml({ tage: [1, 2, 3, 4, 5, 6, 7], von: '21:00', bis: '06:30' })); z.querySelector('small').textContent = 'mit „Speichern“ übernehmen'; return; }
      if (e.target.closest('[data-limitneu]')) { e.target.closest('[data-ks]').querySelector('[data-limits]').insertAdjacentHTML('beforeend', limitZeile('rubrik:spiele', 60, dl)); return; }
      if (e.target.closest('[data-limitweg]')) { e.target.closest('[data-limit]').remove(); return; }
      if (e.target.closest('[data-vorlageanwenden]')) {
        const v = k.querySelector('[data-vorlage]').value; if (!v) return toast('Bitte zuerst eine Vorlage wählen', 'fehler');
        if (!confirm(`Vorlage „${vorlagen.find((x) => x.id === v).name}“ auf „${k.querySelector('[data-name]').value}“ anwenden? Kategorien, Dienste, Ruhezeiten, sichere Suche und Zeitlimits werden ersetzt.`)) return;
        try { await api(`/api/profile/${k.dataset.profilid}/vorlage`, { methode: 'PUT', daten: { vorlage: v } }); toast('Vorlage angewendet'); zeigeProfile(); } catch (err) { toast(err.message, 'fehler'); }
        return;
      }
      if (e.target.closest('[data-fensterneu]')) { e.target.closest('[data-kat]').querySelector('[data-fenster]').insertAdjacentHTML('beforeend', fensterHtml({ tage: [1, 2, 3, 4, 5, 6, 7], von: '20:00', bis: '07:00' })); return; }
      if (e.target.closest('[data-profilweg]')) { if (!confirm('Profil löschen? Zugeordnete Geräte bekommen „Standard“.')) return; await api(`/api/profile/${k.dataset.profilid}`, { methode: 'DELETE' }).catch((err) => toast(err.message, 'fehler')); return zeigeProfile(); }
      if (e.target.closest('[data-profilspeichern]')) {
        const kategorien = {};
        $$('[data-kat]', k).forEach((z) => { kategorien[z.dataset.kat] = { an: z.querySelector('[data-katan]').checked, zeitplan: $$('.fenster', z).map((f) => ({ tage: $$('[data-tag][aria-pressed="true"]', f).map((b) => +b.dataset.tag), von: f.querySelector('[data-von]').value, bis: f.querySelector('[data-bis]').value })) }; });
        const dienste = {};
        $$('[data-pdienst]', k).forEach((x) => { if (x.dataset.wert !== 'standard') dienste[x.dataset.pdienst] = x.dataset.wert; });
        const ks = k.querySelector('[data-ks]'), ruhezeiten = {}, limits = {};
        $$('[data-ruhe]', ks).forEach((z) => { const f = $$('.fenster', z).map((x) => ({ tage: $$('[data-tag][aria-pressed="true"]', x).map((b) => +b.dataset.tag), von: x.querySelector('[data-von]').value, bis: x.querySelector('[data-bis]').value })); if (f.length) ruhezeiten[z.dataset.ruhe] = f; });
        $$('[data-limit]', ks).forEach((z) => { limits[z.querySelector('[data-limitziel]').value] = +z.querySelector('[data-limitmin]').value; });
        const sicherWahl = { suche: ks.querySelector('[data-sicher]').checked, youtube: ks.querySelector('[data-youtube]').value };
        try { await api(`/api/profile/${k.dataset.profilid}`, { methode: 'PUT', daten: { name: k.querySelector('[data-name]').value, farbe: k.querySelector('[data-farbe]').value, kategorien, dienste, ruhezeiten, limits, sicher: sicherWahl } }); toast('Profil gespeichert'); zeigeProfile(); } catch (err) { toast(err.message, 'fehler'); }
      }
    };
    haupt.onchange = async (e) => {
      if (e.target.closest('[data-katan]')) { const z = e.target.closest('[data-kat]'); z.querySelector('small').textContent = e.target.checked ? 'mit „Speichern“ übernehmen' : 'erlaubt'; return; }
      const s = e.target.closest('[data-zuordnen]'); if (!s) return;
      try { await api(`/api/geraete/${encodeURIComponent(s.closest('[data-geraet]').dataset.geraet)}`, { methode: 'PUT', daten: { profil: s.value } }); toast('Gerät zugeordnet'); } catch (err) { toast(err.message, 'fehler'); }
    };
  }
  const fensterHtml = (f) => `<div class="fenster"><div class="tage">${TAGE.map((t, i) => `<button type="button" data-tag="${i + 1}" aria-pressed="${(f.tage || []).includes(i + 1)}">${t}</button>`).join('')}</div>
    <input type="time" data-von value="${esc(f.von)}" aria-label="von"> – <input type="time" data-bis value="${esc(f.bis)}" aria-label="bis"><button type="button" class="knopf klein leise" data-fensterweg aria-label="Fenster entfernen">✕</button></div>`;
  function wochenleiste(zeitplan) {
    if (!zeitplan?.length) return '<i style="left:0;width:100%"></i>';
    const min = (s) => { const [h, m] = String(s).split(':'); return (+h) * 60 + (+m); }, woche = 7 * 1440, teile = [];
    for (const f of zeitplan) for (const t of f.tage || []) {
      const start = (t - 1) * 1440 + min(f.von); let ende = (t - 1) * 1440 + min(f.bis); if (min(f.bis) <= min(f.von)) ende += 1440;
      const s = start % woche, e2 = ende > woche ? ende - woche : ende;
      if (ende > woche) { teile.push([s, woche], [0, e2]); } else teile.push([s, ende]);
    }
    return teile.map(([a, b]) => `<i style="left:${a / woche * 100}%;width:${(b - a) / woche * 100}%"></i>`).join('');
  }

  // ── Kinderschutz ───────────────────────────────────────────────────────────
  const RUHE_RUBRIKEN = [['messenger', '💬 Messenger'], ['social', '📸 Social Media'], ['spiele', '🎮 Spiele'], ['video', '📺 Fernsehen & Video'], ['ki', '🤖 Suche & KI'], ['shopping', '🛒 Shopping'], ['dating', '💘 Dating']];
  const limitOptionen = (dl, gewaehlt) => PROFILRUBRIKEN.map((gid) => dl.gruppen.find((g) => g.id === gid)).filter((gr) => gr && !gr.fest).map((gr) => `<optgroup label="${esc(gr.name)}"><option value="rubrik:${esc(gr.id)}" ${gewaehlt === `rubrik:${gr.id}` ? 'selected' : ''}>Alle: ${esc(gr.name)}</option>${dl.dienste.filter((d) => d.gruppe === gr.id).map((d) => `<option value="dienst:${esc(d.id)}" ${gewaehlt === `dienst:${d.id}` ? 'selected' : ''}>${esc(d.symbol)} ${esc(d.name)}</option>`).join('')}</optgroup>`).join('');
  const limitZeile = (ziel, min, dl) => `<div class="formzeile" data-limit style="margin:6px 0;align-items:center"><select data-limitziel style="flex:1;min-width:0">${limitOptionen(dl, ziel)}</select><input type="number" min="5" max="1440" step="5" value="${esc(min)}" data-limitmin style="width:80px" aria-label="Minuten pro Tag"><small>min/Tag</small><button type="button" class="knopf klein leise" data-limitweg aria-label="Zeitlimit entfernen">✕</button></div>`;
  const kinderschutzHtml = (p, dl, vorlagen) => `<details class="profildienste" data-ks><summary>🧒 Kinderschutz: sichere Suche, Ruhezeiten, Zeitlimits${p.sicher?.suche || Object.keys(p.ruhezeiten || {}).length || Object.keys(p.limits || {}).length ? ' · aktiv' : ''}</summary>
    <div class="kategoriezeile"><label class="schalter"><input type="checkbox" data-sicher ${p.sicher?.suche ? 'checked' : ''}><span></span></label><div><b>🔎 Sichere Suche erzwingen</b>${info('Google, Bing und DuckDuckGo liefern auf den Geräten dieses Profils nur noch gefilterte Ergebnisse (SafeSearch) – egal, was in der Suchmaschine eingestellt ist. Das macht FAH-Adblock über DNS, ohne App auf dem Gerät.')}</div></div>
    <div class="feld" style="margin:8px 0"><label>▶️ YouTube</label><select data-youtube>${[['aus', 'normal'], ['moderat', 'eingeschränkter Modus (moderat)'], ['streng', 'eingeschränkter Modus (streng)']].map(([v, t]) => `<option value="${v}" ${(p.sicher?.youtube || 'aus') === v ? 'selected' : ''}>${t}</option>`).join('')}</select>${info('Der eingeschränkte Modus von YouTube blendet Videos mit Erwachseneninhalten und die Kommentare aus, „streng“ filtert stärker. YouTube selbst bleibt immer erreichbar.')}</div>
    <div style="margin-top:10px"><b>🌙 Ruhezeiten je Rubrik</b>${info('In diesen Zeiten sind alle Dienste der Rubrik für dieses Profil gesperrt, z. B. Messenger nachts. Ein Fenster über Mitternacht (21:00–06:30) gehört zum Starttag. Hilfsangebote wie Nummer gegen Kummer bleiben immer erreichbar.')}
      ${RUHE_RUBRIKEN.map(([r, n]) => { const z = p.ruhezeiten?.[r] || []; return `<div class="kategoriezeile" data-ruhe="${r}"><div style="flex:1;min-width:0"><b>${n}</b> <small style="color:var(--muted)">${z.length ? 'Ruhe zu diesen Zeiten:' : 'keine Ruhezeit'}</small><div data-fenster>${z.map(fensterHtml).join('')}</div><button type="button" class="knopf klein leise" data-ruheneu style="margin-top:6px">+ Ruhezeit</button></div></div>`; }).join('')}</div>
    <div style="margin-top:10px"><b>⏱️ Zeitlimits pro Tag</b>${info('Wie lange ein Dienst oder eine ganze Rubrik am Tag genutzt werden darf. Gezählt wird an den DNS-Anfragen des Geräts – das ist eine Schätzung: Eine App, die im Hintergrund weiterläuft, kann mitzählen. Ist die Zeit um, bleibt der Dienst bis Mitternacht gesperrt; Zusatzzeit gibst du unter <b>Kinderschutz</b>.')}
      <div data-limits>${Object.entries(p.limits || {}).map(([z, m]) => limitZeile(z, m, dl)).join('')}</div><button type="button" class="knopf klein leise" data-limitneu>+ Zeitlimit</button></div>
    <div class="feld" style="margin-top:12px"><label>🎓 Altersvorlage anwenden</label><div style="display:flex;gap:8px;flex-wrap:wrap"><select data-vorlage style="flex:1;min-width:0"><option value="">– Vorlage wählen –</option>${vorlagen.map((v) => `<option value="${esc(v.id)}">${esc(v.name)}</option>`).join('')}</select><button type="button" class="knopf klein" data-vorlageanwenden>Anwenden</button></div>${info('Überschreibt Kategorien, einzelne Dienste, Ruhezeiten, sichere Suche und Zeitlimits dieses Profils mit der Vorlage. Name, Farbe und zugeordnete Geräte bleiben. Danach kannst du alles anpassen.')}</div>
  </details>`;
  const balkenHtml = (z) => { const grenze = z.limit + z.extra, anteil = Math.min(100, Math.round(z.genutzt / Math.max(1, grenze) * 100)); return `<div class="zkbalken" role="img" aria-label="${z.genutzt} von ${grenze} Minuten"><i style="width:${anteil}%;background:${z.aufgebraucht ? 'var(--block)' : anteil > 75 ? '#ffb020' : 'var(--ok, #40e0a0)'}"></i></div>`; };
  const freigabenHtml = (u) => {
    const p = u.proxy || {}, f = u.freigabe || {}, fp = f.proxy, port = f.port;
    const zeile = (ok, titel, text) => `<div class="zeile umbruch"><span class="zsymbol">${ok === true ? '✅' : ok === false ? '⚠️' : '⏳'}</span><div class="haupt"><b>${titel}</b><small>${text}</small></div></div>`;
    const proxyText = !p.gekoppelt ? 'Noch nicht gekoppelt – einmal unten mit einem FAH-Proxy-Admin anmelden. Danach legt FAH-Adblock die Einträge seiner Geräte selbst an und löscht sie wieder.'
      : fp?.ok ? `Automatisch · aktive Instanz ${esc(fp.instanz || '')} · ${vor(fp.zeit)} abgeglichen. Haupt und Fail-over: ${esc(p.urls.join(', '))}`
      : `${esc(fp?.fehler || p.fehler || 'noch nicht abgeglichen')}`;
    const portText = port?.ok ? (port.ziel ? `TCP 853 → ${esc(port.ziel)} (automatisch)` : 'Keine nötig (kein Gerät eingerichtet)') : esc(port?.fehler || 'noch nicht geprüft');
    return `<div style="margin-top:4px"><b>Freigaben – automatisch</b>${info('FAH-Adblock pflegt selbst, was von außen erreichbar sein muss: je Gerät einen Eintrag in FAH-Proxy in der Gruppe <b>„AdBlock DNS Domains“</b> (an der gerade aktiven Instanz – FAH-Proxy spiegelt ihn zur anderen) und genau eine Portfreigabe TCP 853 in der UCG. Fällt der FAH-Adblock-Haupt aus, stellt der Ersatz beides auf sich um.')}
      <div class="zeilen">${zeile(p.gekoppelt ? (fp ? fp.ok : null) : false, 'FAH-Proxy', proxyText)}${zeile(port ? port.ok : null, 'UCG-Portfreigabe', portText)}</div>
      ${p.gekoppelt ? `<div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-top:6px"><button class="knopf klein leise" id="ugabgleich">Jetzt abgleichen</button><button class="knopf klein leise" id="ugentkoppeln">FAH-Proxy entkoppeln</button></div>`
      : `<div style="display:flex;flex-direction:column;gap:8px;margin-top:6px"><div class="feld"><label for="ugpurls">FAH-Proxy-Adressen (Haupt und Fail-over, je Zeile)</label><textarea id="ugpurls" rows="2" placeholder="https://IP-Haupt:28181&#10;https://IP-Failover:28181">${esc((u.proxyVorschlag || []).join('\n'))}</textarea></div>
        <div class="formzeile"><div class="feld"><label for="ugpname">FAH-Proxy-Admin</label><input id="ugpname" type="text" value="admin" autocomplete="off"></div><div class="feld"><label for="ugppw">Passwort</label><input id="ugppw" type="password" autocomplete="off"></div><div class="feld" style="flex:0 1 110px"><label for="ugpcode">2FA-Code</label><input id="ugpcode" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="falls an"></div></div>
        ${info('Einmalig: FAH-Adblock meldet sich damit bei FAH-Proxy an und legt sich dort ein eigenes Konto „fah-adblock“ mit der Rolle <b>Dienst</b> und Zufallspasswort an. Dieses Konto darf nur die Gruppe „AdBlock DNS Domains“ pflegen – keine anderen Einträge, keine Einstellungen. Dein Admin-Passwort wird nicht gespeichert.')}
        <div style="display:flex;justify-content:flex-end"><button class="knopf klein gruen" id="ugkoppeln">Koppeln</button></div></div>`}</div>`;
  };
  // ── Aufs Handy: Web-Push (App auf dem Home-Bildschirm) und ntfy ──
  const pushMoeglich = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window && window.isSecureContext;
  const istIos = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const alsApp = () => window.matchMedia?.('(display-mode: standalone)').matches || navigator.standalone === true;
  const geraetName = () => { const u = navigator.userAgent; return istIos() ? (/iPad/.test(u) || navigator.maxTouchPoints > 1 && !/iPhone/.test(u) ? 'iPad' : 'iPhone') : /Android/.test(u) ? 'Android-Handy' : /Mac/.test(u) ? 'Mac' : /Windows/.test(u) ? 'Windows-PC' : 'Browser'; };
  const schluesselBytes = (t) => { const b = atob(t.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - t.length % 4) % 4)); return Uint8Array.from(b, (c) => c.charCodeAt(0)); };
  async function eigenesAbo() { try { if (!pushMoeglich()) return null; const reg = await navigator.serviceWorker.getRegistration(); return reg ? await reg.pushManager.getSubscription() : null; } catch (e) { return null; } }
  async function pushEinschalten(schluessel) {
    // Reihenfolge für iOS: erst die Erlaubnis (direkt aus dem Tipp), dann Service-Worker und Abo
    const erlaubnis = await Notification.requestPermission();
    if (erlaubnis !== 'granted') throw new Error('Benachrichtigungen sind für FAH-Adblock nicht erlaubt – in den Einstellungen des Geräts unter Mitteilungen freigeben.');
    const reg = await navigator.serviceWorker.register('sw.js'); await navigator.serviceWorker.ready;
    let abo = await reg.pushManager.getSubscription();
    const passt = abo && abo.options?.applicationServerKey && btoa(String.fromCharCode(...new Uint8Array(abo.options.applicationServerKey))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') === schluessel;
    if (abo && !passt) { await abo.unsubscribe(); abo = null; }
    if (!abo) abo = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: schluesselBytes(schluessel) });
    const name = (prompt('Name für dieses Gerät (z. B. iPhone Mama):', geraetName()) || geraetName()).trim().slice(0, 60);
    await api('/api/push/abo', { methode: 'POST', daten: { abo: abo.toJSON(), name } });
  }
  function handyHtml(h, ersatz) {
    if (!h) return '';
    const n = h.ntfy || {}, abos = h.push?.abos || [];
    const pushTeil = !pushMoeglich()
      ? `<div class="hinweiszeile">${!window.isSecureContext ? `Push geht nur über die <b>https-Adresse</b> von FAH-Adblock (z. B. die Adresse in FAH-Proxy), nicht über http://${esc(location.host)}.` : istIos() && !alsApp() ? '<b>iPhone/iPad:</b> diese Seite in Safari öffnen → Teilen <b>⎋</b> → <b>„Zum Home-Bildschirm“</b>. Dann FAH-Adblock vom Home-Bildschirm starten, anmelden und hier Push einschalten (ab iOS 16.4).' : 'Dieser Browser kann keine Push-Benachrichtigungen.'}</div>`
      : `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center"><button class="knopf klein gruen" id="pushan" ${ersatz ? 'disabled' : ''}>🔔 Push auf diesem Gerät einschalten</button></div>`;
    const aboZeilen = abos.map((a) => `<div class="zeile umbruch" data-pushabo="${esc(a.id)}"><span class="zsymbol">${a.fehler ? '⚠️' : '📲'}</span><div class="haupt"><b>${esc(a.name)}</b><small>${esc(a.dienst.includes('apple') ? 'Apple' : a.dienst.includes('google') ? 'Google' : a.dienst.includes('mozilla') ? 'Firefox' : 'Microsoft')} · seit ${esc(new Date(a.seit).toLocaleDateString('de-DE'))}${a.zuletzt ? ` · zuletzt ${vor(a.zuletzt)}` : ''}${a.fehler ? ` · ${esc(a.fehler)}` : ''}</small></div>${ersatz ? '' : '<span style="display:flex;gap:6px;flex:0 0 auto"><button class="knopf klein leise" data-pushtest>Test</button><button class="knopf klein leise" data-pushweg aria-label="Entfernen">✕</button></span>'}</div>`).join('');
    return `<b>📲 Aufs Handy</b>${info('Zusätzlich zur Liste hier kann jede Meldung aufs Handy kommen – freiwillig, ohne Einrichtung bleibt alles in FAH-Adblock. <b>Push:</b> FAH-Adblock als App auf dem Home-Bildschirm, keine Fremd-App nötig (iPhone ab iOS 16.4, Android, auch am PC). <b>ntfy:</b> alternativ über die ntfy-App. Nach draußen gehen nur Gerät, Art und Anzahl – welche Seiten genau, steht nur hier.')}
      ${ersatz ? `<div class="hinweiszeile">🔁 Eingerichtet wird am Haupt – diese Ersatz-Instanz bekommt Push-Geräte und ntfy beim Abgleich und sendet nur, solange der Haupt ausgefallen ist.</div>` : ''}
      <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px">${pushTeil}${aboZeilen ? `<div class="zeilen">${aboZeilen}</div>` : ''}</div>
      <details style="margin-top:10px"><summary>ntfy (optional)${n.thema ? ' · <span class="chip gruen">an</span>' : ''}</summary><div style="display:flex;flex-direction:column;gap:10px;margin-top:10px">
        ${info('ntfy ist eine kostenlose App für iPhone und Android (oder ein eigener ntfy-Server). In der App dasselbe Thema abonnieren. Das Thema ist wie ein Passwort: wer es kennt, liest mit – deshalb lang und zufällig. Leeres Thema = ntfy aus.')}
        <div class="formzeile"><div class="feld"><label for="ntfyurl">ntfy-Adresse</label><input id="ntfyurl" type="url" value="${esc(n.url || 'https://ntfy.sh')}" placeholder="https://ntfy.sh" ${ersatz ? 'disabled' : ''}></div><div class="feld"><label for="ntfythema">Thema</label><div style="display:flex;gap:6px"><input id="ntfythema" type="text" value="${esc(n.thema || '')}" placeholder="leer = aus" style="flex:1;min-width:0" ${ersatz ? 'disabled' : ''}><button type="button" class="knopf klein leise" id="ntfyneu" title="Zufälliges Thema erzeugen" ${ersatz ? 'disabled' : ''}>🎲</button></div></div></div>
        <div class="feld"><label for="ntfyschl">Zugangsschlüssel (nur bei geschütztem ntfy-Server) ${n.schluesselGesetzt ? '<span class="chip gruen">gesetzt</span>' : ''}</label><input id="ntfyschl" type="password" autocomplete="off" placeholder="${n.schluesselGesetzt ? 'leer lassen = unverändert' : 'tk_… (optional)'}" ${ersatz ? 'disabled' : ''}>${n.schluesselGesetzt && !ersatz ? '<label style="font-size:13px"><input type="checkbox" id="ntfyschlweg"> Schlüssel löschen</label>' : ''}</div>
        ${n.fehler ? `<div class="fehlertext">${esc(n.fehler)}</div>` : ''}
        ${ersatz ? '' : '<div style="display:flex;justify-content:flex-end"><button class="knopf klein gruen" id="ntfyspeichern">Speichern</button></div>'}
      </div></details>
      ${!ersatz && (abos.length || n.thema) ? '<div style="display:flex;justify-content:flex-end;margin-top:8px"><button class="knopf klein leise" id="handytest">Testnachricht an alle</button></div>' : ''}`;
  }
  async function zeigeKinderschutz() {
    const [k, g] = await Promise.all([api('/api/kinderschutz'), api('/api/geraete')]);
    S.geraete = g;
    const m = k.meldungen, u = k.unterwegs;
    const nameVon = (id) => g.geraete.find((x) => x.id === id)?.name || id;
    const ersatz = S.ich?.spiegel?.rolle === 'ersatz';
    const zkHtml = k.zeitkonten.length ? k.zeitkonten.map((d) => `<div class="zeile umbruch block" data-zkgeraet="${esc(d.id)}"><div class="haupt"><b>${esc(d.name)}</b><small>Profil ${esc(d.profilName)}</small></div><div style="display:flex;flex-direction:column;gap:10px;margin-top:8px">${d.ziele.map((z) => `<div data-zkziel="${esc(z.ziel)}"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><span>${esc(z.name)}</span><span class="chip ${z.aufgebraucht ? 'rot' : ''}">${z.genutzt} / ${z.limit + z.extra} min${z.extra ? ` (+${z.extra})` : ''}${z.aufgebraucht ? ' · aufgebraucht' : ''}</span></div>${balkenHtml(z)}<div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap"><button class="knopf klein leise" data-mehr="15">+15 min</button><button class="knopf klein leise" data-mehr="30">+30 min</button><button class="knopf klein leise" data-mehr="1440">heute frei</button>${z.extra ? '<button class="knopf klein leise" data-mehr="0">Zusatz zurück</button>' : ''}</div></div>`).join('')}</div></div>`).join('') : `<div class="leer">Noch keine Zeitlimits. Lege sie im Profil fest (Profile → Kinderschutz → Zeitlimits pro Tag).</div>`;
    const verlaufHtml = (m.verlauf || []).slice(0, 15).map((v) => `<div class="zeile umbruch"><span class="zsymbol">${v.ernst ? '⚠️' : 'ℹ️'}</span><div class="haupt"><b>${esc(v.titel)}</b><small>${esc(v.details ? `${v.details} · ` : '')}${esc(v.text)}</small></div><span class="chip ${v.ernst ? 'rot' : ''}" title="${esc(new Date(v.ts).toLocaleString('de-DE'))}${v.handy ? esc(` · aufs Handy: ${v.handy.push ? `Push an ${v.handy.push}` : ''}${v.handy.ntfy ? ' ntfy' : ''}${v.handy.fehler ? ` · Fehler: ${v.handy.fehler.join(', ')}` : ''}`) : ''}">${v.handy ? (v.handy.push || v.handy.ntfy ? '📲 ' : '⚠️ ') : ''}${vor(v.ts)}</span></div>`).join('') || `<div class="leer">${m.an ? 'Noch nichts Auffälliges – gut so.' : 'Meldungen sind aus.'}</div>`;
    const ugZeile = (d) => {
      const zert = d.zertifikatBis ? `<span class="chip gruen">bereit · Zertifikat bis ${new Date(d.zertifikatBis).toLocaleDateString('de-DE')}</span>` : d.wartetAufProxy ? '<span class="chip">wartet auf FAH-Proxy</span>' : d.fehler ? '<span class="chip rot">Zertifikat fehlgeschlagen</span>' : '<span class="chip">Zertifikat wird geholt …</span>';
      const profilLink = `/unterwegs/${encodeURIComponent(d.geheim)}/profil.mobileconfig`;
      return `<div class="zeile umbruch block" data-uggeraet="${esc(d.id)}"><div class="haupt"><b>${esc(d.name)} ${d.an ? '' : '<span class="chip">aus</span>'} ${zert}</b><small class="mono">${esc(d.host || '– Basisdomain fehlt –')}</small>
        ${!d.zertifikatBis && d.wartetAufProxy ? `<small>${u.proxy?.gekoppelt ? 'FAH-Proxy-Eintrag ist angelegt – FAH-Proxy holt gerade das Zertifikat (meist 1–2 Minuten; ist das Let’s-Encrypt-Kontingent für die Domain erschöpft, nimmt es ZeroSSL, das kann ein paar Minuten länger dauern). FAH-Adblock sieht jede Minute nach.' : 'Noch nicht erreichbar – oben FAH-Proxy koppeln, dann legt FAH-Adblock den Eintrag selbst an.'}</small>` : d.fehler && !d.zertifikatBis ? `<small style="color:var(--block)">${esc(d.fehler)}</small>` : ''}<small>${d.zuletzt ? `zuletzt ${d.zuletzt.extern ? 'unterwegs' : 'zu Hause'} über ${esc(d.zuletzt.art)} · ${vor(d.zuletzt.ts)}` : 'noch nie unterwegs gefragt'}</small></div>
        <div class="knopfreihe"><button class="knopf klein leise" data-ugandroid>🤖 Android</button><a class="knopf klein leise" href="${profilLink}" download>🍏 iPhone-Profil</a>
          <button class="knopf klein leise" data-ugname title="Kurzen Namen wählen, z. B. fairphone">✏️ Name</button><button class="knopf klein leise" data-ugschalten>${d.an ? 'Ausschalten' : 'Einschalten'}</button><button class="knopf klein leise" data-ugneu title="Neues Geheimnis für das iPhone-Profil (z. B. Gerät verloren) – der Name bleibt">Neu ausstellen</button><button class="knopf klein leise" data-ugweg aria-label="Entfernen">✕</button></div></div>`;
    };
    const ohneUnterwegs = g.geraete.filter((x) => !u?.geraete.some((d) => d.id === x.id) && !String(x.id).startsWith('ip:'));
    $('#haupt').innerHTML = `${hinweisband()}
      <section class="karte"><div class="kartekopf">🧒 Kinderschutz</div><div class="kartekoerper">${info('Hier steht alles, was Eltern im Alltag brauchen: Meldungen über Auffälliges, Zeitkonten mit „mehr Zeit“, der Schutz unterwegs im Mobilfunk, die immer erreichbaren Hilfsangebote und Altersvorlagen für Profile. <b>Ehrlich gesagt:</b> Ein DNS-Filter sieht nur, <i>welche</i> Seiten ein Gerät aufruft, nie den Inhalt von Chats. Mobbing selbst erkennt er nicht – er sperrt die Orte, an denen es meist passiert (anonyme Frage-Apps, Zufallschats), meldet Versuche und hält Hilfe immer offen. Das Gespräch mit dem Kind ersetzt das nicht.')}</div></section>
      <div class="raster" style="grid-template-columns:repeat(auto-fill,minmax(360px,1fr));margin-top:16px">
      <section class="karte"><div class="kartekopf">🔔 Meldungen<span class="rechts">${m.an ? `<span class="chip ${m.heute ? 'rot' : 'gruen'}">${zahl(m.heute)} heute</span>` : '<span class="chip">aus</span>'}</span></div>
        <div class="kartekoerper" style="padding-bottom:0">${info('Hier sammelt FAH-Adblock, was Geräte aus den gewählten Profilen Auffälliges aufrufen – mehrere Versuche innerhalb einer Minute werden zu <b>einem</b> Eintrag, danach hat dieses Gerät für diese Art eine Ruhepause. Die Zahl von heute steht auch als Kachel im Schutzschild. Aufs Handy kommt eine Meldung nur, wenn du das unten einrichtest.')}</div>
        <div class="zeilen">${verlaufHtml}</div>
        <div class="kartekoerper" id="handyblock">${handyHtml(k.handy, ersatz)}</div>
        <div class="kartekoerper"><details><summary>Einstellungen der Meldungen</summary><div style="display:flex;flex-direction:column;gap:12px;margin-top:10px">
        <label class="feld" style="flex-direction:row;gap:10px;align-items:center"><span class="schalter"><input type="checkbox" id="mean" ${m.an ? 'checked' : ''}><span></span></span><b>Meldungen sammeln</b></label>
        <div class="feld"><label>Für diese Profile</label><div class="chipwahl">${k.profile.map((p) => `<label class="chip"><input type="checkbox" data-meprofil="${esc(p.id)}" ${m.profile?.includes(p.id) ? 'checked' : ''}> ${esc(p.name)}</label>`).join('')}</div>${info('Nur Geräte mit diesen Profilen erscheinen hier – dein eigenes Handy also nicht.')}</div>
        <div class="feld"><label>Melden bei Sperren in</label><div class="chipwahl">${k.kategorien.filter((x) => x.id !== 'werbung').map((x) => `<label class="chip"><input type="checkbox" data-mekat="${esc(x.id)}" ${m.kategorien?.includes(x.id) ? 'checked' : ''}> ${esc(x.symbol)} ${esc(x.name)}</label>`).join('')}</div>${info('Werbung ist bewusst nicht dabei – sie würde ständig melden. Empfohlen: anonyme Chats, Jugendschutz, Drogen und Umgehung.')}</div>
        <label style="font-size:14px"><input type="checkbox" id="medienste" ${m.dienste ? 'checked' : ''}> auch gesperrte Dienste melden (z. B. TikTok im Profil gesperrt)</label>
        <label style="font-size:14px"><input type="checkbox" id="mezeit" ${m.zeitlimit !== false ? 'checked' : ''}> melden, wenn ein Zeitlimit aufgebraucht ist</label>
        <div class="formzeile" style="align-items:center"><label style="font-size:14px;flex:1"><input type="checkbox" id="mestille" ${m.stille !== false ? 'checked' : ''}> Umgehung erkennen: Gerät ist im WLAN, fragt aber seit</label><input id="mestillemin" type="number" min="10" max="720" value="${esc(m.stilleMin || 30)}" style="width:80px"><small>min nicht</small></div>
        ${info('Ist ein Gerät laut UniFi im Netz, schickt aber lange keine Anfrage mehr an FAH-Adblock, hat es vermutlich ein eigenes DNS, eine VPN-App oder iCloud Privat-Relay eingeschaltet – der Filter wäre dann umgangen. Braucht den UniFi-Zugang (Einstellungen). Höchstens ein Eintrag je Gerät alle 6 Stunden.')}
        <div class="formzeile" style="align-items:center"><label for="meruhe" style="flex:1;font-size:14px">Ruhepause nach einem Eintrag (je Gerät und Art)</label><input id="meruhe" type="number" min="5" max="1440" value="${esc(m.ruheMin || 60)}" style="width:80px"><small>min</small></div>
        <div style="display:flex;justify-content:flex-end"><button class="knopf klein gruen" id="mespeichern">Speichern</button></div>
        </div></details></div></section>
      <section class="karte"><div class="kartekopf">⏱️ Zeitkonten heute</div><div class="kartekoerper">${info('Verbrauch der Tageslimits je Gerät (geschätzt aus den DNS-Anfragen). <b>+15 min</b> und <b>+30 min</b> geben sofort Zusatzzeit für heute, <b>heute frei</b> hebt das Limit bis Mitternacht auf. Um Mitternacht beginnt alles neu.')}</div><div class="zeilen" id="zkliste">${zkHtml}</div></section>
      <section class="karte"><div class="kartekopf">📱 Schutz unterwegs<span class="rechts">${u?.an ? (u.dot.laeuft ? `<span class="chip gruen">DoT läuft · Port ${u.dot.port}</span>` : '<span class="chip">an · DoT wartet auf Zertifikat</span>') : '<span class="chip">aus</span>'}</span></div><div class="kartekoerper" style="display:flex;flex-direction:column;gap:12px">
        ${info('Damit filtert FAH-Adblock ein Handy auch im <b>Mobilfunk</b> – mit dem Profil genau dieses Geräts (Kategorien, Ruhezeiten, Zeitlimits, Meldungen). <b>Android:</b> unter „Privates DNS“ den Namen des Geräts eintragen. <b>iPhone/iPad:</b> das Profil auf dem Gerät laden und installieren. Jedes Gerät bekommt einen eigenen Namen; unter diesem Namen ist von außen nur der DNS-Dienst erreichbar, nie diese Oberfläche.')}
        ${ersatz ? `<div class="${u?.uebernommen ? 'fehlertext' : 'leer'}" style="text-align:left;padding:0">${u?.uebernommen ? '⚠️ Der Haupt ist nicht erreichbar – diese Ersatz-Instanz hat den Schutz unterwegs übernommen (Portfreigabe und FAH-Proxy zeigen auf sie). Kommt der Haupt zurück, holt er alles wieder zu sich.' : '🔁 Ersatz-Instanz: Zertifikate und FAH-Proxy-Zugang kommen beim Abgleich vom Haupt. Fällt der Haupt länger als 6 Minuten aus, übernimmt diese Instanz automatisch.'}</div>` : ''}
        <label class="feld" style="flex-direction:row;gap:10px;align-items:center"><span class="schalter"><input type="checkbox" id="ugan" ${u?.an ? 'checked' : ''}><span></span></span><b>Schutz unterwegs</b></label>
        <div class="formzeile"><div class="feld"><label for="ugbasis">Basisdomain</label><input id="ugbasis" type="text" value="${esc(u?.basis || '')}" placeholder="meinname.example.de"></div><div class="feld"><label for="ugmail">E-Mail für Let's Encrypt (optional)</label><input id="ugmail" type="email" value="${esc(u?.email || '')}" placeholder="name@example.de"></div></div>
        ${info('Die Basisdomain muss per Platzhalter (*.basisdomain) öffentlich auf deinen Anschluss zeigen (DynDNS). Alles Weitere erledigt FAH-Adblock selbst: Einträge in FAH-Proxy anlegen und löschen, Portfreigabe TCP 853 in der UCG, Zertifikate holen und erneuern.')}
        <div style="display:flex;justify-content:flex-end"><button class="knopf klein gruen" id="ugspeichern">Speichern</button></div>
        ${u?.an ? `<div class="formzeile" style="align-items:flex-end"><div class="feld"><label for="ugneu">Gerät hinzufügen</label><select id="ugneu">${ohneUnterwegs.map((x) => `<option value="${esc(x.id)}">${esc(x.name)} · Profil ${esc((g.profile.find((p) => p.id === x.profil) || {}).name || x.profil)}</option>`).join('') || '<option value="">– alle Geräte eingerichtet –</option>'}</select></div><button class="knopf klein" id="ughinzu">Hinzufügen</button><button class="knopf klein leise" id="ugzert">Zertifikate jetzt holen</button></div>` : ''}
        ${u?.an ? freigabenHtml(u) : ''}
      </div><div class="zeilen">${(u?.geraete || []).map(ugZeile).join('') || (u?.an ? '<div class="leer">Noch kein Gerät eingerichtet.</div>' : '')}</div></section>
      <section class="karte"><div class="kartekopf">🆘 Hilfsangebote – immer erreichbar</div><div class="kartekoerper">${info('Diese Beratungs- und Notfallstellen sind auf allen Geräten immer erreichbar – keine Liste, kein Profil, keine Ruhezeit und kein Zeitlimit kann sie sperren. Gut zu wissen für Kinder: Hilfe gibt es anonym und kostenlos.')}<div class="zeilen">${k.hilfe.map((h) => `<div class="zeile umbruch"><span class="zsymbol">${esc(h.symbol)}</span><div class="haupt"><b>${esc(h.name)}</b><small>${esc(h.hinweis)} · ${esc(h.domains.join(', '))}</small></div></div>`).join('')}</div></div></section>
      <section class="karte"><div class="kartekopf">🎓 Altersvorlagen</div><div class="kartekoerper">${info('Fertige Profile nach Alter, angelehnt an die Empfehlungen von klicksafe und SCHAU HIN!. Ein Klick legt ein neues Profil an; anpassen kannst du danach alles unter Profile. Fernsehen und YouTube werden nie gesperrt, für Jüngere aber gefiltert.')}<div class="zeilen">${k.vorlagen.map((v) => `<div class="zeile umbruch"><span class="zsymbol" style="color:${esc(v.farbe)}">●</span><div class="haupt"><b>${esc(v.name)}</b><small>${esc(v.beschreibung)}</small></div><button class="knopf klein" data-vorlageneu="${esc(v.id)}">Als Profil anlegen</button></div>`).join('')}</div></div></section>
      </div>`;
    erweiterungenKinderschutz();
    const haupt = $('#haupt');
    const sicher = async (fn, ok) => { try { await fn(); if (ok) toast(ok); zeigeKinderschutz(); } catch (err) { toast(err.message, 'fehler'); } };
    $('#mespeichern').onclick = () => sicher(() => api('/api/kinderschutz/meldungen', { methode: 'PUT', daten: { an: $('#mean').checked,
      profile: $$('[data-meprofil]').filter((x) => x.checked).map((x) => x.dataset.meprofil), kategorien: $$('[data-mekat]').filter((x) => x.checked).map((x) => x.dataset.mekat), dienste: $('#medienste').checked, zeitlimit: $('#mezeit').checked, stille: $('#mestille').checked, stilleMin: +$('#mestillemin').value, ruheMin: +$('#meruhe').value } }), 'Meldungen gespeichert');
    if ($('#pushan')) $('#pushan').onclick = () => sicher(async () => { if (!k.handy?.push?.schluessel) throw new Error('Kein Push-Schlüssel – bitte die Seite neu laden'); await pushEinschalten(k.handy.push.schluessel); }, 'Push ist auf diesem Gerät eingeschaltet – gleich mit „Test“ prüfen');
    eigenesAbo().then(async (abo) => {
      if (!abo || !$('#pushan') || !crypto.subtle) return;
      const h = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(abo.endpoint)))].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 16);
      const a = (k.handy?.push?.abos || []).find((x) => x.kennung === h); if (!a) return;
      $('#pushan').textContent = '🔔 Push auf diesem Gerät erneuern';
      const zeile = $(`[data-pushabo="${a.id}"]`); if (zeile) { zeile.dataset.hier = '1'; zeile.querySelector('b').insertAdjacentHTML('beforeend', ' <span class="chip gruen">dieses Gerät</span>'); }
    });
    if ($('#ntfyneu')) $('#ntfyneu').onclick = () => { const z = 'abcdefghijkmnopqrstuvwxyz23456789', b = crypto.getRandomValues(new Uint8Array(20)); $('#ntfythema').value = `fah-${[...b].map((x) => z[x % z.length]).join('')}`; toast('Neues Thema – in der ntfy-App genau so abonnieren, dann Speichern'); };
    if ($('#ntfyspeichern')) $('#ntfyspeichern').onclick = () => sicher(() => api('/api/benachrichtigung/ntfy', { methode: 'PUT', daten: { url: $('#ntfyurl').value.trim(), thema: $('#ntfythema').value.trim(), ...($('#ntfyschl').value ? { schluessel: $('#ntfyschl').value } : {}), ...($('#ntfyschlweg')?.checked ? { schluesselLoeschen: true } : {}) } }), 'ntfy gespeichert');
    const testErgebnis = (r) => toast(`Testnachricht: ${[r.push ? `Push an ${r.push} ${r.push === 1 ? 'Gerät' : 'Geräte'}` : '', r.ntfy ? 'ntfy' : ''].filter(Boolean).join(' und ') || 'nichts gesendet'}${r.fehler?.length ? ` · ${r.fehler.join(' · ')}` : ''}`, r.fehler?.length ? 'fehler' : undefined);
    if ($('#handytest')) $('#handytest').onclick = async () => { try { testErgebnis(await api('/api/benachrichtigung/test', { methode: 'POST', daten: {} })); zeigeKinderschutz(); } catch (err) { toast(err.message, 'fehler'); } };
    $('#ugspeichern').onclick = () => sicher(() => api('/api/unterwegs', { methode: 'PUT', daten: { an: $('#ugan').checked, basis: $('#ugbasis').value.trim(), email: $('#ugmail').value.trim() } }), 'Schutz unterwegs gespeichert');
    if ($('#ugkoppeln')) $('#ugkoppeln').onclick = () => sicher(() => api('/api/unterwegs/proxy', { methode: 'POST', daten: { urls: $('#ugpurls').value.split(/\s+/).filter(Boolean), name: $('#ugpname').value.trim(), passwort: $('#ugppw').value, code: $('#ugpcode').value.trim() || undefined } }), 'FAH-Proxy gekoppelt – Einträge werden automatisch gepflegt');
    if ($('#ugabgleich')) $('#ugabgleich').onclick = () => sicher(() => api('/api/unterwegs/freigaben', { methode: 'POST', daten: {} }), 'Abgeglichen');
    if ($('#ugentkoppeln')) $('#ugentkoppeln').onclick = () => { if (confirm('FAH-Proxy entkoppeln? Vorhandene Einträge bleiben in FAH-Proxy, werden aber nicht mehr gepflegt.')) sicher(() => api('/api/unterwegs/proxy', { methode: 'DELETE' }), 'Entkoppelt'); };
    if ($('#ughinzu')) $('#ughinzu').onclick = () => { const id = $('#ugneu').value; if (id) sicher(() => api(`/api/unterwegs/geraete/${encodeURIComponent(id)}`, { methode: 'PUT', daten: { an: true } }), 'Gerät eingerichtet – Freigaben und Zertifikat folgen automatisch'); };
    if ($('#ugzert')) $('#ugzert').onclick = () => { toast('Zertifikate werden geholt … (bis zu einer Minute)'); sicher(() => api('/api/unterwegs/zertifikate', { methode: 'POST', daten: {} })); };
    haupt.onclick = async (e) => {
      const pa = e.target.closest('[data-pushabo]');
      if (pa && e.target.closest('[data-pushtest]')) { try { testErgebnis(await api('/api/benachrichtigung/test', { methode: 'POST', daten: { id: pa.dataset.pushabo } })); zeigeKinderschutz(); } catch (err) { toast(err.message, 'fehler'); } return; }
      if (pa && e.target.closest('[data-pushweg]')) { if (confirm('Dieses Gerät bekommt dann keine Push-Benachrichtigungen mehr. Entfernen?')) { const abo = await eigenesAbo(); if (abo && pa.dataset.hier) await abo.unsubscribe().catch(() => {}); sicher(() => api(`/api/push/abo/${encodeURIComponent(pa.dataset.pushabo)}`, { methode: 'DELETE' }), 'Entfernt'); } return; }
      const mehr = e.target.closest('[data-mehr]');
      if (mehr) { const gid = mehr.closest('[data-zkgeraet]').dataset.zkgeraet, ziel = mehr.closest('[data-zkziel]').dataset.zkziel; return sicher(() => api('/api/zeitkonto/mehr', { methode: 'POST', daten: { geraet: gid, ziel, minuten: +mehr.dataset.mehr } }), +mehr.dataset.mehr === 1440 ? 'Für heute frei' : +mehr.dataset.mehr ? `+${mehr.dataset.mehr} min für heute` : 'Zusatzzeit zurückgenommen'); }
      const vn = e.target.closest('[data-vorlageneu]');
      if (vn) return sicher(() => api('/api/profile', { methode: 'POST', daten: { vorlage: vn.dataset.vorlageneu } }), 'Profil angelegt – Geräte ordnest du unter Profile zu');
      const zeile = e.target.closest('[data-uggeraet]'); if (!zeile) return;
      const gid = zeile.dataset.uggeraet, d = u.geraete.find((x) => x.id === gid);
      if (e.target.closest('[data-ugandroid]')) return hinweisDialog(`🤖 Android: ${d.name}`, `<ol class="dialogschritte"><li>Einstellungen → <b>Netzwerk &amp; Internet</b> → <b>Privates DNS</b></li><li><b>„Hostname des Anbieters für privates DNS“</b> wählen</li><li>Diesen Namen eintragen und speichern:</li></ol><div class="mono dialogname">${esc(d.host)}</div>${info('Zu Hause funktioniert das sofort. Unterwegs braucht es zusätzlich die Portfreigabe TCP 853 auf diese Instanz und ein Zertifikat (Status in der Zeile: „bereit“).')}`, [{ text: '📋 Namen kopieren', art: 'gruen', fn: () => navigator.clipboard?.writeText(d.host).then(() => toast('Name kopiert'), () => toast(d.host)) }]);
      if (e.target.closest('[data-ugname]')) { const neu = prompt(`Kurzer Name für ${d.name} (wird zu dns-NAME.${u.basis}):`, d.kennung.replace(/^dns-/, '')); if (!neu) return; return sicher(() => api(`/api/unterwegs/geraete/${encodeURIComponent(gid)}`, { methode: 'PUT', daten: { kennung: neu } }), 'Name geändert'); }
      if (e.target.closest('[data-ugschalten]')) return sicher(() => api(`/api/unterwegs/geraete/${encodeURIComponent(gid)}`, { methode: 'PUT', daten: { an: !d.an } }), d.an ? 'Ausgeschaltet' : 'Eingeschaltet');
      if (e.target.closest('[data-ugneu]')) { if (!confirm(`${d.name}: neues Geheimnis ausstellen? Das alte iPhone-Profil gilt danach nicht mehr – auf dem iPhone/iPad das Profil neu laden. Der Name bleibt.`)) return; return sicher(() => api(`/api/unterwegs/geraete/${encodeURIComponent(gid)}/erneuern`, { methode: 'POST', daten: {} }), 'Neu ausgestellt'); }
      if (e.target.closest('[data-ugweg]')) { if (!confirm(`${d.name} aus dem Schutz unterwegs entfernen?`)) return; return sicher(() => api(`/api/unterwegs/geraete/${encodeURIComponent(gid)}`, { methode: 'DELETE' }), 'Entfernt'); }
    };
  }

  // ── Statistik ──────────────────────────────────────────────────────────────
  async function zeigeStatistik() {
    $('#haupt').innerHTML = `<section class="karte"><div class="kartekopf">📊 Anfragen<span class="rechts"><button class="knopf klein" data-zeitraum="24h" aria-pressed="true">24 h</button><button class="knopf klein leise" data-zeitraum="7d">7 Tage</button></span></div>
      ${info('Alle DNS-Anfragen deiner Geräte über die Zeit: grau erlaubt, rot geblockt. Darunter die häufigsten Domains und die aktivsten Geräte der letzten 24 Stunden.')}<canvas class="diagramm" id="diagramm"></canvas><div class="diagrammlegende"><span><i style="background:var(--rand2)"></i>erlaubt</span><span><i style="background:var(--block)"></i>geblockt</span><span id="diagrammsumme"></span></div></section>
      <div class="zweispaltig"><section class="karte"><div class="kartekopf">⛔ Meistgeblockt · 24 h</div><div id="stopg"></div></section><section class="karte"><div class="kartekopf">✅ Meistaufgerufen · 24 h</div><div id="stope"></div></section></div>
      <section class="karte" style="margin-top:16px"><div class="kartekopf">💻 Aktivste Geräte · 24 h</div><div id="sgeraete"></div></section>`;
    const zeitraum = async (z) => {
      $$('[data-zeitraum]').forEach((b) => { b.setAttribute('aria-pressed', String(b.dataset.zeitraum === z)); b.classList.toggle('leise', b.dataset.zeitraum !== z); });
      const daten = await api(`/api/verlauf?zeitraum=${z}`);
      balken($('#diagramm'), daten.map((d) => ({ e: d.erlaubt, g: d.geblockt, beschriftung: z === '7d' ? new Date(d.tag).toLocaleDateString('de-DE', { weekday: 'short' }) : new Date(d.stunde).getHours() + ' h' })));
      const e = daten.reduce((a, d) => a + d.erlaubt, 0), g = daten.reduce((a, d) => a + d.geblockt, 0);
      $('#diagrammsumme').textContent = `${zahl(e + g)} Anfragen · ${zahl(g)} geblockt (${e + g ? (g / (e + g) * 100).toFixed(1).replace('.', ',') : 0} %)`;
    };
    $$('[data-zeitraum]').forEach((b) => { b.onclick = () => zeitraum(b.dataset.zeitraum); });
    zeitraum('24h');
    const [tg, te, gr] = await Promise.all([api('/api/top?aktion=geblockt&limit=12'), api('/api/top?aktion=erlaubt&limit=12'), api('/api/geraete')]);
    const topHtml = (liste, erlaubt) => liste.length ? liste.map((t) => `<div class="balkenzeile ${erlaubt ? 'erlaubt' : ''}"><span class="mono">${esc(t.domain)}</span><b class="mono">${zahl(t.n)}</b>${dinfo(t.domain)}<div class="balken"><i style="width:${Math.max(2, t.n / liste[0].n * 100)}%"></i></div></div>`).join('') : '<div class="leer">Noch keine Daten.</div>';
    $('#stopg').innerHTML = topHtml(tg); $('#stope').innerHTML = topHtml(te, true);
    const gl = gr.geraete.slice().sort((a, b) => (b.erlaubt + b.geblockt) - (a.erlaubt + a.geblockt)).slice(0, 12), max = Math.max(1, ...gl.map((g) => g.erlaubt + g.geblockt));
    $('#sgeraete').innerHTML = gl.length ? gl.map((g) => `<div class="balkenzeile erlaubt"><span><span class="zsymbol klein">${geraetSymbol(g)}</span> ${esc(g.name)} <small style="color:var(--muted)">· ${String(g.quote).replace('.', ',')} % geblockt</small></span><b class="mono">${zahl(g.erlaubt + g.geblockt)}</b><div class="balken"><i style="width:${(g.erlaubt + g.geblockt) / max * 100}%"></i></div></div>`).join('') : '<div class="leer">Noch keine Daten.</div>';
  }
  function balken(cv, daten) {
    const r = cv.getBoundingClientRect(), dpr = Math.min(2, devicePixelRatio || 1); cv.width = r.width * dpr; cv.height = r.height * dpr;
    const c = cv.getContext('2d'); c.scale(dpr, dpr); const s = getComputedStyle(document.documentElement);
    const unten = 24, oben = 14, links = 44, max = Math.max(1, ...daten.map((d) => d.e + d.g)), bw = (r.width - links - 10) / Math.max(1, daten.length);
    c.font = '11px Inter, system-ui, sans-serif'; c.fillStyle = s.getPropertyValue('--muted'); c.strokeStyle = s.getPropertyValue('--rand'); c.textAlign = 'right';
    for (let i = 0; i <= 4; i++) { const y = oben + (r.height - unten - oben) * i / 4; c.beginPath(); c.moveTo(links, y); c.lineTo(r.width - 10, y); c.stroke(); c.fillText(zahl(Math.round(max * (1 - i / 4))), links - 6, y + 4); }
    c.textAlign = 'center';
    daten.forEach((d, i) => {
      const x = links + i * bw, hoehe = r.height - unten - oben, he = (d.e + d.g) / max * hoehe, hg = d.g / max * hoehe;
      c.fillStyle = s.getPropertyValue('--rand2'); c.fillRect(x + bw * 0.15, oben + hoehe - he, bw * 0.7, he);
      c.fillStyle = s.getPropertyValue('--block'); c.fillRect(x + bw * 0.15, oben + hoehe - hg, bw * 0.7, hg);
      if (daten.length <= 8 || i % 3 === 0) { c.fillStyle = s.getPropertyValue('--muted'); c.fillText(d.beschriftung, x + bw / 2, r.height - 6); }
    });
  }

  // ── Einstellungen ──────────────────────────────────────────────────────────
  async function zeigeEinstellungen() {
    const [e, u, ak, sp] = await Promise.all([api('/api/einstellungen'), api('/api/uebersicht'), api('/api/anbieter'), api('/api/spiegel').catch(() => null)]);
    S.spiegel = sp;
    $('#haupt').innerHTML = `${hinweisband()}<div class="raster" style="grid-template-columns:repeat(auto-fill,minmax(360px,1fr))">
      <section class="karte"><div class="kartekopf">🔐 Verschlüsseltes DNS nach außen</div><div class="kartekoerper">
        ${info('Wohin FAH-Adblock erlaubte Anfragen weiterschickt. Die Verbindung ist verschlüsselt (DNS-over-HTTPS), dadurch sehen weder Vodafone noch jemand im Netz dazwischen, welche Seiten aufgerufen werden. Quad9 prüft zusätzlich gegen Schadsoftware, Cloudflare ist der Rückfall.')}
        <div id="upstreamliste">${e.upstream.map((a, i) => upstreamZeile(a, i, u.upstream.anbieter[i])).join('')}</div>
        <details class="anbieterwahl" ${e.upstream.length ? '' : 'open'}><summary>Kostenlose Anbieter auswählen (${ak.anbieter.length})</summary>
          ${info('Haken setzen = Anbieter wird unten in die Liste aufgenommen. Die <b>Reihenfolge ist die Rangfolge</b>: Der erste antwortende Anbieter gewinnt, fällt er aus, übernimmt der nächste. Mit ▲ und ▼ verschiebst du ihn. Anbieter mit eigener Werbe- oder Trackersperre (z. B. DNSforge, Mullvad AdBlock, AdGuard) sperren zusätzlich nach ihren eigenen Listen – <b>geschützte Dienste und deine eigenen Freigaben sind davon ausgenommen</b>: sperrt ein Anbieter dort, wird automatisch der nächste gefragt.')}
          ${ak.gruppen.map((gr) => `<div class="anbietergruppe"><small>${esc(gr.name)}</small>${ak.anbieter.filter((a) => a.gruppe === gr.id).map((a) => `<label class="anbieterzeile"><input type="checkbox" data-anbieter="${esc(a.url)}" data-name="${esc(a.name)}" ${e.upstream.some((x) => x.url === a.url) ? 'checked' : ''}><span><b>${esc(a.name)}</b> <span class="chip">${esc(a.land)}</span><small>${esc(a.beschreibung)}</small></span></label>`).join('')}</div>`).join('')}
        </details>
        <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap"><button class="knopf klein leise" id="upneu">+ Eigener Anbieter</button><button class="knopf klein leise" id="cacheleeren">Zwischenspeicher leeren</button><button class="knopf klein gruen" id="upspeichern" style="margin-left:auto">Speichern</button></div>
        ${info('Reihenfolge = Vorrang: Antwortet der erste Anbieter nicht, übernimmt der nächste automatisch. <b>Zwischenspeicher leeren</b> vergisst alle gemerkten Antworten – nur nötig, wenn eine Seite nach einer Umstellung beim Anbieter noch falsch auflöst.')}</div></section>
      <section class="karte"><div class="kartekopf">🌐 Netz</div><div class="kartekoerper" style="display:flex;flex-direction:column;gap:12px">
        <div class="feld"><label>DNS-Adresse dieses Blockers</label><div class="mono">${esc(u.dns.bind)}:${u.dns.port} (UDP/TCP)</div>${info('Diese Adresse tragen Geräte als DNS-Server ein – oder später UniFi automatisch per DHCP. Festgelegt in der .env auf dem NAS (DNS_BIND).')}</div>
        <div class="feld"><label for="enetze">Erlaubte Netze (eines je Zeile)</label><textarea id="enetze" rows="3">${esc(e.dns.erlaubteNetze.join('\n'))}</textarea>${info('Nur Geräte aus diesen IP-Bereichen dürfen FAH-Adblock fragen, alle anderen bekommen eine Absage. Das verhindert, dass der Blocker als offener DNS-Server missbraucht wird. Standard: Heimnetz 192.168.1.0/24, WireGuard-VPN 192.168.5.0/24 und das NAS selbst (127.0.0.1). Ein weiteres Netz (z. B. IoT 10.0.20.0/24) hier eintragen, wenn es auch gefiltert werden soll.')}</div>
        <div class="feld"><label for="egateway">Gateway</label><input id="egateway" type="text" value="${esc(e.dns.gateway)}">${info('Dein Router bzw. das UniFi-Gateway. Es kennt die Namen der Geräte im Heimnetz und lokale Einträge – Anfragen zu den lokalen Zonen gehen dorthin.')}</div>
        <div class="feld"><label for="ezonen">Lokale Zonen (eine je Zeile)</label><textarea id="ezonen" rows="4">${esc(e.dns.lokaleZonen.join('\n'))}</textarea>${info('Domain-Endungen, die <b>nicht im Internet</b>, sondern beim Gateway nachgefragt und <b>nie gefiltert</b> werden: Gerätenamen (.localdomain, .lan, .local), die Rückwärtsauflösung von IP-Adressen zu Namen (…in-addr.arpa) und example.org, das im Heimnetz direkt auf das NAS zeigt. Ohne diesen Eintrag würden solche Namen im Internet gesucht und nicht gefunden.')}</div>
        <div class="feld"><label for="erecords">Lokale Records · Split-Horizon (je Zeile: Name Leerzeichen IP)</label><textarea id="erecords" rows="3" placeholder="nextcloud.example.org 192.168.1.29">${esc((e.dns.lokaleRecords || []).map((r) => `${r.host} ${r.ip}`).join('\n'))}</textarea>${info('Lässt einzelne Namen im Heimnetz <b>und im VPN direkt auf eine interne IP</b> zeigen, statt über die WAN-IP – je Zeile: Name, Leerzeichen, interne IP, z. B. <code>nextcloud.example.org 192.168.1.29</code> (der Proxy). Ein <code>*</code> am Anfang gilt für <b>alle Subdomains</b> auf einmal, z. B. <code>*.example.org 192.168.1.29</code> – so brauchst du nicht jede Domain einzeln (exakte Zeilen gehen vor). Zusammen mit der Proxy-Schutzstufe „Nur Heimnetz + VPN" ist die Seite damit von außen gesperrt, für Heim- und VPN-Geräte aber direkt erreichbar. <b>Fürs VPN</b> muss das WireGuard-Gerät diesen Blocker als DNS nutzen (DNS = 192.168.1.29). Diese Namen werden nie gefiltert und nie ins Internet weitergereicht.')}</div>
        <div class="feld"><label><input id="esperrseite" type="checkbox" ${e.sperrseite?.an ? 'checked' : ''}> Sperrseite anzeigen</label>${info('Gesperrte Seiten zeigen statt einer Browser-Fehlermeldung den Hinweis „Diese Seite ist gesperrt“ mit Domain und Grund. Werbung und Tracker bleiben stumm geblockt. Braucht FAH-Proxy mit eingeschalteter Sperrseite. Ohne installiertes Zertifikat warnt der Browser vor der Hinweisseite.')}${u.sperrseite?.zertifikat ? '<a class="knopf klein" href="/sperrseite/zertifikat.crt" style="align-self:flex-start;margin-top:6px">Zertifikat für Geräte laden</a>' : ''}</div>
        <div class="feld"><label for="eproxys">Vertraute Proxys (einer je Zeile)</label><textarea id="eproxys" rows="2" placeholder="z. B. 172.16.0.0/12">${esc((e.web?.vertrauteProxies || []).join('\n'))}</textarea>${info(`Nur wichtig, wenn diese Oberfläche über einen Reverse-Proxy (z. B. Nginx Proxy Manager) erreichbar ist: Dann sieht FAH-Adblock bei jeder Anmeldung nur die Adresse des Proxys – 10 Fehlversuche eines Bots würden die Anmeldung <b>für alle</b> 15 Minuten sperren. Steht hier die Adresse oder das Netz des Proxys (Docker-Container meist 172.16.0.0/12), zählt die Anmeldebremse je echter Absenderadresse aus X-Forwarded-For. Leer = aus. Unabhängig davon bremst FAH-Adblock je Nutzername mit steigender Wartezeit. <b>Diese Anfrage kam von ${esc(e.verbindung?.adresse || '?')}${e.verbindung?.weitergeleitet?.length ? `, weitergeleitet für ${esc(e.verbindung.weitergeleitet.join(' → '))}` : ''}${e.verbindung?.proxy ? ` – Proxy erkannt, die Bremse zählt ${esc(e.verbindung.client)}` : ''}.</b>`)}</div>
        <div class="feld"><label for="etage">Protokoll aufbewahren (Tage)</label><input id="etage" type="number" min="1" max="90" value="${e.protokoll.tage}">${info(`Wie lange jede einzelne Anfrage im Protokoll und in der Rettung bleibt. Die Stundensummen der Statistik bleiben 35 Tage. Mehr Tage = größere Datenbank (derzeit ${bytes(u.protokoll.groesse)}).`)}</div>
        <button class="knopf gruen klein" id="netzspeichern" style="align-self:flex-end">Speichern</button></div></section>
      <section class="karte"><div class="kartekopf">📡 UniFi (Gerätenamen)</div><div class="kartekoerper" style="display:flex;flex-direction:column;gap:12px">
        <div class="feld"><label for="uurl">Adresse</label><input id="uurl" type="text" placeholder="https://192.168.1.1" value="${esc(e.unifi.url)}"></div>
        <div class="feld"><label for="ukey">API-Schlüssel ${e.unifi.schluesselGesetzt ? '<span class="chip gruen">gesetzt</span>' : ''}</label><input id="ukey" type="password" placeholder="${e.unifi.schluesselGesetzt ? 'leer lassen = unverändert' : 'UniFi → Einstellungen → Control Plane → Integrationen'}" autocomplete="off"></div>
        ${info(`Nur lesend: FAH-Adblock holt alle 5 Minuten die Clientliste von UniFi. Dadurch stehen statt IP-Adressen Gerätenamen in der Oberfläche, und Profile hängen an der MAC-Adresse – sie bleiben also erhalten, wenn ein Gerät eine neue IP bekommt. An UniFi wird nichts verändert. ${u.geraete.unifi.stand ? `<b>Zuletzt ${vor(u.geraete.unifi.stand)} · ${u.geraete.unifi.geraete} Geräte gelesen.</b>` : esc(u.geraete.unifi.fehler || '')}`)}
        <div style="display:flex;gap:8px;justify-content:flex-end"><button class="knopf klein leise" id="utest">Verbindung testen</button><button class="knopf klein gruen" id="uspeichern">Speichern</button></div></div></section>
      ${sp ? spiegelKarte(sp) : ''}
      <section class="karte"><div class="kartekopf">👤 Konto & Sicherung</div><div class="kartekoerper" style="display:flex;flex-direction:column;gap:12px">
        ${info('Passwort für diese Weboberfläche (Name: admin). Nach einem Passwortwechsel und beim <b>Abmelden</b> sind alle anderen angemeldeten Browser ebenfalls abgemeldet.')}<form id="pwform" style="display:flex;flex-direction:column;gap:10px"><div class="feld"><label for="pwalt">Bisheriges Passwort</label><input id="pwalt" type="password" autocomplete="current-password" required></div>
        <div class="feld"><label for="pwneu">Neues Passwort (mind. 8 Zeichen)</label><input id="pwneu" type="password" autocomplete="new-password" minlength="8" required></div><button class="knopf gruen klein" type="submit" style="align-self:flex-end">Passwort ändern</button></form>
        <div style="border-top:1px solid var(--rand);padding-top:12px;display:flex;gap:8px;flex-wrap:wrap"><a class="knopf klein" href="/api/sicherung" download>⬇ Sicherung herunterladen</a><label class="knopf klein leise" style="cursor:pointer">⬆ Wiederherstellen<input type="file" id="wiederherstellen" accept="application/json" hidden></label><button class="knopf klein leise" id="abmelden" style="margin-left:auto">Abmelden</button></div>${info('<b>Sicherung</b> speichert Einstellungen, Listen, Profile, Geräte und Regeln als Datei – ohne Passwort und UniFi-Schlüssel. <b>Wiederherstellen</b> spielt eine solche Datei wieder ein, z. B. nach einer Neuinstallation – sie wird vorher vollständig geprüft, eine beschädigte Datei wird abgelehnt und nichts übernommen.')}
        <small style="color:var(--muted)">Version ${esc(u.version)} · DNS-Anfragen seit Start ${zahl(u.dns.zaehler.anfragen)} · abgewiesen ${zahl(u.dns.zaehler.abgewiesen)} · Fehler ${zahl(u.dns.zaehler.fehler)}</small></div></section></div>`;
    $('#upneu').onclick = () => $('#upstreamliste').insertAdjacentHTML('beforeend', upstreamZeile({ name: '', url: 'https://' }, $$('.upzeile').length));
    const upNummern = () => $$('.upzeile').forEach((z, i) => { z.querySelector('.upnr').textContent = i + 1; });
    $('#upstreamliste').onclick = (ev) => {
      const zeile = ev.target.closest('.upzeile'); if (!zeile) return;
      if (ev.target.closest('[data-upweg]')) { const url = zeile.querySelector('[data-upurl]').value; zeile.remove(); const h = $(`[data-anbieter="${CSS.escape(url)}"]`); if (h) h.checked = false; }
      else if (ev.target.closest('[data-uprauf]') && zeile.previousElementSibling) zeile.parentNode.insertBefore(zeile, zeile.previousElementSibling);
      else if (ev.target.closest('[data-uprab]') && zeile.nextElementSibling) zeile.parentNode.insertBefore(zeile.nextElementSibling, zeile);
      else return;
      upNummern();
    };
    $$('[data-anbieter]').forEach((h) => { h.onchange = () => {
      const url = h.dataset.anbieter;
      if (h.checked) { if (!$$('.upzeile').some((z) => z.querySelector('[data-upurl]').value === url)) $('#upstreamliste').insertAdjacentHTML('beforeend', upstreamZeile({ name: h.dataset.name, url }, $$('.upzeile').length)); }
      else $$('.upzeile').filter((z) => z.querySelector('[data-upurl]').value === url).forEach((z) => z.remove());
      upNummern();
      toast('Nicht vergessen: „Speichern“ unten');
    }; });
    $('#upspeichern').onclick = async () => { try { await api('/api/einstellungen', { methode: 'PUT', daten: { upstream: $$('.upzeile').map((z) => ({ name: z.querySelector('[data-upname]').value, url: z.querySelector('[data-upurl]').value })) } }); toast('Anbieter gespeichert'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
    $('#cacheleeren').onclick = async () => { await api('/api/cache/leeren', { methode: 'POST', daten: {} }).catch(() => {}); toast('Zwischenspeicher geleert'); };
    $('#esperrseite').onchange = async (ev) => { try { await api('/api/einstellungen', { methode: 'PUT', daten: { sperrseite: { an: ev.target.checked } } }); toast(ev.target.checked ? 'Sperrseite an' : 'Sperrseite aus'); } catch (err) { ev.target.checked = !ev.target.checked; toast(err.message, 'fehler'); } };
    $('#netzspeichern').onclick = async () => { try { const lokaleRecords = $('#erecords').value.split('\n').map((z) => z.trim().split(/\s+/)).filter((p) => p.length >= 2 && p[0] && p[1]).map((p) => ({ host: p[0], ip: p[1] })); await api('/api/einstellungen', { methode: 'PUT', daten: { dns: { erlaubteNetze: $('#enetze').value.split(/\s+/).filter(Boolean), gateway: $('#egateway').value.trim(), lokaleZonen: $('#ezonen').value.split(/\s+/).filter(Boolean), lokaleRecords }, protokoll: { tage: +$('#etage').value }, web: { vertrauteProxies: $('#eproxys').value.split(/\s+/).filter(Boolean) } } }); toast('Gespeichert'); } catch (err) { toast(err.message, 'fehler'); } };
    $('#uspeichern').onclick = async () => { try { await api('/api/einstellungen/unifi', { methode: 'POST', daten: { url: $('#uurl').value.trim(), schluessel: $('#ukey').value.trim() } }); toast('UniFi gespeichert'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
    $('#utest').onclick = async () => { try { const r = await api('/api/einstellungen/unifi/test', { methode: 'POST', daten: {} }); toast(r.ok ? `✓ ${r.geraete} Geräte gelesen` : `✗ ${r.fehler}`, r.ok ? 'ok' : 'fehler'); } catch (err) { toast(err.message, 'fehler'); } };
    $('#pwform').onsubmit = async (ev) => { ev.preventDefault(); try { await api('/api/passwort', { methode: 'POST', daten: { alt: $('#pwalt').value, neu: $('#pwneu').value } }); S.ich = await api('/api/ich'); toast('Passwort geändert'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
    $('#abmelden').onclick = async () => { await api('/api/abmelden', { methode: 'POST', daten: {} }).catch(() => {}); S.ich = null; zeigeAnmeldung(); };
    spiegelKnoepfe();
    $('#wiederherstellen').onchange = async (ev) => {
      const datei = ev.target.files[0]; if (!datei) return;
      try { const j = JSON.parse(await datei.text()); if (!confirm('Einstellungen, Listen, Profile, Geräte und Regeln aus der Sicherung übernehmen?')) return; await api('/api/wiederherstellung', { methode: 'POST', daten: j }); toast('Sicherung eingespielt'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); }
    };
  }
  // Haupt & Ersatz: zwei Blocker filtern gleich, Geräte bekommen beide per DHCP und weichen bei einem Ausfall selbst aus.
  // Koppeln von EINER Oberfläche aus (09.10.2026): Rolle wählen, Adresse + Konto des Partners – beide richten sich selbst ein.
  function spiegelForm(sp, { rolle = 'ersatz', url = '' } = {}) {
    return `<div style="display:flex;flex-direction:column;gap:10px">
      <div class="feld"><label for="sprolle">Diese Instanz wird</label><select id="sprolle"><option value="haupt"${rolle === 'haupt' ? ' selected' : ''}>Haupt – hier wird eingestellt</option><option value="ersatz"${rolle === 'ersatz' ? ' selected' : ''}>Ersatz – übernimmt alles vom Haupt</option></select>${info('Der Partner bekommt automatisch die andere Rolle.')}</div>
      <div class="feld"><label for="sppurl">Adresse des Partners</label><input id="sppurl" type="text" value="${esc(url)}" placeholder="http://192.168.1.23:8053">${info('Die FAH-Adblock-Oberfläche der anderen Instanz.')}</div>
      <div class="feld"><label for="speigen">Adresse dieser Instanz</label><input id="speigen" type="text" value="${esc(sp.eigene_url || location.origin)}">${info('So erreicht der Partner diese Instanz – meist schon richtig vorbelegt.')}</div>
      <div class="feld"><label for="spname">Name beim Partner</label><input id="spname" type="text" autocomplete="off" autocapitalize="none" spellcheck="false"></div>
      <div class="feld"><label for="sppw">Passwort beim Partner</label><input id="sppw" type="password" autocomplete="off">${info('Nur für das Koppeln, wird nicht gespeichert.')}</div>
      <button class="knopf klein gruen" id="spkoppeln" style="align-self:flex-end">Koppeln</button></div>`;
  }
  function spiegelKarte(sp) {
    const kopf = '<section class="karte"><div class="kartekopf">🔁 Haupt & Ersatz (Fail-over)</div><div class="kartekoerper" style="display:flex;flex-direction:column;gap:12px">';
    const codeWeg = `<details><summary>Mit Kopplungscode (ohne Passwort des Partners)</summary><div style="display:flex;flex-direction:column;gap:10px;margin-top:10px">
        ${sp.rolle === 'ersatz' ? '' : '<div id="spcode"></div><button class="knopf klein leise" id="sphaupt" style="align-self:flex-end">Diese Instanz wird Haupt – Code zeigen</button>'}
        ${sp.rolle === 'haupt' ? '' : `<div class="feld"><label for="spurl">Adresse des Haupts</label><input id="spurl" type="text" placeholder="http://192.168.1.29:8053"></div>
        <div class="feld"><label for="spcodeein">Kopplungscode</label><input id="spcodeein" type="text" autocomplete="off">${info('Achtung: die Einstellungen dieser Instanz werden durch die des Haupts ersetzt.')}</div>
        <button class="knopf klein" id="spersatz" style="align-self:flex-end">Als Ersatz koppeln</button>`}</div></details>`;
    const tauschen = sp.partner_url ? '<button class="knopf klein leise" id="sptausch">Rollen tauschen</button>' : '';
    if (sp.rolle === 'haupt') return `${kopf}${info('Diese Instanz ist der <b>Haupt</b>. Der Ersatz holt sich alle 2 Minuten ihre Einstellungen und filtert genauso.')}
      <div class="mono">${sp.ersatz ? `Ersatz ${esc(sp.ersatz.url || sp.ersatz.ip || '')}${sp.ersatz.zeit ? ` hat zuletzt ${vor(sp.ersatz.zeit)} abgeholt` : ' – noch nicht abgeholt'}` : 'Noch kein Ersatz gekoppelt'}</div>
      <div style="display:flex;gap:8px;justify-content:flex-end">${tauschen}<button class="knopf klein leise" id="sploesen">Kopplung lösen</button></div>
      <div id="spformhuelle"></div>${codeWeg}</div></section>`;
    if (sp.rolle === 'ersatz') return `${kopf}${info('Diese Instanz ist der <b>Ersatz</b> und übernimmt die Einstellungen des Haupts. UniFi-Zugang, Protokoll und Statistik bleiben getrennt.')}
      <div class="mono">Haupt: ${esc(sp.haupt_url)} · abgeglichen ${vor(sp.letzter_abgleich)}${sp.letzte_aenderung ? ` · zuletzt geändert ${vor(sp.letzte_aenderung)}` : ''}</div>
      ${sp.fehler ? `<div class="chip rot">⚠ ${esc(sp.fehler)}</div>` : ''}
      <div style="display:flex;gap:8px;justify-content:flex-end">${tauschen}<button class="knopf klein leise" id="sploesen">Kopplung lösen</button><button class="knopf klein" id="spjetzt">Jetzt abgleichen</button></div>
      <div id="spformhuelle"></div></div></section>`;
    return `${kopf}${info('Zwei Blocker für Ausfallsicherheit: Der <b>Haupt</b> wird eingestellt, der <b>Ersatz</b> übernimmt alles automatisch. In UniFi dann beide als DNS-Server eintragen.')}
      <div id="spformhuelle">${spiegelForm(sp)}</div>${codeWeg}</div></section>`;
  }
  function spiegelKnoepfe() {
    const sp = S.spiegel || {};
    const koppelnBinden = () => {
      if (!$('#spkoppeln')) return;
      $('#spkoppeln').onclick = async () => {
        const haupt = $('#sprolle').value === 'haupt';
        if (!confirm(haupt ? 'Diese Instanz wird Haupt, der Partner Ersatz. Ist diese Instanz noch leer (frisch installiert), holt sie sich vorher die Einstellungen des Partners. Koppeln?'
          : 'Diese Instanz wird Ersatz und übernimmt die Einstellungen des Partners. Ist der Partner noch leer, bekommt er vorher die Einstellungen von hier. Koppeln?')) return;
        $('#spkoppeln').disabled = true;
        try {
          const r = await api('/api/spiegel/partner', { methode: 'POST', daten: { rolle: $('#sprolle').value, url: $('#sppurl').value.trim(), eigene_url: $('#speigen').value.trim(), name: $('#spname').value.trim(), passwort: $('#sppw').value, bestaetigt: true } });
          S.ich = await api('/api/ich');
          toast(`✓ Gekoppelt – diese Instanz ist ${r.rolle === 'haupt' ? 'Haupt' : 'Ersatz'}${r.uebernommen ? `, Einstellungen ${r.uebernommen} übernommen` : ''}`);
          zeigeEinstellungen();
        } catch (err) { toast(err.message, 'fehler'); $('#spkoppeln').disabled = false; }
      };
    };
    koppelnBinden();
    if ($('#sptausch')) $('#sptausch').onclick = () => { $('#spformhuelle').innerHTML = `<div class="kartekopf" style="padding:0;border:0">Rollen tauschen</div>${spiegelForm(sp, { rolle: sp.rolle === 'haupt' ? 'ersatz' : 'haupt', url: sp.partner_url || '' })}`; koppelnBinden(); $('#spname').focus(); };
    const neu = async () => { if (!confirm('Neuen Kopplungscode erzeugen? Ein bereits gekoppelter Ersatz braucht dann den neuen Code.')) return; try { const r = await api('/api/spiegel/haupt', { methode: 'POST', daten: {} }); $('#spcode').innerHTML = `<div class="feld"><label>Kopplungscode – nur jetzt sichtbar, am Ersatz eingeben</label><div class="mono" style="user-select:all">${esc(r.code)}</div></div>`; toast('Kopplungscode erzeugt'); } catch (err) { toast(err.message, 'fehler'); } };
    if ($('#sphaupt')) $('#sphaupt').onclick = neu;
    if ($('#sploesen')) $('#sploesen').onclick = async () => { if (!confirm('Kopplung lösen? Diese Instanz arbeitet danach allein.')) return; try { await api('/api/spiegel/loesen', { methode: 'POST', daten: {} }); S.ich = await api('/api/ich'); toast('Kopplung gelöst'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
    if ($('#spjetzt')) $('#spjetzt').onclick = async () => { try { const r = await api('/api/spiegel/abgleichen', { methode: 'POST', daten: {} }); toast(r.fehler ? `✗ ${r.fehler}` : '✓ Abgeglichen', r.fehler ? 'fehler' : 'ok'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
    if ($('#spersatz')) $('#spersatz').onclick = async () => { if (!confirm('Diese Instanz als Ersatz koppeln? Ihre Einstellungen werden durch die des Haupts ersetzt.')) return; try { await api('/api/spiegel/ersatz', { methode: 'POST', daten: { url: $('#spurl').value.trim(), code: $('#spcodeein').value.trim() } }); S.ich = await api('/api/ich'); toast('Als Ersatz gekoppelt'); zeigeEinstellungen(); } catch (err) { toast(err.message, 'fehler'); } };
  }
  const upstreamZeile = (a, i, st) => `<div class="upzeile formzeile" style="margin-bottom:8px"><div class="uprang"><button class="knopf klein leise" data-uprauf title="nach oben">▲</button><span class="upnr">${i + 1}</span><button class="knopf klein leise" data-uprab title="nach unten">▼</button></div><div class="feld" style="flex:0 1 120px"><label>Name</label><input type="text" data-upname value="${esc(a.name)}"></div><div class="feld"><label>DoH-Adresse ${st?.ms != null ? `<span class="chip gruen">${st.ms} ms</span>` : ''}${st?.fehler ? `<span class="chip rot" title="${esc(st.letzterFehler || '')}">Fehler</span>` : ''}</label><input type="url" data-upurl value="${esc(a.url)}"></div><button class="knopf klein leise" data-upweg aria-label="entfernen">✕</button></div>`;

  // ── Optionale Erweiterungen (Skripte unter erweiterungen/<name>.js, nur wenn der Server sie nennt) ──
  const ERWEITERUNGEN = new Map();
  window.FAH = Object.freeze({ api, esc, info, toast, vor, zahl, hinweisDialog, $, $$, registriere: (name, teile) => { if (/^[a-z0-9-]{1,40}$/.test(name) && teile && typeof teile === 'object') ERWEITERUNGEN.set(name, teile); } });
  async function ladeErweiterungsSkripte() {
    await Promise.all((S.ich?.erweiterungen || []).filter((n) => /^[a-z0-9-]{1,40}$/.test(n) && !document.querySelector(`script[data-erw="${n}"]`)).map((n) => new Promise((fertig) => {
      const sk = document.createElement('script'); sk.src = `erweiterungen/${n}.js?v=${encodeURIComponent(S.ich.version || '')}`; sk.defer = true; sk.dataset.erw = n;
      sk.onload = sk.onerror = () => fertig(); setTimeout(fertig, 8000); document.head.appendChild(sk);
    })));
  }
  function erweiterungenKinderschutz() {
    const raster = $('#haupt .raster'); if (!raster) return;
    for (const [name, teile] of ERWEITERUNGEN) {
      if (typeof teile.kinderschutz !== 'function') continue;
      const el = document.createElement('section'); el.className = 'karte'; el.dataset.erw = name; raster.appendChild(el);
      Promise.resolve().then(() => teile.kinderschutz(el)).catch((err) => { el.innerHTML = `<div class="kartekopf">${esc(name)}</div><div class="kartekoerper fehlertext">${esc(err.message)}</div>`; });
    }
  }

  // ── Start ──────────────────────────────────────────────────────────────────
  async function start() {
    try { S.ich = await api('/api/ich'); } catch (e) { return; }
    await ladeErweiterungsSkripte();
    stoppeAlles(); rahmen();
    window.onhashchange = route;
    await ladeUebersicht();
    liveVerbinden();
    route();
    S.timer.push(setInterval(() => { if (!document.hidden) ladeUebersicht(); }, 5000));
    S.timer.push(setInterval(() => { if (document.hidden) return; if (S.ansicht === 'geraete' && !$('.seitenleiste')) zeigeGeraete(); if (S.ansicht === 'schild') { ladeUebersicht(); topGeblockt(); } }, 20000));   // Kennzahlen und Plakette laufen mit (vorher nur beim Ansichtswechsel)
  }
  start();
})();
