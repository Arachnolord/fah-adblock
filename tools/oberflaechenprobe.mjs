#!/usr/bin/env node
// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// ============================================================================
// Oberflächenprobe: bedient FAH-Adblock in einem echten Chrome (DevTools-Protokoll, ohne
// Puppeteer) – Anmeldung, Schutzschild mit Live-Verkehr, Pause, Geräte + Rettung (Freigabe wirkt
// wirklich im DNS), Protokoll, Listen/Regeln/Domain prüfen, Profile, Statistik, Einstellungen,
// Handybreite, helles Design, keine JS-/CSP-Fehler. Screenshots im Ausgabeordner.
// Aufruf: node tools/oberflaechenprobe.mjs --basis=http://127.0.0.1:8054 --dns=127.0.0.1 --dnsport=5354
//         [--passwort=admin] [--ausgabe=/tmp] [--chrome=/Pfad/zu/Chrome]
import { spawn } from 'node:child_process';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const dnsPacket = require('dns-packet');

const warte = (ms) => new Promise((f) => setTimeout(f, ms));
const arg = Object.fromEntries(process.argv.slice(2).map((a) => { const m = /^--([^=]+)=(.*)$/.exec(a); return m ? [m[1], m[2]] : [a.replace(/^--/, ''), true]; }));
const BASIS = arg.basis || 'http://127.0.0.1:8054', DNS = arg.dns || '127.0.0.1', DNSPORT = +arg.dnsport || 53, PASSWORT = arg.passwort || 'admin';
const CHROME = arg.chrome || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', AUSGABE = arg.ausgabe || os.tmpdir();
const ergebnisse = [];
const pruefe = (name, ok, detail = '') => { ergebnisse.push(!!ok); console.log(`${ok ? 'OK  ' : 'FEHL'} ${name}${detail ? ' – ' + detail : ''}`); };

function dns(name, type = 'A') {
  return new Promise((ok) => {
    const s = dgram.createSocket('udp4'); const uhr = setTimeout(() => { s.close(); ok(null); }, 3000);
    s.on('message', (m) => { clearTimeout(uhr); s.close(); ok(dnsPacket.decode(m)); });
    s.send(dnsPacket.encode({ type: 'query', id: Math.floor(Math.random() * 60000), flags: dnsPacket.RECURSION_DESIRED, questions: [{ type, name }] }), DNSPORT, DNS);
  });
}
// Zufällige Subdomain: an keinem Zwischenspeicher (Betriebssystem, Sicherheitssoftware) vorbei beantwortet; Listen gelten für Subdomains
const frisch = (domain) => `p${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}.${domain}`;
const geblocktDns = async (domain) => (await dns(frisch(domain)))?.answers?.some((a) => a.data === '0.0.0.0' || a.data === '::');
// Eigene Adresse, mit der dieser Rechner den DNS-Server erreicht (für die richtige Gerätekarte)
const eigeneIp = () => new Promise((ok) => { const s = dgram.createSocket('udp4'); s.connect(DNSPORT, DNS, () => { ok(s.address().address); s.close(); }); });
const freierPort = () => new Promise((f) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => f(p)); }); });
async function verbinde(port) {
  let seite;
  for (let i = 0; i < 40 && !seite; i++) { try { seite = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((z) => z.type === 'page'); } catch { } if (!seite) await warte(250); }
  if (!seite) throw new Error('Chrome hat sich nicht gemeldet.');
  const ws = new WebSocket(seite.webSocketDebuggerUrl);
  await new Promise((f, x) => { ws.onopen = f; ws.onerror = x; });
  let id = 0; const offen = new Map(); const ereignisse = [];
  ws.onmessage = (e) => { const n = JSON.parse(e.data); if (n.id && offen.has(n.id)) { offen.get(n.id)(n); offen.delete(n.id); } else if (n.method) ereignisse.push(n); };
  const cdp = (methode, params = {}) => new Promise((f) => { const i = ++id; offen.set(i, f); ws.send(JSON.stringify({ id: i, method: methode, params })); });
  const js = async (ausdruck) => { const r = await cdp('Runtime.evaluate', { expression: ausdruck, awaitPromise: true, returnByValue: true }); if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'JS-Fehler'); return r.result?.result?.value; };
  return { cdp, js, ereignisse, schliesse: () => ws.close() };
}
async function klicke(s, selektor) {
  for (let v = 0; v < 20; v++) {
    const p = await s.js(`(() => { const e = document.querySelector(${JSON.stringify(selektor)}); if (!e) return null; e.scrollIntoView({block:'center'}); const r = e.getBoundingClientRect(); const x = r.left + r.width/2, y = r.top + r.height/2; const g = document.elementFromPoint(x, y); return { x, y, bereit: g === e || e.contains(g) }; })()`);
    if (p?.bereit) { for (const type of ['mousePressed', 'mouseReleased']) await s.cdp('Input.dispatchMouseEvent', { type, x: p.x, y: p.y, button: 'left', buttons: type === 'mousePressed' ? 1 : 0, clickCount: 1 }); return; }
    await warte(250);
  }
  throw new Error(`Element fehlt oder ist verdeckt: ${selektor}`);
}
async function tippe(s, selektor, text) { await s.js(`(() => { const e = document.querySelector(${JSON.stringify(selektor)}); e.focus(); e.value = ''; return 1; })()`); await s.cdp('Input.insertText', { text }); }
async function wartAuf(s, ausdruck, ms = 15000) { const ende = Date.now() + ms; let v; while (Date.now() < ende) { try { v = await s.js(ausdruck); } catch (e) { v = null; } if (v) return v; await warte(300); } return v; }
async function foto(s, name) { const r = await s.cdp('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(AUSGABE, name), Buffer.from(r.result.data, 'base64')); }

async function main() {
  const port = await freierPort(), profil = fs.mkdtempSync(path.join(os.tmpdir(), 'fah-adblock-ui-'));
  const chrome = spawn(CHROME, ['--headless=new', '--use-mock-keychain', '--hide-scrollbars', `--remote-debugging-port=${port}`, `--user-data-dir=${profil}`, 'about:blank'], { stdio: 'ignore' });
  const s = await verbinde(port);
  let verkehr = null;
  try {
    await s.cdp('Runtime.enable'); await s.cdp('Page.enable'); await s.cdp('Log.enable');
    await s.cdp('Emulation.setDeviceMetricsOverride', { width: 1440, height: 950, deviceScaleFactor: 1, mobile: false });
    await s.cdp('Page.navigate', { url: BASIS + '/' });
    pruefe('Anmeldeseite erscheint', await wartAuf(s, "!!document.querySelector('#anmeldeform')"));
    await tippe(s, '#an-pw', 'falsch'); await klicke(s, '#anmeldeform button[type=submit]');
    pruefe('Falsches Passwort wird abgelehnt', await wartAuf(s, "/falsch/.test(document.querySelector('.fehlertext')?.textContent || '')"));
    await tippe(s, '#an-pw', PASSWORT); await klicke(s, '#anmeldeform button[type=submit]');
    pruefe('Anmeldung → Schutzschild mit Kennzahlen', await wartAuf(s, "document.querySelectorAll('#kennzahlen .kz').length === 5 && !!document.querySelector('#buehnencanvas')"));
    // Zeitraum-Schalter (17.09.): Kennzahlen und „Meistgeblockt" für 24 h / 7 Tage / 1 Monat
    pruefe('Schutzschild: Zeitraum-Schalter 24 h / 7 Tage / 1 Monat vorhanden', (await s.js("document.querySelectorAll('[data-schildstunden]').length")) === 3);
    await s.js("document.querySelector('[data-schildstunden=\"168\"]').click(); 1");
    pruefe('Schutzschild: gewählter Zeitraum ist farblich hervorgehoben (andere Hintergrundfarbe als die übrigen Knöpfe)', await wartAuf(s, "(() => { const a = document.querySelector('[data-schildstunden=\"168\"]'), b = document.querySelector('[data-schildstunden=\"24\"]'); return getComputedStyle(a).backgroundColor !== getComputedStyle(b).backgroundColor && getComputedStyle(a).backgroundColor !== 'rgba(0, 0, 0, 0)'; })()", 3000));
    pruefe('Schutzschild: „7 Tage" schaltet Kennzahlen und Liste um', await wartAuf(s, "document.querySelector('#topzeitraum')?.textContent === '7 Tage' && /7 Tage/.test(document.querySelector('#kennzahlen .kz .name')?.textContent || '') && document.querySelector('[data-schildstunden=\"168\"]').getAttribute('aria-pressed') === 'true'", 8000));
    await s.js("document.querySelector('[data-schildstunden=\"720\"]').click(); 1");
    pruefe('Schutzschild: „1 Monat" nennt die Aufbewahrungsgrenze des Protokolls', await wartAuf(s, "/aufbewahrt/.test(document.querySelector('#topgeblockthinweis')?.textContent || '')", 8000));
    await s.js("document.querySelector('[data-schildstunden=\"24\"]').click(); 1"); await warte(500);
    // Reste früherer Läufe entfernen (Freigaben der Testdomains, Pausen)
    await s.js(`(async () => { const ich = await (await fetch('/api/ich')).json(); const h = { 'x-csrf': ich.csrf, 'Content-Type': 'application/json' };
      for (const r of await (await fetch('/api/regeln')).json()) if (/doubleclick|googleadservices|facebook|googlesyndication|app-measurement|bet365/.test(r.muster)) await fetch('/api/regeln/' + r.id, { method: 'DELETE', headers: h, body: '{}' });
      await fetch('/api/pause', { method: 'POST', headers: h, body: JSON.stringify({ minuten: 0 }) }); return 1; })()`);
    // Verkehr erzeugen: erlaubt + geblockt, laufend
    const namen = ['doubleclick.net', 'wikipedia.org', 'googleadservices.com', 'heise.de', 'pagead2.googlesyndication.com', 'github.com', 'app-measurement.com', 'apple.com'];
    let i = 0; verkehr = setInterval(() => { dns(namen[i++ % namen.length]); }, 120);
    const geblockt = await wartAuf(s, "document.querySelectorAll('#geblocktliste .zeile').length", 20000);
    pruefe('Live: „Gerade geblockt“ füllt sich aus dem Livestrom', geblockt > 0, `${geblockt} Zeilen`);
    const bewegt = await s.js(`(async () => { const c = document.getElementById('buehnencanvas'), g = c.getContext('2d'); const bild = () => { const d = g.getImageData(0, 0, c.width, c.height).data; let h = 0; for (let i = 0; i < d.length; i += 97) h = (h * 31 + d[i]) >>> 0; return h; }; const a = bild(); await new Promise(r => setTimeout(r, 700)); return a !== bild(); })()`);
    pruefe('Schutzschild-Bühne animiert (Bild ändert sich)', bewegt);
    // Kennzahlen laufen mit (v24): ohne Ansichtswechsel müssen die Zahlen oben binnen 20 s die DNS-Anfragen zeigen
    pruefe('Schutzschild: Kennzahlen aktualisieren sich von selbst (20-s-Takt)', await wartAuf(s, "parseInt((document.querySelector('#kennzahlen .kz .wert')?.textContent || '0').replace(/\\D/g, ''), 10) > 0", 26000));
    await warte(1500); await foto(s, 'ui-schild.png');
    pruefe('Hinweis auf Startpasswort sichtbar', await s.js("/Startpasswort/.test(document.querySelector('.hinweisband')?.textContent || '')"));
    // Pause global
    await klicke(s, '#pauseknopf'); await klicke(s, '[data-pause="5"]');
    pruefe('Pause 5 min: Kopf zeigt „pausiert“, DNS liefert Werbung ungefiltert', await wartAuf(s, "document.getElementById('statuspille').classList.contains('pause')") && !(await geblocktDns('doubleclick.net')));
    await klicke(s, '#pauseknopf'); await klicke(s, '[data-pause="0"]');
    pruefe('Schutz wieder an: Werbung wieder geblockt', await wartAuf(s, "!document.getElementById('statuspille').classList.contains('pause')") && await geblocktDns('doubleclick.net'));
    // Geräte + Rettung
    await klicke(s, '.navi [data-ansicht="geraete"]');
    pruefe('Geräte: Karte für das Testgerät mit Kurve und Zahlen', await wartAuf(s, "document.querySelectorAll('#geraeteraster .geraet').length > 0 && !!document.querySelector('#geraeteraster canvas')", 15000));
    await foto(s, 'ui-geraete.png');
    const ich = await eigeneIp();
    await s.js(`document.getElementById('geraetsuche').value = ${JSON.stringify(ich)}; document.getElementById('geraetsuche').dispatchEvent(new Event('input')); 1`);
    await wartAuf(s, `document.querySelectorAll('#geraeteraster .geraet').length === 1 && document.querySelector('#geraeteraster .geraet small').textContent.includes(${JSON.stringify(ich)})`, 8000);
    await klicke(s, '#geraeteraster .geraet [data-rettung]');
    const rettung = await wartAuf(s, "[...document.querySelectorAll('.rettungzeile .dom')].map(d => d.textContent).join(',')", 12000);
    pruefe('Rettung: Seitenleiste listet die zuletzt geblockten Domains', /doubleclick\.net/.test(rettung || ''), rettung);
    await foto(s, 'ui-rettung.png');
    await klicke(s, '.rettungzeile[data-domain="doubleclick.net"] [data-frei="60"]');
    await wartAuf(s, "!document.querySelector('.rettungzeile[data-domain=\"doubleclick.net\"]')", 5000);
    await warte(400);
    pruefe('Rettung „Freigeben · 1 h“ wirkt sofort im DNS (auch für Subdomains)', !(await geblocktDns('doubleclick.net')));
    await klicke(s, '.seitenleiste [data-zu]');
    // Protokoll
    await klicke(s, '.navi [data-ansicht="protokoll"]');
    pruefe('Protokoll: Tabelle mit Einträgen', await wartAuf(s, "document.querySelectorAll('#ptabelle tr[data-domain]').length > 5"));
    await klicke(s, '#pgeblockt + span'); await warte(800);
    pruefe('Protokoll: Filter „nur geblockt“', await wartAuf(s, "(() => { const r = [...document.querySelectorAll('#ptabelle tr[data-domain]')]; return r.length > 0 && r.every(z => /geblockt/.test(z.textContent)); })()"));
    // Listen & Regeln
    await klicke(s, '.navi [data-ansicht="listen"]');
    pruefe('Listen: Blocklisten und Freigabelisten (mit Beschreibung und Erklärung)', await wartAuf(s, "document.querySelectorAll('[data-liste]').length >= 12 && /Freigabelisten/.test(document.getElementById('haupt').textContent) && /nur Sperren der Kategorie Werbung/.test(document.getElementById('haupt').textContent) && document.querySelectorAll('.listenkarte .beschreibung').length >= 12"));
    // Manuelle Freigabe gilt für alle Kategorien: Glücksspiel-Domain (im Standard gesperrt) wird erlaubt
    // Glücksspiel im Standard-Profil vorübergehend sperren (Ausgangslage unabhängig von der Konfiguration)
    const vorherProfil = await s.js(`(async () => { const ich = await (await fetch('/api/ich')).json(); const pr = await (await fetch('/api/profile')).json(); const st = pr.profile.find(p => p.id === 'standard');
      const neu = { ...st.kategorien, gluecksspiel: { an: true, zeitplan: [] } };
      await fetch('/api/profile/standard', { method: 'PUT', headers: { 'x-csrf': ich.csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ kategorien: neu }) }); return JSON.stringify(st.kategorien); })()`);
    const gluecks = await s.js(`(async () => { const r = await (await fetch('/api/pruefen?domain=bet365.com')).json(); return r.aktion; })()`);
    await s.js("document.getElementById('rtyp').value = 'erlauben'; document.getElementById('rgeltung').value = 'alle'; document.getElementById('rdauer').value = '0'; 1");
    await tippe(s, '#rmuster', 'bet365.com'); await klicke(s, '#regelform button[type=submit]');
    await wartAuf(s, "[...document.querySelectorAll('.zeilen b.mono')].some(b => b.textContent === 'bet365.com')", 6000);
    const ort = await s.js("(() => { const k = [...document.querySelectorAll('.karte')]; const frei = k.find((x) => /Freigabelisten/.test(x.querySelector('.kartekopf')?.textContent || '')), eigene = k.find((x) => /Eigene Regeln/.test(x.querySelector('.kartekopf')?.textContent || '')); return { frei: frei.querySelectorAll('.zeile b.mono').length, eigene: [...eigene.querySelectorAll('.zeile b.mono')].some((b) => b.textContent === 'bet365.com') }; })()");
    pruefe('Freigabe über „Eigene Regeln → erlauben“ hebt auch Glücksspiel-Sperre auf (DNS); steht nur dort, nicht bei den Freigabelisten', gluecks === 'geblockt' && !(await geblocktDns('bet365.com')) && ort.eigene && ort.frei === 0, `vorher ${gluecks} ${JSON.stringify(ort)}`);
    await s.js(`(async () => { const ich = await (await fetch('/api/ich')).json(); const h = { 'x-csrf': ich.csrf, 'Content-Type': 'application/json' };
      await fetch('/api/profile/standard', { method: 'PUT', headers: h, body: JSON.stringify({ kategorien: ${vorherProfil || '{}'} }) });
      for (const r of await (await fetch('/api/regeln')).json()) if (r.muster === 'bet365.com') await fetch('/api/regeln/' + r.id, { method: 'DELETE', headers: h, body: '{}' }); return 1; })()`);
    await s.js("location.hash = 'schild'; setTimeout(() => location.hash = 'listen', 50); 1"); await wartAuf(s, "document.querySelectorAll('[data-liste]').length >= 12", 8000);
    const regelDa = await s.js("[...document.querySelectorAll('.zeile b.mono')].some(b => b.textContent === 'doubleclick.net')");
    pruefe('Regeln: Freigabe aus der Rettung ist aufgeführt', regelDa);
    await tippe(s, '#prdomain', 'googleadservices.com'); await klicke(s, '#pruefform button[type=submit]');
    pruefe('„Domain prüfen“ erklärt Entscheidung und Liste', await wartAuf(s, "/geblockt/.test(document.getElementById('prergebnis').textContent) && /steht auf/.test(document.getElementById('prergebnis').textContent)"));
    await foto(s, 'ui-listen.png');
    await s.js("[...document.querySelectorAll('[data-regelweg]')].forEach(b => b.click()); 1"); await warte(1500);
    pruefe('Regel entfernen → Werbung wieder geblockt', await geblocktDns('doubleclick.net'));
    // Dienste (21.09.): 18 Rubriken, Smart-TV für alle Hersteller, Ausnahmen im Hinweistext, Suche
    await klicke(s, '.navi [data-ansicht="dienste"]');
    pruefe('Dienste: alle Rubriken (u. a. Schule, Finanzen, Smart Home, Dating, VPN) mit Kacheln', await wartAuf(s, "document.querySelectorAll('.dienstgruppe').length >= 18 && document.querySelectorAll('[data-dienst]').length >= 250"), `${await s.js("document.querySelectorAll('.dienstgruppe').length")} Rubriken`);
    pruefe('Dienste: „Smart-TV-Grundfunktionen“ nennt alle Hersteller und die nicht geschützten Mess-Adressen', await s.js("(() => { const t = document.querySelector('[data-dienst=\"smarttv\"]')?.title || ''; return ['LG', 'Sony', 'Hisense', 'nextlgsdp.com', 'nicht geschützt', 'acr-*.samsungcloud.tv'].every((x) => t.includes(x)); })()"));
    await foto(s, 'ui-dienste.png');
    await tippe(s, '#dsuche', 'edupage'); await s.js("document.querySelector('#dsuche').dispatchEvent(new Event('input', { bubbles: true })); 1");
    pruefe('Dienste: Suche „edupage“ findet genau den Dienst in „Schule & Lernen“ (geschützt)', await wartAuf(s, "document.querySelectorAll('[data-dienst]').length === 1 && !!document.querySelector('[data-dienst=\"edupage\"]:not(.neutral):not(.gesperrt)') && /Schule/.test(document.querySelector('.dienstgruppe small')?.textContent || '')", 6000));
    await tippe(s, '#dsuche', ''); await s.js("document.querySelector('#dsuche').dispatchEvent(new Event('input', { bubbles: true })); 1"); await warte(600);
    // Profile
    await klicke(s, '.navi [data-ansicht="profile"]');
    pruefe('Profile: Standard, Kinder, Unbeschränkt mit Kategorien', await wartAuf(s, "document.querySelectorAll('[data-profilid]').length >= 3 && document.querySelectorAll('[data-profilid=\"kinder\"] .fenster').length >= 1"));
    await foto(s, 'ui-profile.png');
    await s.js("document.querySelector('[data-profilid=\"standard\"] [data-kat=\"social\"] [data-katan]').click(); 1");
    await klicke(s, '[data-profilid="standard"] [data-profilspeichern]');
    await warte(1200);
    pruefe('Profil speichern: Social im Standard gesperrt → facebook.com geblockt', await geblocktDns('facebook.com'));
    await wartAuf(s, "!!document.querySelector('[data-profilid=\"standard\"] [data-kat=\"social\"] [data-katan]')");
    await s.js("document.querySelector('[data-profilid=\"standard\"] [data-kat=\"social\"] [data-katan]').click(); 1");
    await klicke(s, '[data-profilid="standard"] [data-profilspeichern]'); await warte(1200);
    pruefe('Zurückgesetzt: facebook.com wieder erlaubt', !(await geblocktDns('facebook.com')));
    // Statistik, Einstellungen
    await klicke(s, '.navi [data-ansicht="statistik"]');
    pruefe('Statistik: Diagramm und Toplisten', await wartAuf(s, "document.querySelectorAll('#stopg .balkenzeile').length > 0 && document.getElementById('diagrammsumme').textContent.length > 5"));
    await foto(s, 'ui-statistik.png');
    await klicke(s, '.navi [data-ansicht="einstellungen"]');
    pruefe('Einstellungen: Upstream mit Antwortzeit, Netz, UniFi, Konto', await wartAuf(s, "document.querySelectorAll('.upzeile').length >= 2 && !!document.getElementById('enetze') && !!document.getElementById('erecords') && !!document.getElementById('ukey') && !!document.getElementById('pwform')"));
    const infos = await s.js("({anzahl: document.querySelectorAll('#haupt .info').length, zonen: document.getElementById('ezonen').parentElement.querySelector('.info')?.textContent || '', netze: document.getElementById('enetze').parentElement.querySelector('.info')?.textContent || '', records: document.getElementById('erecords').parentElement.querySelector('.info')?.textContent || ''})");
    pruefe('Einstellungen: jede Einstellung mit Erklärung (Lokale Zonen, Erlaubte Netze, Lokale Records …)', infos.anzahl >= 10 && /nicht im Internet/.test(infos.zonen) && /offener DNS-Server/.test(infos.netze) && /VPN/.test(infos.records), `${infos.anzahl} Erklärungen`);
    await foto(s, 'ui-einstellungen.png');
    // Hell
    await klicke(s, '#themeknopf'); await klicke(s, '.navi [data-ansicht="schild"]'); await warte(1500);
    pruefe('Helles Design aktiv', await s.js("document.documentElement.dataset.theme === 'hell'"));
    await foto(s, 'ui-hell.png');
    await klicke(s, '#themeknopf');
    // Handy
    await s.cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    const breiten = {};
    for (const a of ['schild', 'geraete', 'protokoll', 'listen', 'profile', 'einstellungen']) {
      await s.js(`location.hash = '${a}'; 1`); await warte(1300);
      breiten[a] = await s.js('document.documentElement.scrollWidth <= innerWidth + 1');
      if (a === 'schild') await foto(s, 'ui-handy-schild.png');
      if (a === 'geraete') await foto(s, 'ui-handy-geraete.png');
    }
    pruefe('Handy 390 px: keine waagerechte Rollleiste in allen Bereichen, Leiste unten sichtbar', Object.values(breiten).every(Boolean) && await s.js("getComputedStyle(document.querySelector('.untennavi')).display !== 'none'"), JSON.stringify(breiten));
    const fehler = s.ereignisse.filter((e) => e.method === 'Runtime.exceptionThrown').map((e) => e.params.exceptionDetails?.exception?.description || e.params.exceptionDetails?.text);
    const csp = s.ereignisse.filter((e) => e.method === 'Log.entryAdded' && /Content Security Policy|Refused to/i.test(e.params.entry.text)).map((e) => e.params.entry.text);
    pruefe('Keine JavaScript-Fehler und keine CSP-Verstöße', !fehler.length && !csp.length, [...fehler, ...csp].slice(0, 3).join(' | '));
  } finally {
    clearInterval(verkehr); s.schliesse(); chrome.kill(); await warte(1200); try { fs.rmSync(profil, { recursive: true, force: true }); } catch { }
  }
  const ok = ergebnisse.filter(Boolean).length;
  console.log(`\n${ok}/${ergebnisse.length} Prüfungen bestanden. Screenshots: ${AUSGABE}`);
  process.exit(ok === ergebnisse.length ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(2); });
