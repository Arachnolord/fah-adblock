#!/usr/bin/env node
// Screenshots für das Handbuch aus einer lokalen Testinstanz (Beispieldaten, keine Haushaltsdaten).
// Aufruf: node docs/handbuch/bilder.mjs --basis=http://127.0.0.1:8054 --dns=127.0.0.1 --dnsport=5354
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
const arg = Object.fromEntries(process.argv.slice(2).map((a) => { const m = /^--([^=]+)=(.*)$/.exec(a); return m ? [m[1], m[2]] : [a, true]; }));
const BASIS = arg.basis || 'http://127.0.0.1:8054', DNS = arg.dns || '127.0.0.1', DNSPORT = +arg.dnsport || 5354;
const AUS = path.join(path.dirname(new URL(import.meta.url).pathname), 'bilder');
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const dns = (name) => new Promise((ok) => { const s = dgram.createSocket('udp4'); const t = setTimeout(() => { s.close(); ok(); }, 2500); s.on('message', () => { clearTimeout(t); s.close(); ok(); }); s.send(dnsPacket.encode({ type: 'query', id: Math.floor(Math.random() * 60000), flags: 256, questions: [{ type: 'A', name }] }), DNSPORT, DNS); });
const freierPort = () => new Promise((f) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => f(p)); }); });
async function verbinde(port) {
  let seite; for (let i = 0; i < 40 && !seite; i++) { try { seite = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((z) => z.type === 'page'); } catch { } if (!seite) await warte(250); }
  const ws = new WebSocket(seite.webSocketDebuggerUrl); await new Promise((f) => { ws.onopen = f; });
  let id = 0; const offen = new Map(); ws.onmessage = (e) => { const n = JSON.parse(e.data); if (n.id && offen.has(n.id)) { offen.get(n.id)(n); offen.delete(n.id); } };
  const cdp = (m, p = {}) => new Promise((f) => { const i = ++id; offen.set(i, f); ws.send(JSON.stringify({ id: i, method: m, params: p })); });
  const js = async (a) => (await cdp('Runtime.evaluate', { expression: a, awaitPromise: true, returnByValue: true })).result?.result?.value;
  return { cdp, js, schliesse: () => ws.close() };
}
async function wartAuf(s, a, ms = 15000) { const e = Date.now() + ms; while (Date.now() < e) { if (await s.js(a)) return true; await warte(300); } return false; }
async function foto(s, name, selektor = null, { rand = 0, hoehe = 0 } = {}) {
  let clip;
  if (selektor) {
    const b = await s.js(`(() => { const e = document.querySelector(${JSON.stringify(selektor)}); if (!e) return null; e.scrollIntoView({block:'start'}); const r = e.getBoundingClientRect(); return {x: Math.max(0, r.left + scrollX - ${rand}), y: Math.max(0, r.top + scrollY - ${rand}), width: r.width + ${rand * 2}, height: Math.min(r.height + ${rand * 2}, ${hoehe || 100000}), scale: 1}; })()`);
    if (!b) { console.log('fehlt:', selektor); return; }
    clip = b; await s.js("document.querySelector('.kopf') && (document.querySelector('.kopf').style.position = 'relative'); 1"); await warte(400);
  }
  if (!selektor) await s.js("document.querySelector('.kopf') && (document.querySelector('.kopf').style.position = ''); 1");
  const r = await s.cdp('Page.captureScreenshot', { format: 'jpeg', quality: 88, ...(clip ? { clip, captureBeyondViewport: true } : {}) });
  fs.writeFileSync(path.join(AUS, name), Buffer.from(r.result.data, 'base64')); console.log('✓', name);
}
const port = await freierPort(), profil = fs.mkdtempSync(path.join(os.tmpdir(), 'fah-hb-'));
const chrome = spawn(CHROME, ['--headless=new', '--use-mock-keychain', '--hide-scrollbars', `--remote-debugging-port=${port}`, `--user-data-dir=${profil}`, 'about:blank'], { stdio: 'ignore' });
const s = await verbinde(port);
let verkehr;
try {
  await s.cdp('Runtime.enable'); await s.cdp('Page.enable');
  await s.cdp('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 2, mobile: false });
  await s.cdp('Page.navigate', { url: BASIS + '/' });
  await wartAuf(s, "!!document.querySelector('#anmeldeform')"); await warte(800);
  await foto(s, '01-anmeldung.jpg', '.anmeldekarte', { rand: 24 });
  await s.js(`(async () => { await fetch('/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', passwort: 'admin' }) }); return 1; })()`);
  // Beispieldaten: Gerätename, Freigaben, Verkehr
  await s.js(`(async () => { const ich = await (await fetch('/api/ich')).json(); const h = { 'x-csrf': ich.csrf, 'Content-Type': 'application/json' };
    await fetch('/api/geraete/' + encodeURIComponent('ip:127.0.0.1'), { method: 'PUT', headers: h, body: JSON.stringify({ name: 'MacBook (Beispiel)' }) });
    for (const r of await (await fetch('/api/regeln')).json()) await fetch('/api/regeln/' + r.id, { method: 'DELETE', headers: h, body: '{}' });
    await fetch('/api/regeln', { method: 'POST', headers: h, body: JSON.stringify({ typ: 'erlauben', muster: 'instagram.com', geltung: 'alle', notiz: 'Beispiel: manuelle Freigabe' }) });
    await fetch('/api/regeln', { method: 'POST', headers: h, body: JSON.stringify({ typ: 'sperren', muster: 'tiktok.com', geltung: 'profil:kinder', notiz: 'Beispiel' }) });
    await fetch('/api/pause', { method: 'POST', headers: h, body: JSON.stringify({ minuten: 0 }) }); return 1; })()`);
  const namen = ['doubleclick.net', 'wikipedia.org', 'googleadservices.com', 'heise.de', 'pagead2.googlesyndication.com', 'github.com', 'app-measurement.com', 'apple.com', 'spiegel.de', 'ads.yahoo.com', 'tagesschau.de', 'analytics.tiktok.com'];
  let i = 0; verkehr = setInterval(() => { dns(`${i % 3 === 0 ? 'x' + i + '.' : ''}${namen[i++ % namen.length]}`); }, 150);
  await s.js("location.hash = 'schild'; location.reload(); 1"); await warte(1500);
  await wartAuf(s, "document.querySelectorAll('#geblocktliste .zeile').length > 3", 25000); await warte(21500);   // Kennzahlen laufen im 20-s-Takt mit – erst dann fotografieren
  await foto(s, '02-schutzschild.jpg');
  await foto(s, '03-kennzahlen.jpg', '#kennzahlen', { rand: 4 });
  await s.js("document.querySelector('[data-schildstunden=\"168\"]').click(); 1"); await warte(1200);
  await foto(s, '03a-zeitraum.jpg', '.zeitwahl', { rand: 8 });
  await s.js("document.querySelector('[data-schildstunden=\"24\"]').click(); 1"); await warte(600);
  await s.js("document.querySelector('.zweispaltig').scrollIntoView(); 1"); await foto(s, '04-geblockt.jpg', '.zweispaltig');
  await s.js("window.scrollTo(0,0); document.getElementById('pauseknopf').click(); 1"); await warte(500);
  await foto(s, '05-pause.jpg', '.kopfrechts', { rand: 0 });
  const kopf = await s.js("(() => { const a = document.getElementById('pauseaufklapp').getBoundingClientRect(), k = document.querySelector('.kopfrechts').getBoundingClientRect(); return {x: k.left - 20, y: 0, width: k.width + 40, height: a.bottom + 16, scale: 1}; })()");
  const r5 = await s.cdp('Page.captureScreenshot', { format: 'jpeg', quality: 88, clip: kopf }); fs.writeFileSync(path.join(AUS, '05-pause.jpg'), Buffer.from(r5.result.data, 'base64'));
  await s.js("document.getElementById('pauseknopf').click(); location.hash = 'geraete'; 1"); await wartAuf(s, "!!document.querySelector('#geraeteraster .geraet')"); await warte(800);
  await foto(s, '06-geraete.jpg', '#geraeteraster .geraet', { rand: 12 });
  await s.js("document.querySelector('#geraeteraster .geraet [data-rettung]').click(); 1"); await wartAuf(s, "document.querySelectorAll('.rettungzeile').length > 2"); await warte(800);
  await foto(s, '07-rettung.jpg', '.seitenleiste');
  await s.js("document.querySelector('.seitenleiste [data-zu]').click(); location.hash = 'protokoll'; 1"); await wartAuf(s, "document.querySelectorAll('#ptabelle tr[data-domain]').length > 8"); await warte(600);
  await s.cdp('Emulation.setDeviceMetricsOverride', { width: 1440, height: 760, deviceScaleFactor: 2, mobile: false });
  await foto(s, '08-protokoll.jpg');
  await s.cdp('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 2, mobile: false });
  await s.js("location.hash = 'listen'; 1"); await wartAuf(s, "document.querySelectorAll('[data-liste]').length >= 12"); await warte(500);
  await s.js("document.getElementById('prdomain').value = 'googleadservices.com'; document.querySelector('#pruefform button').click(); 1"); await warte(1200);
  await foto(s, '09-domain-pruefen.jpg', '#pruefform', { rand: 0 });
  const pruefKarte = await s.js("(() => { const e = document.getElementById('pruefform').closest('.karte'); const r = e.getBoundingClientRect(); return {x: r.left, y: r.top + scrollY, width: r.width, height: r.height, scale: 1}; })()");
  const r9 = await s.cdp('Page.captureScreenshot', { format: 'jpeg', quality: 88, clip: pruefKarte, captureBeyondViewport: true }); fs.writeFileSync(path.join(AUS, '09-domain-pruefen.jpg'), Buffer.from(r9.result.data, 'base64'));
  const karten = await s.js("[...document.querySelectorAll('#haupt .zweispaltig .karte')].map((k, i) => { k.dataset.hb = 'k' + i; return k.querySelector('.kartekopf').textContent.trim().slice(0, 20); })");
  console.log('Karten:', karten);
  await s.js("(() => { const k = (t) => [...document.querySelectorAll('.karte')].find((x) => (x.querySelector('.kartekopf')?.textContent || '').includes(t)); k('Blocklisten').dataset.hb = 'block'; k('Freigabelisten').dataset.hb = 'frei'; document.getElementById('regelform').closest('.karte').dataset.hb = 'regeln'; return 1; })()");
  await foto(s, '10-blocklisten.jpg', '[data-hb="block"]');
  await foto(s, '11-freigabelisten.jpg', '[data-hb="frei"]');
  await foto(s, '12-eigene-regeln.jpg', '[data-hb="regeln"]');
  await foto(s, '12b-dienste.jpg', '#dienstkarte');
  await s.js("location.hash = 'dienste'; 1"); await wartAuf(s, "document.querySelectorAll('[data-dienst]').length > 100"); await warte(600);
  await foto(s, '13a-dienste.jpg', '#haupt .karte', { hoehe: 1150 });
  await s.js("location.hash = 'profile'; 1"); await wartAuf(s, "document.querySelectorAll('[data-profilid]').length >= 3"); await warte(600);
  await foto(s, '13-profile.jpg', '#haupt');
  await foto(s, '14-profil-kinder.jpg', '[data-profilid="kinder"]', { hoehe: 900 });
  await s.js("(() => { const d = document.querySelector('[data-profilid=kinder] .profildienste'); d.open = true; d.scrollIntoView({ block: 'center' }); return 1; })()"); await warte(500);
  await foto(s, '14a-profildienste.jpg', '[data-profilid="kinder"] .profildienste', { hoehe: 900 });
  await s.js("location.hash = 'statistik'; 1"); await wartAuf(s, "document.querySelectorAll('#stopg .balkenzeile').length > 0"); await warte(1200);
  await foto(s, '15-statistik.jpg', '#haupt');
  await s.cdp('Emulation.setDeviceMetricsOverride', { width: 1040, height: 900, deviceScaleFactor: 2, mobile: false });
  await s.js("location.hash = 'einstellungen'; 1"); await wartAuf(s, "!!document.getElementById('pwform')"); await warte(800);
  const ek = await s.js("[...document.querySelectorAll('#haupt .raster > .karte')].map((k, i) => { k.dataset.hb = 'e' + i; k.style.alignSelf = 'start'; return k.querySelector('.kartekopf').textContent.trim(); })");
  console.log('Einstellungen:', ek);
  await s.js("(() => { const d = document.querySelector('.anbieterwahl'); if (d) d.open = true; return 1; })()"); await warte(400);
  await foto(s, '16a-anbieter.jpg', '.anbieterwahl', { hoehe: 1100 });
  await s.js("(() => { const d = document.querySelector('.anbieterwahl'); if (d) d.open = false; return 1; })()"); await warte(300);
  for (let n = 0; n < ek.length; n++) await foto(s, `16-einstellungen-${n + 1}.jpg`, `[data-hb="e${n}"]`);
  await s.cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await s.js("location.hash = 'schild'; 1"); await warte(2500); await foto(s, '17-handy.jpg');
} finally { clearInterval(verkehr); s.schliesse(); chrome.kill(); await warte(1000); try { fs.rmSync(profil, { recursive: true, force: true }); } catch { } }
