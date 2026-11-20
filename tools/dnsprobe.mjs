#!/usr/bin/env node
// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// ============================================================================
// DNS-Probe gegen einen laufenden FAH-Adblock: echte Anfragen per UDP und TCP.
// Aufruf: node tools/dnsprobe.mjs --server=192.168.1.23 [--port=53] [--lokal=example.org]
//         [--last=2000] (Anfragen je Sekunde für den Lasttest, 0 = aus) [--dauer=20]
import dgram from 'node:dgram';
import net from 'node:net';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const dnsPacket = require('dns-packet');

const arg = Object.fromEntries(process.argv.slice(2).map((a) => { const m = /^--([^=]+)=(.*)$/.exec(a); return m ? [m[1], m[2]] : [a.replace(/^--/, ''), true]; }));
const SERVER = arg.server || '127.0.0.1', PORT = +arg.port || 53, LOKAL = arg.lokal || 'example.org';
const ergebnisse = [];
const pruefe = (name, ok, detail = '') => { ergebnisse.push(!!ok); console.log(`${ok ? 'OK  ' : 'FEHL'} ${name}${detail ? ' – ' + detail : ''}`); };
let nextId = 1;
const frage = (name, type = 'A', { edns = true, dnssec = false } = {}) => dnsPacket.encode({ type: 'query', id: (nextId = (nextId + 1) % 65535), flags: dnsPacket.RECURSION_DESIRED, questions: [{ type, name }], additionals: edns ? [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: dnssec ? dnsPacket.DNSSEC_OK : 0 }] : [] });

function udp(buf, timeout = 4000) {
  return new Promise((ok, nein) => {
    const s = dgram.createSocket('udp4'), start = process.hrtime.bigint();
    const uhr = setTimeout(() => { s.close(); nein(new Error('Zeitüberschreitung')); }, timeout);
    s.on('message', (m) => { clearTimeout(uhr); s.close(); let p; try { p = dnsPacket.decode(m); } catch (e) { p = { flags: m.readUInt16BE(2), answers: Array(m.readUInt16BE(6)).fill({ type: '?' }) }; } ok({ p, ms: Number(process.hrtime.bigint() - start) / 1e6, laenge: m.length }); });
    s.send(buf, PORT, SERVER);
  });
}
function tcp(buf, timeout = 5000) {
  return new Promise((ok, nein) => {
    const sock = net.connect(PORT, SERVER); let puffer = Buffer.alloc(0);
    const uhr = setTimeout(() => { sock.destroy(); nein(new Error('Zeitüberschreitung')); }, timeout);
    sock.on('connect', () => { const k = Buffer.alloc(2); k.writeUInt16BE(buf.length); sock.write(Buffer.concat([k, buf])); });
    sock.on('data', (d) => { puffer = Buffer.concat([puffer, d]); if (puffer.length >= 2 && puffer.length >= 2 + puffer.readUInt16BE(0)) { clearTimeout(uhr); sock.end(); ok({ p: dnsPacket.decode(puffer.subarray(2, 2 + puffer.readUInt16BE(0))) }); } });
    sock.on('error', (e) => { clearTimeout(uhr); nein(e); });
  });
}
const rcode = (p) => p.flags & 15;

try {
  const blk = await udp(frage('doubleclick.net')), blk6 = await udp(frage('doubleclick.net', 'AAAA'));
  pruefe('Werbung geblockt: A → 0.0.0.0, AAAA → ::', blk.p.answers[0]?.data === '0.0.0.0' && blk6.p.answers[0]?.data === '::', `${blk.ms.toFixed(1)} ms`);
  pruefe('Subdomain einer Liste geblockt (ad.doubleclick.net)', (await udp(frage('ad.doubleclick.net'))).p.answers[0]?.data === '0.0.0.0');
  const erst = await udp(frage('wikipedia.org')), zweit = await udp(frage('wikipedia.org'));
  pruefe('Erlaubte Domain löst auf (verschlüsselt über Upstream)', rcode(erst.p) === 0 && erst.p.answers.some((a) => a.type === 'A' && a.data !== '0.0.0.0'), `erste ${erst.ms.toFixed(1)} ms, zweite ${zweit.ms.toFixed(1)} ms`);
  pruefe('Zweite Anfrage aus dem Zwischenspeicher deutlich schneller', zweit.ms < Math.max(5, erst.ms), `${zweit.ms.toFixed(2)} ms`);
  // dns-packet kennt den Namen „HTTPS“ nicht (würde Typ 0 senden) – deshalb Typ 65 ausdrücklich
  const a6 = await udp(frage('google.com', 'AAAA')), h1 = await udp(frage('cloudflare.com', 'UNKNOWN_65')), h2 = await udp(frage('wikipedia.org', 'UNKNOWN_65'));
  pruefe('AAAA und HTTPS-Einträge (Typ 65) werden beantwortet (cloudflare.com hat einen, wikipedia.org keinen)', rcode(a6.p) === 0 && a6.p.answers.some((x) => x.type === 'AAAA') && rcode(h1.p) === 0 && h1.p.answers.length > 0 && rcode(h2.p) === 0, `AAAA ${a6.p.answers.length}, cloudflare.com HTTPS rcode ${rcode(h1.p)}/${h1.p.answers.length}, wikipedia.org HTTPS rcode ${rcode(h2.p)}/${h2.p.answers.length}`);
  pruefe('Nicht existierende Domain → NXDOMAIN', rcode((await udp(frage('gibt-es-nicht-fah-adblock-4711.de'))).p) === 3);
  const sec = await udp(frage('cloudflare.com', 'A', { dnssec: true }));
  pruefe('DNSSEC: AD-Kennzeichen des validierenden Upstreams wird durchgereicht', !!(sec.p.flags & (1 << 5)), `flags ${sec.p.flags.toString(2)}`);
  const ohneEdns = await udp(frage('google.com', 'TXT', { edns: false }));
  const perTcp = await tcp(frage('google.com', 'TXT', { edns: false }));
  pruefe('Große Antwort ohne EDNS: UDP gekürzt (TC) oder ≤ 512 Byte, TCP vollständig', ((ohneEdns.p.flags & (1 << 9)) || ohneEdns.laenge <= 512) && perTcp.p.answers.length > 0, `UDP ${ohneEdns.laenge} B, TC=${!!(ohneEdns.p.flags & (1 << 9))}, TCP ${perTcp.p.answers.length} Einträge`);
  const lokal = await udp(frage(LOKAL));
  pruefe(`Lokale Zone ${LOKAL} über das Gateway`, rcode(lokal.p) === 0 && lokal.p.answers.length > 0, lokal.p.answers.map((a) => a.data).join(', '));
  pruefe('Gesundheitsanfrage', String((await udp(frage('health.fah-adblock', 'TXT'))).p.answers[0]?.data?.[0]) === 'ok');
  pruefe('Firefox-DoH-Kanarie → NXDOMAIN', rcode((await udp(frage('use-application-dns.net'))).p) === 3);

  const last = +(arg.last ?? 0), dauer = +(arg.dauer || 20);
  if (last > 0) {
    const namen = ['wikipedia.org', 'google.com', 'doubleclick.net', 'cloudflare.com', 'github.com', 'heise.de', 'amazon.de', 'apple.com'];
    for (const n of namen) await udp(frage(n));   // Speicher füllen
    const zeiten = []; let fehler = 0, gesendet = 0;
    const sockets = Array.from({ length: 8 }, () => dgram.createSocket('udp4'));
    const offen = new Map();
    const rcodes = {};
    sockets.forEach((s) => { s.on('message', (m) => { const id = m.readUInt16BE(0), t = offen.get(id); if (t !== undefined) { zeiten.push(Number(process.hrtime.bigint() - t) / 1e6); offen.delete(id); const rc = m.readUInt16BE(2) & 15; rcodes[rc] = (rcodes[rc] || 0) + 1; } }); s.bind(); });
    const start = Date.now();
    await new Promise((fertig) => {
      const takt = setInterval(() => {
        const jetzt = Date.now(); if (jetzt - start >= dauer * 1000) { clearInterval(takt); return setTimeout(fertig, 1500); }
        for (let i = 0; i < last / 100; i++) {
          const id = (gesendet % 65000) + 1, buf = dnsPacket.encode({ type: 'query', id, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: namen[gesendet % namen.length] }] });
          offen.set(id, process.hrtime.bigint()); sockets[gesendet % sockets.length].send(buf, PORT, SERVER); gesendet++;
        }
      }, 10);
    });
    fehler = offen.size; sockets.forEach((s) => s.close());
    zeiten.sort((a, b) => a - b);
    const p = (q) => zeiten[Math.min(zeiten.length - 1, Math.floor(zeiten.length * q))] || 0;
    const qps = Math.round(zeiten.length / dauer);
    pruefe(`Last ${last}/s über ${dauer} s: ≥ 99 % beantwortet, keine Abweisung, p99 < 50 ms`, zeiten.length >= gesendet * 0.99 && !rcodes[5] && !rcodes[2] && p(0.99) < 50, `${zahl(gesendet)} gesendet, ${zahl(zeiten.length)} beantwortet (${qps}/s), ohne Antwort ${fehler}, Rcodes ${JSON.stringify(rcodes)}, p50 ${p(0.5).toFixed(2)} ms, p99 ${p(0.99).toFixed(2)} ms`);
  }
} catch (e) { console.error(e); ergebnisse.push(false); }
function zahl(n) { return Number(n).toLocaleString('de-DE'); }
const ok = ergebnisse.filter(Boolean).length;
console.log(`\n${ok}/${ergebnisse.length} Prüfungen bestanden.`);
process.exit(ok === ergebnisse.length ? 0 : 1);
