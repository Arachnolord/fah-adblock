// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// IP-Adressen und Netze (IPv4/IPv6), Domain-Normalisierung.
'use strict';
const net = require('net');

// IPv4-mapped IPv6 → IPv4, in JEDER Schreibweise („::ffff:10.1.2.3“, „::ffff:a01:203“, „0:0:0:0:0:ffff:a01:203“). Die Hex-Form liefert z. B.
// der URL-Parser (25.11.2026: „[::ffff:127.0.0.1]“ wurde zu „::ffff:7f00:1“ und rutschte an den IPv4-Netzen vorbei)
function normIp(ip) {
  const s = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!net.isIPv6(s) || !s.includes('ffff')) return s;
  const b = v6Bytes(s);
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 255 && b[11] === 255) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
  return s;
}

function v4Zahl(ip) { return ip.split('.').reduce((a, n) => a * 256 + (+n), 0); }
function v6Bytes(ip) {
  const [kopf, rumpf] = ip.split('::');
  const teile = (s) => (s ? s.split(':') : []);
  let a = teile(kopf), b = teile(rumpf);
  const erweitere = (liste) => liste.flatMap((t) => (net.isIPv4(t) ? (() => { const z = v4Zahl(t); return [((z >>> 16) & 0xffff).toString(16), (z & 0xffff).toString(16)]; })() : [t]));
  a = erweitere(a); b = erweitere(b);
  const fehlt = 8 - a.length - b.length;
  const alle = rumpf !== undefined ? [...a, ...Array(Math.max(0, fehlt)).fill('0'), ...b] : a;
  const bytes = [];
  for (const t of alle) { const z = parseInt(t || '0', 16); bytes.push((z >> 8) & 255, z & 255); }
  return bytes;
}

// „192.168.1.0/24“ → Prüffunktion
function netz(text) {
  const [adr, pre] = String(text).trim().split('/');
  if (net.isIPv4(adr)) {
    const p = pre === undefined ? 32 : +pre;
    if (!(p >= 0 && p <= 32)) throw new Error(`Ungültiges Netz: ${text}`);
    const g = 2 ** (32 - p), start = Math.floor(v4Zahl(adr) / g) * g;
    return { text: `${adr}/${p}`, v6: false, enthaelt: (ip) => net.isIPv4(ip) && v4Zahl(ip) >= start && v4Zahl(ip) < start + g };
  }
  if (net.isIPv6(adr)) {
    const p = pre === undefined ? 128 : +pre;
    if (!(p >= 0 && p <= 128)) throw new Error(`Ungültiges Netz: ${text}`);
    const basis = v6Bytes(adr.toLowerCase());
    return {
      text: `${adr}/${p}`, v6: true,
      enthaelt: (ip) => {
        if (!net.isIPv6(ip)) return false;
        const b = v6Bytes(ip.toLowerCase());
        for (let bit = 0; bit < p; bit++) { const i = bit >> 3, m = 0x80 >> (bit & 7); if ((b[i] & m) !== (basis[i] & m)) return false; }
        return true;
      },
    };
  }
  throw new Error(`Ungültiges Netz: ${text}`);
}

function netzliste(texte) {
  const liste = (Array.isArray(texte) ? texte : String(texte || '').split(/[,\s]+/)).filter(Boolean).map(netz);
  return { liste, enthaelt: (ip) => { const n = normIp(ip); return liste.some((x) => x.enthaelt(n)); }, texte: liste.map((x) => x.text) };
}

// Domain normalisieren: klein, ohne abschließenden Punkt; ungültig → ''
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
function normDomain(text) {
  const d = String(text || '').trim().toLowerCase().replace(/\.$/, '');
  return DOMAIN.test(d) && !net.isIP(d) ? d : '';
}
// „a.b.c.de“ → ["a.b.c.de", "b.c.de", "c.de", "de"]
function suffixe(domain) {
  const teile = domain.split('.'), aus = [];
  for (let i = 0; i < teile.length; i++) aus.push(teile.slice(i).join('.'));
  return aus;
}

// Listen-IDs landen im Dateinamen (data/listen/<id>.txt) – nur Buchstaben, Ziffern, - und _ (25.11.2026, Prüfung K9: „../x“ aus einer
// Sicherung oder einem Spiegel-Stand hätte sonst Dateien außerhalb des Listenordners überschrieben)
const listenIdOk = (id) => typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(id);

module.exports = { normIp, netz, netzliste, normDomain, suffixe, listenIdOk };
