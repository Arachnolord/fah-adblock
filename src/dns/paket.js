// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// DNS-Nachrichten lesen und bauen (dns-packet, MIT).
'use strict';
const dnsPacket = require('dns-packet');
const roh = require('./roh');

const FLAG_QR = 1 << 15, FLAG_AA = 1 << 10, FLAG_TC = 1 << 9, FLAG_RD = 1 << 8, FLAG_RA = 1 << 7, FLAG_AD = 1 << 5, FLAG_CD = 1 << 4;
const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

// Nur ASCII-Namen mit Labels bis 63 Byte: dns-packet schreibt beim Neubau die Zeichenzahl statt der Bytezahl ins
// Längenfeld – ein Name mit Umlauten/Nicht-ASCII käme sonst als kaputtes Paket zurück. Solche Fragen → FORMERR (ohne Frage-Abschnitt).
function nameGueltig(name) { return /^[\x21-\x7e]*$/.test(name) && name.split('.').every((l) => l.length <= 63); }
function lesen(buf) {
  const p = dnsPacket.decode(buf);
  const ungueltig = (p.questions || []).some((x) => !nameGueltig(String(x.name || '')));
  if (ungueltig) p.questions = [];
  const q = p.questions?.[0];
  const opt = (p.additionals || []).find((r) => r.type === 'OPT');
  return {
    paket: p, id: p.id, ungueltig, frage: q ? { name: String(q.name || '').toLowerCase().replace(/\.$/, ''), typ: q.type, klasse: q.class } : null,
    flags: p.flags || 0, rd: !!((p.flags || 0) & FLAG_RD), cd: !!((p.flags || 0) & FLAG_CD),
    edns: opt ? { udpGroesse: Math.max(512, opt.udpPayloadSize || 512), do: !!(opt.flags & 0x8000) } : null,
  };
}

function optVon(anfrage) {
  return anfrage.edns ? [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: anfrage.edns.do ? 0x8000 : 0, options: [] }] : [];
}

// Antwort auf eine Anfrage mit eigenem Inhalt (Sperre, lokale Antwort, Fehler)
function antwort(anfrage, { rcode = 'NOERROR', answers = [], authorities = [], aa = false } = {}) {
  const q = anfrage.paket.questions || [];
  const flags = FLAG_QR | (anfrage.rd ? FLAG_RD : 0) | FLAG_RA | (aa ? FLAG_AA : 0) | (anfrage.cd ? FLAG_CD : 0) | (RCODE[rcode] ?? 0);
  return dnsPacket.encode({ type: 'response', id: anfrage.id, flags, questions: q, answers, authorities, additionals: optVon(anfrage) });
}

// Gesperrte Domain: A → 0.0.0.0, AAAA → ::, sonst leere Antwort (NOERROR/NODATA) – Apps brechen sofort ab.
// TTL nur 10 s: Geräte und Zwischenspeicher halten die Sperre sonst noch lange nach einer Freigabe (Rettung) fest.
const SPERR_TTL = 10;
const SOA_SPERRE = (name) => ({ name, type: 'SOA', ttl: SPERR_TTL, class: 'IN', data: { mname: 'fah-adblock.local', rname: 'hostmaster.fah-adblock.local', serial: 1, refresh: 3600, retry: 600, expiration: 86400, minimum: SPERR_TTL } });
// Mit sperrIp (Sperrseite): A zeigt auf die Hinweisseite, AAAA bleibt leer, damit der Browser IPv4 nimmt.
function sperrAntwort(anfrage, sperrIp = null) {
  const f = anfrage.frage;
  if (f.typ === 'A') return antwort(anfrage, { answers: [{ name: f.name, type: 'A', class: 'IN', ttl: SPERR_TTL, data: sperrIp || '0.0.0.0' }] });
  if (f.typ === 'AAAA' && sperrIp) return antwort(anfrage, { authorities: [SOA_SPERRE(f.name)] });
  if (f.typ === 'AAAA') return antwort(anfrage, { answers: [{ name: f.name, type: 'AAAA', class: 'IN', ttl: SPERR_TTL, data: '::' }] });
  return antwort(anfrage, { authorities: [SOA_SPERRE(f.name)] });
}

// Upstream-Antwort an den Client anpassen – byte-genau (roh.js): eigene ID, TTLs herabsetzen,
// bei UDP ggf. kürzen (TC). Kein Dekodieren/Neubauen, damit unbekannte Typen (HTTPS/SVCB …) heil bleiben.
function fuerClient(antwortBuf, anfrage, { alterSek = 0, udp = true } = {}) {
  try { return roh.fuerClient(antwortBuf, { id: anfrage.id, edns: anfrage.edns, alterSek, udp }); } catch (e) { return null; }
}

// Kleinste TTL einer Antwort (für den Zwischenspeicher); negative Antworten: SOA-Minimum
function ttlVon(antwortBuf) {
  try {
    const ttl = roh.minTtl(antwortBuf);
    if (ttl !== null) return ttl;
    const rc = roh.rcode(antwortBuf);
    return rc === RCODE.NOERROR || rc === RCODE.NXDOMAIN ? 60 : 0;
  } catch (e) { return 0; }
}

// CNAME-Ziele einer Antwort (für die Erkennung getarnter Tracker)
function cnameZiele(antwortBuf) { try { return roh.cnameZiele(antwortBuf); } catch (e) { return []; } }
function rcodeVon(antwortBuf) { return roh.rcode(antwortBuf); }

// Anfrage für den Upstream: ID 0 (RFC 8484, zwischenspeicherbar), EDNS mit DO-Bit wie beim Client
function upstreamAnfrage(anfrage) {
  const flags = FLAG_RD | (anfrage.cd ? FLAG_CD : 0) | FLAG_AD;
  return dnsPacket.encode({ type: 'query', id: 0, flags, questions: anfrage.paket.questions, additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: anfrage.edns?.do ? 0x8000 : 0, options: [] }] });
}

module.exports = { lesen, antwort, sperrAntwort, fuerClient, ttlVon, cnameZiele, rcodeVon, upstreamAnfrage, RCODE, dnsPacket };
