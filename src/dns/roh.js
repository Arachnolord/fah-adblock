// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// DNS-Antworten auf Byte-Ebene: Upstream-Antworten werden NICHT dekodiert und neu gebaut,
// sondern unverändert weitergereicht – nur ID und TTLs werden an Ort und Stelle geschrieben.
// So kommen auch Eintragstypen heil an, die keine Bibliothek vollständig kennt (HTTPS/SVCB,
// neue DNSSEC-Typen …). Gelesen wird nur, was nötig ist: Kopf, Namen (mit Kompression),
// Typ/Klasse/TTL/Datenlänge, CNAME-Ziele und SOA-Minimum.
'use strict';

const TYP_CNAME = 5, TYP_SOA = 6, TYP_OPT = 41;

function leseName(buf, off) {
  const teile = []; let pos = off, ende = -1, sprung = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('Name über das Paketende');
    const laenge = buf[pos];
    if (laenge === 0) { if (ende < 0) ende = pos + 1; break; }
    if ((laenge & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length || ++sprung > 30) throw new Error('Kompressionszeiger ungültig');
      if (ende < 0) ende = pos + 2;
      pos = ((laenge & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if ((laenge & 0xc0) !== 0) throw new Error('Label-Typ unbekannt');
    teile.push(buf.toString('latin1', pos + 1, pos + 1 + laenge));
    pos += 1 + laenge;
  }
  return { name: teile.join('.').toLowerCase(), ende };
}
function kopf(buf) {
  if (buf.length < 12) throw new Error('Paket zu kurz');
  return { id: buf.readUInt16BE(0), flags: buf.readUInt16BE(2), qd: buf.readUInt16BE(4), an: buf.readUInt16BE(6), ns: buf.readUInt16BE(8), ar: buf.readUInt16BE(10) };
}
function frageEnde(buf) {
  const k = kopf(buf); let pos = 12;
  for (let i = 0; i < k.qd; i++) { pos = leseName(buf, pos).ende + 4; if (pos > buf.length) throw new Error('Frage über das Paketende'); }
  return pos;
}
// Alle Einträge mit Lage im Paket
function eintraege(buf) {
  const k = kopf(buf), liste = [];
  let pos = frageEnde(buf);
  const abschnitte = [['an', k.an], ['ns', k.ns], ['ar', k.ar]];
  for (const [abschnitt, anzahl] of abschnitte) {
    for (let i = 0; i < anzahl; i++) {
      const start = pos, name = leseName(buf, pos);
      pos = name.ende;
      if (pos + 10 > buf.length) throw new Error('Eintrag über das Paketende');
      const typ = buf.readUInt16BE(pos), klasse = buf.readUInt16BE(pos + 2), ttl = buf.readUInt32BE(pos + 4), laenge = buf.readUInt16BE(pos + 8);
      const daten = pos + 10;
      if (daten + laenge > buf.length) throw new Error('Daten über das Paketende');
      liste.push({ abschnitt, start, name: name.name, typ, klasse, ttl, ttlOffset: pos + 4, daten, laenge, ende: daten + laenge });
      pos = daten + laenge;
    }
  }
  return liste;
}
// Rcode inklusive der oberen Bits aus dem OPT-Eintrag (RFC 6891 §6.1.3, z. B. BADVERS = 16): sonst sähe eine solche Fehlerantwort
// wie NOERROR aus und würde gespeichert. Ohne/mit kaputtem OPT zählen nur die 4 Bits im Kopf.
const rcode = (buf) => {
  if (buf.length < 4) return -1;
  const tief = buf.readUInt16BE(2) & 15;
  try { const opt = eintraege(buf).find((e) => e.typ === TYP_OPT && e.abschnitt === 'ar'); return opt ? tief | ((opt.ttl >>> 24) << 4) : tief; } catch (e) { return tief; }
};

// Ist `antwort` eine vollständige, heile, ungekürzte Antwort (QR=1, TC=0) auf genau die Frage(n) von `anfrage`? Frage-Abschnitt ab Byte 12,
// dort nie komprimiert (davor gibt es keinen Namen): Labellängen, Typ und Klasse byte-gleich, nur Buchstaben IN den Labels
// ohne Groß/Klein. Danach müssen alle angekündigten Einträge vollständig vorhanden sein und das Paket genau dort enden. Sonst false.
function passtZu(anfrage, antwort) {
  try {
    const a = kopf(anfrage), b = kopf(antwort);
    if (!(b.flags & 0x8000) || (b.flags & 0x0200) || a.qd !== b.qd) return false;   // QR fehlt oder TC gesetzt (über DoH nie gekürzt)
    const klein = (x) => (x >= 65 && x <= 90 ? x + 32 : x);
    let pos = 12;
    for (let q = 0; q < a.qd; q++) {
      for (;;) {
        if (pos >= anfrage.length || pos >= antwort.length) return false;
        const l = anfrage[pos];
        if (antwort[pos] !== l || l > 63) return false;          // gleiche Länge, keine Zeiger/Sondertypen in der Frage
        if (l === 0) { pos++; break; }
        if (pos + 1 + l > anfrage.length || pos + 1 + l > antwort.length) return false;
        for (let i = pos + 1; i <= pos + l; i++) if (klein(anfrage[i]) !== klein(antwort[i])) return false;
        pos += 1 + l;
      }
      if (pos + 4 > anfrage.length || pos + 4 > antwort.length) return false;
      for (let i = pos; i < pos + 4; i++) if (anfrage[i] !== antwort[i]) return false;   // Typ + Klasse genau
      pos += 4;
    }
    const liste = eintraege(antwort);                             // wirft bei abgeschnittenen Einträgen
    return (liste.length ? liste[liste.length - 1].ende : pos) === antwort.length;   // nichts fehlt, nichts hängt hinten dran
  } catch (e) { return false; }
}

// Kleinste TTL der Antworten; ohne Antworten: SOA-Minimum (negative Antwort)
function minTtl(buf) {
  const liste = eintraege(buf).filter((e) => e.typ !== TYP_OPT);
  const antworten = liste.filter((e) => e.abschnitt === 'an');
  if (antworten.length) return Math.min(...antworten.map((e) => e.ttl));
  const soa = liste.find((e) => e.abschnitt === 'ns' && e.typ === TYP_SOA);
  if (soa) {
    const rname = leseName(buf, leseName(buf, soa.daten).ende).ende;
    const minimum = rname + 16 + 4 <= buf.length ? buf.readUInt32BE(rname + 16) : 300;
    return Math.min(soa.ttl, minimum);
  }
  return null;
}
function cnameZiele(buf) {
  return eintraege(buf).filter((e) => e.abschnitt === 'an' && e.typ === TYP_CNAME).map((e) => leseName(buf, e.daten).name);
}

// Für den Client: Kopie mit dessen ID, TTLs um das Alter verringert, OPT entfernt, wenn der Client kein EDNS
// sprach (und OPT der letzte Eintrag ist), bei UDP über der Grenze → nur Kopf + Frage mit TC-Bit.
// maxTtl > 0: TTLs höchstens so lang (Zeitlimit – das Gerät soll bald wieder fragen)
function fuerClient(antwort, { id, edns = null, alterSek = 0, udp = true, maxTtl = 0 } = {}) {
  let buf = Buffer.from(antwort);
  const liste = eintraege(buf);   // wirft bei kaputten Paketen
  buf.writeUInt16BE(id, 0);
  if (alterSek > 0 || maxTtl > 0) for (const e of liste) if (e.typ !== TYP_OPT) { let t = Math.max(0, e.ttl - alterSek); if (maxTtl > 0) t = Math.min(t, maxTtl); buf.writeUInt32BE(t, e.ttlOffset); }
  if (!edns) {
    const opt = liste.find((e) => e.typ === TYP_OPT);
    if (opt && opt.ende === buf.length) { buf = buf.subarray(0, opt.start); buf.writeUInt16BE(Math.max(0, buf.readUInt16BE(10) - 1), 10); }
  }
  const grenze = edns ? Math.min(Math.max(512, edns.udpGroesse || 512), 1232) : 512;
  if (udp && buf.length > grenze) {
    const ende = frageEnde(buf), gekuerzt = Buffer.from(buf.subarray(0, ende));
    gekuerzt.writeUInt16BE(buf.readUInt16BE(2) | 0x0200, 2);   // TC
    gekuerzt.writeUInt16BE(0, 6); gekuerzt.writeUInt16BE(0, 8); gekuerzt.writeUInt16BE(0, 10);
    return gekuerzt;
  }
  return buf;
}

module.exports = { leseName, kopf, eintraege, rcode, passtZu, minTtl, cnameZiele, fuerClient, TYP_OPT };
