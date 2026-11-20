// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// DNS-Server (UDP + TCP) auf genau einer Adresse. Ablauf je Anfrage:
// Zugang (nur erlaubte Netze) → Bremse je Client → lokale Zone? → Filter → Upstream → CNAME-Prüfung.
'use strict';
const dgram = require('dgram');
const net = require('net');
const { EventEmitter } = require('events');
const paket = require('./paket');
const { normIp } = require('../netz');

const GESUNDHEIT = 'health.fah-adblock';
const KANARIE = new Set(['use-application-dns.net']);   // Firefox: netzweiten Blocker respektieren (kein eigenes DoH)

class DnsServer extends EventEmitter {
  constructor({ bind, port = 53, erlaubt, filter, upstream, lokal, records, geraete, bremse = { rate: 100, schub: 300 }, sperrseite = () => false, jetzt = () => Date.now() }) {
    super();
    Object.assign(this, { bind, port, erlaubt, filter, upstream, lokal, records, geraete, bremse, sperrseite, jetzt });
    this.eimer = new Map();
    this.zaehler = { anfragen: 0, geblockt: 0, abgewiesen: 0, gebremst: 0, fehler: 0, sperrseite: 0 };
    this.udp = null; this.tcp = null; this.gestartet = 0;
  }
  async starten() {
    await new Promise((ok, nein) => {
      this.udp = dgram.createSocket({ type: net.isIPv6(this.bind) ? 'udp6' : 'udp4', reuseAddr: false });
      this.udp.on('error', (e) => { if (!this.gestartet) nein(e); else this.emit('warnung', `UDP: ${e.message}`); });
      this.udp.on('message', (buf, rinfo) => {
        this.bearbeite(buf, rinfo.address, true).then((antwort) => { if (antwort) this.udp.send(antwort, rinfo.port, rinfo.address); }).catch((e) => this.emit('warnung', e.message));
      });
      this.udp.bind(this.port, this.bind, ok);
    });
    await new Promise((ok, nein) => {
      this.tcp = net.createServer((sock) => this.tcpVerbindung(sock));
      this.tcp.on('error', nein);
      this.tcp.listen(this.port, this.bind, ok);
    });
    this.gestartet = this.jetzt();
    setInterval(() => { const grenze = this.jetzt() - 60000; for (const [ip, e] of this.eimer) if (e.zeit < grenze) this.eimer.delete(ip); }, 60000).unref();
  }
  stoppen() { try { this.udp?.close(); } catch (e) {} try { this.tcp?.close(); } catch (e) {} }
  tcpVerbindung(sock) {
    let puffer = Buffer.alloc(0);
    sock.setTimeout(10000, () => sock.destroy());
    sock.on('error', () => {});
    sock.on('data', (d) => {
      puffer = Buffer.concat([puffer, d]);
      if (puffer.length > 70000) return sock.destroy();
      while (puffer.length >= 2) {
        const laenge = puffer.readUInt16BE(0);
        if (puffer.length < 2 + laenge) break;
        const nachricht = puffer.subarray(2, 2 + laenge); puffer = puffer.subarray(2 + laenge);
        this.bearbeite(nachricht, sock.remoteAddress, false).then((antwort) => {
          if (!antwort || sock.destroyed) return;
          const kopf = Buffer.alloc(2); kopf.writeUInt16BE(antwort.length); sock.write(Buffer.concat([kopf, antwort]));
        }).catch(() => {});
      }
    });
  }
  bremseErlaubt(ip) {
    if (ip === this.bind || ip === '127.0.0.1') return true;   // eigene Adresse (Selbsttest, Lastprobe auf dem NAS) nie bremsen
    const jetzt = this.jetzt(), e = this.eimer.get(ip) || { marken: this.bremse.schub, zeit: jetzt };
    e.marken = Math.min(this.bremse.schub, e.marken + (jetzt - e.zeit) / 1000 * this.bremse.rate); e.zeit = jetzt;
    const ok = e.marken >= 1; if (ok) e.marken -= 1;
    this.eimer.set(ip, e);
    return ok;
  }
  // Gesperrte Seiten führen auf die Sperrseite dieser Instanz. Werbung bleibt bei 0.0.0.0, sonst stünde der Hinweis mitten in fremden Seiten.
  sperrIp(e) {
    if (e.seite === false || !this.sperrseite()) return null;
    this.zaehler.sperrseite++;
    return this.bind;
  }
  melde(eintrag) { this.emit('anfrage', eintrag); }
  async bearbeite(buf, adresse, udp) {
    const start = process.hrtime.bigint(), ip = normIp(adresse), ms = () => Math.round(Number(process.hrtime.bigint() - start) / 1e4) / 100;
    let anfrage;
    try { anfrage = paket.lesen(buf); } catch (e) { return null; }
    if (!anfrage.frage) return paket.antwort(anfrage, { rcode: 'FORMERR' });
    const f = anfrage.frage;
    if (!this.erlaubt.enthaelt(ip)) { this.zaehler.abgewiesen++; return paket.antwort(anfrage, { rcode: 'REFUSED' }); }
    if (f.name === GESUNDHEIT) return paket.antwort(anfrage, { aa: true, answers: [{ name: f.name, type: 'TXT', class: 'IN', ttl: 0, data: ['ok'] }] });
    this.zaehler.anfragen++;
    const geraet = this.geraete.von(ip);
    const basis = { ts: this.jetzt(), ip, geraet: geraet.id, geraetName: geraet.name, domain: f.name, typ: f.typ };
    if (!this.bremseErlaubt(ip)) {
      this.zaehler.gebremst++;
      if (this.zaehler.gebremst % 50 === 1) this.melde({ ...basis, aktion: 'gebremst', grund: 'zu viele Anfragen', ms: ms() });
      return paket.antwort(anfrage, { rcode: 'REFUSED' });
    }
    if (KANARIE.has(f.name)) { this.melde({ ...basis, aktion: 'geblockt', grund: 'DoH-Kanarie', ms: ms() }); return paket.antwort(anfrage, { rcode: 'NXDOMAIN' }); }
    // Lokale Records (Split-Horizon): bestimmte Namen direkt auf eine interne IP – vor der Gateway-Zone und dem Upstream, nie gefiltert.
    // Andere Typen oder fehlender passender Eintrag (z. B. AAAA, nur A hinterlegt) → NOERROR ohne Antwort, damit der Name NICHT ins Internet geht.
    if (this.records && !this.records.leer) {
      const rec = this.records.treffer(f.name);
      if (rec) {
        const answers = f.typ === 'A' && rec.a ? [{ name: f.name, type: 'A', class: 'IN', ttl: this.records.ttl, data: rec.a }]
          : f.typ === 'AAAA' && rec.aaaa ? [{ name: f.name, type: 'AAAA', class: 'IN', ttl: this.records.ttl, data: rec.aaaa }]
          : [];
        this.melde({ ...basis, aktion: 'lokal', grund: 'Lokaler Eintrag', ms: ms() });
        return paket.antwort(anfrage, { aa: true, answers });
      }
    }
    // Heimnetz-Namen und Rückwärtsauflösung privater Netze: Gateway fragen, Antwort unverändert
    if (this.lokal.zustaendig(f.name)) {
      try {
        const antwort = await this.lokal.frage(buf);
        this.melde({ ...basis, aktion: 'lokal', grund: 'Gateway', ms: ms() });
        return paket.fuerClient(antwort, anfrage, { udp }) || antwort;
      } catch (e) {
        this.zaehler.fehler++; this.melde({ ...basis, aktion: 'fehler', grund: e.message, ms: ms() });
        return paket.antwort(anfrage, { rcode: 'SERVFAIL' });
      }
    }
    const e = this.filter.entscheide({ geraetId: geraet.id, name: f.name });
    if (e.aktion === 'geblockt') {
      this.zaehler.geblockt++;
      this.melde({ ...basis, aktion: 'geblockt', grund: e.grund, listen: e.listen, regel: e.regel, dienst: e.dienstName, kategorie: e.kategorie, profil: e.profil, ms: ms() });
      return paket.sperrAntwort(anfrage, this.sperrIp(e));
    }
    let r;
    // Was der Betreiber ausdrücklich freigibt, darf auch ein filternder DoH-Anbieter nicht sperren
    const ungefiltert = e.grund === 'Geschützter Dienst' || e.grund === 'Freigabe';
    try { r = await this.upstream.frage(anfrage, paket.upstreamAnfrage(anfrage), { ungefiltert }); } catch (err) {
      this.zaehler.fehler++; this.melde({ ...basis, aktion: 'fehler', grund: err.message, profil: e.profil, ms: ms() });
      return paket.antwort(anfrage, { rcode: 'SERVFAIL' });
    }
    // CNAME-Tarnung: harmlose Domain zeigt auf einen gelisteten Tracker (nicht bei Pause/Freigabe – auch nicht, wenn die Domain nur auf einer Freigabeliste steht)
    if (!['Pause', 'Freigabe', 'Freigabeliste', 'auf Freigabeliste', 'Geschützter Dienst'].includes(e.grund)) {
      // Eine Dienst-Sperre gilt dem Dienst, nicht fremden Diensten auf derselben Infrastruktur: ecs.office.com (Microsoft 365) läuft per CNAME
      // über mira.config.skype.com und svc.ha-teams.office.com (Teams). Wäre der eigene Dienst gesperrt, hätte schon der Filter oben geblockt.
      const eigenerDienst = this.filter.dienstVon(f.name);
      for (const ziel of paket.cnameZiele(r.buf)) {
        const z = this.filter.entscheide({ geraetId: geraet.id, name: ziel });
        if (z.aktion === 'geblockt' && z.grund === 'Dienst gesperrt' && eigenerDienst) continue;
        if (z.aktion === 'geblockt') {
          this.zaehler.geblockt++;
          this.melde({ ...basis, aktion: 'geblockt', grund: 'CNAME-Tarnung', cname: ziel, listen: z.listen, regel: z.regel, kategorie: z.kategorie, profil: e.profil, ms: ms() });
          return paket.sperrAntwort(anfrage, this.sperrIp(z));
        }
      }
    }
    const antwort = paket.fuerClient(r.buf, anfrage, { alterSek: r.alterSek, udp });
    if (!antwort) { this.zaehler.fehler++; return paket.antwort(anfrage, { rcode: 'SERVFAIL' }); }
    this.melde({ ...basis, aktion: 'erlaubt', grund: ['Pause', 'Freigabe', 'Freigabeliste', 'Geschützter Dienst'].includes(e.grund) ? e.grund : '', regel: e.regel, dienst: e.dienstName, listen: e.grund === 'Freigabeliste' ? e.listen : undefined, profil: e.profil, cache: r.cache, anbieter: r.anbieter, rcode: paket.rcodeVon(r.buf), ms: ms() });
    return antwort;
  }
  status() { return { bind: this.bind, port: this.port, laeuft: !!this.gestartet, seit: this.gestartet, zaehler: this.zaehler, erlaubteNetze: this.erlaubt.texte, schleifeMs: this.schleife?.() || null }; }
}

module.exports = { DnsServer, GESUNDHEIT };
