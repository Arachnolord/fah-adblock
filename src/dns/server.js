// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// DNS-Server (UDP + TCP) auf genau einer Adresse. Ablauf je Anfrage:
// Zugang (nur erlaubte Netze) → Bremse je Client → lokale Zone? → Filter → Upstream → CNAME-Prüfung.
// Unterwegs (DoT/DoH, src/unterwegs.js) kommen Anfragen mit `kontext` {extern, geraet}: das Gerät ist über seine Kennung
// bekannt, nicht über die IP; Heimnetz-Namen (lokale Records, private Rückwärtszonen) gibt es von draußen nicht.
'use strict';
const dgram = require('dgram');
const net = require('net');
const { EventEmitter } = require('events');
const paket = require('./paket');
const { normIp } = require('../netz');

const GESUNDHEIT = 'health.fah-adblock';
const KANARIE = new Set(['use-application-dns.net']);   // Firefox: netzweiten Blocker respektieren (kein eigenes DoH)

class DnsServer extends EventEmitter {
  constructor({ bind, port = 53, erlaubt, filter, upstream, lokal, records, geraete, bremse = { rate: 100, schub: 300 }, sperrseite = () => false, jetzt = () => Date.now(), zeitkonto = null }) {
    super();
    Object.assign(this, { bind, port, erlaubt, filter, upstream, lokal, records, geraete, bremse, sperrseite, jetzt, zeitkonto });
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
    if (ip === this.bind || ip === '127.0.0.1') return true;
    return this.bremseSchluessel(ip);
  }
  bremseSchluessel(ip) {   // eigene Adresse (Selbsttest, Lastprobe auf dem NAS) nie bremsen
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
  async bearbeite(buf, adresse, udp, kontext = null) {
    const start = process.hrtime.bigint(), ip = normIp(adresse), ms = () => Math.round(Number(process.hrtime.bigint() - start) / 1e4) / 100;
    let anfrage;
    try { anfrage = paket.lesen(buf); } catch (e) { return null; }
    // Antworten (QR=1) nie beantworten – sonst spielen sich zwei Resolver mit gefälschtem Absender endlos Pingpong (25.11.2026)
    if (anfrage.antwort) return null;
    const extern = !!kontext?.extern;
    // Fremde Netze bekommen nur REFUSED – auch keine FORMERR/NOTIMP mehr, damit kaputte Pakete von außen nichts auslösen
    if (!extern && !this.erlaubt.enthaelt(ip)) { this.zaehler.abgewiesen++; return paket.antwort(anfrage, { rcode: 'REFUSED' }); }
    if (anfrage.opcode !== 'QUERY') return paket.antwort(anfrage, { rcode: 'NOTIMP' });
    // genau eine Frage: gefiltert und zwischengespeichert wird nur die erste, eine zweite liefe sonst ungeprüft nach oben
    if (!anfrage.frage || anfrage.fragen !== 1) return paket.antwort(anfrage, { rcode: 'FORMERR' });
    const f = anfrage.frage;
    if (f.name === GESUNDHEIT) return paket.antwort(anfrage, { aa: true, answers: [{ name: f.name, type: 'TXT', class: 'IN', ttl: 0, data: ['ok'] }] });
    this.zaehler.anfragen++;
    if (extern) this.zaehler.unterwegs = (this.zaehler.unterwegs || 0) + 1;
    const geraet = kontext?.geraet ? { ...kontext.geraet, ip } : this.geraete.von(ip);
    // Unterwegs: keine öffentliche IP des Kindes im Protokoll (Datensparsamkeit)
    const basis = { ts: this.jetzt(), ip: extern ? 'unterwegs' : ip, geraet: geraet.id, geraetName: geraet.name, domain: f.name, typ: f.typ };
    // Bremse unterwegs je Quell-IP UND je Gerät+IP – ein Fremder mit dem (öffentlich auffindbaren) Gerätenamen leert nicht die Bremse des Kindes
    if (!(extern ? this.bremseSchluessel(`extip:${ip}`) && this.bremseSchluessel(`ext:${geraet.id}|${ip}`) : this.bremseErlaubt(ip))) {
      this.zaehler.gebremst++;
      if (this.zaehler.gebremst % 50 === 1) this.melde({ ...basis, aktion: 'gebremst', grund: 'zu viele Anfragen', ms: ms() });
      return paket.antwort(anfrage, { rcode: 'REFUSED' });
    }
    if (KANARIE.has(f.name)) { this.melde({ ...basis, aktion: 'geblockt', grund: 'DoH-Kanarie', ms: ms() }); return paket.antwort(anfrage, { rcode: 'NXDOMAIN' }); }
    // Lokale Records (Split-Horizon): bestimmte Namen direkt auf eine interne IP – vor der Gateway-Zone und dem Upstream, nie gefiltert.
    // Andere Typen oder fehlender passender Eintrag (z. B. AAAA, nur A hinterlegt) → NOERROR ohne Antwort, damit der Name NICHT ins Internet geht.
    // Von draußen: private Namen und Rückwärtszonen gibt es nicht, alles andere (auch die eigene Domain) geht ins Internet
    if (extern && this.lokal.zustaendig(f.name) && /(^|\.)(arpa|lan|local|localdomain|internal|home)$/.test(f.name)) {
      this.melde({ ...basis, aktion: 'lokal', grund: 'Heimnetz-Name (unterwegs)', ms: ms() });
      return paket.antwort(anfrage, { rcode: 'NXDOMAIN' });
    }
    if (!extern && this.records && !this.records.leer) {
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
    if (!extern && this.lokal.zustaendig(f.name)) {
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
      return paket.sperrAntwort(anfrage, extern ? null : this.sperrIp(e));
    }
    // Sichere Suche: Google/Bing/DuckDuckGo/YouTube auf die gefilterte Fassung des Anbieters umlenken (CNAME + deren Adressen)
    const sicher = e.grund === 'Pause' ? null : this.filter.sicherZiel(geraet.id, f.name);
    if (sicher) return this.sichereSuche(anfrage, f, sicher, { ...basis, profil: e.profil }, ms);
    let r;
    // Was der Betreiber ausdrücklich freigibt, darf auch ein filternder DoH-Anbieter nicht sperren
    const ungefiltert = e.grund === 'Geschützter Dienst' || e.grund === 'Freigabe' || e.grund === 'Hilfsangebot';
    try { r = await this.upstream.frage(anfrage, paket.upstreamAnfrage(anfrage), { ungefiltert }); } catch (err) {
      this.zaehler.fehler++; if (e.grund !== 'Hilfsangebot') this.melde({ ...basis, aktion: 'fehler', grund: err.message, profil: e.profil, ms: ms() });   // Hilfsangebote nie ins Protokoll, auch nicht als Fehler
      return paket.antwort(anfrage, { rcode: 'SERVFAIL' });
    }
    // Rcode zuerst (25.11.2026): erweiterter Rcode vom Upstream (BADVERS, BADCOOKIE …) betrifft UNSERE Anfrage nach oben, nicht die des Clients – und
    // ginge bei Clients ohne EDNS als NOERROR durch (das OPT mit den oberen Bits fällt dort weg) → SERVFAIL. Andere Fehler (SERVFAIL/REFUSED, wenn alle
    // Anbieter so antworten) gehen unverändert weiter – ohne CNAME-Prüfung und ohne Zeitkonto (es wurde nichts aufgelöst).
    const rcOben = paket.rcodeVon(r.buf), fehlerOben = rcOben !== paket.RCODE.NOERROR && rcOben !== paket.RCODE.NXDOMAIN;
    if (rcOben > 15) { this.zaehler.fehler++; if (e.grund !== 'Hilfsangebot') this.melde({ ...basis, aktion: 'fehler', grund: 'Upstream-Fehler (erweiterter Rcode)', profil: e.profil, ms: ms() }); return paket.antwort(anfrage, { rcode: 'SERVFAIL' }); }
    // CNAME-Tarnung: harmlose Domain zeigt auf einen gelisteten Tracker (nicht bei Pause/Freigabe – auch nicht, wenn die Domain nur auf einer Freigabeliste steht)
    if (!fehlerOben && !['Pause', 'Freigabe', 'Freigabeliste', 'auf Freigabeliste', 'Geschützter Dienst', 'Hilfsangebot'].includes(e.grund)) {
      // Eine Dienst-Sperre gilt dem Dienst, nicht fremden Diensten auf derselben Infrastruktur: ecs.office.com (Microsoft 365) läuft per CNAME
      // über mira.config.skype.com und svc.ha-teams.office.com (Teams). Wäre der eigene Dienst gesperrt, hätte schon der Filter oben geblockt.
      const eigenerDienst = this.filter.dienstVon(f.name);
      for (const ziel of paket.cnameZiele(r.buf)) {
        const z = this.filter.entscheide({ geraetId: geraet.id, name: ziel });
        if (z.aktion === 'geblockt' && z.grund === 'Dienst gesperrt' && eigenerDienst) continue;
        if (z.aktion === 'geblockt') {
          this.zaehler.geblockt++;
          this.melde({ ...basis, aktion: 'geblockt', grund: 'CNAME-Tarnung', cname: ziel, listen: z.listen, regel: z.regel, kategorie: z.kategorie, profil: e.profil, ms: ms() });
          return paket.sperrAntwort(anfrage, extern ? null : this.sperrIp(z));
        }
      }
    }
    // Zeitlimit: Nutzung vermerken; Antworten kurz halten (60 s), damit eine Sperre nach Ablauf schnell greift
    let maxTtl = 0;
    if (this.zeitkonto && e.grund !== 'Pause' && !fehlerOben) {
      const profil = this.filter.profilVon(geraet.id), dienst = profil.limits ? this.filter.dienstVon(f.name) : null;
      const ziele = dienst ? this.filter.limitZiele(profil, dienst, f.name) : [];
      if (ziele.length) { this.zeitkonto.vermerke(geraet.id, ziele, basis.ts); maxTtl = 60; }
    }
    // Ruhezeit/Zeitplan beginnt bald (K15): Antwort nicht über den Beginn hinaus im Gerät gültig lassen
    if (e.grund !== 'Pause' && e.grund !== 'Hilfsangebot' && !fehlerOben && this.filter.ttlDeckel) { const deckel = this.filter.ttlDeckel(geraet.id, f.name, basis.ts); if (deckel) maxTtl = maxTtl ? Math.min(maxTtl, deckel) : deckel; }
    // Unterwegs ohne Alterung der TTL: sonst verriete eine sinkende TTL, welche Namen zu Hause gerade aufgerufen wurden
    const antwort = paket.fuerClient(r.buf, anfrage, { alterSek: extern ? 0 : r.alterSek, udp, maxTtl: extern ? (maxTtl || 300) : maxTtl });
    if (!antwort) { this.zaehler.fehler++; return paket.antwort(anfrage, { rcode: 'SERVFAIL' }); }
    // Hilfsangebote vertraulich: keine Zeile im Protokoll, im Livestrom, in Statistik oder Rettung
    if (e.grund === 'Hilfsangebot') return antwort;
    this.melde({ ...basis, aktion: 'erlaubt', grund: ['Pause', 'Freigabe', 'Freigabeliste', 'Geschützter Dienst', 'Hilfsangebot'].includes(e.grund) ? e.grund : '', regel: e.regel, dienst: e.dienstName, listen: e.grund === 'Freigabeliste' ? e.listen : undefined, profil: e.profil, cache: r.cache, anbieter: r.anbieter, rcode: paket.rcodeVon(r.buf), ms: ms() });
    return antwort;
  }
  // Umlenkung auf die sichere Fassung: Adressen des Ziels beim Upstream holen und unter dem gefragten Namen als CNAME-Kette ausliefern.
  // HTTPS/SVCB und andere Typen bekommen eine leere Antwort – sonst brächten sie Adressen/ECH der ungefilterten Fassung mit.
  async sichereSuche(anfrage, f, ziel, basis, ms) {
    const typ = f.typ === 'A' || f.typ === 'AAAA' ? f.typ : null;
    let answers = [];
    if (typ) {
      try {
        const q = paket.lesen(paket.dnsPacket.encode({ type: 'query', id: 0, flags: paket.dnsPacket.RECURSION_DESIRED, questions: [{ type: typ, name: ziel, class: 'IN' }] }));
        const r = await this.upstream.frage(q, paket.upstreamAnfrage(q), { ungefiltert: true });
        const rcZiel = paket.rcodeVon(r.buf);
        if (rcZiel !== paket.RCODE.NOERROR) throw new Error(`Upstream-Fehler ${rcZiel} für ${ziel}`);
        const p = paket.dnsPacket.decode(r.buf);
        const adressen = (p.answers || []).filter((x) => x.type === typ);
        if (!adressen.length) throw new Error(`keine ${typ}-Adresse für ${ziel}`);
        answers = [{ name: f.name, type: 'CNAME', class: 'IN', ttl: 300, data: ziel }, ...adressen.map((x) => ({ name: ziel, type: typ, class: 'IN', ttl: Math.min(300, x.ttl || 300), data: x.data }))];
      } catch (err) {
        this.zaehler.fehler++; this.melde({ ...basis, aktion: 'fehler', grund: `Sichere Suche: ${err.message}`, ms: ms() });
        return paket.antwort(anfrage, { rcode: 'SERVFAIL' });
      }
    }
    this.melde({ ...basis, aktion: 'erlaubt', grund: 'Sichere Suche', anbieter: ziel, ms: ms() });
    return paket.antwort(anfrage, { answers });
  }
  status() { return { bind: this.bind, port: this.port, laeuft: !!this.gestartet, seit: this.gestartet, zaehler: this.zaehler, erlaubteNetze: this.erlaubt.texte, schleifeMs: this.schleife?.() || null }; }
}

module.exports = { DnsServer, GESUNDHEIT };
