#!/usr/bin/env node
// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// ============================================================================
// Kernprobe (ohne Netz): Netze, Listen-Parser, Filter (Pause, Freigabe, Sperre, Profile,
// Zeitpläne über Mitternacht), DNS-Pakete (Sperrantwort, Kürzen, TTL, CNAME), Upstream
// (Zwischenspeicher, Rückfall), DNS-Server-Ablauf (Zugang, Bremse, lokale Zone, CNAME-Tarnung,
// SERVFAIL), Protokoll (Summen, Rettung), Anmeldung, Einstellungen und die Web-API (CSRF, 401).
// Aufruf: node tools/kernprobe.mjs
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import http2 from 'node:http2';
import dgram from 'node:dgram';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
process.env.TZ = 'Europe/Berlin';
const { netzliste, normIp, normDomain } = require('../src/netz.js');
const { Listen, parse } = require('../src/dns/listen.js');
const { Filter, zeitplanAktiv, sekundenBisStart, musterLesen } = require('../src/dns/filter.js');
const paket = require('../src/dns/paket.js');
const { Upstream, DohAnbieter, Lokal } = require('../src/dns/upstream.js');
const { DnsServer } = require('../src/dns/server.js');
const { Records } = require('../src/dns/records.js');
const { Protokoll } = require('../src/protokoll.js');
const { Geraete, clientName } = require('../src/geraete.js');
const { Auth } = require('../src/auth.js');
const { Einstellungen, bereinigen, vorgaben, verschluesseln, entschluesseln } = require('../src/einstellungen.js');
const { webServer, liveSenden } = require('../src/web/server.js');
const { Spiegel } = require('../src/spiegel.js');
const { Benachrichtigung, pushVerschluesseln, vapidKopf, endpunktOk } = require('../src/benachrichtigung.js');
const { Meldungen } = require('../src/meldungen.js');
const nodeCrypto = require('node:crypto');
const dnsPacket = require('dns-packet');

const ergebnisse = [];
const pruefe = (name, ok, detail = '') => { ergebnisse.push(!!ok); console.log(`${ok ? 'OK  ' : 'FEHL'} ${name}${detail && !ok ? ' – ' + detail : ''}`); };
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fah-adblock-kern-'));
const frage = (name, type = 'A', { edns = true, id = 4711 } = {}) => dnsPacket.encode({ type: 'query', id, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type, name }], additionals: edns ? [{ type: 'OPT', name: '.', udpPayloadSize: 1232 }] : [] });

try {
  // ── Netze ────────────────────────────────────────────────────────────────
  const n = netzliste(['192.168.1.0/24', '192.168.5.0/24', 'fd00::/8', '127.0.0.1/32']);
  pruefe('Netze: IPv4/IPv6, IPv4-mapped, fremde Adressen abgelehnt', n.enthaelt('192.168.1.117') && n.enthaelt('::ffff:192.168.5.2') && n.enthaelt('fd71:6e97::3') && !n.enthaelt('10.0.20.5') && !n.enthaelt('8.8.8.8') && normIp('::FFFF:192.168.1.1') === '192.168.1.1');
  pruefe('Domains: normalisiert, IPs und Unsinn abgelehnt', normDomain('Ads.Example.COM.') === 'ads.example.com' && !normDomain('1.2.3.4') && !normDomain('a..b') && !normDomain('x y.de'));

  // ── Listen ───────────────────────────────────────────────────────────────
  const { domains } = parse(['# Kommentar', '0.0.0.0 ads.example.com', '127.0.0.1 tracker.example.net # hinten', '||adblock.example.org^', '||opt.example.org^$third-party', '*.wild.example.de', 'plain.example.io', '@@||ausnahme.example.com^', '0.0.0.0 localhost', 'ungültig domain', '::1 ip6-localhost', ''].join('\n'));
  pruefe('Listen-Parser: hosts, AdBlock, Wildcard, reine Domains; localhost/Ausnahmen/Unsinn ignoriert', ['ads.example.com', 'tracker.example.net', 'adblock.example.org', 'opt.example.org', 'wild.example.de', 'plain.example.io'].every((d) => domains.has(d)) && !domains.has('ausnahme.example.com') && !domains.has('localhost') && domains.size === 6, [...domains].join(','));
  const lv = path.join(tmp, 'listen'); fs.mkdirSync(path.join(lv, 'listen'), { recursive: true });
  const holer = async (url) => ({ text: url.includes('werbung') ? 'ads.example.com\ndoubleclick.net\n' + Array.from({ length: 20 }, (_, i) => `ad${i}.example.com`).join('\n') : url.includes('social') ? 'facebook.com\ninstagram.com\n' + Array.from({ length: 10 }, (_, i) => `s${i}.social.de`).join('\n') : 'kaputt', geaendert: 1 });
  const listen = new Listen({ verzeichnis: lv, holer, protokoll: () => {} });
  const QUELLEN = [{ id: 'w', name: 'Werbung', url: 'https://x/werbung', kategorie: 'werbung', an: true }, { id: 's', name: 'Social', url: 'https://x/social', kategorie: 'social', an: true }, { id: 'k', name: 'Kaputt', url: 'https://x/kaputt', kategorie: 'werbung', an: true }];
  listen.konfigurieren(QUELLEN); listen.laden();
  const erg = await listen.aktualisieren();
  pruefe('Listen: laden, zu kleine Liste verworfen (Fehler an der Liste)', listen.index.size === 34 && /verworfen/.test(erg.k) && listen.status().quellen.find((q) => q.id === 'k').fehler);
  pruefe('Listen: Treffer gelten für Subdomains, nicht für Nachbarn', listen.treffer('x.y.doubleclick.net').join() === 'w' && listen.treffer('notdoubleclick.net').length === 0 && listen.treffer('www.facebook.com').join() === 's');

  // ── Freigabelisten ───────────────────────────────────────────────────────
  const fr = parse(['@@|www3.doubleclick.net^|', '@@||kurz.example.org^', '1drv.com', '@@||*cdn.x.com^', '*.alle.example.net'].join('\n'), { art: 'erlauben' });
  pruefe('Freigabeliste: reine Domains und |x^| genau, ||x^ und *.x mit Subdomains, * mitten im Namen übersprungen', [...fr.exakt].sort().join() === '1drv.com,www3.doubleclick.net' && [...fr.domains].sort().join() === 'alle.example.net,kurz.example.org' && fr.ungueltig === 1);
  pruefe('Blockliste ignoriert Ausnahmezeilen (@@)', parse('@@||frei.de^\nsperr.de').domains.size === 1);

  const T = Date.UTC(2026, 8, 16, 18, 30);   // Mi 20:30 in Berlin
  let jetzt = T;
  const filter = new Filter({ listen, jetzt: () => jetzt, zeitzone: 'Europe/Berlin' });
  const profile = [
    { id: 'standard', kategorien: { werbung: { an: true, zeitplan: [] } } },
    { id: 'kinder', kategorien: { werbung: { an: true, zeitplan: [] }, social: { an: true, zeitplan: [{ tage: [1, 2, 3, 4, 5, 6, 7], von: '20:00', bis: '07:00' }] } } },
  ];
  const basis = { profile, listen: QUELLEN, geraete: { kind: { profil: 'kinder' } }, pausen: { global: 0, geraete: {} } };
  filter.konfigurieren({ ...basis, regeln: [] });
  pruefe('Filter: Werbung geblockt (Standard), Social erlaubt, unbekanntes Gerät = Standard', filter.entscheide({ geraetId: 'x', name: 'ads.example.com' }).aktion === 'geblockt' && filter.entscheide({ geraetId: 'x', name: 'facebook.com' }).aktion === 'erlaubt');
  {
    // 25.11.2026 (K15): TTL-Deckel vor einem Sperrfenster – Kinder-Profil sperrt Social 20:00–07:00 (Liste „s“)
    const tag = (h, m) => Date.UTC(2026, 8, 16, h - 2, m);   // Mi in Berlin (Sommerzeit, UTC+2)
    const vorher = filter.ttlDeckel('kind', 'www.facebook.com', tag(19, 55)), mittags = filter.ttlDeckel('kind', 'www.facebook.com', tag(12, 0)), standard = filter.ttlDeckel('x', 'www.facebook.com', tag(19, 55)), ungelistet = filter.ttlDeckel('kind', 'seite.de', tag(19, 55));
    const woche = sekundenBisStart([{ tage: [1], von: '01:00', bis: '02:00' }], Date.UTC(2026, 8, 20, 21, 0), 'Europe/Berlin');   // So 23:00 → Mo 01:00
    const ganzTag = sekundenBisStart([{ tage: [4], von: '00:00', bis: '00:00' }], tag(23, 0), 'Europe/Berlin');                // Mi 23:00 → Do 00:00
    pruefe('TTL-Deckel (K15): erlaubte Social-Antwort 5 min vor Sperrbeginn höchstens 300 s, mittags bis zum Abend; ohne Zeitplan/ungelistet kein Deckel; Fenster über Wochenwechsel und ganztägig',
      vorher === 300 && mittags === 8 * 3600 && standard === 0 && ungelistet === 0 && woche === 7200 && ganzTag === 3600, JSON.stringify({ vorher, mittags, standard, ungelistet, woche, ganzTag }));
  }
  pruefe('Sperrseite: Kinder-Sperre zählt, unbekannte Domain nicht', !!filter.sperrgrund('facebook.com') && filter.sperrgrund('harmlos-unbekannt.example') === null);
  pruefe('Filter: Kinder-Profil sperrt Social um 20:30', filter.entscheide({ geraetId: 'kind', name: 'facebook.com' }).aktion === 'geblockt');
  jetzt = Date.UTC(2026, 8, 17, 4, 30);      // Do 06:30 – Fenster vom Vortag läuft noch
  pruefe('Zeitplan über Mitternacht: 06:30 noch gesperrt', filter.entscheide({ geraetId: 'kind', name: 'facebook.com' }).aktion === 'geblockt');
  jetzt = Date.UTC(2026, 8, 17, 10, 0);      // Do 12:00
  pruefe('Zeitplan: 12:00 erlaubt', filter.entscheide({ geraetId: 'kind', name: 'facebook.com' }).aktion === 'erlaubt');
  pruefe('Zeitplan: nur an gewählten Tagen, Fenster ohne Mitternacht', zeitplanAktiv([{ tage: [6, 7], von: '09:00', bis: '12:00' }], Date.UTC(2026, 8, 19, 8, 0), 'Europe/Berlin') && !zeitplanAktiv([{ tage: [6, 7], von: '09:00', bis: '12:00' }], Date.UTC(2026, 8, 18, 8, 0), 'Europe/Berlin'));
  jetzt = T;
  filter.konfigurieren({ ...basis, regeln: [
    { id: 'r1', typ: 'erlauben', muster: 'ads.example.com', geltung: 'geraet:mac1', bis: null },
    { id: 'r2', typ: 'sperren', muster: '*.sperr.de', geltung: 'alle', bis: null },
    { id: 'r3', typ: 'sperren', muster: 'weg.de', geltung: 'profil:kinder', bis: null },
    { id: 'r4', typ: 'erlauben', muster: 'doubleclick.net', geltung: 'alle', bis: T - 1 },
  ] });
  pruefe('Freigabe nur für das Gerät, andere bleiben gesperrt', filter.entscheide({ geraetId: 'mac1', name: 'ads.example.com' }).grund === 'Freigabe' && filter.entscheide({ geraetId: 'mac2', name: 'ads.example.com' }).aktion === 'geblockt');
  pruefe('„*.sperr.de“ sperrt Subdomains, nicht die Domain selbst', filter.entscheide({ name: 'a.sperr.de' }).aktion === 'geblockt' && filter.entscheide({ name: 'sperr.de' }).aktion === 'erlaubt');
  pruefe('Profil-Regel gilt nur im Profil; abgelaufene Freigabe wirkt nicht', filter.entscheide({ geraetId: 'kind', name: 'x.weg.de' }).aktion === 'geblockt' && filter.entscheide({ geraetId: 'y', name: 'weg.de' }).aktion === 'erlaubt' && filter.entscheide({ name: 'doubleclick.net' }).aktion === 'geblockt');
  filter.konfigurieren({ ...basis, regeln: [], pausen: { global: 0, geraete: { mac9: T + 60000 } } });
  pruefe('Pause je Gerät: dieses Gerät ungefiltert, andere nicht', filter.entscheide({ geraetId: 'mac9', name: 'ads.example.com' }).grund === 'Pause' && filter.entscheide({ geraetId: 'mac8', name: 'ads.example.com' }).aktion === 'geblockt');
  filter.konfigurieren({ ...basis, regeln: [], pausen: { global: T + 60000, geraete: {} } });
  pruefe('Globale Pause und automatisches Ende', filter.entscheide({ name: 'ads.example.com' }).grund === 'Pause' && filter.entscheide({ name: 'ads.example.com', jetzt: T + 60001 }).aktion === 'geblockt');
  let fm = null; try { musterLesen('kein domain'); } catch (e) { fm = e.message; }
  pruefe('Regelmuster: ungültige Eingabe abgelehnt', /Keine gültige Domain/.test(fm || ''));
  {
    const di = require('../public/domaininfo.js');
    const t = (d) => di.beschreibe(d)?.text || '';
    pruefe('Domain-Info: bekannte Dienste mit Anbieter und Zweck, genauester Eintrag gewinnt', /^Microsoft Teams – Telemetrie/.test(t('eu-teams.events.data.microsoft.com')) && /^Google Marketing Platform/.test(t('p31190.doubleclick.net')) && /^New Relic/.test(t('bam.nr-data.net')) && /^Visual Studio App Center/.test(t('in.appcenter.ms')), t('eu-teams.events.data.microsoft.com'));
    pruefe('Domain-Info: Schlüsselwörter ergänzen („hier: …“), Produkt im Namen, Unbekanntes = null, Nachbar-Domain kein Treffer', /hier: Telemetrie/.test(t('euc-excel-telemetry.officeapps.live.com')) && !/hier:/.test(t('ad.doubleclick.net')) && /^Microsoft Excel/.test(t('euc-excel-telemetry.officeapps.live.com')) && /Anbieter unbekannt/.test(t('telemetry.irgendwas.co.uk')) && di.beschreibe('www.unbekannt-xyz.de') === null && di.beschreibe('notdoubleclick.net') === null && !!di.beschreibe('graph.facebook.com').hinweis);
  }
  filter.konfigurieren({ ...basis, regeln: [] });

  // Freigabeliste im Filter: hebt nur Werbe-Sperren auf, genau vs. Subdomains, eigene Sperre hat Vorrang
  const lvF = path.join(tmp, 'listenF'); fs.mkdirSync(lvF, { recursive: true });
  const holerF = async (url) => ({ text: url.includes('werbung') ? ['doubleclick.net', 'kaputt-app.example.com', 'tracker.example.com', ...Array.from({ length: 12 }, (_, i) => `w${i}.example.com`)].join('\n')
    : url.includes('boese') ? ['phish.example.com', 'doubleclick.net', ...Array.from({ length: 12 }, (_, i) => `b${i}.example.com`)].join('\n')
    : ['kaputt-app.example.com', '@@||tracker.example.com^', '@@|doubleclick.net^|', ...Array.from({ length: 12 }, (_, i) => `f${i}.example.org`)].join('\n') });
  const QF = [{ id: 'w', url: 'https://x/werbung', kategorie: 'werbung', an: true }, { id: 'b', url: 'https://x/boese', kategorie: 'schadsoftware', an: true }, { id: 'f', url: 'https://x/frei', kategorie: 'freigabe', an: true }];
  const listenF = new Listen({ verzeichnis: lvF, holer: holerF, protokoll: () => {} }); listenF.konfigurieren(QF); listenF.laden(); await listenF.aktualisieren();
  const filterF = new Filter({ listen: listenF, jetzt: () => T, zeitzone: 'Europe/Berlin' });
  filterF.konfigurieren({ profile: [{ id: 'standard', kategorien: { werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] } } }], listen: QF, geraete: {}, pausen: { global: 0, geraete: {} }, regeln: [] });
  pruefe('Freigabeliste hebt Werbesperre auf (genauer Eintrag)', filterF.entscheide({ name: 'kaputt-app.example.com' }).grund === 'Freigabeliste' && filterF.entscheide({ name: 'sub.kaputt-app.example.com' }).aktion === 'geblockt');
  pruefe('Freigabeliste mit ||domain^ gilt auch für Subdomains', filterF.entscheide({ name: 'a.tracker.example.com' }).grund === 'Freigabeliste');
  pruefe('Freigabeliste hebt KEINE Schadsoftware-Sperre auf (auch wenn zusätzlich Werbung)', filterF.entscheide({ name: 'doubleclick.net' }).aktion === 'geblockt' && filterF.entscheide({ name: 'doubleclick.net' }).kategorie);
  filterF.konfigurieren({ profile: [{ id: 'standard', kategorien: { werbung: { an: true, zeitplan: [] } } }], listen: QF, geraete: {}, pausen: { global: 0, geraete: {} }, regeln: [{ id: 'x', typ: 'sperren', muster: 'kaputt-app.example.com', geltung: 'alle' }] });
  pruefe('Eigene Sperrregel geht der Freigabeliste vor', filterF.entscheide({ name: 'kaputt-app.example.com' }).grund === 'Eigene Regel');
  const QF2 = [...QF.slice(0, 2), { id: 'eigen-abc', url: 'https://x/frei', kategorie: 'freigabe', an: true }];
  const lvF2 = path.join(tmp, 'listenF2'); fs.mkdirSync(lvF2, { recursive: true });
  const listenF2 = new Listen({ verzeichnis: lvF2, holer: holerF, protokoll: () => {} }); listenF2.konfigurieren(QF2); listenF2.laden(); await listenF2.aktualisieren();
  const filterF2 = new Filter({ listen: listenF2, jetzt: () => T, zeitzone: 'Europe/Berlin' });
  filterF2.konfigurieren({ profile: [{ id: 'standard', kategorien: { werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] } } }], listen: QF2, geraete: {}, pausen: { global: 0, geraete: {} }, regeln: [{ id: 'm', typ: 'erlauben', muster: 'b1.example.com', geltung: 'alle' }] });
  pruefe('Selbst hinzugefügte Freigabeliste hebt auch Nicht-Werbe-Sperren auf (z. B. Schadsoftware/Jugendschutz)', filterF2.entscheide({ name: 'doubleclick.net' }).grund === 'Freigabeliste');
  pruefe('Manuelle Freigabe (Regel) hebt jede Kategorie auf', filterF2.entscheide({ name: 'b1.example.com' }).grund === 'Freigabe');

  // ── Geschützte Dienste (Streaming & Medien) ─────────────────────────────
  {
    // Fall 19.09.2026: zwei „SmartTV“-Sperrlisten sperrten Samsung-Konto und Push → Fernseher ließ sich nicht mehr per Handy (SmartThings) bedienen
    const SAMSUNG_NOETIG = ['gld.push.samsungosp.com', 'auth2.samsungosp.com', 'account.samsung.com', 'api.smartthings.com', 'invitation.samsungiotcloud.com', 'api.samsungcloud.com', 'fc.samsungcloud.tv', 'vas.samsungapps.com', 'prd-euw1-ucs.aibixby.com'];
    const SAMSUNG_SPUREN = ['acr-eu-prd.samsungcloud.tv', 'log-ingestion-eu.samsungacr.com', 'ureca.samsungapps.com', 'smetrics.samsung.com'];
    // Betreiber-Vorgabe 21.09.2026: „Smart-TV-Grundfunktionen“ gilt für ALLE Hersteller – Hosts aus den SmartTV-Sperrlisten (Perflyst, hkamran80)
    const TV_NOETIG = ['de.nextlgsdp.com', 'ngfts.lge.com', 'us.service.lgtvcommon.com', 'bravia-cfgdst-ore-pro.bda.ndmdhs.com', 'ssm1.internet.sony.tv', 'bravia.dl.playstation.net', 'mhc-ajax-eu.myhomescreen.tv',
      'api.eu.hismarttv.com', 'deviceportal.nettvservices.com', 'ftv-smtv.ntp-fireos.com', 'androidtvchannels-pa.googleapis.com', 'api.roku.com', 'sso.internetat.tv'];
    const TV_SPUREN = ['collect-eu-fy2022.myhomescreen.tv', 'usage-us-fy2030.myhomescreen.tv', 'us.ad.lgsmartad.com', 'scribe.logs.roku.com', 'ad.nettvservices.com', 'acr-jp-prd.samsungcloud.tv', 'api.cid.samba.tv', 'log.internetat.tv', 'aic.cdpbeacon.lgtvcommon.com'];
    // Betreiber-Vorgabe 21.09.2026: beim Dienst „Microsoft Teams“ müssen ALLE Teams-Dienste frei sein – Hosts aus dem echten Protokoll (MacBook, iPhone, VPN)
    // und aus Microsofts Endpunktliste (endpoints.office.com, IDs 12/27/127): Anruf-Infrastruktur (früher Skype), Trouter, Relay, Konfiguration, Diagnosekanal, GIFs
    const TEAMS_NOETIG = ['teams.live.com', 'eu-teams.events.data.microsoft.com', 'teams.events.data.microsoft.com', 'us-teams.events.data.microsoft.com', 'eu-ic3.events.data.microsoft.com', 'eu-mobile.events.data.microsoft.com', 'teams.pipe.aria.microsoft.com',
      'config.edge.skype.com', 'emea.cc.skype.com', 'eu-api.asm.skype.com', 'trap.skype.com', 'api.flightproxy.skype.com', 'go-eu.trouter.teams.microsoft.com', '52-115-173-89.relay.teams.microsoft.com', 'gateway-eu.az.relay.teams.cloud.microsoft',
      'pub-ent-euno-13-t.trouter.communications.svc.cloud.microsoft', 'atm.teams.mira.tm.svc.cloud.microsoft', 'statics.teams.cdn.office.net', 'teams.office.com', 'svc.ms-acdc-teams.office.com', 'svc.ha-teams.office.com', 'teams-mrc-ww-perf.tm-4.office.com',
      'teams.nel.measure.office.net', 'partition-cname-trouter.pub-ent-euwe-14.ic3-edf-trouter.westeurope-prod.cosmic.office.net', 'teams.public.onecdn.static.microsoft', 'teamsinstaller.public.onecdn.static.microsoft',
      'api.flightproxy.teams.trafficmanager.net', 'config.teams.trafficmanager.net', 'euaz.msit.relay.teams.trafficmanager.net', 'config.edge.skype.com.trafficmanager.net', 'cc-emea-skype.trafficmanager.net', 'asm-api-golocal-geo-eu-teams.trafficmanager.net',
      'teams-events-data.trafficmanager.net', 'sipfed.online.lync.com', 'join.secure.skypeassets.com', 'media3.giphy.com'];
    const TEAMS_FREMD = ['watson.events.data.microsoft.com', 'vortex.data.microsoft.com', 'browser.events.data.microsoft.com', 'ads.giphy.com', 'giphy-analytics.giphy.com', 'bat.bing.com'];
    const OFFICE_DIAGNOSE = ['eu-office.events.data.microsoft.com', 'office.events.data.microsoft.com', 'eu.aria.events.data.trafficmanager.net', 'office-events-data.trafficmanager.net'];   // samt direkt abgefragter Zwischennamen
    const holerD = async (url) => ({ text: (url.includes('werbung') ? ['lcprd1.samsungcloudsolution.net', 'ichnaea.netflix.com', 'tvp-ads-log.samsungads.com', 'waipu.tv', 'notyoutube.com', ...SAMSUNG_NOETIG, ...SAMSUNG_SPUREN, ...TV_NOETIG, ...TV_SPUREN, ...TEAMS_NOETIG, ...TEAMS_FREMD, ...OFFICE_DIAGNOSE, 'dual-s-0005-office.config.skype.com'] : ['youtube.com', 'tiktok.com']).concat(Array.from({ length: 12 }, (_, i) => `f${i}.example.org`)).join('\n'), geaendert: T });
    const QD = [{ id: 'w', url: 'https://x/werbung', kategorie: 'werbung', an: true }, { id: 's', url: 'https://x/social', kategorie: 'social', an: true }];
    const lvD = path.join(tmp, 'listenD'); fs.mkdirSync(lvD, { recursive: true });
    const listenD = new Listen({ verzeichnis: lvD, holer: holerD, protokoll: () => {} }); listenD.konfigurieren(QD); listenD.laden(); await listenD.aktualisieren();
    const fD = new Filter({ listen: listenD, jetzt: () => T, zeitzone: 'Europe/Berlin' });
    const profileD = [{ id: 'standard', kategorien: { werbung: { an: true, zeitplan: [] } } }, { id: 'kinder', kategorien: { werbung: { an: true, zeitplan: [] }, social: { an: true, zeitplan: [] } } }];
    const basisD = { profile: profileD, listen: QD, geraete: { kind: { profil: 'kinder' } }, pausen: { global: 0, geraete: {} } };
    fD.konfigurieren({ ...basisD, regeln: [], dienste: {} });
    pruefe('Geschützte Dienste: Samsung-Verbindungsprüfung, Netflix und waipu auf Werbeliste → erlaubt; Samsung-Werbung bleibt geblockt; Nachbar-Domain kein Dienst',
      fD.entscheide({ name: 'lcprd1.samsungcloudsolution.net' }).grund === 'Geschützter Dienst' && fD.entscheide({ name: 'ichnaea.netflix.com' }).aktion === 'erlaubt' && fD.entscheide({ name: 'live.waipu.tv' }).dienst === 'waipu'
      && fD.entscheide({ name: 'tvp-ads-log.samsungads.com' }).aktion === 'geblockt' && fD.entscheide({ name: 'notyoutube.com' }).aktion === 'geblockt');
    pruefe('Geschützte Dienste: Samsung-Konto, SmartThings, Samsung Cloud und Bixby bleiben trotz Sperrliste erreichbar (Fernseher per Handy bedienen)',
      SAMSUNG_NOETIG.every((name) => fD.entscheide({ name }).grund === 'Geschützter Dienst'));
    pruefe('Geschützte Dienste: Ausnahmen – Sehverhaltens-Erkennung (ACR) und Statistik innerhalb geschützter Samsung-Domains bleiben geblockt',
      SAMSUNG_SPUREN.every((name) => fD.entscheide({ name }).aktion === 'geblockt' && fD.entscheide({ name }).grund === 'Liste'));
    pruefe('Smart-TV-Grundfunktionen gilt für alle Hersteller: LG, Sony, Panasonic, Hisense, Philips, Fire TV, Android TV, Roku, Samsung',
      TV_NOETIG.every((name) => fD.entscheide({ name }).dienst === 'smarttv' && fD.entscheide({ name }).grund === 'Geschützter Dienst'), TV_NOETIG.filter((name) => fD.entscheide({ name }).dienst !== 'smarttv').join(' '));
    pruefe('Smart-TV: Sehverhaltens-Erkennung, Nutzungsstatistik und Werbung der Hersteller bleiben geblockt (auch künftige Regionen/Jahrgänge per Vorsilbe)',
      TV_SPUREN.every((name) => fD.entscheide({ name }).aktion === 'geblockt'), TV_SPUREN.filter((name) => fD.entscheide({ name }).aktion !== 'geblockt').join(' '));
    pruefe('Geschützte Dienste: YouTube auf Social-Liste bleibt auch im Kinder-Profil frei, solange nicht gesperrt; TikTok (kein Dienst) wird gesperrt',
      fD.entscheide({ geraetId: 'kind', name: 'www.youtube.com' }).aktion === 'erlaubt' && fD.entscheide({ geraetId: 'kind', name: 'tiktok.com' }).aktion === 'geblockt');
    fD.konfigurieren({ ...basisD, regeln: [{ id: 'x', typ: 'sperren', muster: 'waipu.tv', geltung: 'alle' }], dienste: { youtube: { gesperrt: true, geltung: 'profil:kinder' }, netflix: { gesperrt: true, geltung: 'alle' } } });   // alte Schreibweise „gesperrt“ wird weiter verstanden
    pruefe('Geschützte Dienste: vom Betreiber gesperrt – YouTube nur für Kinder, Netflix für alle; eigene Sperrregel geht dem Schutz vor',
      fD.entscheide({ geraetId: 'kind', name: 'm.youtube.com' }).grund === 'Dienst gesperrt' && fD.entscheide({ geraetId: 'papa', name: 'm.youtube.com' }).aktion === 'erlaubt'
      && fD.entscheide({ geraetId: 'papa', name: 'www.netflix.com' }).grund === 'Dienst gesperrt' && fD.entscheide({ name: 'live.waipu.tv' }).grund === 'Eigene Regel');
    fD.konfigurieren({ ...basisD, regeln: [], dienste: { netflix: { modus: 'listen' }, tiktok: { modus: 'frei' } } });
    pruefe('Dienste-Zustände: „nach Listen“ lässt die Blockliste wieder greifen, „geschützt“ hebt auch Social-Media-Sperren im Kinder-Profil auf',
      fD.entscheide({ name: 'ichnaea.netflix.com' }).aktion === 'geblockt' && fD.entscheide({ geraetId: 'kind', name: 'www.tiktok.com' }).grund === 'Geschützter Dienst');
    {
      // 25.11.2026 (K5): „nur für Profil Kinder sperren“ lässt alle anderen beim bisherigen Grundzustand (Netflix = geschützt), nicht „nach Listen“
      fD.konfigurieren({ ...basisD, regeln: [], dienste: { netflix: { modus: 'sperren', geltung: 'profil:kinder' } } });
      const kind = fD.entscheide({ geraetId: 'kind', name: 'ichnaea.netflix.com' }), papa = fD.entscheide({ geraetId: 'papa', name: 'ichnaea.netflix.com' });
      fD.konfigurieren({ ...basisD, regeln: [], dienste: { netflix: { modus: 'sperren', geltung: 'profil:kinder', grund: 'listen' } } });
      const papaListen = fD.entscheide({ geraetId: 'papa', name: 'ichnaea.netflix.com' });
      pruefe('Dienst nur für ein Profil gesperrt (K5): Kind gesperrt, alle anderen behalten den Grundzustand (Vorgabe geschützt bzw. gemerkt „nach Listen“)',
        kind.grund === 'Dienst gesperrt' && papa.grund === 'Geschützter Dienst' && papaListen.aktion === 'geblockt' && papaListen.grund === 'Liste', JSON.stringify({ kind: kind.grund, papa: papa.grund, papaListen: papaListen.grund }));
    }
    const profileAusnahme = [profileD[0], { ...profileD[1], dienste: { tiktok: 'sperren', whatsapp: 'frei' } }];
    fD.konfigurieren({ ...basisD, profile: profileAusnahme, regeln: [], dienste: { tiktok: { modus: 'frei' } } });
    pruefe('Profil-Ausnahmen je Dienst: im Kinder-Profil TikTok gesperrt (trotz global geschützt), WhatsApp erlaubt; andere Profile unberührt',
      fD.entscheide({ geraetId: 'kind', name: 'www.tiktok.com' }).grund === 'Dienst gesperrt' && fD.entscheide({ geraetId: 'kind', name: 'web.whatsapp.com' }).grund === 'Geschützter Dienst'
      && fD.entscheide({ geraetId: 'papa', name: 'www.tiktok.com' }).grund === 'Geschützter Dienst');
    fD.konfigurieren({ ...basisD, regeln: [], dienste: { teams: { modus: 'frei' } } });
    { const teams = require('../src/dienste.js').DIENSTE.find((x) => x.id === 'teams'), prof = { limits: { 'rubrik:messenger': 60, 'dienst:teams': 30 } };
      pruefe('Zeitkonto (K6): mitbenutzte Domains (giphy bei Teams) zählen nicht ins Zeitlimit, echte Teams-Namen schon',
        fD.limitZiele(prof, teams, 'media.giphy.com').length === 0 && fD.limitZiele(prof, teams, 'teams.microsoft.com').length === 2 && fD.istMitbenutzt(teams, 'media1.giphy.com') && !fD.istMitbenutzt(teams, 'teams.microsoft.com')); }
    pruefe('Microsoft Teams geschützt: ALLE Teams-Dienste bleiben trotz Sperrliste frei – Anruf-Infrastruktur (früher Skype), Trouter, Relay, Konfiguration, Diagnosekanal, GIFs, direkt abgefragte Zwischennamen',
      TEAMS_NOETIG.every((name) => fD.entscheide({ name }).dienst === 'teams' && fD.entscheide({ name }).grund === 'Geschützter Dienst'), TEAMS_NOETIG.filter((name) => fD.entscheide({ name }).dienst !== 'teams').join(' '));
    pruefe('Microsoft Teams geschützt: fremde Microsoft-Telemetrie, Bing- und Giphy-Werbung bleiben geblockt; Office-Diagnose gehört zu Microsoft 365 (dort „nach Listen“)',
      [...TEAMS_FREMD, ...OFFICE_DIAGNOSE].every((name) => fD.entscheide({ name }).aktion === 'geblockt') && OFFICE_DIAGNOSE.every((name) => fD.dienstVon(name)?.id === 'microsoft365'),
      [...TEAMS_FREMD, ...OFFICE_DIAGNOSE].filter((name) => fD.entscheide({ name }).aktion !== 'geblockt').join(' '));
    fD.konfigurieren({ ...basisD, regeln: [], dienste: { teams: { modus: 'sperren', geltung: 'alle' }, microsoft365: { modus: 'frei' } } });
    pruefe('Microsoft Teams gesperrt: Anruf-Infrastruktur mitgesperrt, aber die Office-Konfiguration (ecs.office.com läuft per CNAME über einen skype.com-Namen) und die Office-Diagnose bleiben bei Microsoft 365',
      fD.entscheide({ name: 'config.edge.skype.com' }).grund === 'Dienst gesperrt' && fD.entscheide({ name: 'dual-s-0005-office.config.skype.com' }).grund === 'Geschützter Dienst'
      && OFFICE_DIAGNOSE.every((name) => fD.entscheide({ name }).grund === 'Geschützter Dienst'));
    {
      // Der Dienst „Skype“ ist in „Microsoft Teams“ aufgegangen – gespeicherte Zustände unbekannter Dienste dürfen das Speichern eines Profils nicht blockieren
      const wS = { ...JSON.parse(JSON.stringify(vorgaben({}))), dienste: { skype: { modus: 'sperren', geltung: 'alle' }, teams: { modus: 'frei' } } };
      wS.profile[0].dienste = { skype: 'sperren', whatsapp: 'frei' };
      const gemeldet = []; bereinigen(wS, vorgaben({}), (t) => gemeldet.push(t));
      pruefe('Einstellungen: Zustände nicht mehr vorhandener Dienste (Skype → Teams) werden entfernt und gemeldet, bekannte bleiben',
        !require('../src/dienste.js').DIENSTE.some((d) => d.id === 'skype') && !('skype' in wS.dienste) && wS.dienste.teams.modus === 'frei' && JSON.stringify(wS.profile[0].dienste) === '{"whatsapp":"frei"}' && gemeldet.some((t) => /skype/.test(t)), JSON.stringify({ d: wS.dienste, p: wS.profile[0].dienste, gemeldet }));
    }
    const kat = require('../src/dienste.js'), ids = new Set(), doppelt = [];
    for (const d of kat.DIENSTE) { if (ids.has(d.id)) doppelt.push(d.id); ids.add(d.id); for (const dom of d.domains) { const andere = kat.DIENSTE.filter((x) => x.domains.includes(dom)); if (andere.length > 1) doppelt.push(dom); } }
    const anb = require('../src/anbieter.js'), aIds = new Set(anb.ANBIETER.map((a) => a.id));
    const unter = (host, dom) => host === dom || host.endsWith('.' + dom);
    const ausserFalsch = kat.DIENSTE.flatMap((d) => (d.ausser || []).filter((a) => !d.domains.some((dom) => unter(a.replace(/^[^*]*\*\./, ''), dom)) || /\*/.test(a.replace(/^[a-z0-9-]*\*\./, ''))).map((a) => `${d.id}:${a}`));
    const mitbenutztFalsch = kat.DIENSTE.flatMap((d) => (d.mitbenutzt || []).filter((m) => !d.domains.includes(m)).map((m) => `${d.id}:${m}`));
    const leereRubriken = kat.GRUPPEN.filter((g) => !kat.DIENSTE.some((d) => d.gruppe === g.id)).map((g) => g.id);
    const domainFalsch = kat.DIENSTE.flatMap((d) => d.domains.filter((dom) => !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(dom)).map((dom) => `${d.id}:${dom}`));
    pruefe('Katalog: Ausnahmen liegen unter einer Domain des eigenen Dienstes, keine leere Rubrik, Domains wohlgeformt; neue Rubriken vorhanden',
      !ausserFalsch.length && !mitbenutztFalsch.length && !leereRubriken.length && !domainFalsch.length && ['smarthome', 'finanzen', 'lernen', 'reisen', 'telko', 'mail', 'dating', 'vpn'].every((id) => kat.GRUPPEN.some((g) => g.id === id)),
      `Ausnahmen: ${ausserFalsch.slice(0, 4)} · mitbenutzt: ${mitbenutztFalsch.slice(0, 4)} · leer: ${leereRubriken} · Domains: ${domainFalsch.slice(0, 4)}`);
    {
      // Betreiber-Vorgabe 15.11.2026: Pokémon GO ab Werk für alle Geräte frei – Hosts aus dem echten Protokoll (inkl. Scopely-Namen seit 2025)
      const pgo = kat.DIENSTE.find((d) => d.id === 'pokemongo'), idx = kat.index();
      const von = (h) => { const t = h.split('.'); for (let i = 0; i < t.length; i++) { const d = idx.get(t.slice(i).join('.')); if (d) return d.id; } return null; };
      const hosts = ['pgorelease.nianticlabs.com', 'asset-cdn-rel.nianticstatic.com', 'store.pokemongo.com', 'media.pokemongo-get.com', 'signin.scopelyexplore.com', 'wayfarer.scopely.com', 'sso.pokemon.com'];
      pruefe('Katalog: Pokémon GO und PokeRaid sind ab Werk geschützt (auch ohne Einstellung), Pokémon GO deckt die Scopely-Namen; übrige Spiele bleiben nach Listen',
        kat.modusVon(pgo, {}).modus === 'frei' && kat.modusVon(kat.DIENSTE.find((d) => d.id === 'pokeraid'), {}).modus === 'frei' && von('app.pokeraid.me') === 'pokeraid' && von('poketrade.me') === 'pokeraid' && hosts.every((h) => von(h) === 'pokemongo') && von('www.scopely.com') === null && kat.modusVon(kat.DIENSTE.find((d) => d.id === 'roblox'), {}).modus === 'listen',
        `${kat.modusVon(pgo, {}).modus} · ${hosts.filter((h) => von(h) !== 'pokemongo')}`);
    }
    pruefe('Kataloge: Dienste eindeutig und je Rubrik mit Vorgabe, DNS-Anbieter eindeutig und alle per HTTPS',
      kat.DIENSTE.length >= 100 && !doppelt.length && kat.GRUPPEN.every((g) => ['frei', 'listen'].includes(g.vorgabe)) && kat.DIENSTE.every((d) => kat.GRUPPEN.some((g) => g.id === d.gruppe))
      && anb.ANBIETER.length >= 15 && aIds.size === anb.ANBIETER.length && anb.ANBIETER.every((a) => a.url.startsWith('https://') && a.beschreibung && a.land) && !!anb.vonUrl('https://dns.quad9.net/dns-query'),
      `${kat.DIENSTE.length} Dienste, ${anb.ANBIETER.length} Anbieter, doppelt: ${doppelt.slice(0, 3)}`);
  }

  // Einstellungen: neue Vorgabelisten (Freigabelisten) werden bestehenden Installationen einmalig ergänzt
  const ev = path.join(tmp, 'einst'); fs.mkdirSync(ev, { recursive: true });
  fs.writeFileSync(path.join(ev, 'einstellungen.json'), JSON.stringify({ version: 1, listen: [{ id: 'hagezi-pro', name: 'HaGeZi Pro', url: 'x', kategorie: 'werbung', an: false }], kategorien: [{ id: 'werbung', name: 'W' }], profile: [], regeln: [], geraete: {}, pausen: { global: 0, geraete: {} }, dns: {}, unifi: {}, protokoll: { tage: 7 } }));
  const e1 = new Einstellungen({ verzeichnis: ev, geheimnis: 'z'.repeat(20), env: {} }).laden();
  pruefe('Update: Freigabelisten ergänzt, eigene Einstellung (Liste aus) bleibt, Kategorie „freigabe“ vorhanden', e1.werte.listen.some((l) => l.id === 'frei-adguard' && l.an) && e1.werte.listen.find((l) => l.id === 'hagezi-pro').an === false && e1.werte.kategorien.some((k) => k.id === 'freigabe' && k.art === 'erlauben'));
  e1.aendern((w) => { w.listen = w.listen.filter((l) => l.id !== 'frei-anudeep'); });
  const e2 = new Einstellungen({ verzeichnis: ev, geheimnis: 'z'.repeat(20), env: {} }).laden();
  pruefe('Update: vom Nutzer entfernte Vorgabeliste kommt nicht wieder', !e2.werte.listen.some((l) => l.id === 'frei-anudeep'));
  {
    // 25.11.2026 (K13): scheitert das Speichern (volle Platte), wirft aendern und der Stand im Speicher bleibt unverändert (vorher schon übernommen,
    // ein erneuter Versuch kam nie, nach einem Neustart war der alte Stand wieder da); Beobachter werden dann nicht benachrichtigt
    let gemeldet = 0; e2.beobachten(() => gemeldet++);
    const keinOrdner = path.join(tmp, 'ist-eine-datei'); fs.writeFileSync(keinOrdner, 'x');
    const vorher = e2.werte.regeln.length, datei = e2.datei; e2.datei = path.join(keinOrdner, 'einstellungen.json');   // Elternpfad ist eine Datei → Schreiben scheitert
    let geworfen = false; try { e2.aendern((w) => { w.regeln.push({ id: 'neu', typ: 'sperren', muster: 'x.de' }); }); } catch (e) { geworfen = true; }
    const unveraendert = e2.werte.regeln.length === vorher && gemeldet === 0;
    e2.datei = datei; e2.aendern((w) => { w.regeln.push({ id: 'neu', typ: 'sperren', muster: 'x.de' }); });
    pruefe('Einstellungen: Schreibfehler → aendern wirft, Speicher unverändert, kein Beobachter; danach normal speicherbar', geworfen && unveraendert && e2.werte.regeln.length === vorher + 1 && gemeldet === 1, JSON.stringify({ geworfen, unveraendert, gemeldet }));
  }
  {
    // Kaputte Einstellungsdatei (z. B. aus einer fehlerhaften Sicherung): Start darf nie scheitern
    const ek = path.join(tmp, 'einstK'); fs.mkdirSync(ek, { recursive: true });
    fs.writeFileSync(path.join(ek, 'einstellungen.json'), JSON.stringify({ version: 1, listen: [null, 7, { id: 'eigen-1', url: 'https://x/l', kategorie: 'werbung', an: true }], profile: [null, { id: 'kinder', name: 'K' }], regeln: [null, { id: 'r', typ: 'sperren', muster: 'a.de', geltung: 'alle' }, { id: 'kaputt' }], geraete: { a: null, b: { profil: 'kinder' } }, dienste: { youtube: 'x' }, pausen: { global: 'x', geraete: { a: 'x', b: 5 } }, dns: { erlaubteNetze: ['kaputt', '10.0.0.0/8'], gateway: 'nix', lokaleZonen: 'x' }, upstream: [null, { url: 'ftp://x' }], protokoll: { tage: 'viele' }, web: { vertrauteProxies: ['x', '172.16.0.0/12'] } }));
    const meldungen = []; const ek1 = new Einstellungen({ verzeichnis: ek, geheimnis: 'z'.repeat(20), env: {} });
    const alt = console.warn; console.warn = (t) => meldungen.push(t);
    let wk = null, fehler = null; try { wk = ek1.laden().werte; } catch (e) { fehler = e.message; } finally { console.warn = alt; }
    let startbar = false; try { netzliste(wk.dns.erlaubteNetze); new Upstream({ anbieter: wk.upstream }); new Filter({ listen }).konfigurieren({ regeln: wk.regeln, profile: wk.profile, listen: wk.listen, geraete: wk.geraete, pausen: wk.pausen, dienste: wk.dienste }); startbar = true; } catch (e) { fehler = e.message; }
    pruefe('Einstellungen: kaputte Einträge (null, falsche Typen, ungültige Netze/Gateway/Anbieter) werden übersprungen und gemeldet – Start bleibt möglich',
      !fehler && startbar && wk.listen.every((l) => l && typeof l.id === 'string') && wk.listen.some((l) => l.id === 'eigen-1') && wk.profile.map((p) => p.id).join() === 'standard,kinder' && wk.regeln.length === 1 && !('a' in wk.geraete) && wk.geraete.b.profil === 'kinder' && Object.keys(wk.dienste).length === 0
      && wk.pausen.global === 0 && wk.pausen.geraete.b === 5 && !('a' in wk.pausen.geraete) && wk.dns.erlaubteNetze.join() === '10.0.0.0/8' && wk.dns.gateway === '192.168.1.1' && wk.dns.lokaleZonen.length > 0 && wk.upstream.length === 3 && wk.upstream[0].name === 'Quad9'
      && wk.protokoll.tage === 7 && wk.web.vertrauteProxies.join() === '172.16.0.0/12' && meldungen.length >= 6, fehler || JSON.stringify({ meldungen, wk }));
    // 25.11.2026 (K7): kaputte Datei wird weggesichert (nie überschrieben), der letzte gute Stand (.bak) gilt – nur ohne Sicherung die Vorgaben
    const altErr = console.error; console.error = () => {};
    fs.writeFileSync(path.join(ek, 'einstellungen.json'), '[1,2]');
    let e3 = null; try { console.warn = () => {}; e3 = new Einstellungen({ verzeichnis: ek, geheimnis: 'z'.repeat(20), env: {} }).laden(); } catch (e) {} finally { console.warn = alt; }
    const kaputt1 = fs.readdirSync(ek).filter((x) => x.startsWith('einstellungen.json.kaputt-'));
    fs.rmSync(path.join(ek, 'einstellungen.json.bak')); fs.writeFileSync(path.join(ek, 'einstellungen.json'), '{ kaputt');
    let e4 = null; try { console.warn = () => {}; e4 = new Einstellungen({ verzeichnis: ek, geheimnis: 'z'.repeat(20), env: {} }).laden(); } catch (e) {} finally { console.warn = alt; console.error = altErr; }
    const kaputt2 = fs.readdirSync(ek).filter((x) => x.startsWith('einstellungen.json.kaputt-'));
    pruefe('Einstellungen: kaputte Datei → weggesichert, letzter guter Stand (.bak) geladen + Warnung; ohne Sicherung Vorgaben + Warnung; nie still überschrieben',
      e3 && e3.werte.dns.erlaubteNetze.join() === '10.0.0.0/8' && /letzte gesicherte Stand/.test(e3.warnung || '') && kaputt1.length === 1 && fs.readFileSync(path.join(ek, kaputt1[0]), 'utf8') === '[1,2]'
      && e4 && e4.werte.upstream.length === 3 && e4.werte.profile.length === 3 && /Werkseinstellungen/.test(e4.warnung || '') && kaputt2.length === 2, JSON.stringify({ w3: e3?.warnung, w4: e4?.warnung, kaputt2 }));
    {
      // Werksvorgabe (Betreiber 21.09.2026): Quad9 → Cloudflare → DNS.SB. Kein voreingestellter Anbieter darf selbst Werbung/Tracker oder Jugendschutz filtern –
      // ein filternder Anbieter sperrte unbemerkt Teams-Adressen (FAH-Adblock filtert selbst, ein zweiter Filter macht Fehler unsichtbar)
      const vU = vorgaben({}).upstream, katU = require('../src/anbieter.js').ANBIETER;
      const gruppeVon = (u) => katU.find((a) => a.url === u.url)?.gruppe;
      pruefe('Vorgabe DoH-Anbieter: Quad9 → Cloudflare → DNS.SB, alle aus dem Katalog und keiner mit eigener Werbe- oder Jugendschutzsperre',
        vU.map((u) => u.name).join(' → ') === 'Quad9 → Cloudflare → DNS.SB' && vU.every((u) => ['schutz', 'neutral'].includes(gruppeVon(u))) && katU.find((a) => a.id === 'dnsforge').gruppe === 'werbung',
        JSON.stringify(vU.map((u) => [u.name, gruppeVon(u)])));
    }
  }

  // ── DNS-Pakete ───────────────────────────────────────────────────────────
  const a = paket.lesen(frage('ads.example.com', 'A')), aaaa = paket.lesen(frage('ads.example.com', 'AAAA')), https65 = paket.lesen(frage('ads.example.com', 'HTTPS'));
  const pa = dnsPacket.decode(paket.sperrAntwort(a)), p6 = dnsPacket.decode(paket.sperrAntwort(aaaa)), ph = dnsPacket.decode(paket.sperrAntwort(https65));
  pruefe('Sperrantwort: A=0.0.0.0, AAAA=::, andere leer mit SOA; ID und Frage übernommen; TTL 10 s', pa.answers[0].ttl === 10 && pa.answers[0].data === '0.0.0.0' && p6.answers[0].data === '::' && ph.answers.length === 0 && ph.authorities[0].type === 'SOA' && pa.id === 4711 && pa.questions[0].name === 'ads.example.com');
  const sa = dnsPacket.decode(paket.sperrAntwort(a, '10.9.9.9')), s6 = dnsPacket.decode(paket.sperrAntwort(aaaa, '10.9.9.9')), sh = dnsPacket.decode(paket.sperrAntwort(https65, '10.9.9.9'));
  pruefe('Sperrseite: A zeigt auf die Instanz, AAAA und HTTPS bleiben leer', sa.answers[0].data === '10.9.9.9' && s6.answers.length === 0 && s6.authorities.length === 1 && sh.answers.length === 0);
  const gross = dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_DESIRED | dnsPacket.RECURSION_AVAILABLE, questions: [{ type: 'TXT', name: 'gross.de' }], answers: Array.from({ length: 30 }, (_, i) => ({ type: 'TXT', name: 'gross.de', ttl: 300, data: ['x'.repeat(60) + i] })) });
  const ohneEdns = paket.lesen(frage('gross.de', 'TXT', { edns: false }));
  const gekuerzt = dnsPacket.decode(paket.fuerClient(gross, ohneEdns, { udp: true })), tcp = dnsPacket.decode(paket.fuerClient(gross, ohneEdns, { udp: false }));
  pruefe('Große Antwort: über UDP gekürzt mit TC-Bit, über TCP vollständig', (gekuerzt.flags & (1 << 9)) && gekuerzt.answers.length === 0 && tcp.answers.length === 30 && gekuerzt.id === 4711);
  {
    // 25.11.2026 (K16): gekürzte Antwort an einen EDNS-Client behält ein OPT (DO wie beim Client); Frage in der Schreibweise des Clients (0x20)
    const groesser = dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: [{ type: 'TXT', name: 'gross.de' }], answers: Array.from({ length: 40 }, (_, i) => ({ type: 'TXT', name: 'gross.de', ttl: 300, data: ['x'.repeat(60) + i] })) });
    const mitEdns = paket.lesen(dnsPacket.encode({ type: 'query', id: 5, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'TXT', name: 'gross.de' }], additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: 0x8000, options: [] }] }));
    const tcE = dnsPacket.decode(paket.fuerClient(groesser, mitEdns, { udp: true })), tcOhne = dnsPacket.decode(paket.fuerClient(groesser, ohneEdns, { udp: true }));
    const optE = tcE.additionals.find((x) => x.type === 'OPT');
    const gemischt = paket.lesen(dnsPacket.encode({ type: 'query', id: 6, flags: dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: 'WwW.ExAmPlE.CoM' }] }));
    const ausSpeicher = dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: [{ type: 'A', name: 'www.example.com' }], answers: [{ type: 'A', name: 'www.example.com', ttl: 60, data: '1.2.3.4' }] });
    const zurueck = dnsPacket.decode(paket.fuerClient(ausSpeicher, gemischt, {})), fremd = dnsPacket.decode(paket.fuerClient(ausSpeicher, paket.lesen(frage('anders.example')), {}));
    pruefe('K16: gekürzte UDP-Antwort an EDNS-Client mit OPT (DO übernommen, 1232), ohne EDNS ohne OPT; Frage in Schreibweise des Clients, fremde Frage unverändert',
      (tcE.flags & (1 << 9)) && optE && optE.udpPayloadSize === 1232 && (optE.flags & 0x8000) && tcE.additionals.length === 1 && (tcOhne.flags & (1 << 9)) && tcOhne.additionals.length === 0
      && zurueck.questions[0].name === 'WwW.ExAmPlE.CoM' && zurueck.answers[0].data === '1.2.3.4' && fremd.questions[0].name === 'www.example.com', JSON.stringify({ optE, q: zurueck.questions[0].name }));
  }
  const mitTtl = dnsPacket.encode({ type: 'response', id: 0, questions: [{ type: 'A', name: 'x.de' }], answers: [{ type: 'CNAME', name: 'x.de', ttl: 300, data: 'ads.example.com' }, { type: 'A', name: 'ads.example.com', ttl: 120, data: '1.2.3.4' }] });
  pruefe('TTL: kleinste TTL erkannt, beim Ausliefern um das Alter verringert; CNAME-Ziele gelesen', paket.ttlVon(mitTtl) === 120 && dnsPacket.decode(paket.fuerClient(mitTtl, a, { alterSek: 20 })).answers[1].ttl === 100 && paket.cnameZiele(mitTtl).join() === 'ads.example.com');

  // HTTPS/SVCB (Typ 65) und unbekannte Typen: byte-genau durchgereicht (Rohbau eines Pakets ohne Bibliothek)
  const rohName = (n) => Buffer.concat([...n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
  const rr = (typ, ttl, daten) => { const b = Buffer.alloc(10); b.writeUInt16BE(typ, 0); b.writeUInt16BE(1, 2); b.writeUInt32BE(ttl, 4); b.writeUInt16BE(daten.length, 8); return Buffer.concat([Buffer.from([0xc0, 12]), b, daten]); };
  const svcb = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x33, 0x02, 0x68, 0x32, 0x00, 0x05, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);   // Priorität 1, Ziel „.“, alpn h3,h2, ech (Rohdaten)
  const kopfB = Buffer.alloc(12); kopfB.writeUInt16BE(0, 0); kopfB.writeUInt16BE(0x8180, 2); kopfB.writeUInt16BE(1, 4); kopfB.writeUInt16BE(2, 6); kopfB.writeUInt16BE(0, 8); kopfB.writeUInt16BE(1, 10);
  const opt = Buffer.concat([Buffer.from([0]), (() => { const b = Buffer.alloc(10); b.writeUInt16BE(41, 0); b.writeUInt16BE(1232, 2); b.writeUInt32BE(0, 4); b.writeUInt16BE(0, 8); return b; })()]);
  const httpsAntwort = Buffer.concat([kopfB, rohName('beispiel.de'), Buffer.from([0x00, 0x41, 0x00, 0x01]), rr(65, 300, svcb), rr(99, 200, Buffer.from('unbekannter-typ')), opt]);
  const qHttps = paket.lesen(frage('beispiel.de', 'HTTPS'));
  const durch = paket.fuerClient(httpsAntwort, qHttps, { alterSek: 50 });
  pruefe('HTTPS-Eintrag (Typ 65) und unbekannte Typen byte-genau durchgereicht, nur ID/TTL angepasst', !!durch && durch.readUInt16BE(0) === 4711 && durch.subarray(12).toString('hex').replace(/0000012c|0000fa/g, '') !== '' && durch.includes(svcb) && durch.includes(Buffer.from('unbekannter-typ')) && paket.ttlVon(durch) === 150 && durch.length === httpsAntwort.length);
  const ohneEdnsQ = paket.lesen(frage('beispiel.de', 'HTTPS', { edns: false }));
  const ohneOpt = paket.fuerClient(httpsAntwort, ohneEdnsQ, {});
  pruefe('Client ohne EDNS: OPT-Eintrag des Upstreams wird entfernt', ohneOpt.readUInt16BE(10) === 0 && ohneOpt.length === httpsAntwort.length - opt.length);
  {
    const umlaut = paket.lesen(frage('müller.de', 'A', { id: 99 })), fe = dnsPacket.decode(paket.antwort(umlaut, { rcode: 'FORMERR' }));
    pruefe('Nicht-ASCII-Name: als ungültig erkannt, FORMERR mit gleicher ID und ohne Frage-Abschnitt (kein kaputtes Paket); normale Namen unverändert',
      umlaut.ungueltig && umlaut.frage === null && (fe.flags & 15) === 1 && fe.id === 99 && fe.questions.length === 0 && !paket.lesen(frage('www.example.com')).ungueltig && paket.lesen(frage('a-b_c.example.com')).frage.name === 'a-b_c.example.com');
  }

  // ── Upstream ─────────────────────────────────────────────────────────────
  let uhrU = 1000000; const rufe = { q1: 0, q2: 0 }; let q1kaputt = false;
  const antwortFuer = (buf, ttl = 60) => { const q = dnsPacket.decode(buf); return dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: q.questions, answers: [{ type: 'A', name: q.questions[0].name, ttl, data: '9.9.9.9' }] }); };
  const fabrik = (x) => ({ name: x.name, gesperrtBis: 0, fehler: 0, frage: async (buf) => { rufe[x.name]++; if (x.name === 'q1' && q1kaputt) throw new Error('down'); return antwortFuer(buf); }, status: () => ({}) });
  const up = new Upstream({ anbieter: [{ name: 'q1' }, { name: 'q2' }], jetzt: () => uhrU, anbieterFabrik: fabrik });
  const an = paket.lesen(frage('seite.de'));
  const r1 = await up.frage(an, paket.upstreamAnfrage(an)); const r2 = await up.frage(an, paket.upstreamAnfrage(an));
  pruefe('Zwischenspeicher: zweite Anfrage aus dem Speicher', !r1.cache && r2.cache && rufe.q1 === 1);
  uhrU += 61000; q1kaputt = true;
  const r3 = await up.frage(an, paket.upstreamAnfrage(an));
  pruefe('TTL abgelaufen → neu gefragt; erster Anbieter weg → Rückfall auf den zweiten', !r3.cache && r3.anbieter === 'q2' && rufe.q2 === 1);
  const gleichzeitig = await Promise.all([1, 2, 3].map(() => { const x = paket.lesen(frage('parallel.de')); return up.frage(x, paket.upstreamAnfrage(x)); }));
  pruefe('Gleichzeitige gleiche Anfragen: nur ein Upstream-Ruf', gleichzeitig.every((x) => x.buf) && rufe.q2 === 2);
  {
    // Filternde DoH-Anbieter (DNSforge, Mullvad AdBlock, AdGuard …) sperren selbst – beim Betreiber beantwortete DNSforge 12–14 % aller Auflösungen (Rückfall, wenn Quad9 hakt)
    // und sperrte config.edge.skype.com + trap.skype.com: Teams-Anrufe gingen „ab und an“ nicht. Was der Betreiber ausdrücklich freigibt, darf kein Anbieter überstimmen.
    const adr = (buf) => dnsPacket.decode(buf).answers.find((x) => x.type === 'A')?.data, rufF = { hakt: 0, filter: 0, neutral: 0 }; let alleSperren = false;
    const antF = (buf, data, rcode = 0) => { const q = dnsPacket.decode(buf); return dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE | rcode, questions: q.questions, answers: rcode ? [] : [{ type: 'A', name: q.questions[0].name, ttl: 300, data }] }); };
    const fabrikF = (x) => ({ name: x.name, gesperrtBis: 0, fehler: 0, status: () => ({}), frage: async (buf) => { rufF[x.name]++; const name = dnsPacket.decode(buf).questions[0].name;
      if (x.name === 'hakt') throw new Error('Zeitüberschreitung'); if (x.name === 'filter' || alleSperren) return name.startsWith('nx.') ? antF(buf, null, 3) : antF(buf, '0.0.0.0'); return antF(buf, '52.1.2.3'); } });
    const upF = new Upstream({ anbieter: [{ name: 'hakt' }, { name: 'filter' }, { name: 'neutral' }], jetzt: () => 5000000, anbieterFabrik: fabrikF });
    const fr = (name, opt) => { const x = paket.lesen(frage(name)); return upF.frage(x, paket.upstreamAnfrage(x), opt); };
    const normal = await fr('config.edge.skype.com'), frei1 = await fr('config.edge.skype.com', { ungefiltert: true }), frei2 = await fr('config.edge.skype.com', { ungefiltert: true }), nx = await fr('nx.trap.skype.com', { ungefiltert: true });
    alleSperren = true; const ueberall = await fr('ueberall.skype.com', { ungefiltert: true });
    pruefe('Upstream: Sperrantwort eines filternden Anbieters (0.0.0.0 oder NXDOMAIN) gilt nicht für ausdrücklich Freigegebenes – nächster Anbieter wird gefragt, auch wenn die Sperrantwort schon im Zwischenspeicher liegt; sperren alle, bleibt es bei der Antwort',
      adr(normal.buf) === '0.0.0.0' && normal.anbieter === 'filter' && adr(frei1.buf) === '52.1.2.3' && frei1.anbieter === 'neutral' && !frei1.cache && frei2.cache && adr(frei2.buf) === '52.1.2.3' && adr(nx.buf) === '52.1.2.3' && adr(ueberall.buf) === '0.0.0.0',
      JSON.stringify({ normal: [adr(normal.buf), normal.anbieter], frei1: [adr(frei1.buf), frei1.anbieter, frei1.cache], frei2: [adr(frei2.buf), frei2.cache], nx: adr(nx.buf), ueberall: adr(ueberall.buf) }));
  }
  {
    // DoH-Anbieter gegen einen lokalen HTTP/2-Server, der zunächst nicht antwortet: nach der 2. Zeitüberschreitung in Folge
    // wird die Sitzung verworfen, der nächste Versuch verbindet neu (vorher blieb die tote Sitzung für immer)
    const h2 = http2.createServer(); let haengen = true, sitzungen = 0;
    h2.on('session', () => sitzungen++);
    h2.on('stream', (st) => { if (haengen) return; st.respond({ ':status': 200, 'content-type': 'application/dns-message' }); st.end(antwortFuer(frage('doh.example'))); });
    await new Promise((r) => h2.listen(0, '127.0.0.1', r));
    const doh = new DohAnbieter({ name: 'lokal', url: `http://127.0.0.1:${h2.address().port}/dns-query` });
    const f1 = await doh.frage(frage('doh.example'), 120).catch((e) => e.message), s1 = doh.sitzung;
    const f2 = await doh.frage(frage('doh.example'), 120).catch((e) => e.message), s2 = doh.sitzung;
    haengen = false;
    const f3 = await doh.frage(frage('doh.example'), 2000).then(() => 'ok', (e) => e.message);
    pruefe('DoH: 1. Zeitüberschreitung behält die Sitzung, 2. verwirft sie, danach neue Verbindung und Antwort', /Zeitüberschreitung/.test(f1) && s1 && /Zeitüberschreitung/.test(f2) && s2 === null && f3 === 'ok' && sitzungen === 2 && doh.zeitueberschreitungen === 0, `${f1} | ${f2} | ${f3} | Sitzungen ${sitzungen}`);
    doh.sitzungVerwerfen(); h2.close();
  }
  {
    // 25.11.2026 (Prüfung K8): DoH-Antwort muss eine DNS-Antwort auf GENAU diese Frage sein, höchstens 64 KiB, Inhaltstyp application/dns-message
    const h2v = http2.createServer(); let art = 'ok';
    h2v.on('stream', (st, kopf) => {
      const teile = []; st.on('data', (d) => teile.push(d)); st.on('end', () => {
        const anf = Buffer.concat(teile);
        if (art === 'typ') { st.respond({ ':status': 200, 'content-type': 'text/html' }); return st.end('<html>Anmeldung</html>'); }
        st.respond({ ':status': 200, 'content-type': art === 'mimex' ? 'application/dns-messagex' : 'application/dns-message; charset=binary' });
        const q = dnsPacket.decode(anf).questions[0];
        if (art === 'tc') { const k = Buffer.from(antwortFuer(anf)); k.writeUInt16BE(k.readUInt16BE(2) | 0x0200, 2); return st.end(k); }  // TC gesetzt
        if (art === 'kurz') { const k = Buffer.from(antwortFuer(anf)); return st.end(k.subarray(0, k.length - 6)); }               // Eintrag abgeschnitten
        if (art === 'hinten') return st.end(Buffer.concat([antwortFuer(anf), Buffer.from([0, 0, 0])]));                             // Müll hinten dran
        if (art === 'typ97') return st.end(dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: [{ ...q, type: 'UNKNOWN_97' }], answers: [] }));
        if (art === 'opt') return st.end(dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: [{ ...q, name: q.name.toUpperCase() }], answers: [{ type: 'A', name: q.name, ttl: 60, data: '9.9.9.9' }], additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, flags: 0, options: [] }] }));
        if (art === 'gross') return st.end(Buffer.alloc(70000, 1));
        if (art === 'fremd') return st.end(antwortFuer(frage('anders.example')));
        if (art === 'anfrage') return st.end(anf);   // Echo der Anfrage = QR=0, keine Antwort
        st.end(antwortFuer(anf));
      });
    });
    await new Promise((r) => h2v.listen(0, '127.0.0.1', r));
    const dv = new DohAnbieter({ name: 'pruef', url: `http://127.0.0.1:${h2v.address().port}/dns-query` });
    const versuch = async (a, typ = 'A') => { art = a; return dv.frage(paket.upstreamAnfrage(paket.lesen(frage('Pruef.Example', typ))), 2000).then((b) => 'ok:' + (dnsPacket.decode(b).answers[0]?.data ?? '-'), (e) => e.message); };
    const v = { ok: await versuch('ok'), opt: await versuch('opt'), typ: await versuch('typ'), mimex: await versuch('mimex'), gross: await versuch('gross'), fremd: await versuch('fremd'), anfrage: await versuch('anfrage'), kurz: await versuch('kurz'), hinten: await versuch('hinten'), tc: await versuch('tc'), typ97: await versuch('typ97', 'UNKNOWN_65') };
    pruefe('DoH: passende Antwort angenommen (auch mit OPT, Name in anderer Schreibweise, Inhaltstyp mit Parameter); abgelehnt: falscher/ähnlicher Inhaltstyp, über 64 KiB, andere Frage, reine Anfrage (QR=0), abgeschnittener Eintrag, Müll am Ende, TC-Bit, Typ 97 statt 65',
      v.ok === 'ok:9.9.9.9' && v.opt === 'ok:9.9.9.9' && /keine DNS-Antwort/.test(v.typ) && /keine DNS-Antwort/.test(v.mimex) && /zu groß/.test(v.gross) && ['fremd', 'anfrage', 'kurz', 'hinten', 'tc', 'typ97'].every((k) => /fremde/.test(v[k])), JSON.stringify(v));
    dv.sitzungVerwerfen(); h2v.close();
  }
  {
    // 25.11.2026 (K8): SERVFAIL/REFUSED mit HTTP 200 = weicher Fehler → nächster Anbieter; antworten alle so, geht die erste Fehlerantwort weiter (nicht gespeichert)
    const rufS = { a: 0, b: 0, c: 0 }; let allesKaputt = false;
    const fehlerAntwort = (buf, rcode) => { const q = dnsPacket.decode(buf); return dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE | rcode, questions: q.questions, answers: [] }); };
    const fabrikS = (x) => ({ name: x.name, gesperrtBis: 0, fehler: 0, status: () => ({}), frage: async (buf) => { rufS[x.name]++;
      if (x.name === 'a') return fehlerAntwort(buf, 2); if (x.name === 'b' || allesKaputt) return fehlerAntwort(buf, 5); return antwortFuer(buf); } });
    // erweiterter Rcode (BADVERS = 16: Kopf 0, obere Bits im OPT) zählt wie jeder andere Fehler – nicht als NOERROR speichern
    const badvers = (buf) => { const q = dnsPacket.decode(buf); return dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: q.questions, answers: [], additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, extendedRcode: 1, ednsVersion: 0, flags: 0, options: [] }] }); };
    const rufB = { x: 0, y: 0 };
    const upB = new Upstream({ anbieter: [{ name: 'x' }, { name: 'y' }], jetzt: () => 7000000, anbieterFabrik: (x) => ({ name: x.name, gesperrtBis: 0, fehler: 0, status: () => ({}), frage: async (buf) => { rufB[x.name]++; return x.name === 'x' ? badvers(buf) : antwortFuer(buf); } }) });
    const xb = paket.lesen(frage('badvers.example')), rb1 = await upB.frage(xb, paket.upstreamAnfrage(xb)), rb2 = await upB.frage(xb, paket.upstreamAnfrage(xb));
    pruefe('Upstream: erweiterter Rcode im OPT (BADVERS) erkannt → nächster Anbieter; die echte Antwort wird gespeichert, BADVERS nicht', paket.rcodeVon(badvers(paket.upstreamAnfrage(xb))) === 16 && paket.rcodeVon(antwortFuer(paket.upstreamAnfrage(xb))) === 0 && rb1.anbieter === 'y' && rb2.cache && rb2.anbieter === 'y', JSON.stringify({ rb1: rb1.anbieter, rb2: [rb2.anbieter, rb2.cache], rufB }));
    const upS = new Upstream({ anbieter: [{ name: 'a' }, { name: 'b' }, { name: 'c' }], jetzt: () => 7000000, anbieterFabrik: fabrikS });
    const frS = (name) => { const x = paket.lesen(frage(name)); return upS.frage(x, paket.upstreamAnfrage(x)); };
    const gut = await frS('servfail.example');
    allesKaputt = true; const schlecht1 = await frS('bogus.example'), schlecht2 = await frS('bogus.example');
    pruefe('Upstream: SERVFAIL/REFUSED des ersten Anbieters → nächster wird gefragt; scheitern alle, kommt die erste Fehlerantwort (SERVFAIL) und nichts wird gespeichert; Anbieter werden dafür nicht ausgesetzt',
      gut.anbieter === 'c' && (dnsPacket.decode(gut.buf).flags & 15) === 0 && (dnsPacket.decode(schlecht1.buf).flags & 15) === 2 && schlecht1.anbieter === 'a' && !schlecht2.cache && upS.anbieter.every((x) => x.gesperrtBis === 0),
      JSON.stringify({ gut: gut.anbieter, s1: [schlecht1.anbieter, dnsPacket.decode(schlecht1.buf).flags & 15], s2cache: schlecht2.cache, rufS }));
  }
  {
    // Fund 14: Gateway-Antwort für lokale Zonen muss zu ID und Frage passen – Fremdpakete werden verworfen
    const gw = dgram.createSocket('udp4'); await new Promise((r) => gw.bind(0, '127.0.0.1', r));
    const gwAntwort = (q, id, name) => dnsPacket.encode({ type: 'response', id, flags: dnsPacket.RECURSION_AVAILABLE, questions: [{ type: 'A', name }], answers: [{ type: 'A', name, ttl: 60, data: name === q.questions[0].name ? '192.168.1.23' : '6.6.6.6' }] });
    gw.on('message', (m, r) => { const q = dnsPacket.decode(m); gw.send(gwAntwort(q, q.id + 1, q.questions[0].name), r.port, r.address); gw.send(gwAntwort(q, q.id, 'anders.lan'), r.port, r.address); setTimeout(() => gw.send(gwAntwort(q, q.id, q.questions[0].name), r.port, r.address), 40); });
    const lokal = new Lokal({ gateway: '127.0.0.1', zonen: ['lan'], port: gw.address().port });
    const t0 = Date.now(), la = dnsPacket.decode(await lokal.frage(frage('nas.lan', 'A', { id: 321 }), 1500)), dauer = Date.now() - t0;
    pruefe('Gateway: Pakete mit fremder ID oder anderer Frage verworfen, passende Antwort angenommen', la.id === 321 && la.answers[0].data === '192.168.1.23' && dauer >= 30, JSON.stringify(la.answers));
    gw.close();
  }

  // ── DNS-Server-Ablauf ────────────────────────────────────────────────────
  const upFake = { frage: async (anf) => { const nm = anf.frage.name; if (nm === 'kaputt.de') throw new Error('alle Anbieter weg'); const q = { questions: anf.paket.questions }; const antworten = nm === 'getarnt.de' ? [{ type: 'CNAME', name: nm, ttl: 60, data: 'track.doubleclick.net' }, { type: 'A', name: 'track.doubleclick.net', ttl: 60, data: '1.1.1.1' }] : [{ type: 'A', name: nm, ttl: 60, data: '5.6.7.8' }]; return { buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, ...q, answers: antworten }), alterSek: 0, cache: false, anbieter: 'fake' }; } };
  const lokalFake = { zustaendig: (nm) => nm.endsWith('example.org'), frage: async (buf) => { const q = dnsPacket.decode(buf); return dnsPacket.encode({ type: 'response', id: q.id, flags: dnsPacket.RECURSION_AVAILABLE, questions: q.questions, answers: [{ type: 'A', name: q.questions[0].name, ttl: 60, data: '192.168.1.23' }] }); } };
  const records = new Records({ eintraege: [{ host: 'intern.example.org', ip: '192.168.1.29' }, { host: 'v6.example.lan', ip: 'fd00::1' }, { host: '*.intern.example', ip: '192.168.1.50' }, { host: 'spezial.intern.example', ip: '192.168.1.60' }, { host: 'BAD HOST', ip: '1.2.3.4' }, { host: 'ok.example', ip: 'nonsense' }] });
  const srv = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter, upstream: upFake, lokal: lokalFake, records, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) }, bremse: { rate: 5, schub: 5 } });
  const ereignisse = []; srv.on('anfrage', (e) => ereignisse.push(e));
  const dek = async (name, ip = '192.168.1.5', typ = 'A') => dnsPacket.decode(await srv.bearbeite(frage(name, typ), ip, true));
  pruefe('Server: fremdes Netz bekommt REFUSED (kein offener Resolver)', ((await dek('seite.de', '8.8.8.8')).flags & 15) === 5);
  pruefe('Server: Werbung → 0.0.0.0, normale Seite → Upstream-Antwort', (await dek('ads.example.com', '192.168.1.6')).answers[0].data === '0.0.0.0' && (await dek('seite.de', '192.168.1.6')).answers[0].data === '5.6.7.8');
  pruefe('Server: lokale Zone geht ans Gateway', (await dek('nginx.example.org', '192.168.1.6')).answers[0].data === '192.168.1.23' && ereignisse.at(-1).aktion === 'lokal');
  pruefe('Records: ungültige Einträge verworfen, v4→A / v6→AAAA', records.exakt.size === 3 && records.wild.length === 1 && !records.leer && records.treffer('v6.example.lan').aaaa === 'fd00::1' && !records.treffer('bad host') && !records.treffer('ok.example'));
  pruefe('Records: Wildcard matcht Subdomains (jede Tiefe), exakt gewinnt, Apex nicht', records.treffer('foo.intern.example').a === '192.168.1.50' && records.treffer('a.b.intern.example').a === '192.168.1.50' && records.treffer('spezial.intern.example').a === '192.168.1.60' && !records.treffer('intern.example'));
  pruefe('Server: lokaler Record schlägt die lokale Zone (→ 192.168.1.29, nie gefiltert)', (await dek('intern.example.org', '192.168.1.9')).answers[0].data === '192.168.1.29' && ereignisse.at(-1).aktion === 'lokal' && ereignisse.at(-1).grund === 'Lokaler Eintrag');
  { const aaaa = await dek('intern.example.org', '192.168.1.9', 'AAAA'); pruefe('Server: lokaler Record ohne AAAA → NOERROR ohne Antwort (kein Internet-Leak)', (aaaa.flags & 15) === 0 && (aaaa.answers?.length || 0) === 0); }
  const getarnt = await dek('getarnt.de', '192.168.1.6');
  pruefe('Server: CNAME-Tarnung erkannt und geblockt', getarnt.answers[0]?.data === '0.0.0.0' && ereignisse.at(-1).grund === 'CNAME-Tarnung');
  pruefe('Server: Upstream-Ausfall → SERVFAIL, Ereignis „fehler“', ((await dek('kaputt.de', '192.168.1.6')).flags & 15) === 2 && ereignisse.at(-1).aktion === 'fehler');
  const bremsErg = []; for (let i = 0; i < 8; i++) bremsErg.push(((await dek('seite.de', '192.168.1.7')).flags & 15));
  pruefe('Server: Bremse je Client greift nach dem Schub', bremsErg.slice(0, 5).every((c) => c === 0) && bremsErg.slice(5).every((c) => c === 5), bremsErg.join());
  pruefe('Server: Gesundheitsanfrage wird intern beantwortet', (await dek('health.fah-adblock', '192.168.1.8', 'TXT')).answers[0].data[0].toString() === 'ok');
  pruefe('Server: Firefox-DoH-Kanarie → NXDOMAIN', ((await dek('use-application-dns.net', '192.168.1.8')).flags & 15) === 3);
  pruefe('Server: Frage mit Nicht-ASCII-Namen → FORMERR statt kaputtem Paket', ((await dek('müller.de', '192.168.1.8')).flags & 15) === 1);
  {
    // 25.11.2026 (Prüfung K3/K10): Antworten (QR=1) nie beantworten – sonst Pingpong zweier Resolver mit gefälschtem Absender, auch über die
    // Gesundheitsfrage (die vor der Bremse steht); Opcode ≠ QUERY → NOTIMP; nicht genau eine Frage → FORMERR; fremdes Netz nur REFUSED
    const roh = (o) => dnsPacket.encode({ id: 77, flags: dnsPacket.RECURSION_DESIRED, ...o });
    const qr = await srv.bearbeite(roh({ type: 'response', questions: [{ type: 'TXT', name: 'health.fah-adblock' }], answers: [{ type: 'TXT', name: 'health.fah-adblock', ttl: 0, data: ['ok'] }] }), '192.168.1.21', true);
    const qrFremd = await srv.bearbeite(roh({ type: 'response', questions: [] }), '8.8.8.8', true);
    const status = dnsPacket.decode(await srv.bearbeite(roh({ type: 'query', flags: (2 << 11) | dnsPacket.RECURSION_DESIRED, questions: [{ type: 'A', name: 'seite.de' }] }), '192.168.1.22', true));
    const zwei = dnsPacket.decode(await srv.bearbeite(roh({ type: 'query', questions: [{ type: 'A', name: 'seite.de' }, { type: 'A', name: 'ads.example.com' }] }), '192.168.1.23', true));
    const leer = dnsPacket.decode(await srv.bearbeite(roh({ type: 'query', questions: [] }), '192.168.1.23', true));
    const leerFremd = dnsPacket.decode(await srv.bearbeite(roh({ type: 'query', questions: [] }), '8.8.4.4', true));
    // Weicher Upstream-Fehler (SERVFAIL von allen Anbietern) mit CNAME auf einen gelisteten Tracker: geht als SERVFAIL weiter, nicht als Sperre
    const upSf = { frage: async (anf) => ({ buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE | 2, questions: anf.paket.questions, answers: [{ type: 'CNAME', name: anf.frage.name, ttl: 60, data: 'ads.example.com' }] }), alterSek: 0, cache: false, anbieter: 'x' }) };
    const srvSf = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter, upstream: upSf, lokal: lokalFake, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } });
    const sf = dnsPacket.decode(await srvSf.bearbeite(frage('harmlos.example'), '192.168.1.24', true));
    pruefe('Server: SERVFAIL aller Anbieter mit CNAME auf Tracker → SERVFAIL weitergereicht (keine CNAME-Sperre auf eine Fehlerantwort)', (sf.flags & 15) === 2 && !sf.answers.some((x) => x.data === '0.0.0.0'), JSON.stringify(sf.answers));
    pruefe('Server: Antwortpakete (QR=1) werden verworfen (auch Gesundheitsfrage, auch aus fremdem Netz); Opcode STATUS → NOTIMP mit Opcode STATUS in der Antwort; zwei Fragen oder keine → FORMERR; fremdes Netz ohne Frage → REFUSED',
      qr === null && qrFremd === null && (status.flags & 15) === 4 && status.opcode === 'STATUS' && (zwei.flags & 15) === 1 && (leer.flags & 15) === 1 && (leerFremd.flags & 15) === 5,
      JSON.stringify({ qr, qrFremd, status: [status.flags & 15, status.opcode], zwei: zwei.flags & 15, leer: leer.flags & 15, leerFremd: leerFremd.flags & 15 }));
  }
  {
    const upC = { frage: async (anf) => ({ buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions, answers: [{ type: 'CNAME', name: anf.frage.name, ttl: 60, data: 'w5.example.com' }, { type: 'A', name: 'w5.example.com', ttl: 60, data: '1.1.1.1' }] }), alterSek: 0, cache: false, anbieter: 'fake' }) };
    const srvC = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: filterF, upstream: upC, lokal: lokalFake, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } });
    const evC = []; srvC.on('anfrage', (e) => evC.push(e));
    const frei = dnsPacket.decode(await srvC.bearbeite(frage('f3.example.org'), '192.168.1.5', true)), fremd = dnsPacket.decode(await srvC.bearbeite(frage('irgendwas.example.net'), '192.168.1.5', true));
    pruefe('CNAME-Prüfung: Domain nur auf einer Freigabeliste bleibt erlaubt, unbekannte Domain mit Tracker-CNAME wird geblockt', frei.answers[0]?.type === 'CNAME' && evC[0].aktion === 'erlaubt' && fremd.answers[0]?.data === '0.0.0.0' && evC[1].grund === 'CNAME-Tarnung', JSON.stringify(evC.map((e) => [e.domain, e.aktion, e.grund])));
  }
  {
    // Teams gesperrt, Microsoft 365 auf Vorgabe: ecs.office.com (Konfiguration aller Office-Apps) läuft per CNAME über Teams-Namen – die Sperre gilt dem Dienst, nicht fremden Diensten auf derselben Infrastruktur
    const KETTEN = { 'ecs.office.com': ['ecs.office.trafficmanager.net', 'mira.config.skype.com', 'svc.ha-teams.office.com', 'teams-mrc-ww-acdcatm.trafficmanager.net', 'svc.ms-acdc-teams.office.com'],
      'kurz.example.net': ['config.edge.skype.com'], 'blickpunkt.example.net': ['ideas-iris.westeurope-prod.cosmic.office.net'] };
    const upT = { frage: async (anf) => { const kette = [anf.frage.name, ...(KETTEN[anf.frage.name] || [])]; return { buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions,
      answers: [...kette.slice(1).map((ziel, i) => ({ type: 'CNAME', name: kette[i], ttl: 60, data: ziel })), { type: 'A', name: kette.at(-1), ttl: 60, data: '52.1.2.3' }] }), alterSek: 0, cache: false, anbieter: 'fake' }; } };
    const fT = new Filter({ listen }); fT.konfigurieren({ regeln: [], profile: [{ id: 'standard', kategorien: {} }], listen: [], geraete: {}, pausen: { global: 0, geraete: {} }, dienste: { teams: { modus: 'sperren', geltung: 'alle' } } });
    const srvT = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fT, upstream: upT, lokal: lokalFake, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } });
    const evT = []; srvT.on('anfrage', (e) => evT.push(e));
    const antwortT = async (name) => dnsPacket.decode(await srvT.bearbeite(frage(name), '192.168.1.5', true)).answers.at(-1)?.data;
    const ergT = {}; for (const name of ['ecs.office.com', 'kurz.example.net', 'blickpunkt.example.net', 'config.edge.skype.com', 'teams.microsoft.com', 'media0.giphy.com', 'adl.windows.com']) ergT[name] = await antwortT(name);
    pruefe('Teams gesperrt: Office-Konfiguration (CNAME über Teams-Namen) bleibt erreichbar, mitbenutzte Namen (Giphy, Microsofts Container-Plattform, Geräte-Updates) werden nicht mitgesperrt; Teams selbst und getarnte Zugänge bleiben zu',
      ergT['ecs.office.com'] === '52.1.2.3' && ergT['blickpunkt.example.net'] === '52.1.2.3' && ergT['media0.giphy.com'] === '52.1.2.3' && ergT['adl.windows.com'] === '52.1.2.3'
      && ergT['kurz.example.net'] === '0.0.0.0' && ergT['config.edge.skype.com'] === '0.0.0.0' && ergT['teams.microsoft.com'] === '0.0.0.0' && evT.find((e) => e.domain === 'kurz.example.net').grund === 'CNAME-Tarnung', JSON.stringify(ergT));
  }
  {
    // Server reicht die Freigabe an den Upstream durch: geschützter Dienst und eigene Freigaberegel ja, gewöhnliche Domain nein
    const gesehen = {}; const upS = { frage: async (anf, buf, opt) => { gesehen[anf.frage.name] = !!opt?.ungefiltert; return { buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions, answers: [{ type: 'A', name: anf.frage.name, ttl: 60, data: '52.1.2.3' }] }), alterSek: 0, cache: false, anbieter: 'fake' }; } };
    const fS = new Filter({ listen }); fS.konfigurieren({ regeln: [{ id: 'r', typ: 'erlauben', muster: 'frei.example.org', geltung: 'alle' }], profile: [{ id: 'standard', kategorien: {} }], listen: [], geraete: {}, pausen: { global: 0, geraete: {} }, dienste: { teams: { modus: 'frei' } } });
    const srvS = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fS, upstream: upS, lokal: lokalFake, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } });
    for (const name of ['config.edge.skype.com', 'frei.example.org', 'gewoehnlich.example.org']) await srvS.bearbeite(frage(name), '192.168.1.5', true);
    pruefe('Server: geschützter Dienst und eigene Freigabe werden „ungefiltert“ aufgelöst, gewöhnliche Domains weiter über die gewählten Anbieter', gesehen['config.edge.skype.com'] === true && gesehen['frei.example.org'] === true && gesehen['gewoehnlich.example.org'] === false, JSON.stringify(gesehen));
  }

  // ── Protokoll ────────────────────────────────────────────────────────────
  let uhrP = Date.now();
  const prot = new Protokoll({ datei: path.join(tmp, 'p.db'), jetzt: () => uhrP });
  for (const e of ereignisse) prot.aufnehmen({ ...e, geraetName: 'Testgerät', ts: uhrP });
  prot.aufnehmen({ ts: uhrP, ip: '192.168.1.6', geraet: 'ip:192.168.1.6', geraetName: 'Testgerät', domain: 'ads.example.com', typ: 'A', aktion: 'geblockt', grund: 'Liste', listen: ['w'] });
  prot.schreiben();
  const kz = prot.kennzahlen();
  const kz7 = prot.kennzahlen(168), kz30 = prot.kennzahlen(720), kzX = prot.kennzahlen(5);
  pruefe('Protokoll: Kennzahlen je Zeitraum (24 h / 7 Tage / 1 Monat) – Zeitraum-Zahlen umfassen mindestens „heute", unbekannter Wert fällt auf 24 h zurück',
    kz.zeitraum?.stunden === 24 && kz7.zeitraum.stunden === 168 && kz30.zeitraum.stunden === 720 && kzX.zeitraum.stunden === 24
    && kz7.zeitraum.anfragen >= kz.heute.anfragen && kz30.zeitraum.anfragen >= kz7.zeitraum.anfragen && kz.zeitraum.anfragen >= kz.heute.anfragen);
  pruefe('Protokoll: Kennzahlen aus Stunden-Summen', kz.heute.geblockt >= 3 && kz.heute.anfragen >= ereignisse.length && kz.aktiveGeraete >= 1, JSON.stringify(kz));
  const ret = prot.rettung('ip:192.168.1.6');
  pruefe('Rettung: geblockte Domains des Geräts, gebündelt, neueste zuerst', ret.some((r) => r.domain === 'ads.example.com' && r.n === 2) && ret.some((r) => r.domain === 'getarnt.de'), JSON.stringify(ret));
  pruefe('Protokoll: Filter „nur geblockt“, Suche und Gerätestatistik', prot.eintraege({ nurGeblockt: true }).every((z) => z.aktion === 'geblockt') && prot.eintraege({ suche: 'example' }).length === 3 && prot.geraeteStatistik().some((g) => g.id === 'ip:192.168.1.6' && g.geblockt >= 2));
  pruefe('Protokoll: Obergrenzen – limit -1/0/9999 werden auf 1 … 500 begrenzt (Einträge und Top-Domains)', prot.eintraege({ limit: -1 }).length === 1 && prot.eintraege({ limit: 0 }).length === prot.eintraege({ limit: 100 }).length && prot.eintraege({ limit: 9999 }).length <= 500 && prot.topDomains({ limit: -1 }).length === 1);
  uhrP += 8 * 86400000; prot.aufraeumen();
  pruefe('Protokoll: Aufbewahrung – alte Einträge gelöscht', prot.eintraege({}).length === 0);
  for (let i = 0; i < 300; i++) prot.gemerkt(`k${i}`, 1000, () => i);
  const deckel = prot.cache.size; uhrP += 2000; prot.gemerkt('neu', 1000, () => 1);
  pruefe('Protokoll: Statistik-Zwischenspeicher gedeckelt (≤ 200) und abgelaufene Einträge beim Einfügen entfernt', deckel <= 200 && prot.cache.size === 1 && prot.gemerkt('neu', 1000, () => 2) === 1, `${deckel} → ${prot.cache.size}`);
  prot.schliessen();

  // ── Geräte-Zuordnung (IP → MAC) ──────────────────────────────────────────
  {
    let uhrG = 5_000_000_000, rufeG = 0;
    const MAC61 = 'aa:aa:aa:aa:aa:61', MAC60 = 'bb:bb:bb:bb:bb:60', zuordnungen = [];
    const sta = [{ mac: MAC61.toUpperCase(), ip: '192.168.1.61', name: 'Neues Handy', dev_id: 1681, assoc_time: (uhrG - 120000) / 1000 }, { mac: MAC60, ip: '192.168.1.60', name: 'Switch', assoc_time: (uhrG - 600000) / 1000 }];
    const holer = async (z, pfad) => { if (pfad.includes('stat/sta')) { rufeG++; return { data: sta }; } if (pfad.includes('rest/user')) return { data: [{ mac: 'CC:CC:CC:CC:CC:01', name: 'Gast Smartphone ALT' }, { mac: MAC60, name: '' }] }; return { data: [] }; };
    const g = new Geraete({ zugang: () => ({ url: 'https://x', schluessel: 'k' }), gateway: () => '', jetzt: () => uhrG, holer, protokoll: () => {}, onZuordnung: (z) => zuordnungen.push(z) });
    g.vorbelegen([{ mac: 'aa:aa:aa:aa:aa:50', name: 'Kinder-Tablet', ip: '192.168.1.50', zuletzt: uhrG - 1000 }, { ipId: true, ip: '192.168.1.60', zuletzt: uhrG - 5000 }, { ipId: true, ip: '192.168.5.2', zuletzt: uhrG }]);
    pruefe('Geräte: nach Neustart sofort per MAC erkannt (letzte Zuordnung aus dem Protokoll), ohne UniFi-Abfrage', g.von('192.168.1.50').id === 'aa:aa:aa:aa:aa:50' && rufeG === 0);
    const erst = g.von('192.168.1.61'); await g.laeuft;
    const danach = g.von('192.168.1.61');
    pruefe('Geräte: unbekannte IP → UniFi sofort gefragt, danach per MAC; Zuordnung ab Verbindungsbeginn gemeldet (auch Alt-Einträge, nie VPN)',
      erst.id === 'ip:192.168.1.61' && rufeG === 1 && danach.id === MAC61 && danach.name === 'Neues Handy'
      && zuordnungen.some((z) => z.von === 'ip:192.168.1.61' && z.nach === MAC61 && z.seit === uhrG - 120000) && zuordnungen.some((z) => z.von === 'ip:192.168.1.60' && z.nach === MAC60)
      && !zuordnungen.some((z) => z.von.includes('192.168.5')), JSON.stringify(zuordnungen));
    pruefe('Geräte: ohne Namen → Hersteller bzw. „private MAC“', clientName({ mac: '94:be:46:00:00:01', oui: 'Apple' }) === 'Gerät von Apple' && clientName({ mac: '9a:00:00:00:00:31' }) === 'Gerät mit privater MAC' && clientName({ mac: '52:54:00:00:00:9d' }) === 'Gerät mit privater MAC' && clientName({ mac: '94:be:46:00:00:01' }) === '' && clientName({ mac: 'x', hostname: ' pc ' }) === 'pc');
    pruefe('Geräte: Namen auch für bekannte Offline-Geräte (UniFi rest/user), Online-Name bleibt', g.nameVon('cc:cc:cc:cc:cc:01') === 'Gast Smartphone ALT' && g.nameVon('52:54:00:00:00:9d') === 'Gerät mit privater MAC' && g.nameVon('ip:192.168.1.5') === '' && g.iconVon(MAC61) === 1681 && g.iconVon(MAC60) === null && g.nameVon(MAC60) === 'Switch' && g.status().unifi.geraete === 2);
    g.von('192.168.1.99'); const r1 = rufeG; uhrG += 16000; g.von('192.168.1.99'); await g.laeuft; const r2 = rufeG; uhrG += 16000; g.von('192.168.1.99'); const r3 = rufeG;
    pruefe('Geräte: sofortige UniFi-Abfragen gedrosselt (15 s global, 5 min je IP), VPN löst keine aus', r1 === 1 && r2 === 2 && r3 === 2 && (g.von('192.168.5.9'), rufeG === 2), `${r1},${r2},${r3},${rufeG}`);
    // Veraltete IP→MAC-Zuordnung: Vorbelegung, die UniFi nicht bestätigt, ist nach der Abfrage weg; DHCP-Wechsel räumt die alte IP auf; nach 24 h gilt ein Eintrag als unbekannt
    const vorbelegtWeg = !g.jeIp.has('192.168.1.50') && g.von('192.168.1.50').id === 'ip:192.168.1.50';
    sta[0].ip = '192.168.1.62'; uhrG += 16000; await g.unifiLesen();
    const gewechselt = g.von('192.168.1.61').id === 'ip:192.168.1.61' && g.von('192.168.1.62').id === MAC61;
    uhrG += 25 * 3600000; const alt24 = g.von('192.168.1.62').id === 'ip:192.168.1.62'; await g.laeuft; const wiederDa = g.von('192.168.1.62').id === MAC61;
    pruefe('Geräte: nicht bestätigte Vorbelegung entfernt, DHCP-Wechsel räumt alte IP auf, Eintrag älter als 24 h = unbekannt (UniFi neu gefragt)', vorbelegtWeg && gewechselt && alt24 && wiederDa, `${vorbelegtWeg} ${gewechselt} ${alt24} ${wiederDa}`);

    const pz = new Protokoll({ datei: path.join(tmp, 'z.db'), jetzt: () => uhrG });
    const ev = (ts, geraet, aktion = 'erlaubt', domain = 'seite.de') => pz.aufnehmen({ ts, ip: '192.168.1.61', geraet, geraetName: geraet.startsWith('ip:') ? '192.168.1.61' : 'Neues Handy', domain, typ: 'A', aktion, grund: aktion === 'geblockt' ? 'Liste' : '', listen: aktion === 'geblockt' ? ['w'] : undefined });
    ev(uhrG - 3 * 3600000, 'ip:192.168.1.61'); ev(uhrG - 30000, 'ip:192.168.1.61'); ev(uhrG - 20000, 'ip:192.168.1.61', 'geblockt', 'ads.example.com'); ev(uhrG, MAC61);
    pz.schreiben();
    const vorher = pz.kennzahlen().aktiveGeraete;
    const nz = pz.zusammenfuehren('ip:192.168.1.61', MAC61, uhrG - 120000, 'Neues Handy');
    const stat = pz.geraeteStatistik(uhrG - 86400000), mac = stat.find((x) => x.id === MAC61), rest = stat.find((x) => x.id === 'ip:192.168.1.61');
    pruefe('Protokoll: Zusammenführen verschiebt Anfragen, Stunden-Summen, Rettung und Livepuffer; ältere bleiben; aktive Geräte nicht mehr doppelt',
      nz === 2 && vorher === 2 && pz.kennzahlen().aktiveGeraete === 1 && pz.eintraege({ geraet: MAC61 }).length === 3 && pz.eintraege({ geraet: 'ip:192.168.1.61' }).length === 1
      && mac.erlaubt + mac.geblockt === 3 && mac.geblockt === 1 && rest && rest.erlaubt === 1 && pz.rettung(MAC61, 60).some((x) => x.domain === 'ads.example.com')
      && pz.ring.filter((e) => e.geraet === MAC61).length === 3, JSON.stringify({ nz, vorher, stat }));
    pz.zusammenfuehren('ip:192.168.1.61', MAC61, 0, 'Neues Handy');
    pruefe('Protokoll: vollständig zusammengeführt → „ip:…“-Gerät verschwindet; bekannteGeraete liefert MAC + IP', !pz.geraeteStatistik(0).some((x) => x.id === 'ip:192.168.1.61') && pz.bekannteGeraete().some((x) => x.mac === MAC61 && x.ip === '192.168.1.61') && !pz.bekannteGeraete().some((x) => x.ipId && x.ip === '192.168.1.61'));
    pz.schliessen();
  }

  // ── Anmeldung, Einstellungen ─────────────────────────────────────────────
  let uhrA = Date.now();
  const auth = new Auth({ verzeichnis: tmp, geheimnis: 'x'.repeat(32), jetzt: () => uhrA });
  const ok = auth.anmelden('admin', 'admin', '1.1.1.1');
  const sitz = auth.sitzungLesen(`fah_adblock=${ok.cookie}`);
  pruefe('Anmeldung: Erststart admin/admin, Sitzung gültig, Standardpasswort markiert', ok.cookie && sitz?.name === 'admin' && sitz.standardPasswort && sitz.csrf);
  const [inhalt, sig] = ok.cookie.split('.');
  const manipuliert = Buffer.from(JSON.stringify({ n: 'admin', b: Date.now() + 1e12 })).toString('base64url');
  pruefe('Anmeldung: manipuliertes Cookie abgelehnt, falsches Passwort abgelehnt', !auth.sitzungLesen(`fah_adblock=${manipuliert}.${sig}`) && !!inhalt && auth.anmelden('admin', 'falsch', '2.2.2.2').fehler);
  for (let i = 0; i < 10; i++) auth.anmelden(`bot${i}`, 'falsch', '3.3.3.3');
  {
    // 25.11.2026 (K7): kaputte Nutzerdatei → nie wieder admin/admin. Mit Sicherung gilt der letzte gute Stand; ohne Sicherung Einmal-Passwort im Protokoll
    const ad = path.join(tmp, 'auth-kaputt'); fs.mkdirSync(ad, { recursive: true });
    const a1 = new Auth({ verzeichnis: ad, geheimnis: 'q'.repeat(32) }); a1.passwortAendern('admin', 'admin', 'Geheim-12345');
    const altErr = console.error, logs = []; console.error = (...x) => logs.push(x.join(' '));
    fs.writeFileSync(path.join(ad, 'nutzer.json'), '{"nutzer": [');
    const a2 = new Auth({ verzeichnis: ad, geheimnis: 'q'.repeat(32) });
    const mitSicherung = !!a2.anmelden('admin', 'Geheim-12345', '9.9.9.1').cookie && !a2.anmelden('admin', 'admin', '9.9.9.2').cookie;
    fs.rmSync(path.join(ad, 'nutzer.json.bak')); fs.writeFileSync(path.join(ad, 'nutzer.json'), 'kaputt');
    const a3 = new Auth({ verzeichnis: ad, geheimnis: 'q'.repeat(32) }); console.error = altErr;
    const einmal = (logs.join('\n').match(/Einmal-Passwort: (\S+)/) || [])[1];
    const standard = a3.anmelden('admin', 'admin', '9.9.9.3');
    pruefe('Anmeldung: kaputte Nutzerdatei → letzter gesicherter Stand; ohne Sicherung kein admin/admin, sondern Einmal-Passwort aus dem Protokoll (Hinweis bei falscher Anmeldung); kaputte Dateien weggesichert',
      mitSicherung && !standard.cookie && /Einmal-Passwort/.test(standard.fehler || '') && !!einmal && !!a3.anmelden('admin', einmal, '9.9.9.4').cookie && fs.readdirSync(ad).filter((x) => x.startsWith('nutzer.json.kaputt-')).length === 2,
      JSON.stringify({ mitSicherung, standard, einmal: !!einmal }));
  }
  pruefe('Anmeldung: Bremse je Adresse nach 10 Fehlversuchen (auch mit richtigem Passwort)', /Zu viele Versuche/.test(auth.anmelden('admin', 'admin', '3.3.3.3').fehler || ''));
  uhrA += 2 * 3600000;   // Zähler je Name verfällt nach 1 h Ruhe
  const bekannt = auth.anmelden('admin', 'admin', '5.5.5.8');   // dieser Browser war schon einmal angemeldet → Geräte-Cookie
  for (const ip of ['5.5.5.1', '5.5.5.2']) auth.anmelden('admin', 'falsch', ip);
  const dritter = auth.anmelden('admin', 'falsch', '5.5.5.3'), gesperrt = auth.anmelden('admin', 'falsch', '5.5.5.4');
  // 25.11.2026 (K14 nach Gegenprüfung): Fremde werden in der Sperre gar nicht geprüft (auch das richtige Passwort nicht – kein zusätzlicher
  // Rateversuch, egal wie viele Adressen); ein bekanntes Gerät kommt durch, aber höchstens 5 Prüfungen je 15 min; fremdes/verändertes Cookie zählt nicht
  const fremdRichtig = auth.anmelden('admin', 'admin', '5.5.5.9'), gc = `fah_adblock_geraet=${bekannt.geraet}`;
  const gefaelscht = auth.anmelden('admin', 'admin', '5.5.5.10', `fah_adblock_geraet=${bekannt.geraet.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'))}`);
  const frei = auth.anmelden('admin', 'admin', '5.5.5.4', gc);
  for (let i = 0; i < 3; i++) auth.anmelden('admin', 'falsch', `5.5.6.${i}`);   // wieder gesperrt
  for (let i = 0; i < 5; i++) auth.anmelden('admin', 'falsch', '5.5.5.11', gc);
  const geraetErschoepft = auth.anmelden('admin', 'admin', '5.5.5.12', gc);
  pruefe('Anmeldung: Bremse je Nutzername über Adressen hinweg (ab dem 3. Fehlversuch steigende Wartezeit 2 s, 4 s … 15 min); in der Sperre kein Passwort-Test für Fremde, bekanntes Gerät kommt mit dem richtigen Passwort durch (höchstens 5 Prüfungen je 15 min), gefälschtes Geräte-Cookie zählt nicht',
    !!bekannt.cookie && !!bekannt.geraet && /falsch/.test(dritter.fehler) && /diesen Namen/.test(gesperrt.fehler || '') && /diesen Namen/.test(fremdRichtig.fehler || '') && /diesen Namen/.test(gefaelscht.fehler || '') && !!frei.cookie
    && /diesen Namen/.test(geraetErschoepft.fehler || '') && Auth.wartezeit(2) === 0 && Auth.wartezeit(3) === 2000 && Auth.wartezeit(4) === 4000 && Auth.wartezeit(30) === 900000,
    JSON.stringify([dritter, gesperrt, fremdRichtig, gefaelscht, !!frei.cookie, geraetErschoepft]));
  uhrA += 3600000;
  const pwNeu = auth.passwortAendern('admin', 'admin', 'neuesPasswort1');
  pruefe('Passwort ändern: altes muss stimmen, danach kein Standardpasswort', auth.passwortAendern('admin', 'falsch', 'neuesPasswort1').fehler && pwNeu.ok && !auth.sitzungLesen(`fah_adblock=${auth.anmelden('admin', 'neuesPasswort1', '4.4.4.4').cookie}`).standardPasswort);
  {
    const c1 = auth.anmelden('admin', 'neuesPasswort1', '6.6.6.6').cookie, vorher = !!auth.sitzungLesen(`fah_adblock=${c1}`);
    auth.sitzungenBeenden('admin');
    const c2 = auth.anmelden('admin', 'neuesPasswort1', '6.6.6.6').cookie, pw2 = auth.passwortAendern('admin', 'neuesPasswort1', 'nochNeuer12');
    const altForm = Buffer.from(JSON.stringify({ n: 'admin', b: uhrA + 1e6, c: 'x' })).toString('base64url');
    const neu = new Auth({ verzeichnis: tmp, geheimnis: 'x'.repeat(32), jetzt: () => uhrA });
    pruefe('Sitzungen: Abmelden und Passwortwechsel machen alle bisherigen Cookies ungültig (auch nach Neustart), das neue Cookie aus dem Passwortwechsel gilt; Cookies ohne Zähler (Vorversion) gelten nicht',
      vorher && !auth.sitzungLesen(`fah_adblock=${c1}`) && !!auth.sitzungLesen(`fah_adblock=${c2}`) === false && !!pw2.cookie && auth.sitzungLesen(`fah_adblock=${pw2.cookie}`)?.name === 'admin' && neu.sitzungLesen(`fah_adblock=${pw2.cookie}`)?.name === 'admin' && !neu.sitzungLesen(`fah_adblock=${c2}`) && !auth.sitzungLesen(`fah_adblock=${altForm}.${auth.signatur(altForm)}`));
  }
  pruefe('Geheimnisse: AES-GCM hin und zurück, falscher Schlüssel liefert nichts', entschluesseln(verschluesseln('geheim123', 'a'.repeat(20)), 'a'.repeat(20)) === 'geheim123' && entschluesseln(verschluesseln('geheim123', 'a'.repeat(20)), 'b'.repeat(20)) === '');

  // ── Web-API ──────────────────────────────────────────────────────────────
  fs.mkdirSync(path.join(tmp, 'web'), { recursive: true });
  const einst = new Einstellungen({ verzeichnis: path.join(tmp, 'web'), geheimnis: 'y'.repeat(32), env: {} }).laden();
  const prot2 = new Protokoll({ datei: path.join(tmp, 'web', 'p.db') });
  const authW = new Auth({ verzeichnis: path.join(tmp, 'web'), geheimnis: 'y'.repeat(32) });
  fs.mkdirSync(path.join(tmp, 'pub'), { recursive: true }); fs.writeFileSync(path.join(tmp, 'pub', 'index.html'), '<h1>ok</h1><link rel="stylesheet" href="app.css"><script src="app.js" defer></script>');
  // Erweiterungen (allgemeine Schnittstelle): Probe-Erweiterung, eine kaputte, ein ungültiger Ordnername
  const { ladeErweiterungen } = require('../src/erweiterungen.js');
  const erwLeer = ladeErweiterungen(path.join(tmp, 'gibtsnicht'), {});
  const erwDir = path.join(tmp, 'erw'); for (const n of ['probe', 'kaputt', 'Ungueltig!']) fs.mkdirSync(path.join(erwDir, n), { recursive: true });
  fs.writeFileSync(path.join(erwDir, 'probe', 'index.js'), "module.exports = (d) => ({ name: 'probe', oberflaeche: true, routen(route, h) { route('GET', '/api/probe-erw', () => ({ ok: true, a: d.a, hilfen: typeof h.pruefe + typeof h.w })); }, kachel: () => ['', '7', 'Probe', 'unter', 'kinderschutz'] });");
  fs.writeFileSync(path.join(erwDir, 'kaputt', 'index.js'), "throw new Error('absichtlich');");
  fs.writeFileSync(path.join(erwDir, 'Ungueltig!', 'index.js'), "module.exports = () => ({ name: 'x' });");
  const erwLogs = [], erw = ladeErweiterungen(erwDir, { a: 1, protokoll: (t) => erwLogs.push(t) });
  pruefe('Erweiterungen: Ordner fehlt → []', Array.isArray(erwLeer) && erwLeer.length === 0);
  pruefe('Erweiterungen: Erweiterung, die beim Laden wirft, stoppt den Rest nicht; ungültige Ordnernamen werden übergangen', erw.length === 1 && erw[0].name === 'probe' && erwLogs.some((t) => t.includes('kaputt') && t.includes('absichtlich')), JSON.stringify({ n: erw.map((e) => e.name), erwLogs }));
  const web = webServer({ auth: authW, einst, listen, filter, upstream: up, dns: srv, geraete: { status: () => ({ unifi: {} }), unifiLesen: async () => 0, iconVon: (id) => (id === 'aa:bb:cc:dd:ee:ff' ? 1681 : null), nameVon: () => '' }, protokoll: prot2, live: new Set(), version: 'probe', statisch: path.join(tmp, 'pub'), daten: path.join(tmp, 'web'), erweiterungen: erw });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const B = `http://127.0.0.1:${web.address().port}`;
  const holen = (p, o = {}) => fetch(B + p, o);
  {
    // 25.11.2026 (K17): Livestrom trennt Zuhörer mit über 1 MB Rückstau, die anderen bekommen weiter Daten
    const geschrieben = [], zu = []; const fake = (name, rueckstau) => ({ name, writableLength: rueckstau, destroyed: false, write: (x) => geschrieben.push(name), destroy() { this.destroyed = true; zu.push(name); } });
    const liveProbe = new Set([fake('liest', 100), fake('haengt', 2e6)]);
    liveSenden(liveProbe, 'data: x\n\n');
    pruefe('Livestrom (K17): Zuhörer mit > 1 MB Rückstau getrennt und entfernt, lesende bekommen die Daten', geschrieben.join() === 'liest' && zu.join() === 'haengt' && liveProbe.size === 1, JSON.stringify({ geschrieben, zu }));
  }
  {
    // 25.11.2026 (Prüfung K1): `GET //` warf vor dem try → unbehandelte Ablehnung → Prozess (und DNS) beendet. Jetzt 400, Server läuft weiter.
    const roheAntwort = (ziel) => new Promise((ok) => { const net = require('node:net'); const s = net.connect(web.address().port, '127.0.0.1', () => s.write(`GET ${ziel} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`)); let t = ''; s.on('data', (d) => { t += d; }); s.on('end', () => ok(t.split('\r\n')[0])); s.on('error', (e) => ok('Fehler ' + e.message)); });
    const z1 = await roheAntwort('//'), z2 = await roheAntwort('//a:b'), z3 = await roheAntwort('/%'), danach = (await holen('/api/uebersicht')).status;
    pruefe('Web: ungültiges Anfrageziel (//, //a:b, kaputte %-Kodierung) → 400, Server läuft danach weiter', / 400 /.test(z1) && / 400 /.test(z2) && / 400 /.test(z3) && danach === 401, `${z1} | ${z2} | ${z3} | ${danach}`);
  }
  pruefe('Web: ohne Anmeldung 401, statische Seite erreichbar, Pfad-Ausbruch landet auf index.html', (await holen('/api/uebersicht')).status === 401 && (await (await holen('/')).text()).includes('ok') && !(await (await holen('/..%2f..%2fetc%2fpasswd')).text()).includes('root:'));
  const login = await holen('/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', passwort: 'admin' }) });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const ich = await (await holen('/api/ich', { headers: { cookie } })).json();
  pruefe('Web: Anmeldung setzt HttpOnly-/SameSite-Cookie (dazu das Geräte-Cookie nur für /api/anmelden), /api/ich liefert CSRF-Token', /fah_adblock_geraet=[^;]+; Path=\/api\/anmelden; HttpOnly; SameSite=Strict/.test(login.headers.get('set-cookie')) && /HttpOnly/.test(login.headers.get('set-cookie')) && /SameSite=Strict/.test(login.headers.get('set-cookie')) && ich.csrf && ich.standardPasswort);
  const ohneCsrf = await holen('/api/pause', { method: 'POST', headers: { cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ minuten: 5 }) });
  const fremd = await holen('/api/pause', { method: 'POST', headers: { cookie, 'x-csrf': ich.csrf, origin: 'https://boese.example', 'Content-Type': 'application/json' }, body: JSON.stringify({ minuten: 5 }) });
  pruefe('Web: Schreiben ohne CSRF-Token oder von fremder Herkunft → 403', ohneCsrf.status === 403 && fremd.status === 403);
  const post = (p, daten, m = 'POST') => holen(p, { method: m, headers: { cookie, 'x-csrf': ich.csrf, 'Content-Type': 'application/json' }, body: JSON.stringify(daten) });
  {
    const pe = await (await holen('/api/probe-erw', { headers: { cookie } })).json();
    const ue = await (await holen('/api/uebersicht', { headers: { cookie } })).json();
    pruefe('Erweiterungen: Test-Erweiterung im Temp-Ordner wird geladen, Route /api/probe-erw antwortet, /api/ich nennt sie, /api/uebersicht enthält ihre Kachel', pe.ok && pe.a === 1 && pe.hilfen === 'functionfunction' && JSON.stringify(ich.erweiterungen) === '["probe"]' && ue.erweiterungen?.[0]?.[2] === 'Probe', JSON.stringify({ pe, e: ich.erweiterungen, k: ue.erweiterungen }));
  }
  const regel = await (await post('/api/regeln', { typ: 'erlauben', muster: 'ads.example.com', geltung: 'geraet:mac7', minuten: 60 })).json();
  const falsch = await post('/api/regeln', { typ: 'erlauben', muster: 'nix da', geltung: 'alle' });
  pruefe('Web: Regel mit Ablauf gespeichert, ungültige Regel 400', !!regel.id && regel.bis > Date.now() && einst.werte.regeln.some((r) => r.id === regel.id) && falsch.status === 400);
  const pauseR = await (await post('/api/pause', { minuten: 5 })).json();
  pruefe('Web: globale Pause gespeichert', pauseR.bis > Date.now() && einst.werte.pausen.global === pauseR.bis);
  const profilPut = await post('/api/profile/standard', { kategorien: { werbung: { an: true, zeitplan: [] }, freigabe: { an: true, zeitplan: [] } } }, 'PUT');
  pruefe('Profil speichern mit (alter) Kategorie „freigabe“ → kein Fehler, wird ignoriert', profilPut.status === 200 && !einst.werte.profile.find((p) => p.id === 'standard').kategorien.freigabe);
  const seite = await (await holen('/', { headers: { cookie } })).text();
  pruefe('index.html bindet app.js/app.css mit Versionskennung ein (kein veralteter Browser-Zwischenspeicher)', seite.includes('app.js?v=probe') && seite.includes('app.css?v=probe'));
  const pruef = await (await holen('/api/pruefen?domain=ads.example.com', { headers: { cookie } })).json();
  pruefe('Web: „Domain prüfen“ nennt Entscheidung und Listen', pruef.listen.includes('w') && pruef.aktion);
  // Gerätesymbole: nur Ziffern, aus dem Zwischenspeicher ohne Netz, Symbol-ID in der Geräteliste
  const png = Buffer.from('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6a0a50000000049454e44ae426082', 'hex');
  fs.mkdirSync(path.join(tmp, 'web', 'symbole'), { recursive: true }); fs.writeFileSync(path.join(tmp, 'web', 'symbole', '1681.png'), png);
  const symOk = await holen('/api/symbol/1681', { headers: { cookie } }), symBoese = await holen('/api/symbol/..%2f..%2fnutzer', { headers: { cookie } }), symOhne = await holen('/api/symbol/1681');
  await post('/api/geraete/' + encodeURIComponent('aa:bb:cc:dd:ee:ff'), { profil: 'kinder' }, 'PUT');
  const gl = await (await holen('/api/geraete', { headers: { cookie } })).json();
  pruefe('Web: Gerätesymbol aus dem Zwischenspeicher (PNG), ungültige ID abgelehnt, ohne Anmeldung 401, Symbol-ID in der Geräteliste',
    symOk.status === 200 && symOk.headers.get('content-type') === 'image/png' && Buffer.from(await symOk.arrayBuffer()).equals(png) && [400, 404].includes(symBoese.status) && symOhne.status === 401
    && gl.geraete.find((g) => g.id === 'aa:bb:cc:dd:ee:ff')?.icon === 1681, `${symOk.status} ${symBoese.status} ${symOhne.status}`);
  const dPut = await post('/api/dienste/youtube', { modus: 'sperren', geltung: 'profil:kinder' }, 'PUT'), dFalsch = await post('/api/dienste/youtube', { modus: 'sperren', geltung: 'profil:gibtsnicht' }, 'PUT'), dUnbekannt = await post('/api/dienste/gibtsnicht', { modus: 'sperren' }, 'PUT');
  const dListe = await (await holen('/api/dienste', { headers: { cookie } })).json();
  await post('/api/dienste/youtube', { modus: 'frei' }, 'PUT');
  const dListen = await post('/api/dienste/tiktok', { modus: 'listen' }, 'PUT'), dArt = await post('/api/dienste/tiktok', { modus: 'unsinn' }, 'PUT');
  {
    await post('/api/dienste/spotify', { modus: 'listen' }, 'PUT'); await post('/api/dienste/spotify', { modus: 'sperren', geltung: 'profil:kinder' }, 'PUT');
    await post('/api/dienste/netflix', { modus: 'sperren', geltung: 'profil:kinder' }, 'PUT');
    const ds = einst.werte.dienste;
    pruefe('Web (K5): Sperre nur für ein Profil merkt den bisherigen Grundzustand (Spotify vorher „nach Listen“ → grund listen); Vorgabe wird nicht extra gespeichert',
      ds.spotify?.modus === 'sperren' && ds.spotify?.grund === 'listen' && ds.netflix?.modus === 'sperren' && ds.netflix?.grund === undefined, JSON.stringify({ spotify: ds.spotify, netflix: ds.netflix }));
    await post('/api/dienste/spotify', { modus: 'frei' }, 'PUT'); await post('/api/dienste/netflix', { modus: 'frei' }, 'PUT');
  }
  const pDienste = await post('/api/profile/kinder', { kategorien: {}, dienste: { tiktok: 'sperren', whatsapp: 'frei' } }, 'PUT');
  const pFalsch = await post('/api/profile/kinder', { kategorien: {}, dienste: { gibtsnicht: 'sperren' } }, 'PUT');
  const anbieter = await (await holen('/api/anbieter', { headers: { cookie } })).json();
  pruefe('Web: Dienst-Zustand „nach Listen“ = Vorgabe wird nicht gespeichert, unbekannter Zustand 400; Anbieterkatalog mit Gruppen',
    dListen.status === 200 && !einst.werte.dienste.tiktok && dArt.status === 400 && pDienste.status === 200 && pFalsch.status === 400
    && JSON.stringify(einst.werte.profile.find((x) => x.id === 'kinder').dienste) === '{"tiktok":"sperren","whatsapp":"frei"}' && anbieter.anbieter.length >= 15 && anbieter.gruppen.length >= 3 && anbieter.anbieter.every((a) => a.url.startsWith('https://')));
  pruefe('Web: Dienst sperren/freigeben, ungültiges Profil und unbekannter Dienst abgelehnt, Liste mit Gruppen und Status',
    dPut.status === 200 && dFalsch.status === 400 && dUnbekannt.status === 400 && dListe.dienste.find((d) => d.id === 'youtube').modus === 'sperren' && dListe.gruppen.length >= 8 && !einst.werte.dienste.youtube, `${dPut.status} ${dFalsch.status} ${dUnbekannt.status}`);
  // Gateway nur als IP, Obergrenzen bei limit
  const gwFalsch = await post('/api/einstellungen', { dns: { gateway: 'router.local' } }, 'PUT'), gwOk = await post('/api/einstellungen', { dns: { gateway: '192.168.1.1' } }, 'PUT'), gwLeer = await post('/api/einstellungen', { dns: { gateway: '' } }, 'PUT');
  const limitTop = await holen('/api/top?limit=-1', { headers: { cookie } }), limitProt = await holen('/api/protokoll?limit=-1', { headers: { cookie } });
  pruefe('Web: Gateway muss eine IP sein (leer erlaubt), limit=-1 hebt keine Obergrenze auf', gwFalsch.status === 400 && gwOk.status === 200 && gwLeer.status === 200 && einst.werte.dns.gateway === '' && limitTop.status === 200 && limitProt.status === 200 && (await limitTop.json()).length <= 1 && (await limitProt.json()).length <= 1);
  await post('/api/einstellungen', { dns: { gateway: '192.168.1.1' } }, 'PUT');
  // Wiederherstellung: kaputte Sicherung wird komplett abgelehnt, gültige übernommen
  const sicherung = await (await holen('/api/sicherung', { headers: { cookie } })).json();
  const regelnVorher = JSON.stringify(einst.werte.regeln), upVorher = JSON.stringify(einst.werte.upstream);
  const kaputt = async (aenderung) => { const s = JSON.parse(JSON.stringify(sicherung)); Object.assign(s.einstellungen, aenderung); const r = await post('/api/wiederherstellung', s); return `${r.status} ${(await r.json()).fehler || ''}`; };
  const k1 = await kaputt({ regeln: [null] }), k2 = await kaputt({ dns: { erlaubteNetze: ['kaputt'] } }), k3 = await kaputt({ upstream: [{ name: 'x', url: 'http://unsicher' }] }), k4 = await kaputt({ profile: [{ id: 'nurkinder', name: 'K' }] }), k5 = await kaputt({ listen: [{ id: 'l', url: 'nix', kategorie: 'werbung' }] }), k6 = await kaputt({ geraete: { 'aa:bb': { profil: 'gibtsnicht' } } }), k7 = await kaputt({ dns: { gateway: 'nix' } });
  const unveraendert = regelnVorher === JSON.stringify(einst.werte.regeln) && upVorher === JSON.stringify(einst.werte.upstream);
  const s2 = JSON.parse(JSON.stringify(sicherung)); s2.einstellungen.regeln = [{ id: 'wieder', typ: 'sperren', muster: 'zurueck.de', geltung: 'alle' }]; s2.einstellungen.web = { vertrauteProxies: ['172.16.0.0/12'] }; s2.einstellungen.sperrseite = { an: true };
  const gut = await post('/api/wiederherstellung', s2);
  const sperrUebernommen = einst.werte.sperrseite.an === true;
  einst.aendern((x) => { x.sperrseite = { an: false }; });
  pruefe('Wiederherstellung: kaputte Sicherungen (null-Regel, ungültiges Netz, http-Anbieter, fehlendes Standardprofil, Listen-URL, unbekanntes Profil, Gateway) → 400 mit Klartext und nichts übernommen; gültige Sicherung übernommen (auch Sperrseite, sonst bliebe sie am Ersatz aus)',
    [k1, k2, k3, k4, k5, k6, k7].every((k) => /^400 Sicherung nicht übernommen: ./.test(k)) && unveraendert && gut.status === 200 && sperrUebernommen && einst.werte.regeln.length === 1 && einst.werte.regeln[0].id === 'wieder' && einst.werte.web.vertrauteProxies.join() === '172.16.0.0/12', [k1, k2, k3, k4, k5, k6, k7].join(' | '));
  // Anmeldebremse hinter einem Proxy: ohne vertrauten Proxy zählt alles als eine Adresse, mit ihm je X-Forwarded-For (Eintrag, den der Proxy anhängt)
  einst.aendern((x) => { x.web.vertrauteProxies = []; });
  const anm = (name, passwort, xff) => holen('/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json', ...(xff ? { 'x-forwarded-for': xff } : {}) }, body: JSON.stringify({ name, passwort }) });
  for (let i = 0; i < 10; i++) await anm(`bot${i}`, 'falsch', `203.0.113.${i + 10}`);
  const alleGesperrt = await anm('admin', 'admin', '203.0.113.99');
  einst.aendern((x) => { x.web.vertrauteProxies = ['127.0.0.1/32']; });
  const mitProxy = await anm('admin', 'admin', '203.0.113.99'), kette = await (await holen('/api/einstellungen', { headers: { cookie, 'x-forwarded-for': '198.51.100.7, 203.0.113.5' } })).json();
  const ohneKopf = await (await holen('/api/einstellungen', { headers: { cookie } })).json();
  pruefe('Web: Anmeldebremse hinter NPM – ohne vertrauten Proxy sperren 10 Bot-Versuche alle (Fehler von früher), mit vertrautem Proxy zählt die echte Absenderadresse; bei Ketten der vom Proxy angehängte Eintrag',
    alleGesperrt.status === 401 && /Zu viele Versuche/.test((await alleGesperrt.json()).fehler) && mitProxy.status === 200 && kette.verbindung.client === '203.0.113.5' && kette.verbindung.proxy === true && ohneKopf.verbindung.client === '127.0.0.1' && ohneKopf.verbindung.proxy === false, JSON.stringify([alleGesperrt.status, mitProxy.status, kette.verbindung]));
  // Passwortwechsel gibt der aktuellen Sitzung ein neues Cookie, alte Cookies sind ungültig; Abmelden beendet alle Sitzungen
  const pwWeb = await post('/api/passwort', { alt: 'admin', neu: 'passwort123' });
  const cookieNeu = (pwWeb.headers.get('set-cookie') || '').split(';')[0];
  const altUngueltig = (await holen('/api/ich', { headers: { cookie } })).status, neuGueltig = (await holen('/api/ich', { headers: { cookie: cookieNeu } })).status;
  const ichNeu = await (await holen('/api/ich', { headers: { cookie: cookieNeu } })).json();
  const zweite = (await anm('admin', 'passwort123', '203.0.113.42')).headers.get('set-cookie').split(';')[0];
  await holen('/api/abmelden', { method: 'POST', headers: { cookie: cookieNeu, 'x-csrf': ichNeu.csrf, 'Content-Type': 'application/json' }, body: '{}' });
  pruefe('Web: nach Passwortwechsel altes Cookie 401, neues gültig; Abmelden macht auch andere Sitzungen ungültig', pwWeb.status === 200 && cookieNeu.startsWith('fah_adblock=') && altUngueltig === 401 && neuGueltig === 200 && (await holen('/api/ich', { headers: { cookie: zweite } })).status === 401 && (await holen('/api/ich', { headers: { cookie: cookieNeu } })).status === 401, `${pwWeb.status} ${altUngueltig} ${neuGueltig}`);
  // ── Haupt & Ersatz (09.10.2026): Ersatz übernimmt die Einstellungen des Haupts, ändern nur am Haupt ──
  const instanz = async (name) => {
    const dir = path.join(tmp, name); fs.mkdirSync(dir, { recursive: true });
    const ei = new Einstellungen({ verzeichnis: dir, geheimnis: `${name}`.repeat(8), env: {} }).laden();
    const sp = new Spiegel({ verzeichnis: dir, einst: ei, geheimnis: `${name}`.repeat(8), version: 'probe', anwenden: () => {} });
    const wi = webServer({ auth: new Auth({ verzeichnis: dir, geheimnis: `${name}`.repeat(8) }), einst: ei, listen, filter, upstream: up, dns: srv, geraete: { status: () => ({ unifi: {} }), unifiLesen: async () => 0, iconVon: () => null, nameVon: () => '' }, protokoll: prot2, live: new Set(), version: 'probe', statisch: path.join(tmp, 'pub'), daten: dir, spiegel: sp });
    await new Promise((r) => wi.listen(0, '127.0.0.1', r));
    const basis = `http://127.0.0.1:${wi.address().port}`;
    const ck = (await fetch(basis + '/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', passwort: 'admin' }) })).headers.get('set-cookie').split(';')[0];
    const cs = (await (await fetch(basis + '/api/ich', { headers: { cookie: ck } })).json()).csrf;
    const sende = (pf, daten, m = 'POST') => fetch(basis + pf, { method: m, headers: { cookie: ck, 'x-csrf': cs, 'Content-Type': 'application/json' }, body: JSON.stringify(daten) });
    return { ei, sp, wi, basis, sende };
  };
  const H = await instanz('haupt'); const E = await instanz('ersatz');
  const { code: spCode } = await (await H.sende('/api/spiegel/haupt', {})).json();
  H.ei.aendern((x) => { x.regeln.push({ id: 'r-haupt', typ: 'sperren', muster: 'nur-am-haupt.example', geltung: 'alle' }); x.pausen.global = Date.now() + 600000; x.web = { vertrauteProxies: ['172.16.0.0/12'] }; });
  {
    // 25.11.2026 (Prüfung K2): Transport v2 – Code nie auf der Leitung, Stand verschlüsselt, Wiederholung/alter Zeitstempel/anderer Pfad abgelehnt
    const { holen: spHolen, umschlagBauen, schluesselVonCode } = require('../src/spiegel.js');
    const altErsatz = await fetch(H.basis + '/api/spiegel/stand', { headers: { Authorization: `Bearer ${spCode}` } });
    const altText = (await altErsatz.json()).fehler || '';
    const spFalsch = await spHolen(H.basis, 'falsch').then(() => 'ok', (e) => `${e.message}|${e.antwort}`);
    const spStand = await spHolen(H.basis, spCode);
    const K = schluesselVonCode(spCode), post = (pf, u) => fetch(H.basis + pf, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(u) });
    const { umschlag } = umschlagBauen(K, '/api/spiegel/stand', undefined, '');
    const r1 = await post('/api/spiegel/stand', umschlag), r1Text = await r1.text(), r2 = await post('/api/spiegel/stand', umschlag);
    const alt = (await post('/api/spiegel/stand', umschlagBauen(K, '/api/spiegel/stand', undefined, '', Date.now() - 6 * 60000).umschlag)).status;
    const anderPfad = (await post('/api/spiegel/stand', umschlagBauen(K, '/api/spiegel/meldung', undefined, '').umschlag)).status;
    const veraendert = { ...umschlagBauen(K, '/api/spiegel/stand', undefined, '').umschlag }; veraendert.url = 'http://boese.example:8053';
    const verStatus = (await post('/api/spiegel/stand', veraendert)).status;
    pruefe('Spiegel v2: alter Ersatz (Bearer) bekommt 409 mit Hinweis; falscher Code 401; Haupt liefert verschlüsselt (Code nicht in der Anfrage, Regeln nicht im Klartext), ohne UniFi-Zugang/vertraute Proxys; Wiederholung, Zeitstempel > 5 min, anderer Pfad und veränderter Umschlag → 401',
      altErsatz.status === 409 && /alte Kopplung/.test(altText) && /lehnt|Kopplungscode/.test(spFalsch) && /\|true$/.test(spFalsch) && spStand.art === 'fah-adblock-sicherung' && !('unifi' in spStand.einstellungen) && !('web' in spStand.einstellungen) && spStand.einstellungen.regeln.some((r) => r.id === 'r-haupt')
      && !JSON.stringify(umschlag).includes(spCode) && r1.status === 200 && !r1Text.includes('r-haupt') && !r1Text.includes('nur-am-haupt') && r2.status === 401 && alt === 401 && anderPfad === 401 && verStatus === 401,
      JSON.stringify({ alt: altErsatz.status, spFalsch, r1: r1.status, klar: r1Text.includes('r-haupt'), r2: r2.status, altTs: alt, anderPfad, verStatus }));
    // Mann in der Mitte ohne Code: gefälschte Antwort lässt sich nicht öffnen und zählt NICHT als „Haupt gesehen“
    const falle = http.createServer((q, r) => { q.resume(); q.on('end', () => { const eph = nodeCrypto.generateKeyPairSync('x25519'); r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(JSON.stringify({ v: 2, pub: eph.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), daten: 'AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA==.e30=' })); }); });
    await new Promise((r) => falle.listen(0, '127.0.0.1', r));
    const mitm = await spHolen(`http://127.0.0.1:${falle.address().port}`, spCode).then(() => 'geöffnet', (e) => `${e.message}|${e.antwort}`);
    falle.close();
    pruefe('Spiegel v2: gefälschte Antwort (ohne Code) → „nicht entschlüsselbar“, zählt nicht als Lebenszeichen des Haupts', /nicht entschlüsselbar/.test(mitm) && /\|undefined$/.test(mitm), mitm);
    // F3/F4 (Gegenprüfung): Schlüssel am Haupt nur verschlüsselt gespeichert (alte spiegel.json mit Klartext-Hash wird umgestellt);
    // Umschläge von vor dem Start des Haupts werden abgelehnt (Einmalwerte liegen nur im Speicher)
    const sd = path.join(tmp, 'spiegel-alt'); fs.mkdirSync(sd, { recursive: true });
    const altHash = nodeCrypto.createHash('sha256').update('alter-code-123').digest('hex');
    const vorStart = umschlagBauen(schluesselVonCode('alter-code-123'), '/api/spiegel/stand', undefined, '', Date.now() - 1000).umschlag;
    fs.writeFileSync(path.join(sd, 'spiegel.json'), JSON.stringify({ rolle: 'haupt', code_hash: altHash }));
    const sA = new Spiegel({ verzeichnis: sd, einst: H.ei, geheimnis: 's'.repeat(32), version: 'probe', anwenden: () => {} });
    const gespeichert = fs.readFileSync(path.join(sd, 'spiegel.json'), 'utf8');
    let vorStartFehler = ''; try { sA.standFuer(vorStart, '127.0.0.1'); } catch (e) { vorStartFehler = `${e.status} ${e.message}`; }
    const nachStart = sA.standFuer(umschlagBauen(schluesselVonCode('alter-code-123'), '/api/spiegel/stand', undefined, '').umschlag, '127.0.0.1');
    pruefe('Spiegel v2 (Gegenprüfung): alter Klartext-Hash wird beim Start verschlüsselt (Datei enthält ihn nicht mehr), Kopplung gilt weiter; Umschlag von vor dem Start → 401',
      !gespeichert.includes(altHash) && JSON.parse(gespeichert).k && sA.status().code_gesetzt && nachStart?.v === 2 && /^401 .*Neustart/.test(vorStartFehler), vorStartFehler);
  }
  const spKoppeln = await E.sende('/api/spiegel/ersatz', { url: H.basis, code: spCode });
  pruefe('Spiegel: Ersatz koppeln übernimmt Regeln und Pausen, eigene Proxys bleiben', spKoppeln.status === 200 && E.ei.werte.regeln.some((r) => r.id === 'r-haupt') && E.ei.werte.pausen.global === H.ei.werte.pausen.global && !(E.ei.werte.web?.vertrauteProxies || []).length, `HTTP ${spKoppeln.status}`);
  const spGesperrt = await E.sende('/api/regeln', { typ: 'erlauben', muster: 'x.example', geltung: 'alle' });
  const spUnifi = await E.sende('/api/einstellungen/unifi', { url: 'https://192.168.1.1', schluessel: '' });
  pruefe('Spiegel: am Ersatz sind Änderungen gesperrt (409 mit Hinweis), UniFi-Zugang bleibt einstellbar', spGesperrt.status === 409 && /Haupt/.test((await spGesperrt.json()).fehler) && spUnifi.status !== 409);
  H.ei.aendern((x) => { x.regeln.push({ id: 'r-spaeter', typ: 'erlauben', muster: 'spaeter.example', geltung: 'alle' }); });
  const spSt = await E.sp.abgleichen();
  const gesundE = await (await fetch(E.basis + '/api/health')).json(); const gesundH = await (await fetch(H.basis + '/api/health')).json();
  pruefe('Spiegel: Abgleich holt neue Regeln; Haupt merkt sich den Abruf; /api/health zeigt die Rolle', !spSt.fehler && E.ei.werte.regeln.some((r) => r.id === 'r-spaeter') && H.sp.status().ersatz && H.sp.status().ersatz.zeit > 0 && gesundE.rolle === 'ersatz' && gesundH.rolle === 'haupt');
  {
    // 25.11.2026 (K2/K4/K11): Austausch über den verschlüsselten Kanal – Daten des Ersatzes kommen beim Haupt an, die Antwort beim Ersatz, beide
    // Seiten bekommen K (32 Byte) statt des Codes; der Austausch läuft auch, wenn die Übernahme des Stands scheitert (Haupt neuer als Ersatz)
    let amHaupt = null, kHaupt = null, amErsatz = null, kErsatz = null;
    H.sp.austausch = { empfangen: (d, K) => { amHaupt = d; kHaupt = K; return { nutzungBestaetigt: (d.nutzung || []).map((p) => p.lauf), aufgebraucht: { g1: ['dienst:x'] } }; } };
    E.sp.austausch = { sammeln: () => ({ meldungen: { ereignisse: [{ titel: 'probe' }] }, nutzung: [{ lauf: 'lauf-probe-123', tag: 'x', daten: {} }] }), uebernehmen: (a, K) => { amErsatz = a; kErsatz = K; }, zurueck: () => {} };
    const anwendenAlt = E.sp.anwenden; E.sp.anwenden = () => { throw new Error('Sicherung nicht übernommen: Feld unbekannt'); };
    H.ei.aendern((x) => { x.regeln.push({ id: 'r-neuer', typ: 'erlauben', muster: 'neuer.example', geltung: 'alle' }); });
    const gesehenVorher = E.sp.z.haupt_gesehen || 0; await new Promise((r) => setTimeout(r, 5));
    const stA = await E.sp.abgleichen(); E.sp.anwenden = anwendenAlt; H.sp.austausch = null; E.sp.austausch = null;
    pruefe('Spiegel v2: Austausch kommt verschlüsselt an (beide Seiten mit K statt Code), läuft auch bei gescheiterter Übernahme; Haupt gilt dann trotzdem als gesehen (K4)',
      amHaupt?.meldungen?.ereignisse?.[0]?.titel === 'probe' && amErsatz?.nutzungBestaetigt?.[0] === 'lauf-probe-123' && amErsatz?.aufgebraucht?.g1?.[0] === 'dienst:x' && kHaupt?.length === 32 && kErsatz?.length === 32 && kHaupt.equals(kErsatz)
      && /nicht übernommen/.test(stA.fehler || '') && E.sp.z.haupt_gesehen > gesehenVorher, JSON.stringify({ fehler: stA.fehler, amErsatz }));
  }
  {
    // K11: Zeitkonto-Pakete mit Lauf-ID und Tag – verlorene Antwort führt nicht zu Doppelzählung, Pakete von gestern zählen nie heute
    const { Zeitkonto } = require('../src/zeitkonto.js');
    let uz = Date.UTC(2026, 10, 25, 20, 0); const zkE = new Zeitkonto({ jetzt: () => uz, zeitzone: 'Europe/Berlin' }), zkH = new Zeitkonto({ jetzt: () => uz, zeitzone: 'Europe/Berlin' });
    zkE.vermerke('g', ['dienst:tiktok'], uz); uz += 120000; zkE.vermerke('g', ['dienst:tiktok'], uz);
    const p1 = zkE.abholen(); zkH.annehmen(p1);                       // Haupt zählt, Antwort geht verloren
    uz += 60000; zkE.vermerke('g', ['dienst:tiktok'], uz);
    const p2 = zkE.abholen(); const best = zkH.annehmen(p2); zkE.bestaetigen(best);   // erneut gesendet + neues Paket
    const minH = zkH.genutztMin('g', 'dienst:tiktok'), minE = zkE.genutztMin('g', 'dienst:tiktok'), offen = zkE.abholen().length;
    zkE.vermerke('g', ['dienst:tiktok'], uz + 30000); const vorMitternacht = zkE.abholen();
    uz = Date.UTC(2026, 10, 25, 23, 5);   // 00:05 in Berlin
    const nachMitternacht = zkE.abholen(), bestGestern = zkH.annehmen(vorMitternacht);
    pruefe('Zeitkonto (K11): erneut gesendetes Paket zählt beim Haupt nur einmal; bestätigte Pakete verschwinden; nach Mitternacht kein Paket von gestern, ein altes Paket wird bestätigt, aber nicht gebucht',
      p1.length === 1 && p2.length === 2 && minH === minE && minH === 4 && offen === 0 && vorMitternacht.length === 1 && nachMitternacht.length === 0 && bestGestern.length === 1 && zkH.genutztMin('g', 'dienst:tiktok') === 0,
      JSON.stringify({ p1: p1.length, p2: p2.length, minH, minE, offen, vor: vorMitternacht.length, nach: nachMitternacht.length, best: bestGestern.length, heuteH: zkH.genutztMin('g', 'dienst:tiktok') }));
  }
  H.sp.hauptWerden(); const spAlt = await E.sp.abgleichen();
  pruefe('Spiegel: neuer Code am Haupt → Ersatz meldet den Fehler, behält seinen Stand', /Kopplungscode/.test(spAlt.fehler || '') && E.ei.werte.regeln.some((r) => r.id === 'r-spaeter'));
  // ── Koppeln von einer Oberfläche (09.10.2026): Partner-Adresse + Konto; leere Instanz holt sich den Stand der eingerichteten ──
  const PA = await instanz('pa'); const PB = await instanz('pb'); const PC = await instanz('pc');
  PA.ei.aendern((x) => { x.regeln.push({ id: 'r-pa', typ: 'sperren', muster: 'nur-bei-pa.example', geltung: 'alle' }); });
  const pk1 = await PB.sende('/api/spiegel/partner', { rolle: 'haupt', url: PA.basis, eigene_url: PB.basis, name: 'admin', passwort: 'admin', bestaetigt: true });
  const pk1j = await pk1.json();
  pruefe('Partner: frisch installierte Instanz wird Haupt und holt zuerst die Einstellungen des Partners, der Partner wird Ersatz', pk1.status === 200 && pk1j.uebernommen === 'vom Partner' && PB.sp.rolle === 'haupt' && PA.sp.rolle === 'ersatz' && PA.sp.status().haupt_url === PB.basis && PB.ei.werte.regeln.some((r) => r.id === 'r-pa') && PA.ei.werte.regeln.some((r) => r.id === 'r-pa') && PB.sp.status().partner_url === PA.basis, JSON.stringify(pk1j));
  const pk2 = await PA.sende('/api/spiegel/partner', { rolle: 'haupt', url: PB.basis, eigene_url: PA.basis, name: 'admin', passwort: 'admin', bestaetigt: true });
  pruefe('Partner: Rollen tauschen vom Ersatz aus – beide eingerichtet, nichts übernommen', pk2.status === 200 && (await pk2.json()).uebernommen === null && PA.sp.rolle === 'haupt' && PB.sp.rolle === 'ersatz' && PB.sp.status().haupt_url === PA.basis);
  const pk3 = await PA.sende('/api/spiegel/partner', { rolle: 'ersatz', url: PC.basis, eigene_url: PA.basis, name: 'admin', passwort: 'admin', bestaetigt: true });
  const pk3j = await pk3.json();
  pruefe('Partner: als Ersatz mit leerem Partner – der Partner bekommt zuerst die Einstellungen von hier und wird Haupt', pk3.status === 200 && pk3j.uebernommen === 'zum Partner' && PC.sp.rolle === 'haupt' && PA.sp.rolle === 'ersatz' && PC.ei.werte.regeln.some((r) => r.id === 'r-pa') && PA.ei.werte.regeln.some((r) => r.id === 'r-pa'), JSON.stringify(pk3j));
  const PD = await instanz('pd'); const { code: pdCode } = PD.sp.hauptWerden();
  let leerFehler = ''; try { await E.sp.ersatzWerden(PD.basis, pdCode); } catch (e) { leerFehler = e.message; }
  PC.ei.aendern((x) => { x.regeln = []; x.geraete = {}; x.dienste = {}; }); const pcLeer = await PA.sp.abgleichen();
  pruefe('Partner: ein leerer Haupt überschreibt nie eine eingerichtete Instanz (Koppeln und Abgleich)', /noch leer/.test(leerFehler) && E.ei.werte.regeln.some((r) => r.id === 'r-spaeter') && /noch leer/.test(pcLeer.fehler || '') && PA.ei.werte.regeln.some((r) => r.id === 'r-pa'), `${leerFehler} | ${pcLeer.fehler}`);
  const gesundPA = await (await fetch(PA.basis + '/api/health')).json();
  const pkFalsch = await PD.sende('/api/spiegel/partner', { rolle: 'ersatz', url: PB.basis, eigene_url: PD.basis, name: 'admin', passwort: 'falsch', bestaetigt: true });
  const pkEigen = await PD.sende('/api/spiegel/partner', { rolle: 'ersatz', url: PD.basis, eigene_url: PD.basis, name: 'admin', passwort: 'admin', bestaetigt: true });
  pruefe('Partner: falsches Passwort → 400 mit Hinweis, eigene Adresse abgelehnt; /api/health nennt App und Partner', pkFalsch.status === 400 && /Anmeldung beim Partner/.test((await pkFalsch.json()).fehler) && pkEigen.status === 400 && PD.sp.rolle === 'haupt' && gesundPA.app === 'fah-adblock' && gesundPA.partner === PC.basis, JSON.stringify(gesundPA));

  // ── Kinderschutz (23.11.2026) ────────────────────────────────────────────
  {
    const { Zeitkonto } = require('../src/zeitkonto.js');
    const { Meldungen } = require('../src/meldungen.js');
    const { Unterwegs } = require('../src/unterwegs.js');
    const { Acme, csr } = require('../src/acme.js');
    const ks = require('../src/daten/kinderschutz.js');
    const kd = path.join(tmp, 'ks'); fs.mkdirSync(kd, { recursive: true });
    // Einstellungen: neue Kategorien/Listen, Migration des Profils „Kinder“ genau einmal
    const v0 = vorgaben({});
    pruefe('Kinderschutz: Kategorien anonym/drogen/umgehung/piraterie und Listen ab Werk, Betrug-Liste aus', ['anonym', 'drogen', 'umgehung', 'piraterie'].every((k) => v0.kategorien.some((x) => x.id === k)) && v0.listen.find((l) => l.id === 'fah-anonym')?.url === 'eingebaut:anonym' && v0.listen.find((l) => l.id === 'blp-betrug')?.an === false);
    const alt = JSON.parse(JSON.stringify(v0)); delete alt.migrationen; alt.profile = alt.profile.map((p) => (p.id === 'kinder' ? { id: 'kinder', name: 'Kinder', farbe: '#fff', kategorien: { werbung: { an: true, zeitplan: [] } } } : p));
    alt.vorgabenListen = alt.listen.filter((l) => !['fah-anonym', 'blp-drogen', 'blp-vaping', 'hagezi-umgehung', 'blp-piraterie', 'blp-betrug'].includes(l.id)).map((l) => l.id);
    alt.listen = alt.listen.filter((l) => alt.vorgabenListen.includes(l.id));
    fs.writeFileSync(path.join(kd, 'einstellungen.json'), JSON.stringify(alt));
    const eM = new Einstellungen({ verzeichnis: kd, geheimnis: 'k'.repeat(32), env: {} }).laden();
    const kM = eM.werte.profile.find((p) => p.id === 'kinder');
    const migriert = kM.kategorien.anonym?.an && kM.kategorien.umgehung?.an && kM.ruhezeiten?.messenger?.length && kM.sicher?.suche && eM.werte.listen.some((l) => l.id === 'blp-drogen') && eM.werte.migrationen.includes('kinderschutz-2026-11');
    eM.aendern((x) => { x.profile.find((p) => p.id === 'kinder').kategorien.anonym.an = false; delete x.profile.find((p) => p.id === 'kinder').ruhezeiten; });
    const eM2 = new Einstellungen({ verzeichnis: kd, geheimnis: 'k'.repeat(32), env: {} }).laden();
    pruefe('Kinderschutz: Migration ergänzt das Profil „Kinder“ einmal – spätere Änderungen des Betreibers bleiben', migriert && eM2.werte.profile.find((p) => p.id === 'kinder').kategorien.anonym.an === false && !eM2.werte.profile.find((p) => p.id === 'kinder').ruhezeiten);
    const { holen: listeHolen } = require('../src/dns/listen.js');
    const eingebaut = await listeHolen('eingebaut:anonym');
    {
      // 25.11.2026 (K12): kein Listen-Download ins interne Netz – Loopback/Metadaten/Link-local nie, private Netze nur als ausdrücklich eingetragene IP,
      // nie über einen Namen (DNS-Rebinding) oder eine Umleitung; geprüft wird die tatsächlich verbundene Adresse
      const { zielErlaubt } = require('../src/dns/listen.js');
      const stub = (adr) => (name, opt, cb) => cb(null, [{ address: adr, family: adr.includes(':') ? 6 : 4 }]);
      const r = async (url, o = {}) => listeHolen(url, { timeout: 400, ...o }).then(() => 'geladen', (e) => e.message);
      const loop = await r('http://127.0.0.1:9/liste'), meta = await r('http://169.254.169.254/latest/meta-data'), v6 = await r('http://[::1]:9/x');
      const rebind = await r('http://liste.example/x', { aufloesen: stub('127.0.0.1') }), privName = await r('http://liste.example/x', { aufloesen: stub('192.168.1.20') });
      const datei = await r('file:///etc/passwd'), privIp = await r('http://10.255.255.1:9/x');
      const gemappt = await Promise.all(['http://[::ffff:7f00:1]:9/x', 'http://[0:0:0:0:0:ffff:a9fe:a9fe]/x', 'http://[64:ff9b::7f00:1]/x', 'http://[::7f00:1]/x'].map((u) => r(u)));
      pruefe('Listen-Download (K12): Loopback, Metadaten, ::1, IPv4 in IPv6 (::ffff:7f00:1, NAT64, IPv4-kompatibel), Name → 127.0.0.1 oder privat, file: abgelehnt; ausdrücklich eingetragene private IP erlaubt (scheitert hier nur an der Verbindung)',
        [loop, meta, v6, ...gemappt].every((x) => /internen Netz/.test(x)) && [rebind, privName].every((x) => /ins interne Netz/.test(x)) && /Nur http/.test(datei) && !/intern/.test(privIp)
        && zielErlaubt('185.199.108.133', false) && !zielErlaubt('::ffff:127.0.0.1', false) && !zielErlaubt('::ffff:c0a8:101', false) && zielErlaubt('::ffff:c0a8:101', true) && zielErlaubt('10.20.30.40', true) && !zielErlaubt('127.0.0.1', true),
        JSON.stringify({ loop, meta, v6, gemappt, rebind, privName, datei, privIp }));
    }
    pruefe('Kinderschutz: eingebaute Liste „anonym“ wird aus dem Programm gelesen (ngl.link, tellonym.me)', parse(eingebaut.text).domains.has('ngl.link') && parse(eingebaut.text).domains.has('tellonym.me'));

    // Filter: Hilfe, Ruhezeit, Zeitlimit, sichere Suche
    const T = Date.parse('2026-11-23T22:00:00+01:00');   // Montag 22:00
    const lK = new Listen({ verzeichnis: path.join(kd, 'l'), holer: async (u) => ({ text: u.includes('anonym') ? ks.ANONYM.join('\n') : 'juuuport.de\nporn.example.com\n' + Array.from({ length: 12 }, (_, i) => `x${i}.example.com`).join('\n') }), protokoll: () => {} });
    lK.konfigurieren([{ id: 'a', url: 'eingebaut:anonym', kategorie: 'anonym', an: true }, { id: 'j', url: 'https://x/jugend', kategorie: 'jugendschutz', an: true }]); lK.laden(); await lK.aktualisieren();
    let jetztK = T; const zk = new Zeitkonto({ jetzt: () => jetztK, zeitzone: 'Europe/Berlin' });
    const fK = new Filter({ listen: lK, jetzt: () => jetztK, zeitzone: 'Europe/Berlin', zeitkonto: zk });
    const profK = { id: 'kinder', kategorien: { anonym: { an: true, zeitplan: [] }, jugendschutz: { an: true, zeitplan: [] } }, ruhezeiten: { messenger: [{ tage: [1, 2, 3, 4, 5, 6, 7], von: '21:00', bis: '06:30' }], spiele: [{ tage: [1], von: '21:00', bis: '23:00' }] }, sicher: { suche: true, youtube: 'moderat' }, limits: { 'dienst:tiktok': 30, 'rubrik:spiele': 60 } };
    fK.konfigurieren({ regeln: [{ id: 'r1', typ: 'sperren', muster: 'juuuport.de', geltung: 'alle' }], profile: [{ id: 'standard', kategorien: {} }, profK], listen: lK.quellen, geraete: { kind: { profil: 'kinder' } }, pausen: { global: 0, geraete: {} }, dienste: {} });
    const hilfe = fK.entscheide({ geraetId: 'kind', name: 'www.juuuport.de' });
    { const dk = fK.ttlDeckel('kind', 'web.whatsapp.com', T - 90 * 60000), dkHilfe = fK.ttlDeckel('kind', 'www.juuuport.de', T - 90 * 60000);   // T = Mo 22:00 → 20:30
      pruefe('TTL-Deckel (K15): Messenger-Ruhezeit ab 21:00 → um 20:30 erlaubte WhatsApp-Antwort höchstens 1800 s; Hilfsangebot ohne Deckel', dk === 1800 && dkHilfe === 0, JSON.stringify({ dk, dkHilfe })); }
    pruefe('Kinderschutz: Hilfsangebote bleiben erreichbar – auch gegen Sperrregel und Jugendschutz-Liste', hilfe.aktion === 'erlaubt' && hilfe.grund === 'Hilfsangebot' && fK.entscheide({ geraetId: 'kind', name: 'ngl.link' }).aktion === 'geblockt' && fK.entscheide({ geraetId: 'kind', name: 'ngl.link' }).kategorie === 'anonym');
    const nachts = fK.entscheide({ geraetId: 'kind', name: 'web.whatsapp.com' });
    jetztK = Date.parse('2026-11-23T12:00:00+01:00'); const mittags = fK.entscheide({ geraetId: 'kind', name: 'web.whatsapp.com' }); jetztK = T;
    pruefe('Kinderschutz: Ruhezeit Messenger sperrt WhatsApp nachts (über Mitternacht), mittags frei; Pokémon GO bleibt von der Spiele-Ruhezeit ausgenommen', nachts.aktion === 'geblockt' && nachts.grund === 'Ruhezeit' && mittags.aktion === 'erlaubt' && fK.entscheide({ geraetId: 'kind', name: 'pokemongo.com' }).aktion === 'erlaubt' && fK.entscheide({ geraetId: 'kind', name: 'roblox.com' }).grund === 'Ruhezeit' && fK.entscheide({ geraetId: 'anderes', name: 'web.whatsapp.com' }).aktion === 'erlaubt');
    // Zeitkonto: Sitzung 10:00–10:29 (alle 60 s eine Anfrage) = 30 min → TikTok aufgebraucht; +15 min → wieder frei
    jetztK = Date.parse('2026-11-23T10:00:00+01:00');
    for (let i = 0; i < 30; i++) zk.vermerke('kind', fK.limitZiele(profK, fK.dienstVon('tiktok.com')), jetztK + i * 60000);
    jetztK += 30 * 60000;
    const leer = fK.entscheide({ geraetId: 'kind', name: 'tiktok.com' });
    zk.mehr('kind', 'dienst:tiktok', 15);
    const wieder = fK.entscheide({ geraetId: 'kind', name: 'tiktok.com' });
    zk.vermerke('kind', ['dienst:tiktok'], jetztK + 20 * 60000);   // Lücke > 5 min: neue Sitzung, nur 1 min
    pruefe('Kinderschutz: Zeitkonto zählt Sitzungen, Limit sperrt mit Grund „Zeitlimit“, +15 min gibt frei, Lücke > 5 min startet neu', zk.genutztMin('kind', 'dienst:tiktok') === 31 && leer.aktion === 'geblockt' && leer.grund === 'Zeitlimit' && wieder.aktion === 'erlaubt', `${zk.genutztMin('kind', 'dienst:tiktok')} ${leer.grund} ${wieder.aktion}`);
    jetztK = Date.parse('2026-11-24T08:00:00+01:00');
    pruefe('Kinderschutz: Zeitkonto beginnt um Mitternacht neu (Zusatzzeit verfällt)', zk.genutztMin('kind', 'dienst:tiktok') === 0 && zk.extraMin('kind', 'dienst:tiktok') === 0);
    jetztK = T;
    pruefe('Kinderschutz: sichere Suche – Google (alle Länder), Bing, DuckDuckGo, YouTube moderat; nicht für andere Profile', fK.sicherZiel('kind', 'www.google.de') === 'forcesafesearch.google.com' && fK.sicherZiel('kind', 'google.co.uk') === 'forcesafesearch.google.com' && fK.sicherZiel('kind', 'www.bing.com') === 'strict.bing.com' && fK.sicherZiel('kind', 'duckduckgo.com') === 'safe.duckduckgo.com' && fK.sicherZiel('kind', 'm.youtube.com') === 'restrictmoderate.youtube.com' && !fK.sicherZiel('kind', 'mail.google.com') && !fK.sicherZiel('anderes', 'www.google.de'));

    // DNS-Server: sichere Suche (CNAME + Adressen, HTTPS leer), TTL-Deckel bei Zeitlimit, unterwegs ohne Heimnetz-Namen
    const upK = { frage: async (anf) => ({ buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions, answers: anf.frage.typ === 'A' ? [{ type: 'A', name: anf.frage.name, ttl: 3600, data: anf.frage.name === 'forcesafesearch.google.com' ? '216.239.38.120' : '9.9.9.9' }] : [] }), alterSek: 0, cache: false, anbieter: 'fake' }) };
    const lokalK = { zustaendig: (nm) => /(^|\.)(lan|arpa|example\.org)$/.test(nm), frage: async () => { throw new Error('darf unterwegs nicht gefragt werden'); } };
    const recK = new Records({ eintraege: [{ host: 'nas.example.org', ip: '192.168.1.23' }] });
    const srvK = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fK, upstream: upK, lokal: lokalK, records: recK, geraete: { von: (ip) => ({ id: ip === '192.168.1.50' ? 'kind' : `ip:${ip}`, name: ip }) }, zeitkonto: zk });
    const ks1 = dnsPacket.decode(await srvK.bearbeite(frage('www.google.de'), '192.168.1.50', true));
    const ks2 = dnsPacket.decode(await srvK.bearbeite(frage('www.google.de', 'HTTPS'), '192.168.1.50', true));
    const tt = dnsPacket.decode(await srvK.bearbeite(frage('www.tiktok.com'), '192.168.1.50', true));
    pruefe('DNS: sichere Suche liefert CNAME forcesafesearch.google.com + Adresse, HTTPS-Eintrag leer; Zeitlimit-Dienst mit TTL ≤ 60 s', ks1.answers[0]?.type === 'CNAME' && ks1.answers[0].data === 'forcesafesearch.google.com' && ks1.answers[1]?.data === '216.239.38.120' && ks2.answers.length === 0 && ks2.rcode === 'NOERROR' && tt.answers[0]?.ttl <= 60);
    const ext = { extern: true, geraet: { id: 'kind', name: 'Kind' } };
    const e1 = dnsPacket.decode(await srvK.bearbeite(frage('ngl.link'), '203.0.113.7', false, ext));
    const e2 = dnsPacket.decode(await srvK.bearbeite(frage('nas.example.org'), '203.0.113.7', false, ext));
    const e3 = dnsPacket.decode(await srvK.bearbeite(frage('drucker.lan'), '203.0.113.7', false, ext));
    const e4 = dnsPacket.decode(await srvK.bearbeite(frage('ngl.link'), '203.0.113.7', true));
    pruefe('DNS unterwegs: fremde IP mit Geräte-Kontext wird mit dem Profil des Geräts gefiltert, Heimnetz-Records gehen nicht raus, .lan → NXDOMAIN, ohne Kontext REFUSED', e1.answers[0]?.data === '0.0.0.0' && e2.answers[0]?.data === '9.9.9.9' && e3.rcode === 'NXDOMAIN' && e4.rcode === 'REFUSED');

    // Meldungen: gebündelt, Ruhezeit, nur gewählte Profile, Ersatz reicht weiter, Umgehungsverdacht
    const eK = new Einstellungen({ verzeichnis: path.join(kd, 'm'), geheimnis: 'k'.repeat(32), env: {} }).laden();
    eK.aendern((x) => { x.meldungen = { ...x.meldungen, an: true, profile: ['kinder'] }; x.geraete.kind = { profil: 'kinder', name: 'Kind' }; });
    let ersatz = false;
    const mel = new Meldungen({ einst: eK, jetzt: () => jetztK, istErsatz: () => ersatz, kategorieName: (k) => ({ anonym: 'Anonyme Chats' }[k] || k), protokoll: () => {} });
    const blk = (domain) => ({ ts: jetztK, geraet: 'kind', geraetName: 'Kind', profil: 'kinder', aktion: 'geblockt', grund: 'Liste', kategorie: 'anonym', domain });
    mel.beachte(blk('ngl.link')); mel.beachte(blk('ngl.link')); mel.beachte(blk('tellonym.me'));
    mel.beachte({ ...blk('ngl.link'), profil: 'standard', geraet: 'papa' });
    await mel.abschicken('kind|kat:anonym');
    mel.beachte(blk('ngl.link'));   // in der Ruhezeit
    pruefe('Meldungen: drei Sperren → EIN Eintrag mit Domains und Anzahl, Ruhezeit unterdrückt den nächsten, anderes Profil meldet nichts, nichts geht nach draußen', mel.verlauf.length === 1 && /3 Versuche/.test(mel.verlauf[0].text) && /ngl\.link \(2×\)/.test(mel.verlauf[0].details) && /tellonym/.test(mel.verlauf[0].details) && /Anonyme Chats/.test(mel.verlauf[0].titel) && mel.verlauf[0].ernst && mel.buendel.size === 0 && mel.unterdrueckt === 1 && !mel.senden && !mel.verlauf[0].handy);
    ersatz = true; mel.beachte(blk('omegle.com')); const abgeholt = mel.abholen(); ersatz = false;
    const mel2 = new Meldungen({ einst: eK, jetzt: () => jetztK, protokoll: () => {} });
    mel2.empfangen({ ereignisse: abgeholt.ereignisse, zuletzt: { kind: jetztK } });
    pruefe('Meldungen: Ersatz sammelt statt zu senden, Haupt übernimmt Ereignisse und „zuletzt gesehen“', abgeholt.ereignisse.length === 1 && mel2.buendel.has('kind|kat:anonym') && mel2.zuletzt.get('kind') === jetztK);
    const st = jetztK;
    const melS = new Meldungen({ einst: eK, jetzt: () => st, protokoll: () => {},
      geraete: { stand: st, jeMac: new Map([['kind', { gesehen: st, ip: '192.168.1.50', verbunden: st - 3 * 3600000, name: 'Kind' }]]) }, filter: { profilVon: (g) => ({ id: g === 'kind' ? 'kinder' : 'standard' }) } });
    melS.zuletzt.set('kind', st - 45 * 60000);
    const verdacht = melS.pruefeStille(), nochmal = melS.pruefeStille();
    pruefe('Meldungen: Umgehungsverdacht, wenn das Gerät im Netz ist, aber seit 45 min nicht fragt – nur einmal je 6 h', verdacht.join() === 'kind' && nochmal.length === 0 && /fragt FAH-Adblock nicht mehr/.test(melS.verlauf[0]?.titel));
    // Neustart (neue Instanz, gleiche Liste): die 6-h-Ruhe gilt weiter – sonst kommt die Meldung nach jedem Neustart erneut
    const melS2 = new Meldungen({ einst: eK, jetzt: () => st + 60 * 60000, protokoll: () => {},
      geraete: { stand: st + 60 * 60000, jeMac: new Map([['kind', { gesehen: st + 60 * 60000, ip: '192.168.1.50', verbunden: st - 3 * 3600000, name: 'Kind' }]]) }, filter: { profilVon: (g) => ({ id: g === 'kind' ? 'kinder' : 'standard' }) } });
    melS2.verlauf = [...melS.verlauf]; melS2.zuletzt.set('kind', st - 45 * 60000);
    pruefe('Meldungen: Umgehungsverdacht nach einem Neustart nicht erneut innerhalb von 6 h', melS2.pruefeStille().length === 0);

    // ACME: Ablauf gegen einen nachgebauten Server (Signaturen werden geprüft), CSR
    const kontoJwk = {}; let bestellt = 0;
    const fakeAcme = async (url, o = {}) => {
      const r = (status, json, kopf = {}) => ({ status, json, text: typeof json === 'string' ? json : JSON.stringify(json), kopf: { 'replay-nonce': `n${Math.random()}`, ...kopf } });
      if (url === 'https://acme.test/dir') return r(200, { newNonce: 'https://acme.test/nonce', newAccount: 'https://acme.test/acct', newOrder: 'https://acme.test/order' });
      if (url === 'https://acme.test/nonce') return r(200, '');
      const body = JSON.parse(o.daten), geschuetzt = JSON.parse(Buffer.from(body.protected, 'base64url'));
      if (geschuetzt.jwk) Object.assign(kontoJwk, geschuetzt.jwk);
      const echt = require('node:crypto').verify('sha256', Buffer.from(`${body.protected}.${body.payload}`), { key: require('node:crypto').createPublicKey({ key: kontoJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(body.signature, 'base64url'));
      if (!echt || geschuetzt.url !== url) return r(400, { detail: 'Signatur falsch' });
      if (url === 'https://acme.test/acct') return r(201, { status: 'valid' }, { location: 'https://acme.test/acct/1' });
      if (url === 'https://acme.test/order') { bestellt++; return r(201, { status: 'pending', authorizations: ['https://acme.test/authz'], finalize: 'https://acme.test/fin' }, { location: 'https://acme.test/order/1' }); }
      if (url === 'https://acme.test/authz') return r(200, { status: fakeAcme.geprueft ? 'valid' : 'pending', challenges: [{ type: 'http-01', url: 'https://acme.test/chall', token: 'tok-beispiel-1' }] });
      if (url === 'https://acme.test/chall') { fakeAcme.geprueft = acmeK.antwort('tok-beispiel-1') === `tok-beispiel-1.${acmeK.daumen()}`; return r(200, {}); }
      if (url === 'https://acme.test/fin') { fakeAcme.csr = JSON.parse(Buffer.from(body.payload, 'base64url')).csr; return r(200, { status: 'processing' }); }
      if (url === 'https://acme.test/order/1') return r(200, { status: 'valid', certificate: 'https://acme.test/cert' });
      if (url === 'https://acme.test/cert') return r(200, fakeAcme.kette);
      return r(404, {});
    };
    const sk = require('node:child_process').spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', path.join(kd, 'k.pem'), '-out', path.join(kd, 'c.pem'), '-days', '90', '-subj', '/CN=dns-kind1234.example.org', '-addext', 'subjectAltName=DNS:dns-kind1234.example.org'], { stdio: 'ignore' });
    const mitOpenssl = sk.status === 0;
    if (mitOpenssl) {
      // 25.11.2026 (Prüfung K13): Scheitert das erste Merken des UniFi-Zertifikatabdrucks (volle Platte), wird NICHTS gesendet (Schlüssel nie
      // über eine nicht festgenagelte Verbindung) und der Prozess stürzt nicht ab
      const { unifiAnfrage } = require('../src/geraete.js');
      let empfangen = 0;
      const ts = require('node:tls').createServer({ key: fs.readFileSync(path.join(kd, 'k.pem')), cert: fs.readFileSync(path.join(kd, 'c.pem')) }, (s) => { s.on('data', (d) => { empfangen += d.length; }); s.on('error', () => {}); });
      await new Promise((r) => ts.listen(0, '127.0.0.1', r));
      const ergU = await unifiAnfrage({ url: `https://127.0.0.1:${ts.address().port}`, schluessel: 'geheim', abdruck: '', merken: () => { throw new Error('Platte voll'); } }, 'GET', '/proxy/network/api/s/default/stat/sta').then(() => 'gesendet', (e) => e.message);
      await new Promise((r) => setTimeout(r, 100));
      pruefe('UniFi: Abdruck nicht speicherbar → Anfrage abgelehnt, kein Byte HTTP (API-Schlüssel) gesendet', /nicht speicherbar/.test(ergU) && empfangen === 0, `${ergU} | empfangen ${empfangen}`);
      ts.close();
      // Erster Kontakt merkt den Abdruck UND hält ihn im Zugang fest: die Folgeanfrage mit demselben Zugang (Portfreigabe GET → POST) gegen ein
      // ANDERES Zertifikat sendet nichts und überschreibt den gemerkten Abdruck nicht (vorher galt sie wieder als „erster Kontakt“)
      const sk2 = require('node:child_process').spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', path.join(kd, 'k2.pem'), '-out', path.join(kd, 'c2.pem'), '-days', '1', '-subj', '/CN=fremd'], { stdio: 'ignore' });
      if (sk2.status === 0) {
        const httpsU = require('node:https'); let emp2 = 0;
        const echtU = httpsU.createServer({ key: fs.readFileSync(path.join(kd, 'k.pem')), cert: fs.readFileSync(path.join(kd, 'c.pem')) }, (q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end('{"data":[]}'); });
        const fremdU = require('node:tls').createServer({ key: fs.readFileSync(path.join(kd, 'k2.pem')), cert: fs.readFileSync(path.join(kd, 'c2.pem')) }, (s) => { s.on('data', (d) => { emp2 += d.length; }); s.on('error', () => {}); });
        await new Promise((r) => echtU.listen(0, '127.0.0.1', r)); await new Promise((r) => fremdU.listen(0, '127.0.0.1', r));
        let gemerkt = ''; const uz = { url: `https://127.0.0.1:${echtU.address().port}`, schluessel: 'geheim', abdruck: '', merken: (fp) => { gemerkt = fp; } };
        const e1 = await unifiAnfrage(uz, 'GET', '/x').then(() => 'ok', (e) => e.message); const nachErst = gemerkt;
        uz.url = `https://127.0.0.1:${fremdU.address().port}`;
        const e2 = await unifiAnfrage(uz, 'POST', '/y', { a: 1 }).then(() => 'gesendet', (e) => e.message);
        await new Promise((r) => setTimeout(r, 100));
        pruefe('UniFi: Folgeanfrage mit demselben Zugang gegen fremdes Zertifikat → abgelehnt, kein Byte gesendet, gemerkter Abdruck unverändert', e1 === 'ok' && nachErst && uz.abdruck === nachErst && /geändert/.test(e2) && emp2 === 0 && gemerkt === nachErst, JSON.stringify({ e1, e2, emp2, gleich: gemerkt === nachErst }));
        echtU.close(); fremdU.close();
      }
    }
    fakeAcme.kette = mitOpenssl ? fs.readFileSync(path.join(kd, 'c.pem'), 'utf8') : '';
    const acmeK = new Acme({ verzeichnis: kd, verzeichnisUrl: 'https://acme.test/dir', anfrager: fakeAcme, warten: async () => {}, protokoll: () => {} });
    if (mitOpenssl) {
      const z = await acmeK.zertifikat('dns-kind1234.example.org');
      pruefe('ACME: Konto, Bestellung, HTTP-Prüfung (Schlüsselautorisierung), CSR, Zertifikat – alle Anfragen korrekt signiert', z.kette.includes('BEGIN CERTIFICATE') && z.bis > Date.now() && fakeAcme.geprueft && !!fakeAcme.csr && bestellt === 1 && acmeK.herausforderungen.size === 0);
    } else pruefe('ACME: CSR ist DER und enthält den Namen (ohne openssl kein Ablauf-Test)', csr('dns-x.example.org', require('node:crypto').generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey).includes(Buffer.from('dns-x.example.org')));

    // Web: Vorlagen, Hilfe fest, Kinderschutz-API, unterwegs (Gerätename nur DoH/ACME/Profil), DoT
    const eW = new Einstellungen({ verzeichnis: path.join(kd, 'w'), geheimnis: 'w'.repeat(32), env: {} }).laden();
    const fW = new Filter({ listen: lK, zeitkonto: zk }); const kfg = () => fW.konfigurieren({ regeln: eW.werte.regeln, profile: eW.werte.profile, listen: lK.quellen, geraete: eW.werte.geraete, pausen: eW.werte.pausen, dienste: eW.werte.dienste }); kfg(); eW.beobachten(kfg);
    const srvW = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fW, upstream: upK, lokal: lokalK, records: recK, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) }, zeitkonto: zk });
    const acmeW = new Acme({ verzeichnis: path.join(kd, 'w'), verzeichnisUrl: 'https://acme.test/dir', anfrager: fakeAcme, warten: async () => {}, protokoll: () => {} });
    const unt = new Unterwegs({ einst: eW, dns: srvW, verzeichnis: path.join(kd, 'w'), acme: acmeW, bind: '127.0.0.1', port: 0, nameVon: () => 'Kind', pruefer: async () => null, protokoll: () => {} });
    const melW = new Meldungen({ einst: eW, protokoll: () => {} });
    const authK = new Auth({ verzeichnis: path.join(kd, 'w'), geheimnis: 'w'.repeat(32) });
    const webK = webServer({ auth: authK, einst: eW, listen: lK, filter: fW, upstream: upK, dns: srvW, geraete: { status: () => ({ unifi: {} }), unifiLesen: async () => 0, iconVon: () => null, nameVon: () => '' }, protokoll: prot2, live: new Set(), version: 'probe', statisch: path.join(tmp, 'pub'), daten: path.join(kd, 'w'), zeitkonto: zk, meldungen: melW, unterwegs: unt, acme: acmeW });
    await new Promise((r) => webK.listen(0, '127.0.0.1', r));
    const BK = `http://127.0.0.1:${webK.address().port}`;
    const lgK = await fetch(BK + '/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', passwort: 'admin' }) });
    const ck = lgK.headers.get('set-cookie').split(';')[0], csK = (await (await fetch(BK + '/api/ich', { headers: { cookie: ck } })).json()).csrf;
    const sK = (p, daten, m = 'POST') => fetch(BK + p, { method: m, headers: { cookie: ck, 'x-csrf': csK, 'Content-Type': 'application/json' }, body: JSON.stringify(daten) });
    const neuP = await (await sK('/api/profile', { vorlage: 'klasse5' })).json();
    const hilfeAus = await sK('/api/dienste/juuuport', { modus: 'sperren', geltung: 'alle' }, 'PUT');
    const ruheFalsch = await sK(`/api/profile/${neuP.id}`, { ruhezeiten: { hilfe: [{ tage: [1], von: '20:00', bis: '07:00' }] } }, 'PUT');
    const limitFalsch = await sK(`/api/profile/${neuP.id}`, { limits: { 'dienst:juuuport': 30 } }, 'PUT');
    const limitOk = await sK(`/api/profile/${neuP.id}`, { limits: { 'dienst:tiktok': 45 }, sicher: { suche: true, youtube: 'streng' }, ruhezeiten: { messenger: [{ tage: [1, 2, 3, 4, 5], von: '21:00', bis: '06:30' }] } }, 'PUT');
    const pW = eW.werte.profile.find((p) => p.id === neuP.id);
    pruefe('Web: Profil aus Altersvorlage, Hilfe nicht sperrbar, Ruhezeit/Zeitlimit für Hilfe abgelehnt, gültige Werte gespeichert', neuP.limits?.['rubrik:spiele'] === 90 && neuP.dienste?.tiktok === 'sperren' && neuP.sicher?.youtube === 'moderat' && hilfeAus.status === 400 && ruheFalsch.status === 400 && limitFalsch.status === 400 && limitOk.status === 200 && pW.limits['dienst:tiktok'] === 45 && pW.sicher.youtube === 'streng' && pW.ruhezeiten.messenger[0].tage.length === 5);
    eW.aendern((x) => { x.geraete.kind = { profil: neuP.id, name: 'Kind' }; });
    const mehr = await (await sK('/api/zeitkonto/mehr', { geraet: 'kind', ziel: 'dienst:tiktok', minuten: 30 })).json();
    const ksApi = await (await fetch(BK + '/api/kinderschutz', { headers: { cookie: ck } })).json();
    const melOeff = await (await sK('/api/kinderschutz/meldungen', { an: true, stilleMin: 45, url: 'https://fremd.example.org', thema: 'egal-egal-egal' }, 'PUT')).json();
    pruefe('Web: Kinderschutz-API – Zeitkonto +30 min, Hilfsangebote gelistet, Meldungen ohne Fremddienst (keine Adresse/Thema gespeichert)', mehr.extra === 30 && ksApi.hilfe.some((h) => h.id === 'juuuport') && ksApi.zeitkonten.some((g) => g.id === 'kind' && g.ziele.some((z) => z.ziel === 'dienst:tiktok' && z.extra === 30)) && melOeff.an === true && melOeff.stilleMin === 45 && !('url' in melOeff) && !('thema' in melOeff) && ksApi.meldungen.an === true);
    await sK('/api/unterwegs', { an: true, basis: 'example.org' }, 'PUT');
    const ug = await (await sK('/api/unterwegs/geraete/kind', { an: true }, 'PUT')).json();
    const gU = ug.geraete.find((g) => g.id === 'kind');
    const hostU = gU.host, port = webK.address().port;
    const mitHost = (pfad, o = {}) => new Promise((ok) => { const rq = http.request({ host: '127.0.0.1', port, path: pfad, method: o.method || 'GET', headers: { host: hostU, ...(o.headers || {}) } }, (res) => { const t = []; res.on('data', (d) => t.push(d)); res.on('end', () => ok({ status: res.statusCode, typ: res.headers['content-type'], buf: Buffer.concat(t) })); }); rq.end(o.body); });
    const ui = await mitHost('/'), api = await mitHost('/api/uebersicht'), anm = await mitHost('/api/anmelden', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"name":"admin","passwort":"admin"}' });
    const dohQ = Buffer.from(frage('ngl.link', 'A', { id: 0 })).toString('base64url');
    const doh = await mitHost(`/dns-query/${gU.geheim}?dns=${dohQ}`), dohFalsch = await mitHost(`/dns-query/${'x'.repeat(32)}?dns=${dohQ}`);
    const dohPost = await mitHost(`/dns-query/${gU.geheim}`, { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: Buffer.from(frage('web.whatsapp.com', 'A', { id: 0 })) });
    const prof = await mitHost(`/unterwegs/${gU.geheim}/profil.mobileconfig`);
    acmeW.herausforderungen.set('probetoken123', 'probetoken123.abc');
    const ch = await mitHost('/.well-known/acme-challenge/probetoken123');
    pruefe('Unterwegs: unter dem Gerätenamen keine Oberfläche, API oder Anmeldung (404); DoH GET/POST filtert mit dem Profil des Geräts; falsches Geheimnis 404', hostU === 'dns-kind.example.org' && ui.status === 404 && api.status === 404 && anm.status === 404 && doh.status === 200 && doh.typ === 'application/dns-message' && dnsPacket.decode(doh.buf).answers[0]?.data === '0.0.0.0' && dohFalsch.status === 404 && dohPost.status === 200 && dnsPacket.decode(dohPost.buf).answers.length > 0);
    const mitHost2 = (h, pfad, m = 'GET') => new Promise((ok) => { const rq = http.request({ host: '127.0.0.1', port, path: pfad, method: m, headers: { host: h } }, (res) => { res.resume(); res.on('end', () => ok(res.statusCode)); }); rq.end(); });
    const punkt = await mitHost2(`${hostU}.`, '/api/uebersicht'), mitPort = await mitHost2(`${hostU.toUpperCase()}:443`, '/'), alteBasis = await mitHost2('dns-alt12345.alte-basis.example', '/api/health'), tiefer = await mitHost2(`dns-a.b.${hostU}`, '/');
    const proto = await sK('/api/unterwegs/geraete/__proto__', { an: false }, 'PUT'), proto2 = await sK('/api/geraete/__proto__', { name: 'x' }, 'PUT');
    pruefe('Sicherheit: Oberfläche/API nie unter einem dns-Namen (Punkt am Ende, Port, Großschreibung, alte Basisdomain, tiefere Namen); __proto__ als ID → 400', punkt === 404 && mitPort === 404 && alteBasis === 404 && tiefer === 404 && proto.status === 400 && proto2.status === 400 && ({}).an === undefined && ({}).name === undefined);
    // Hilfsangebote nicht im Protokoll; unterwegs feste TTL statt gealterter (kein Ausspähen des Zwischenspeichers), keine öffentliche IP im Protokoll
    const vorher = [];
    srvK.on('anfrage', (x) => vorher.push(x));
    await srvK.bearbeite(frage('www.juuuport.de'), '192.168.1.50', true);
    const upAlt = { frage: async (anf) => ({ buf: dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions, answers: [{ type: 'A', name: anf.frage.name, ttl: 300, data: '9.9.9.9' }] }), alterSek: 250, cache: true, anbieter: 'fake' }) };
    const srvA = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fK, upstream: upAlt, lokal: lokalK, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } });
    const imLog = []; srvA.on('anfrage', (x) => imLog.push(x));
    const ttlExt = dnsPacket.decode(await srvA.bearbeite(frage('example.com'), '203.0.113.9', false, ext)).answers[0]?.ttl, ttlInt = dnsPacket.decode(await srvA.bearbeite(frage('example.com'), '192.168.1.9', true)).answers[0]?.ttl;
    pruefe('Datenschutz: Hilfsangebot ohne Protokollzeile; unterwegs ungealterte TTL und „unterwegs“ statt öffentlicher IP', !vorher.some((x) => x.domain === 'www.juuuport.de') && ttlExt === 300 && ttlInt === 50 && imLog[0]?.ip === 'unterwegs');
    {
      // 25.11.2026: Hilfsangebot auch bei Upstream-Ausfall nicht im Protokoll (vorher Zeile „fehler“ mit der Domain); erweiterter Upstream-Rcode
      // (BADVERS) → SERVFAIL für Clients mit UND ohne EDNS (ohne EDNS sah er vorher wie NOERROR aus, weil das OPT wegfällt)
      const upWeg = { frage: async () => { throw new Error('alle Anbieter weg'); } };
      const badv = (anf) => dnsPacket.encode({ type: 'response', id: 0, flags: dnsPacket.RECURSION_AVAILABLE, questions: anf.paket.questions, answers: [], additionals: [{ type: 'OPT', name: '.', udpPayloadSize: 1232, extendedRcode: 1, ednsVersion: 0, flags: 0, options: [] }] });
      const upBv = { frage: async (anf) => ({ buf: badv(anf), alterSek: 0, cache: false, anbieter: 'x' }) };
      const logW = [], srvW2 = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fK, upstream: upWeg, lokal: lokalK, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } }); srvW2.on('anfrage', (x) => logW.push(x));
      const logB = [], srvB = new DnsServer({ bind: '127.0.0.1', erlaubt: netzliste(['192.168.1.0/24']), filter: fK, upstream: upBv, lokal: lokalK, geraete: { von: (ip) => ({ id: `ip:${ip}`, name: ip }) } }); srvB.on('anfrage', (x) => logB.push(x));
      const weg = dnsPacket.decode(await srvW2.bearbeite(frage('www.juuuport.de'), '192.168.1.51', true));
      const bvEdns = dnsPacket.decode(await srvB.bearbeite(frage('seite.de'), '192.168.1.52', true)), bvOhne = dnsPacket.decode(await srvB.bearbeite(frage('seite.de', 'A', { edns: false }), '192.168.1.53', true));
      await srvB.bearbeite(frage('www.juuuport.de'), '192.168.1.54', true);
      pruefe('Datenschutz/K8: Hilfsangebot bei Upstream-Ausfall und bei erweitertem Rcode ohne Protokollzeile (SERVFAIL); BADVERS → SERVFAIL mit und ohne EDNS',
        (weg.flags & 15) === 2 && !logW.some((x) => /juuuport/.test(x.domain)) && (bvEdns.flags & 15) === 2 && (bvOhne.flags & 15) === 2 && !logB.some((x) => /juuuport/.test(x.domain)) && logB.some((x) => x.aktion === 'fehler' && x.domain === 'seite.de'),
        JSON.stringify({ weg: weg.flags & 15, logW: logW.map((x) => x.domain), bvEdns: bvEdns.flags & 15, bvOhne: bvOhne.flags & 15, logB: logB.map((x) => [x.domain, x.aktion]) }));
    }
    pruefe('Unterwegs: iPhone-Profil mit DoH-Adresse des Geräts, ACME-Prüfung unter dem Gerätenamen erreichbar', prof.status === 200 && prof.typ === 'application/x-apple-aspen-config' && prof.buf.toString().includes(`https://${hostU}/dns-query/${gU.geheim}`) && prof.buf.toString().includes('<key>PayloadScope</key><string>System</string>') && ch.status === 200 && ch.buf.toString() === 'probetoken123.abc');
    if (mitOpenssl) {
      unt.speichereZertifikat(hostU, { schluessel: fs.readFileSync(path.join(kd, 'k.pem'), 'utf8'), kette: fs.readFileSync(path.join(kd, 'c.pem'), 'utf8'), bis: Date.now() + 80 * 86400000 });
      unt.dotPruefen(); await new Promise((r) => setTimeout(r, 200));
      const dotPort = unt.server.address().port;
      const dotFrage = (servername, name) => new Promise((ok) => {
        const tls = require('node:tls'); const s = tls.connect({ host: '127.0.0.1', port: dotPort, servername, rejectUnauthorized: false }, () => { const q = Buffer.from(frage(name)); const k = Buffer.alloc(2); k.writeUInt16BE(q.length); s.write(Buffer.concat([k, q])); });
        let p = Buffer.alloc(0); s.on('data', (d) => { p = Buffer.concat([p, d]); if (p.length >= 2 && p.length >= 2 + p.readUInt16BE(0)) { ok(dnsPacket.decode(p.subarray(2))); s.destroy(); } });
        s.on('error', () => ok(null)); setTimeout(() => { s.destroy(); ok(null); }, 3000);
      });
      const dot = await dotFrage(hostU, 'ngl.link'), dotFremd = await dotFrage('dns-fremd123.example.org', 'ngl.link');
      pruefe('Unterwegs: DNS-over-TLS erkennt das Gerät am Namen (SNI) und filtert mit dessen Profil; fremder Name → kein Handshake', dot?.answers?.[0]?.data === '0.0.0.0' && dotFremd === null);
      unt.stoppen();
    // ── Freigaben automatisch: FAH-Proxy (aktive Instanz), UCG-Portfreigabe, Übergabe an den Ersatz ──
    {
      const { FahProxy } = require('../src/fahproxy.js');
      const fakeProxy = (aktiv) => {
        const z = { aktiv, konten: [{ name: 'admin', pw: 'adminpw', rolle: 'admin' }], domains: [{ id: 'd1', domain: 'nas.example.org', ziel: 'http://192.168.1.23:5000', schutz: 'heimnetz', notiz: '' }, { id: 'd2', domain: 'dns-alt.example.org', ziel: 'http://x:8053', schutz: 'oeffentlich', notiz: 'FAH-Adblock unterwegs: Altgerät' }], sitzungen: new Map(), schreib: 0 };
        z.anfragen = 0;
        z.srv = require('node:https').createServer({ key: fs.readFileSync(path.join(kd, 'k.pem')), cert: fs.readFileSync(path.join(kd, 'c.pem')) }, (req, res) => {
          z.anfragen++;
          let t = ''; req.on('data', (d) => { t += d; }); req.on('end', () => {
            const b = t ? JSON.parse(t) : {}, url = new URL(req.url, 'http://x'), kek = Object.fromEntries(String(req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => c.split('=')));
            const send = (st, j, kopf = {}) => { res.writeHead(st, { 'Content-Type': 'application/json', ...kopf }); res.end(JSON.stringify(j)); };
            if (url.pathname === '/api/anmelden') { const k = z.konten.find((x) => x.name === b.name && x.pw === b.passwort); if (!k) return send(401, { ok: false, fehler: { meldung: 'falsch' } }); const sid = `s${Math.random()}`, csrf = `c${Math.random()}`; z.sitzungen.set(sid, { csrf, name: k.name, rolle: k.rolle }); return send(200, { ok: true, ergebnis: { name: k.name } }, { 'Set-Cookie': [`fp_sitzung=${sid}; HttpOnly`, `fp_csrf=${csrf}`] }); }
            const sitz = z.sitzungen.get(kek.fp_sitzung); if (!sitz) return send(401, { ok: false, fehler: { meldung: 'Bitte anmelden' } });
            const csrf = sitz.csrf;
            const dienstPfad = url.pathname.startsWith('/api/dienst/') || url.pathname === '/api/abmelden';
            if (sitz.rolle !== 'admin' && !(sitz.rolle === 'dienst' && dienstPfad)) return send(403, { ok: false, fehler: { code: 'E_RECHTE', meldung: 'Keine Berechtigung' } });
            z.zugriffe = (z.zugriffe || []).concat(`${sitz.rolle} ${req.method} ${url.pathname}`);
            if (req.method !== 'GET' && req.headers['x-fp-csrf'] !== csrf) return send(403, { ok: false, fehler: { meldung: 'CSRF' } });
            if (req.method !== 'GET' && !z.aktiv && url.pathname !== '/api/abmelden') return send(403, { ok: false, fehler: { meldung: 'nicht aktiv' } });
            if (req.method !== 'GET') z.schreib++;
            if (url.pathname === '/api/uebersicht') return send(200, { ok: true, ergebnis: { aktiv: z.aktiv, domains: z.domains } });
            if (url.pathname === '/api/konten' && req.method === 'GET') return send(200, { ok: true, ergebnis: z.konten.map((k) => ({ name: k.name })) });
            if (url.pathname === '/api/konten' && req.method === 'POST') { z.konten.push({ name: b.name, pw: b.passwort, rolle: b.rolle }); return send(200, { ok: true, ergebnis: {} }); }
            const eigen = (d) => d.domain.startsWith('dns-') && (d.rubrik === 'AdBlock DNS Domains' || String(d.notiz || '').startsWith('FAH-Adblock unterwegs'));
            if (url.pathname === '/api/dienst/dns' && req.method === 'GET') return send(200, { ok: true, ergebnis: { aktiv: z.aktiv, domains: z.domains.filter(eigen) } });
            if (url.pathname === '/api/dienst/dns' && req.method === 'PUT') {
              const r = { angelegt: [], geaendert: [], geloescht: [], fremd: [] }, soll = new Map(b.soll.map((x) => [x.domain, x.name]));
              for (const d of [...z.domains]) { if (!eigen(d) || !d.domain.endsWith(`.${b.basis}`)) continue; if (!soll.has(d.domain)) { z.domains = z.domains.filter((x) => x !== d); r.geloescht.push(d.domain); } else if (d.ziel !== b.ziel || d.rubrik !== 'AdBlock DNS Domains') { Object.assign(d, { ziel: b.ziel, rubrik: 'AdBlock DNS Domains', schutz: 'oeffentlich' }); r.geaendert.push(d.domain); } }
              for (const [dom, name] of soll) { const d = z.domains.find((x) => x.domain === dom); if (d && !eigen(d)) r.fremd.push(dom); else if (!d) { z.domains.push({ id: `d${z.domains.length + 9}`, domain: dom, ziel: b.ziel, schutz: 'oeffentlich', rubrik: 'AdBlock DNS Domains', notiz: `FAH-Adblock unterwegs: ${name}` }); r.angelegt.push(dom); } }
              return send(200, { ok: true, ergebnis: r });
            }
            if (url.pathname === '/api/dienst/zertifikate') return send(200, { ok: true, ergebnis: { zertifikate: z.domains.filter(eigen).map((d) => ({ domain: d.domain, kette: fs.readFileSync(path.join(kd, 'c.pem'), 'utf8'), schluessel: fs.readFileSync(path.join(kd, 'k.pem'), 'utf8') })) } });
            if (url.pathname === '/api/dienst/herabstufen') { const k = z.konten.find((x) => x.name === sitz.name); k.rolle = 'dienst'; return send(200, { ok: true, ergebnis: { rolle: 'dienst' } }); }
            if (url.pathname === '/api/dienst/konto' && req.method === 'DELETE') { z.konten = z.konten.filter((k) => k.name !== sitz.name); return send(200, { ok: true, ergebnis: {} }); }
            if (url.pathname.startsWith('/api/konten/') && req.method === 'DELETE') { z.konten = z.konten.filter((k) => k.name !== url.pathname.slice(12)); return send(200, { ok: true, ergebnis: {} }); }
            if (url.pathname === '/api/domains' && req.method === 'POST') { z.domains.push({ id: `d${z.domains.length + 9}`, ...b }); return send(200, { ok: true, ergebnis: {} }); }
            const dm = /^\/api\/domains\/(.+)$/.exec(url.pathname);
            if (dm && req.method === 'DELETE') { z.domains = z.domains.filter((d) => d.id !== dm[1]); return send(200, { ok: true, ergebnis: {} }); }
            if (dm && req.method === 'PUT') { z.domains = z.domains.map((d) => (d.id === dm[1] ? { ...d, ...b } : d)); return send(200, { ok: true, ergebnis: {} }); }
            if (url.pathname === '/api/abmelden') return send(200, { ok: true, ergebnis: {} });
            send(404, { ok: false, fehler: { meldung: 'unbekannt' } });
          });
        });
        return z;
      };
      const PA = fakeProxy(false), PB = fakeProxy(true);
      for (const p of [PA, PB]) await new Promise((r) => p.srv.listen(0, '127.0.0.1', r));
      const uA = `https://127.0.0.1:${PA.srv.address().port}`, uB = `https://127.0.0.1:${PB.srv.address().port}`;
      const fp = new FahProxy({ verzeichnis: path.join(kd, 'w'), geheimnis: 'w'.repeat(32), protokoll: () => {} });
      const falsch = await fp.koppeln({ urls: [uA, uB], name: 'admin', passwort: 'nein' }).then(() => 'ok', (e) => e.message);
      await fp.koppeln({ urls: [uA, uB], name: 'admin', passwort: 'adminpw' });
      const konto = PB.konten.find((k) => k.name === 'fah-adblock');
      pruefe('FAH-Proxy koppeln: falsches Admin-Passwort scheitert; eigenes Konto „fah-adblock“ mit Rolle DIENST an der AKTIVEN Instanz, Passwort verschlüsselt (0600), Admin-Passwort nicht gespeichert', /falsch|aktive/.test(falsch) && konto && konto.rolle === 'dienst' && konto.pw.length >= 30 && !PA.konten.some((k) => k.name === 'fah-adblock') && !fs.readFileSync(path.join(kd, 'w', 'fah-proxy.json'), 'utf8').includes(konto.pw) && !fs.readFileSync(path.join(kd, 'w', 'fah-proxy.json'), 'utf8').includes('adminpw') && (fs.statSync(path.join(kd, 'w', 'fah-proxy.json')).mode & 0o777) === 0o600);
      PA.konten.push({ ...konto });   // FAH-Proxy spiegelt Konten zur anderen Instanz
      const { Sitzung } = require('../src/fahproxy.js');
      const vorPin = PB.anfragen, pinFehler = await new Sitzung(uB, { abdruck: 'AA:BB' }).anmelden('fah-adblock', konto.pw).then(() => 'gesendet', (e) => e.message);
      const httpAbgelehnt = await fp.koppeln({ urls: ['http://127.0.0.1:1'], name: 'admin', passwort: 'x' }).then(() => 'ok', (e) => e.message);
      pruefe('FAH-Proxy: fremdes Zertifikat → Abbruch VOR dem Senden (keine Anfrage kommt an), nur https-Adressen', /geändert/.test(pinFehler) && PB.anfragen === vorPin && /nur https/.test(httpAbgelehnt));
      // UCG nachgebaut (https, selbstsigniert)
      const ucg = { liste: [{ _id: 'p1', name: 'FAH-Proxy HTTPS', enabled: true, dst_port: '443', fwd: '192.168.1.29', fwd_port: '28443', proto: 'tcp', pfwd_interface: 'wan', destination_ip: 'any', destination_ips: [] }], aufrufe: [] };
      const ucgSrv = require('node:https').createServer({ key: fs.readFileSync(path.join(kd, 'k.pem')), cert: fs.readFileSync(path.join(kd, 'c.pem')) }, (req, res) => {
        let t = ''; req.on('data', (d) => { t += d; }); req.on('end', () => {
          ucg.aufrufe.push(req.method); const id = req.url.split('/portforward/')[1];
          if (req.headers['x-api-key'] !== 'ucgschluessel123456') { res.writeHead(401); return res.end('{}'); }
          if (req.method === 'POST') ucg.liste.push({ _id: `p${ucg.liste.length + 5}`, ...JSON.parse(t) });
          if (req.method === 'PUT') ucg.liste = ucg.liste.map((p) => (p._id === id ? { ...p, ...JSON.parse(t) } : p));
          if (req.method === 'DELETE') ucg.liste = ucg.liste.filter((p) => p._id !== id);
          res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ data: ucg.liste }));
        });
      });
      await new Promise((r) => ucgSrv.listen(0, '127.0.0.1', r));
      const unifiZ = () => ({ url: `https://127.0.0.1:${ucgSrv.address().port}`, schluessel: 'ucgschluessel123456' });
      const untH = new Unterwegs({ einst: eW, dns: srvW, verzeichnis: path.join(kd, 'w'), acme: null, bind: '192.168.1.29', port: 853, zielUrl: () => 'http://192.168.1.29:8053', proxy: fp, unifi: unifiZ, nameVon: () => 'Kind', protokoll: () => {} });
      await untH.freigabenPflegen();
      const dnsEintrag = PB.domains.find((d) => d.domain === hostU), pf = ucg.liste.find((p) => p.name === 'FAH-Adblock DoT (unterwegs)');
      const nurDienst = (PB.zugriffe || []).filter((x) => x.startsWith('dienst ')).every((x) => / \/api\/(dienst\/|abmelden)/.test(x));
      pruefe('Freigaben: FAH-Proxy-Eintrag des Geräts in der Gruppe „AdBlock DNS Domains“ an der aktiven Instanz (Ziel = diese Instanz, öffentlich), Altgerät gelöscht, fremde Domain unberührt, Dienst-Konto nutzt nur die Dienst-Schnittstelle; UCG-Portfreigabe 853 → Haupt', dnsEintrag?.ziel === 'http://192.168.1.29:8053' && dnsEintrag.schutz === 'oeffentlich' && dnsEintrag.rubrik === 'AdBlock DNS Domains' && nurDienst && !PB.domains.some((d) => d.domain === 'dns-alt.example.org') && PB.domains.some((d) => d.domain === 'nas.example.org') && PA.schreib === 0 && pf?.fwd === '192.168.1.29' && pf.fwd_port === '853' && pf.proto === 'tcp' && untH.freigabe.proxy.ok && untH.freigabe.port.ok);
      await untH.zertifikateVomProxy();
      pruefe('Zertifikat kommt von FAH-Proxy (kein eigenes ACME – je Name nur EIN Zertifikat), nur für eigene Gerätenamen', untH.zert.has(hostU) && untH.zert.size === 1 && !untH.zustand.get(hostU)?.fehler);
      const vorher = ucg.aufrufe.length; await untH.freigabenPflegen();
      PA.aktiv = true; PB.aktiv = false; PA.domains = JSON.parse(JSON.stringify(PB.domains));   // FAH-Proxy-Failover: NAS übernimmt
      eW.aendern((x) => { delete x.unterwegs.geraete.kind; });
      await untH.freigabenPflegen();
      pruefe('Freigaben: zweiter Lauf ändert nichts an der UCG; nach FAH-Proxy-Failover schreibt es an die neue aktive Instanz – gelöschtes Gerät verschwindet dort, ohne Gerät auch die Portfreigabe', ucg.aufrufe.slice(vorher, vorher + 1).join() === 'GET' && !PA.domains.some((d) => d.domain === hostU) && !ucg.liste.some((p) => p.name === 'FAH-Adblock DoT (unterwegs)') && ucg.liste.some((p) => p.name === 'FAH-Proxy HTTPS'));
      eW.aendern((x) => { x.unterwegs.geraete.kind = { kennung: 'dns-kind', geheim: gU.geheim, an: true }; });
      // Übergabe an den Ersatz und Übernahme bei Ausfall des Haupts
      const code = 'kopplungscode-test-1234567890';
      untH.speichereZertifikat(hostU, { schluessel: fs.readFileSync(path.join(kd, 'k.pem'), 'utf8'), kette: fs.readFileSync(path.join(kd, 'c.pem'), 'utf8'), bis: Date.now() + 80 * 86400000 });
      let paket = null;
      const ed = path.join(kd, 'ersatz'); fs.mkdirSync(ed, { recursive: true });
      const fpE = new FahProxy({ verzeichnis: ed, geheimnis: 'e'.repeat(32), protokoll: () => {} });
      let hauptZuletzt = Date.now();
      const untE = new Unterwegs({ einst: eW, dns: srvW, verzeichnis: ed, acme: null, istErsatz: () => true, hauptZuletzt: () => hauptZuletzt, bind: '192.168.1.23', port: 853, zielUrl: () => 'http://192.168.1.23:8053', proxy: fpE, unifi: unifiZ, nameVon: () => 'Kind', protokoll: () => {} });
      paket = untH.paketFuerErsatz(code, null, untE.ersatzSchluessel());
      const ohneSchluessel = untH.paketFuerErsatz(code, null, null);
      const uebernommen1 = untE.paketUebernehmen(paket, code), zweimal = untH.paketFuerErsatz(code, untE.paketHash, untE.ersatzSchluessel());
      let falscherCode = false; try { untE.paketHash = null; const p2 = untH.paketFuerErsatz(code, null, untE.ersatzSchluessel()); untE.paketUebernehmen(p2, 'falsch'); } catch (e) { falscherCode = true; }
      let alterSchluessel = false; try { untE.paketHash = null; untE.ersatzSchluessel(); untE.paketUebernehmen(paket, code); } catch (e) { alterSchluessel = true; }
      const vorAusfall = await untE.freigabenPflegen().then(() => PA.domains.find((d) => d.domain === hostU)?.ziel || 'keins');
      hauptZuletzt = Date.now() - 7 * 60000;
      await untE.freigabenPflegen();
      pruefe('Failover: Ersatz bekommt Zertifikat und FAH-Proxy-Zugang verschlüsselt (unveränderte Übergabe nur als Prüfsumme, falscher Code scheitert); übernimmt erst nach 6 min Ausfall – dann zeigen FAH-Proxy-Eintrag und Portfreigabe auf den Ersatz', uebernommen1 && !ohneSchluessel.daten && untE.zert.has(hostU) && fpE.gekoppelt() && fpE.passwort() === konto.pw && !zweimal.daten && falscherCode && alterSchluessel && vorAusfall === 'keins' && PA.domains.find((d) => d.domain === hostU)?.ziel === 'http://192.168.1.23:8053' && ucg.liste.find((p) => p.name === 'FAH-Adblock DoT (unterwegs)')?.fwd === '192.168.1.23' && untE.dotSoll());
      await untH.freigabenPflegen();
      pruefe('Failover zurück: der Haupt holt FAH-Proxy-Eintrag und Portfreigabe mit seiner nächsten Pflege zurück', PA.domains.find((d) => d.domain === hostU)?.ziel === 'http://192.168.1.29:8053' && ucg.liste.find((p) => p.name === 'FAH-Adblock DoT (unterwegs)')?.fwd === '192.168.1.29');
      // Benachrichtigungen (Push-Schlüssel, Abos, ntfy) reisen im selben verschlüsselten Paket zum Ersatz
      const bnH = new Benachrichtigung({ verzeichnis: kd, geheimnis: 'h'.repeat(32), istErsatz: () => false, protokoll: () => {} });
      const bnE = new Benachrichtigung({ verzeichnis: ed, geheimnis: 'e'.repeat(32), istErsatz: () => true, protokoll: () => {} });
      const uaT = nodeCrypto.createECDH('prime256v1'); uaT.generateKeys();
      bnH.ntfySetzen({ thema: 'fah-testthema-123456', schluessel: 'tk_testschluessel1' });
      bnH.aboHinzufuegen({ abo: { endpoint: 'https://web.push.apple.com/QWERTY123', keys: { p256dh: uaT.getPublicKey().toString('base64url'), auth: nodeCrypto.randomBytes(16).toString('base64url') } }, name: 'iPhone', sub: 'https://adblock.example.org' });
      untH.zusatz = { geben: () => bnH.fuerErsatz(), nehmen: (x) => bnH.vomHaupt(x) };
      untE.zusatz = { geben: () => bnE.fuerErsatz(), nehmen: (x) => bnE.vomHaupt(x) };
      const bnVorher = bnE.oeffentlicherSchluessel();
      untE.paketHash = null; untE.paketUebernehmen(untH.paketFuerErsatz(code, null, untE.ersatzSchluessel()), code);
      const stE = bnE.status(), roh = fs.readFileSync(path.join(ed, 'benachrichtigung.json'), 'utf8');
      pruefe('Failover Benachrichtigungen: Ersatz bekommt Push-Schlüssel des Haupt, Abos und ntfy samt Zugangsschlüssel (vorher keinen eigenen Schlüssel; auf der Platte verschlüsselt)', bnVorher === null && bnE.oeffentlicherSchluessel() === bnH.oeffentlicherSchluessel() && stE.push.abos.length === 1 && stE.ntfy.thema === 'fah-testthema-123456' && stE.ntfy.schluesselGesetzt && stE.vomHaupt && !roh.includes('tk_testschluessel1') && !roh.includes(bnH.fuerErsatz().vapid.d), JSON.stringify(stE).slice(0, 200));
      // Pfad-Ausbruch über einen gefälschten Namen; Haupt „gesehen“ auch bei abgelehntem Code
      let ausbruch = false; try { untE.dateien('dns-x./../../sperrseite-ca'); } catch (e) { ausbruch = true; }
      const spE = new Spiegel({ verzeichnis: ed, einst: eW, geheimnis: 'e'.repeat(32), version: 'probe', anwenden: () => {}, holen: async () => { throw Object.assign(new Error('Der Haupt lehnt den Kopplungscode ab'), { antwort: true }); } });
      spE.z = { rolle: 'ersatz', haupt_url: 'http://127.0.0.1:1', code: verschluesseln('x', 'e'.repeat(32)), letzter_abgleich: Date.now() - 3600000 };
      await spE.abgleichen(); spE.stoppen();
      pruefe('Sicherheit: Gerätename mit „..“ wird nie zum Dateipfad; Haupt antwortet (Code abgelehnt) → gilt als erreichbar, der Ersatz übernimmt nicht', ausbruch && Date.now() - spE.hauptZuletzt() < 5000);
      eW.aendern((x) => { x.unterwegs.kurznamen = 0; x.unterwegs.geraete['aa:bb:cc:00:00:01'] = { kennung: 'dns-rrhp6y35co5wxeax', geheim: 'g'.repeat(32), an: true }; x.unterwegs.geraete['aa:bb:cc:00:00:02'] = { kennung: 'dns-fairphone', geheim: 'h'.repeat(32), an: true }; x.geraete['aa:bb:cc:00:00:01'] = { name: 'Gast Smartphone' }; });
      const umgestellt = untH.kurznamenUmstellen(), zweimal2 = untH.kurznamenUmstellen();
      pruefe('Unterwegs: alte Zufallsnamen einmalig auf kurze Namen umgestellt (dns-Gast-smartphone), eigene kurze Namen bleiben', umgestellt === 1 && zweimal2 === 0 && eW.werte.unterwegs.geraete['aa:bb:cc:00:00:01'].kennung === 'dns-Gast-smartphone' && eW.werte.unterwegs.geraete['aa:bb:cc:00:00:02'].kennung === 'dns-fairphone' && eW.werte.unterwegs.kurznamen === 1);
      untE.stoppen(); untH.stoppen(); for (const p of [PA, PB]) p.srv.close(); ucgSrv.close();
    }
    }
    webK.close();
  }
  // ── Benachrichtigungen aufs Handy: Web-Push (RFC 8291/8292) und ntfy ──
  {
    const b = (t) => Buffer.from(t, 'base64url');
    const vektor = pushVerschluesseln(b('BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4'), b('BTBZMqHH6r4Tts7J_aSIgg'), 'When I grow up, I want to be a watermelon', { asPrivat: b('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw'), salz: b('DGv6ra1nlYgDCS1FRnbzlw') });
    pruefe('Web-Push: Verschlüsselung trifft den Prüfvektor aus RFC 8291 Byte für Byte', vektor.toString('base64url') === 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN');
    pruefe('Web-Push: nur https-Endpunkte der Browser-Push-Dienste (kein http, kein Port, keine fremden Hosts, keine Zugangsdaten in der Adresse)', endpunktOk('https://web.push.apple.com/abc') && endpunktOk('https://fcm.googleapis.com/fcm/send/x') && endpunktOk('https://wns2-db5p.notify.windows.com/w/?token=x') && !endpunktOk('http://web.push.apple.com/abc') && !endpunktOk('https://web.push.apple.com:8443/abc') && !endpunktOk('https://web.push.apple.com.boese.example/abc') && !endpunktOk('https://10.0.0.1/abc') && !endpunktOk('https://u:p@fcm.googleapis.com/x'));
    const bd = path.join(tmp, 'benachrichtigung'); fs.mkdirSync(bd, { recursive: true });
    const gesendet = []; let antwort = 201;
    const bn = new Benachrichtigung({ verzeichnis: bd, geheimnis: 'g'.repeat(32), protokoll: () => {}, anfrager: async (url, o) => { gesendet.push({ url, ...o }); return { status: url.includes('ntfy') ? 200 : antwort, text: '' }; } });
    const ua = nodeCrypto.createECDH('prime256v1'); ua.generateKeys(); const auth = nodeCrypto.randomBytes(16);
    const abo = { endpoint: 'https://web.push.apple.com/TOKEN-1', keys: { p256dh: ua.getPublicKey().toString('base64url'), auth: auth.toString('base64url') } };
    let falsch = 0; for (const x of [{ ...abo, endpoint: 'https://boese.example/x' }, { ...abo, keys: { p256dh: 'AAAA', auth: abo.keys.auth } }, { ...abo, keys: { p256dh: abo.keys.p256dh, auth: 'kurz' } }]) { try { bn.aboHinzufuegen({ abo: x, name: 'x' }); } catch (e) { falsch++; } }
    const id = bn.aboHinzufuegen({ abo, name: 'iPhone <b>Mama</b>', sub: 'https://adblock.example.org' });
    const id2 = bn.aboHinzufuegen({ abo, name: 'iPhone neu', sub: 'https://adblock.example.org' });
    pruefe('Web-Push: ungültige Abos abgelehnt; dasselbe Gerät zweimal = ein Eintrag; Name ohne HTML', falsch === 3 && id === id2 && bn.status().push.abos.length === 1 && !bn.status().push.abos[0].name.includes('<'));
    const erg = await bn.senden({ titel: 'Tablet: Anonyme Chats gesperrt', text: '3 Versuche – gesperrt.', ernst: true, tag: 'aa|kat:anonym' });
    const g = gesendet[0], k = g?.kopf || {};
    // Empfängerseite (wie der Browser): entschlüsseln
    const body = g.daten, salt = body.subarray(0, 16), idlen = body[20], asPub = body.subarray(21, 21 + idlen), ct = body.subarray(21 + idlen);
    const ikm = Buffer.from(nodeCrypto.hkdfSync('sha256', ua.computeSecret(asPub), auth, Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPub]), 32));
    const de = nodeCrypto.createDecipheriv('aes-128-gcm', Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16)), Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12)));
    de.setAuthTag(ct.subarray(ct.length - 16)); const klar = Buffer.concat([de.update(ct.subarray(0, ct.length - 16)), de.final()]);
    const inhalt = JSON.parse(klar.subarray(0, klar.length - 1).toString('utf8'));
    // VAPID: Signatur mit dem öffentlichen Schlüssel prüfen
    const [, t, kk] = /^vapid t=([^,]+), k=(.+)$/.exec(k.Authorization || '') || [];
    const [h64, c64, s64] = String(t).split('.'), claims = JSON.parse(Buffer.from(c64 || '', 'base64url').toString());
    const pub = Buffer.from(kk || '', 'base64url'), jwkPub = { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') };
    const sigOk = nodeCrypto.verify('sha256', Buffer.from(`${h64}.${c64}`), { key: nodeCrypto.createPublicKey({ key: jwkPub, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s64 || '', 'base64url'));
    pruefe('Web-Push: Senden verschlüsselt (aes128gcm, Empfänger entschlüsselt), VAPID-Signatur gültig (aud = Push-Dienst, sub = eigene Adresse, exp ≤ 24 h), dringend bei ernsten Meldungen', erg.push === 1 && k['Content-Encoding'] === 'aes128gcm' && k.TTL === '86400' && k.Urgency === 'high' && inhalt.titel === 'Tablet: Anonyme Chats gesperrt' && inhalt.tag === 'aa|kat:anonym' && sigOk && claims.aud === 'https://web.push.apple.com' && claims.sub === 'https://fah-adblock.example.org' && claims.exp - Date.now() / 1000 <= 86400 && kk === bn.oeffentlicherSchluessel(), JSON.stringify({ erg, k: Object.keys(k), claims, sigOk }));
    antwort = 410; await bn.senden({ titel: 'x', text: 'y' });
    pruefe('Web-Push: abgelaufenes Abo (410) wird entfernt', bn.status().push.abos.length === 0);
    bn.aboHinzufuegen({ abo, name: 'iPhone' }); antwort = 201;
    bn.ntfySetzen({ thema: 'fah-abcdefghijklmnop' }); bn.z.ntfy = { ...bn.z.ntfy, url: 'http://ntfy.example.org', schluessel: verschluesseln('tk_geheim12345', 'g'.repeat(32)) };   // Altbestand: http an fremden Server
    gesendet.length = 0; const e2 = await bn.senden({ titel: 'T', text: 'x' });
    bn.ntfySetzen({ url: 'http://192.168.1.5:8090' }); bn.ntfySetzen({ schluessel: 'tk_geheim12345' });
    gesendet.length = 0; const e3 = await bn.senden({ titel: 'T', text: 'x' }); const nt = gesendet.find((x) => x.url.includes('192.168.1.5'));
    let themaFalsch = 0; for (const t of ['kurz']) { try { bn.ntfySetzen({ thema: t }); } catch (e) { themaFalsch++; } }
    bn.ntfySetzen({ url: 'https://ntfy.sh' }); try { bn.ntfySetzen({ thema: 'kinderschutz12' }); } catch (e) { themaFalsch++; }
    let urlFalsch = 0; for (const u of ['http://10.irgendwas.example', 'http://127.0.0.1:80', 'https://169.254.169.254', 'https://u:p@ntfy.sh', 'http://ntfy.example.org']) { try { bn.ntfySetzen({ url: u }); } catch (e) { urlFalsch++; } }
    themaFalsch = themaFalsch === 2 && urlFalsch === 5;
    bn.ntfySetzen({ url: 'http://192.168.1.5:8090' });
    pruefe('ntfy: Zugangsschlüssel nie unverschlüsselt ins Internet (http an fremden Server scheitert, Push geht trotzdem); im eigenen Netz geht http; neue Adresse löscht den alten Schlüssel; kurzes Thema abgelehnt', e2.ntfy === false && e2.push === 1 && e3.ntfy === true && JSON.parse(nt.daten).topic === 'fah-abcdefghijklmnop' && nt.kopf.Authorization === 'Bearer tk_geheim12345' && !fs.readFileSync(path.join(bd, 'benachrichtigung.json'), 'utf8').includes('tk_geheim'), JSON.stringify({ e2, e3 }));
    bn.ntfySetzen({ schluessel: 'tk_geheim12345' }); const vorWechsel = bn.status().ntfy.schluesselGesetzt; bn.ntfySetzen({ url: 'https://ntfy.sh' });
    pruefe('ntfy: Adresswechsel ohne neuen Schlüssel löscht den Schlüssel; http nur an private IPs, nie Loopback/Link-Local/Zugangsdaten in der Adresse; auf ntfy.sh mind. 20 Zeichen', vorWechsel && !bn.status().ntfy.schluesselGesetzt && themaFalsch);
    // Meldungen: nach draußen ohne Domains, in der Liste mit
    const an = []; const ml = new Meldungen({ einst: { werte: { meldungen: { an: true, profile: ['kinder'], kategorien: ['anonym'], ruheMin: 60 } } }, senden: async (n) => { an.push(n); return { ntfy: null, push: 1, fehler: [] }; }, kategorieName: () => 'Anonyme Chats', protokoll: () => {} });
    ml.sammle('kat:anonym', { geraet: 'aa:bb', geraetName: 'Tablet', kategorie: 'anonym', domain: 'ngl.link' }); ml.sammle('kat:anonym', { geraet: 'aa:bb', geraetName: 'Tablet', kategorie: 'anonym', domain: 'ngl.link' });
    await ml.abschicken('aa:bb|kat:anonym');
    pruefe('Meldungen: aufs Handy nur Gerät, Art und Anzahl – die Domains stehen nur in der Liste; Eintrag merkt sich den Versand', an.length === 1 && an[0].titel === 'Tablet: Anonyme Chats gesperrt' && !JSON.stringify(an[0]).includes('ngl') && an[0].ernst === true && ml.verlauf[0].details.includes('ngl.link (2×)') && ml.verlauf[0].handy?.push === 1, JSON.stringify({ an, v: ml.verlauf[0] }));
    // Hängender Server: harte Frist, die Meldung steht sofort in der Liste
    const haengt = http.createServer((q, r) => { r.writeHead(200); const t = setInterval(() => r.write('.'), 300); r.on('close', () => clearInterval(t)); }).listen(0, '127.0.0.1');
    await new Promise((f) => haengt.once('listening', f));
    const { anfrageFuerTest } = require('../src/benachrichtigung.js');
    const t0 = Date.now(); let haengFehler = ''; try { await anfrageFuerTest(`http://127.0.0.1:${haengt.address().port}/`, { daten: '{}', zeitlimit: 1500 }); } catch (e) { haengFehler = e.message; }
    const dauer = Date.now() - t0; haengt.close();
    let sofort = false; const mh = new Meldungen({ einst: { werte: { meldungen: { an: true } } }, senden: () => new Promise(() => {}), protokoll: () => {} });
    mh.melden({ titel: 'a', text: 'b' }); sofort = mh.verlauf.length === 1;
    const unb = []; const mu = new Meldungen({ einst: { werte: { meldungen: { an: true, profile: ['kinder'], kategorien: ['anonym'] } } }, senden: async (n) => { unb.push(n); return { ntfy: true, push: 0, fehler: [] }; }, kategorieName: () => 'Anonyme Chats', protokoll: () => {} });
    mu.sammle('kat:anonym', { geraet: 'aa:bb:cc:dd:ee:ff', kategorie: 'anonym', domain: 'ngl.link' }); await mu.abschicken('aa:bb:cc:dd:ee:ff|kat:anonym');
    pruefe('Versand: tröpfelnder Server endet nach der harten Frist; Meldung steht sofort in der Liste, auch wenn das Senden hängt; ohne Gerätenamen geht keine MAC nach draußen', haengFehler === 'Zeitüberschreitung' && dauer < 4000 && sofort && unb[0]?.titel === 'Unbenanntes Gerät: Anonyme Chats gesperrt' && mu.verlauf[0].titel.startsWith('aa:bb'), JSON.stringify({ haengFehler, dauer, sofort, unb }));
    const mH = []; const mlH = new Meldungen({ einst: { werte: { meldungen: { an: true } } }, senden: async (n) => { mH.push(n); return { ntfy: true, push: 0, fehler: [] }; }, protokoll: () => {} });
    await mlH.melden({ titel: 'h', text: 'i', handy: false });
    pruefe('Meldungen: handy:false → Eintrag in der Liste, senden nicht aufgerufen', mlH.verlauf.length === 1 && mH.length === 0);
    const ohne = new Meldungen({ einst: { werte: { meldungen: { an: true } } }, protokoll: () => {} }); await ohne.melden({ titel: 'x', text: 'y' });
    pruefe('Meldungen: ohne eingerichteten Weg bleibt alles in der Liste (kein Versand, kein Fehler)', ohne.verlauf.length === 1 && !ohne.verlauf[0].handy);
  }
  for (const x of [PA, PB, PC, PD]) { x.sp.stoppen(); x.wi.close(); }
  E.sp.stoppen(); H.wi.close(); E.wi.close();
  web.close(); prot2.schliessen();
} catch (e) {
  console.error(e); ergebnisse.push(false);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
const okZahl = ergebnisse.filter(Boolean).length;
console.log(`\n${okZahl}/${ergebnisse.length} Prüfungen bestanden.`);
process.exit(okZahl === ergebnisse.length ? 0 : 1);
