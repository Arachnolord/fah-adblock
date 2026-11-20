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
const { Filter, zeitplanAktiv, musterLesen } = require('../src/dns/filter.js');
const paket = require('../src/dns/paket.js');
const { Upstream, DohAnbieter, Lokal } = require('../src/dns/upstream.js');
const { DnsServer } = require('../src/dns/server.js');
const { Records } = require('../src/dns/records.js');
const { Protokoll } = require('../src/protokoll.js');
const { Geraete, clientName } = require('../src/geraete.js');
const { Auth } = require('../src/auth.js');
const { Einstellungen, bereinigen, vorgaben, verschluesseln, entschluesseln } = require('../src/einstellungen.js');
const { webServer } = require('../src/web/server.js');
const { Spiegel } = require('../src/spiegel.js');
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
    const profileAusnahme = [profileD[0], { ...profileD[1], dienste: { tiktok: 'sperren', whatsapp: 'frei' } }];
    fD.konfigurieren({ ...basisD, profile: profileAusnahme, regeln: [], dienste: { tiktok: { modus: 'frei' } } });
    pruefe('Profil-Ausnahmen je Dienst: im Kinder-Profil TikTok gesperrt (trotz global geschützt), WhatsApp erlaubt; andere Profile unberührt',
      fD.entscheide({ geraetId: 'kind', name: 'www.tiktok.com' }).grund === 'Dienst gesperrt' && fD.entscheide({ geraetId: 'kind', name: 'web.whatsapp.com' }).grund === 'Geschützter Dienst'
      && fD.entscheide({ geraetId: 'papa', name: 'www.tiktok.com' }).grund === 'Geschützter Dienst');
    fD.konfigurieren({ ...basisD, regeln: [], dienste: { teams: { modus: 'frei' } } });
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
    fs.writeFileSync(path.join(ek, 'einstellungen.json'), '[1,2]');
    let wk2 = null; try { console.warn = () => {}; wk2 = new Einstellungen({ verzeichnis: ek, geheimnis: 'z'.repeat(20), env: {} }).laden().werte; } catch (e) {} finally { console.warn = alt; }
    pruefe('Einstellungen: Datei mit falschem Grundtyp → Vorgaben', !!wk2 && wk2.upstream.length === 3 && wk2.profile.length === 3);
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
  pruefe('Anmeldung: Bremse je Adresse nach 10 Fehlversuchen (auch mit richtigem Passwort)', /Zu viele Versuche/.test(auth.anmelden('admin', 'admin', '3.3.3.3').fehler || ''));
  uhrA += 2 * 3600000;   // Zähler je Name verfällt nach 1 h Ruhe
  for (const ip of ['5.5.5.1', '5.5.5.2']) auth.anmelden('admin', 'falsch', ip);
  const dritter = auth.anmelden('admin', 'falsch', '5.5.5.3'), gesperrt = auth.anmelden('admin', 'admin', '5.5.5.4');
  uhrA += 2500; const frei = auth.anmelden('admin', 'admin', '5.5.5.4');
  pruefe('Anmeldung: Bremse je Nutzername über Adressen hinweg – ab dem 3. Fehlversuch steigende Wartezeit (2 s, 4 s … 15 min), danach wieder frei',
    /falsch/.test(dritter.fehler) && /diesen Namen/.test(gesperrt.fehler || '') && !!frei.cookie && Auth.wartezeit(2) === 0 && Auth.wartezeit(3) === 2000 && Auth.wartezeit(4) === 4000 && Auth.wartezeit(30) === 900000, JSON.stringify([dritter, gesperrt, !!frei.cookie]));
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
  const web = webServer({ auth: authW, einst, listen, filter, upstream: up, dns: srv, geraete: { status: () => ({ unifi: {} }), unifiLesen: async () => 0, iconVon: (id) => (id === 'aa:bb:cc:dd:ee:ff' ? 1681 : null), nameVon: () => '' }, protokoll: prot2, live: new Set(), version: 'probe', statisch: path.join(tmp, 'pub'), daten: path.join(tmp, 'web') });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const B = `http://127.0.0.1:${web.address().port}`;
  const holen = (p, o = {}) => fetch(B + p, o);
  pruefe('Web: ohne Anmeldung 401, statische Seite erreichbar, Pfad-Ausbruch landet auf index.html', (await holen('/api/uebersicht')).status === 401 && (await (await holen('/')).text()).includes('ok') && !(await (await holen('/..%2f..%2fetc%2fpasswd')).text()).includes('root:'));
  const login = await holen('/api/anmelden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'admin', passwort: 'admin' }) });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  const ich = await (await holen('/api/ich', { headers: { cookie } })).json();
  pruefe('Web: Anmeldung setzt HttpOnly-/SameSite-Cookie, /api/ich liefert CSRF-Token', /HttpOnly/.test(login.headers.get('set-cookie')) && /SameSite=Strict/.test(login.headers.get('set-cookie')) && ich.csrf && ich.standardPasswort);
  const ohneCsrf = await holen('/api/pause', { method: 'POST', headers: { cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ minuten: 5 }) });
  const fremd = await holen('/api/pause', { method: 'POST', headers: { cookie, 'x-csrf': ich.csrf, origin: 'https://boese.example', 'Content-Type': 'application/json' }, body: JSON.stringify({ minuten: 5 }) });
  pruefe('Web: Schreiben ohne CSRF-Token oder von fremder Herkunft → 403', ohneCsrf.status === 403 && fremd.status === 403);
  const post = (p, daten, m = 'POST') => holen(p, { method: m, headers: { cookie, 'x-csrf': ich.csrf, 'Content-Type': 'application/json' }, body: JSON.stringify(daten) });
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
  const spFalsch = await fetch(H.basis + '/api/spiegel/stand', { headers: { Authorization: 'Bearer falsch' } });
  const spOhne = await fetch(H.basis + '/api/spiegel/stand');
  const spStand = await (await fetch(H.basis + '/api/spiegel/stand', { headers: { Authorization: `Bearer ${spCode}` } })).json();
  pruefe('Spiegel: Haupt liefert nur mit Kopplungscode, ohne UniFi-Zugang und vertraute Proxys', spFalsch.status === 401 && spOhne.status === 401 && spStand.art === 'fah-adblock-sicherung' && !('unifi' in spStand.einstellungen) && !('web' in spStand.einstellungen) && spStand.einstellungen.regeln.some((r) => r.id === 'r-haupt'));
  const spKoppeln = await E.sende('/api/spiegel/ersatz', { url: H.basis, code: spCode });
  pruefe('Spiegel: Ersatz koppeln übernimmt Regeln und Pausen, eigene Proxys bleiben', spKoppeln.status === 200 && E.ei.werte.regeln.some((r) => r.id === 'r-haupt') && E.ei.werte.pausen.global === H.ei.werte.pausen.global && !(E.ei.werte.web?.vertrauteProxies || []).length, `HTTP ${spKoppeln.status}`);
  const spGesperrt = await E.sende('/api/regeln', { typ: 'erlauben', muster: 'x.example', geltung: 'alle' });
  const spUnifi = await E.sende('/api/einstellungen/unifi', { url: 'https://192.168.1.1', schluessel: '' });
  pruefe('Spiegel: am Ersatz sind Änderungen gesperrt (409 mit Hinweis), UniFi-Zugang bleibt einstellbar', spGesperrt.status === 409 && /Haupt/.test((await spGesperrt.json()).fehler) && spUnifi.status !== 409);
  H.ei.aendern((x) => { x.regeln.push({ id: 'r-spaeter', typ: 'erlauben', muster: 'spaeter.example', geltung: 'alle' }); });
  const spSt = await E.sp.abgleichen();
  const gesundE = await (await fetch(E.basis + '/api/health')).json(); const gesundH = await (await fetch(H.basis + '/api/health')).json();
  pruefe('Spiegel: Abgleich holt neue Regeln; Haupt merkt sich den Abruf; /api/health zeigt die Rolle', !spSt.fehler && E.ei.werte.regeln.some((r) => r.id === 'r-spaeter') && H.sp.status().ersatz && H.sp.status().ersatz.zeit > 0 && gesundE.rolle === 'ersatz' && gesundH.rolle === 'haupt');
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
