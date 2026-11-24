// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Kinderschutz-Daten (23.11.2026): eigene, handgepflegte Listen – keine fremden Datensätze.
//   ANONYM      – anonyme Frage-Apps und Zufallschats: dort läuft das meiste Cybermobbing, dort sprechen Fremde Kinder an
//   HILFE       – Beratungs- und Notfallstellen: immer erreichbar, in keinem Profil sperrbar
//   SICHERSUCHE – erzwungene sichere Suche (Google, Bing, DuckDuckGo) und eingeschränkter YouTube-Modus per DNS
//   VORLAGEN    – Altersvorlagen für Profile (Grundschule, Klasse 5–7, ab 14)
'use strict';

// Jede Domain gilt samt Subdomains. Aufgenommen nur, was öffentlich auflösbar war (Prüfung 23.11.2026).
const ANONYM = [
  // anonyme Fragen, „Ehrlichkeits“-Apps (Mobbing-Werkzeug Nr. 1 unter Jugendlichen)
  'ngl.link', 'tellonym.me', 'ask.fm', 'getsendit.com', 'onyolo.com', 'lipsi.app', 'sarahah.com', 'curiouscat.live',
  // anonyme Orts- und Gruppenchats
  'jodel.com', 'whisper.sh', 'yikyak.com',
  // Freunde finden / Live-Video mit Fremden
  'getwinkapp.com', 'yubo.live', 'wizz.chat', 'hoop.photo', 'liveme.com', 'kik.com',
  // Zufalls-Videochats (Omegle-Nachfolger)
  'omegle.com', 'uhmegle.com', 'ome.tv', 'chatroulette.com', 'monkey.app', 'azarlive.com', 'holla.world', 'chatspin.com', 'emeraldchat.com',
  'chathub.cam', 'shagle.com', 'camsurf.com', 'bazoocam.org', 'chatrandom.com', 'tinychat.com', 'thundr.com', 'chitchat.gg',
  'talkwithstranger.com', 'chatib.us', 'strangermeetup.com',
];

// [id, Name, Symbol, Domains, Hinweis] – Rubrik „hilfe“, fest geschützt
const HILFE = [
  ['nummergegenkummer', 'Nummer gegen Kummer', '📞', 'nummergegenkummer.de', 'Kinder- und Jugendtelefon 116 111, Elterntelefon'],
  ['krisenchat', 'krisenchat', '💬', 'krisenchat.de', 'Chat-Beratung für junge Menschen, rund um die Uhr'],
  ['jugendnotmail', 'JugendNotmail', '✉️', 'jugendnotmail.de', 'Online-Beratung für Kinder und Jugendliche'],
  ['juuuport', 'JUUUPORT', '🤝', 'juuuport.de', 'Jugendliche helfen bei Cybermobbing und Ärger im Netz'],
  ['telefonseelsorge', 'TelefonSeelsorge', '☎️', 'telefonseelsorge.de', 'Telefon, Chat und Mail, anonym und kostenlos'],
  ['u25', '[U25] Suizidprävention', '🌱', 'u25-deutschland.de ich-bin-alles.de', 'Mail-Beratung von Gleichaltrigen; Wissen zu Depression'],
  ['bke', 'bke-Onlineberatung', '🧭', 'bke-beratung.de', 'Beratung für Jugendliche und Eltern'],
  ['hilfetelefon', 'Hilfetelefon Gewalt', '🆘', 'hilfetelefon.de frauen-gegen-gewalt.de weisser-ring.de', 'Hilfe bei Gewalt, Opferhilfe'],
  ['missbrauch', 'Hilfe bei Missbrauch', '🛡️', 'hilfe-portal-missbrauch.de beauftragte-missbrauch.de hilfe-telefon-missbrauch.online nina-info.de save-me-online.de trau-dich.de zartbitter.de wildwasser.de kinderschutzbund.de', 'Hilfe-Telefon, Beratungsstellen, Schutz vor Übergriffen im Netz'],
  ['meldestellen', 'Meldestellen & Netz-Hilfe', '🚩', 'klicksafe.de jugendschutz.net internet-beschwerdestelle.de hateaid.org polizei-beratung.de cybermobbing-hilfe.de', 'Inhalte melden, Hilfe bei Hass, Erpressung und Mobbing'],
  ['hilfe-at-ch', 'Rat auf Draht & 147', '🇦🇹', 'rataufdraht.at 147.ch projuventute.ch', 'Notrufe für Kinder in Österreich und der Schweiz'],
];

// Google-Suche: alle Länder-Domains (www.google.com/supported_domains, Stand 23.11.2026)
const GOOGLE_TLD = `com ad ae com.af com.ag al am co.ao com.ar as at com.au az ba com.bd be bf bg com.bh bi bj com.bn com.bo com.br bs bt co.bw by com.bz ca cd cf cg ch ci
co.ck cl cm cn com.co co.cr com.cu cv com.cy cz de dj dk dm com.do dz com.ec ee com.eg es com.et fi com.fj fm fr ga ge gg com.gh com.gi gl gm gr com.gt gy com.hk hn hr ht hu
co.id ie co.il im co.in iq is it je com.jm jo co.jp co.ke com.kh ki kg co.kr com.kw kz la com.lb li lk co.ls lt lu lv com.ly co.ma md me mg mk ml com.mm mn com.mt mu mv mw
com.mx com.my co.mz com.na com.ng com.ni ne nl no com.np nr nu co.nz com.om com.pa com.pe com.pg com.ph com.pk pl pn com.pr ps pt com.py com.qa ro ru rw com.sa com.sb sc se
com.sg sh si sk com.sl sn so sm sr st com.sv td tg co.th com.tj tl tm tn to com.tr tt com.tw co.tz com.ua co.ug co.uk com.uy co.uz com.vc co.ve co.vi com.vn vu ws rs co.za
co.zm co.zw cat`.split(/\s+/).filter(Boolean);

// Genaue Namen → Ziel. Die Anbieter liefern unter dem Ziel nur die gefilterte Fassung aus (offizieller Weg aller drei).
const SUCHE = new Map([
  ...GOOGLE_TLD.flatMap((t) => [[`google.${t}`, 'forcesafesearch.google.com'], [`www.google.${t}`, 'forcesafesearch.google.com']]),
  ['bing.com', 'strict.bing.com'], ['www.bing.com', 'strict.bing.com'],
  ['duckduckgo.com', 'safe.duckduckgo.com'], ['www.duckduckgo.com', 'safe.duckduckgo.com'], ['start.duckduckgo.com', 'safe.duckduckgo.com'],
]);
const YOUTUBE = ['www.youtube.com', 'm.youtube.com', 'youtube.com', 'youtubei.googleapis.com', 'youtube.googleapis.com', 'www.youtube-nocookie.com'];
const YOUTUBE_ZIEL = { moderat: 'restrictmoderate.youtube.com', streng: 'restrict.youtube.com' };

/** Ziel der sicheren Suche für einen Namen, sonst null. `sicher` = {suche: bool, youtube: 'aus'|'moderat'|'streng'} */
function sicherZiel(name, sicher) {
  if (!sicher) return null;
  if (sicher.suche && SUCHE.has(name)) return SUCHE.get(name);
  if (YOUTUBE_ZIEL[sicher.youtube] && YOUTUBE.includes(name)) return YOUTUBE_ZIEL[sicher.youtube];
  return null;
}

const IMMER = [1, 2, 3, 4, 5, 6, 7];
const fenster = (von, bis, tage = IMMER) => [{ tage, von, bis }];
const an = (...ids) => Object.fromEntries(ids.map((id) => [id, { an: true, zeitplan: [] }]));
const DATING = ['tinder', 'bumble', 'lovoo', 'parship', 'hinge', 'grindr'];
const sperren = (...ids) => Object.fromEntries(ids.map((id) => [id, 'sperren']));

// Altersvorlagen (angelehnt an gängige Empfehlungen: klicksafe, schau-hin.info). Mediendienste wie YouTube werden nie gesperrt
// (Betreiber-Vorgabe), für Jüngere aber im eingeschränkten Modus ausgeliefert.
const VORLAGEN = [
  {
    id: 'grundschule', name: 'Grundschule (6–10 Jahre)', farbe: '#7bd88f',
    beschreibung: 'Keine sozialen Netzwerke und Chats, Spiele höchstens 1 Stunde am Tag und abends Ruhe, sichere Suche, YouTube streng gefiltert',
    kategorien: an('werbung', 'schadsoftware', 'jugendschutz', 'gluecksspiel', 'social', 'anonym', 'drogen', 'umgehung', 'piraterie'),
    dienste: { ...sperren('whatsapp', 'telegram', 'signal', 'messenger', 'discord', 'viber', 'wechat', 'knuddels', 'ometv', 'characterai', 'metaai', 'grok'), ...sperren(...DATING) },
    ruhezeiten: { spiele: fenster('19:30', '07:00') },
    sicher: { suche: true, youtube: 'streng' },
    limits: { 'rubrik:spiele': 60 },
  },
  {
    id: 'klasse5', name: 'Klasse 5 bis 7 (10–13 Jahre)', farbe: '#ffb020',
    beschreibung: 'WhatsApp, Signal und Threema erlaubt, TikTok, Snapchat und Discord noch nicht; Messenger-Nachtruhe 21:00–06:30, Spiele 1,5 Stunden am Tag',
    kategorien: an('werbung', 'schadsoftware', 'jugendschutz', 'gluecksspiel', 'social', 'anonym', 'drogen', 'umgehung', 'piraterie'),
    dienste: { whatsapp: 'frei', signal: 'frei', threema: 'frei', ...sperren('tiktok', 'snapchat', 'discord', 'knuddels', 'ometv', 'characterai'), ...sperren(...DATING) },
    ruhezeiten: { messenger: fenster('21:00', '06:30'), spiele: fenster('20:30', '07:00') },
    sicher: { suche: true, youtube: 'moderat' },
    limits: { 'rubrik:spiele': 90 },
  },
  {
    id: 'ab14', name: 'Ab 14 Jahren', farbe: '#5cc8ff',
    beschreibung: 'Soziale Netzwerke erlaubt; anonyme Chats, Drogen, Glücksspiel und Umgehung bleiben gesperrt; Nachtruhe für Messenger und Social Media 22:30–06:00',
    kategorien: an('werbung', 'schadsoftware', 'jugendschutz', 'gluecksspiel', 'anonym', 'drogen', 'umgehung'),
    dienste: { ...sperren('ometv', 'knuddels'), ...sperren(...DATING) },
    ruhezeiten: { messenger: fenster('22:30', '06:00'), social: fenster('22:30', '06:00') },
    sicher: { suche: true, youtube: 'aus' },
    limits: {},
  },
];

// Rubriken, für die ein Profil Ruhezeiten haben kann (Hilfe nie)
const RUHE_RUBRIKEN = ['messenger', 'social', 'spiele', 'video', 'ki', 'shopping', 'dating'];

module.exports = { ANONYM, HILFE, SUCHE, YOUTUBE, YOUTUBE_ZIEL, sicherZiel, VORLAGEN, RUHE_RUBRIKEN, GOOGLE_TLD };
