// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Dienste-Katalog (Vorbild AdGuard „Blockierte Dienste“, nach Rubriken).
// Jeder Dienst hat einen von drei Zuständen:
//   frei    – geschützt: KEINE Liste kann ihn blocken (Vorgabe für Medien, Musik und Geräte-Grundfunktionen,
//             Betreiber-Vorgabe 15.09.2026: Mediendienste nie blocken, außer er sperrt sie selbst)
//   listen  – normal: die Blocklisten und das Profil entscheiden (Vorgabe für Social Media, Spiele, Shopping …)
//   sperren – vom Betreiber gesperrt, für alle Geräte, ein Profil oder ein Gerät
// Domains gelten inklusive Subdomains; jede Domain gehört zu genau einem Dienst.
// Ausnahmen (7. Feld): reine Mess- und Werbe-Adressen INNERHALB einer geschützten Domain – für sie entscheiden
// weiter die Blocklisten (z. B. acr-eu-prd.samsungcloud.tv = Sehverhaltens-Erkennung, während fc.samsungcloud.tv
// zum Betrieb des Fernsehers gehört). So schützt ein Dienst die Funktion, ohne die Überwachung mit freizugeben.
// Schreibweise: „log.internetat.tv“ (samt Subdomains) oder mit Vorsilbe „acr-*.samsungcloud.tv“ – trifft jeden Host, dessen
// Name direkt vor der Domain mit „acr-“ beginnt (neue Regionen/Jahrgänge der Hersteller sind damit gleich abgedeckt).
// Mitbenutzt (8. Feld): Namen, die der Dienst braucht, die ihm aber nicht allein gehören (fremder Anbieter, gemeinsame Plattform) – bei „frei“
// mitgeschützt, bei „sperren“ NICHT mitgesperrt (dort entscheiden die Listen). Sonst nähme „Teams im Kinder-Profil sperren“ allen Apps die GIFs.
'use strict';

const GRUPPEN = [
  { id: 'video', name: 'Fernsehen & Video', vorgabe: 'frei' },
  { id: 'musik', name: 'Musik & Audio', vorgabe: 'frei' },
  { id: 'social', name: 'Social Media', vorgabe: 'listen' },
  { id: 'messenger', name: 'Messenger & Konferenzen', vorgabe: 'listen' },
  { id: 'spiele', name: 'Spiele', vorgabe: 'listen' },
  { id: 'shopping', name: 'Shopping', vorgabe: 'listen' },
  { id: 'ki', name: 'Suche & KI', vorgabe: 'listen' },
  { id: 'nachrichten', name: 'Nachrichten', vorgabe: 'listen' },
  { id: 'arbeit', name: 'Cloud & Arbeit', vorgabe: 'listen' },
  { id: 'mail', name: 'E-Mail', vorgabe: 'listen' },
  { id: 'lernen', name: 'Schule & Lernen', vorgabe: 'frei' },
  { id: 'finanzen', name: 'Finanzen, Behörden & Gesundheit', vorgabe: 'frei' },
  { id: 'reisen', name: 'Reisen & Mobilität', vorgabe: 'listen' },
  { id: 'telko', name: 'Telefon & Internet', vorgabe: 'listen' },
  { id: 'dating', name: 'Dating', vorgabe: 'listen' },
  { id: 'vpn', name: 'VPN & Umgehung', vorgabe: 'listen' },
  { id: 'smarthome', name: 'Smart Home & Geräte', vorgabe: 'frei' },
  { id: 'system', name: 'Geräte & System', vorgabe: 'frei' },
  // Kinderschutz (23.11.2026): Beratungs- und Notfallstellen – fest geschützt, weder hier noch im Profil sperrbar, auch nicht von Ruhezeiten oder Zeitlimits
  { id: 'hilfe', name: 'Hilfe & Beratung', vorgabe: 'frei', fest: true },
];

const ROH = [
  // ── Fernsehen & Video ────────────────────────────────────────────────────
  ['waipu', 'waipu.tv', '📺', 'video', 'waipu.tv wpstr.tv exaring.net exaring.de exaring.ag'],
  ['youtube', 'YouTube', '▶️', 'video', 'youtube.com youtu.be ytimg.com googlevideo.com youtube-nocookie.com youtubekids.com youtubei.googleapis.com yt3.ggpht.com yt4.ggpht.com'],
  ['netflix', 'Netflix', '🎬', 'video', 'netflix.com netflix.net nflxvideo.net nflximg.net nflximg.com nflxext.com nflxso.net'],
  ['primevideo', 'Prime Video', '🎥', 'video', 'primevideo.com amazonvideo.com aiv-cdn.net aiv-delivery.net pv-cdn.net'],
  ['disneyplus', 'Disney+', '🏰', 'video', 'disneyplus.com disney-plus.net dssott.com bamgrid.com disneystreaming.com'],
  ['dazn', 'DAZN', '⚽', 'video', 'dazn.com indazn.com'],
  ['joyn', 'Joyn', '🟣', 'video', 'joyn.de'],
  ['prosiebensat1', 'ProSieben & Sat.1', '🅿️', 'video', 'prosieben.de sat1.de kabeleins.de sixx.de prosiebenmaxx.de sat1gold.de'],
  ['rtlplus', 'RTL+', '🔴', 'video', 'rtlplus.de rtl.de tvnow.de vox.de rtl2.de'],
  ['ard', 'ARD Mediathek', '1️⃣', 'video', 'ard.de ardmediathek.de daserste.de br.de wdr.de ndr.de swr.de mdr.de hr.de rbb-online.de sr.de radiobremen.de sportschau.de phoenix.de'],
  ['zdf', 'ZDF Mediathek', '2️⃣', 'video', 'zdf.de 3sat.de'],
  ['arte', 'arte', '🎭', 'video', 'arte.tv'],
  ['orf', 'ORF', '🇦🇹', 'video', 'orf.at'],
  ['srf', 'SRF', '🇨🇭', 'video', 'srf.ch'],
  ['servustv', 'ServusTV', '🐂', 'video', 'servustv.com'],
  ['magentatv', 'MagentaTV', '🩷', 'video', 'magentatv.de'],
  ['zattoo', 'Zattoo', '📡', 'video', 'zattoo.com zahs.tv'],
  ['plutotv', 'Pluto TV', '🪐', 'video', 'pluto.tv'],
  ['sky', 'Sky / WOW', '🌌', 'video', 'sky.de wowtv.de'],
  ['paramount', 'Paramount+', '⛰️', 'video', 'paramountplus.com'],
  ['discoveryplus', 'Discovery+', '🧭', 'video', 'discoveryplus.com eurosport.com eurosport.de', '', 'ssa.eurosport.com ssa.eurosport.de ad.eurosport.com'],
  ['crunchyroll', 'Crunchyroll', '🍥', 'video', 'crunchyroll.com crunchyroll.net'],
  ['rakutentv', 'Rakuten TV', '🅡', 'video', 'rakuten.tv'],
  ['vimeo', 'Vimeo', '🎞️', 'video', 'vimeo.com vimeocdn.com'],
  ['twitch', 'Twitch', '🎮', 'video', 'twitch.tv ttvnw.net jtvnw.net'],
  ['plex', 'Plex', '🟧', 'video', 'plex.tv plex.direct plex.app'],
  ['jellyfin', 'Jellyfin & Emby', '🪼', 'video', 'jellyfin.org emby.media'],
  ['appletv', 'Apple TV+', '🍎', 'video', 'tv.apple.com mzstatic.com'],
  ['hbomax', 'HBO Max', '🟪', 'video', 'max.com hbomax.com'],
  ['kika', 'KiKA & TOGGO', '🧒', 'video', 'kika.de toggo.de superrtl.de'],
  ['dailymotion', 'Dailymotion', '🎦', 'video', 'dailymotion.com dmcdn.net', '', 'dmads.dailymotion.com dmxleo.dailymotion.com'],
  ['kick', 'Kick', '🟩', 'video', 'kick.com'],
  ['hbbtv', 'HbbTV', '📟', 'video', 'redbutton.de sim-technik.de hbbtv.qvc.de', 'Zusatzangebote der Sender über die rote Taste der Fernbedienung', 'hbbtv-track.redbutton.de redbutton-adproxy-lb-prod.redbutton.de adex.redbutton.de adex-retargeting.redbutton.de prod-tracking.redbutton.de tracking.redbutton.de'],

  // ── Musik & Audio ────────────────────────────────────────────────────────
  ['spotify', 'Spotify', '🎧', 'musik', 'spotify.com scdn.co spotifycdn.com pscdn.co'],
  ['applemusic', 'Apple Music', '🎼', 'musik', 'music.apple.com itunes.apple.com'],
  ['amazonmusic', 'Amazon Music', '🎶', 'musik', 'music.amazon.de music.amazon.com'],
  ['deezer', 'Deezer', '🎵', 'musik', 'deezer.com dzcdn.net'],
  ['tidal', 'Tidal', '🌊', 'musik', 'tidal.com'],
  ['soundcloud', 'SoundCloud', '☁️', 'musik', 'soundcloud.com sndcdn.com'],
  ['bandcamp', 'Bandcamp', '💿', 'musik', 'bandcamp.com bcbits.com'],
  ['audible', 'Audible', '🎙️', 'musik', 'audible.de audible.com audible.co.uk'],
  ['radio', 'Radio & Podcast', '📻', 'musik', 'radio.de radio.net tunein.com radioplayer.de laut.fm podcasts.apple.com ardaudiothek.de', 'Radio & Podcasts'],
  ['shazam', 'Shazam', '🔵', 'musik', 'shazam.com'],
  ['tonies', 'Toniebox', '🧸', 'musik', 'tonies.com tonies.de boxine.de tonie.cloud', '', 'sentry-*.boxine.de sentry-1.eu-central-1.prod.tonie.cloud'],

  // ── Social Media ─────────────────────────────────────────────────────────
  ['facebook', 'Facebook', '📘', 'social', 'facebook.com facebook.net fbcdn.net fbsbx.com'],
  ['instagram', 'Instagram', '📸', 'social', 'instagram.com cdninstagram.com'],
  ['threads', 'Threads', '🧵', 'social', 'threads.net'],
  ['tiktok', 'TikTok', '🎵', 'social', 'tiktok.com tiktokv.com tiktokv.eu tiktokcdn.com tiktokcdn-eu.com tiktokcdn-us.com ttwstatic.com byteoversea.com ibytedtos.com ibyteimg.com'],
  ['snapchat', 'Snapchat', '👻', 'social', 'snapchat.com sc-static.net sc-cdn.net snapkit.com'],
  ['x', 'X (Twitter)', '✖️', 'social', 'twitter.com x.com twimg.com t.co'],
  ['reddit', 'Reddit', '👽', 'social', 'reddit.com redditstatic.com redditmedia.com redd.it'],
  ['pinterest', 'Pinterest', '📌', 'social', 'pinterest.com pinterest.de pinimg.com'],
  ['tumblr', 'Tumblr', '📓', 'social', 'tumblr.com'],
  ['linkedin', 'LinkedIn', '💼', 'social', 'linkedin.com licdn.com'],
  ['mastodon', 'Mastodon', '🐘', 'social', 'joinmastodon.org mastodon.social'],
  ['bluesky', 'Bluesky', '🦋', 'social', 'bsky.app bsky.social'],
  ['bereal', 'BeReal', '📷', 'social', 'bereal.com'],
  ['vk', 'VK', '🇷🇺', 'social', 'vk.com'],
  ['ninegag', '9GAG', '😂', 'social', '9gag.com'],
  ['imgur', 'Imgur', '🖼️', 'social', 'imgur.com'],
  ['capcut', 'CapCut', '✂️', 'social', 'capcut.com capcutapi.com'],
  ['knuddels', 'Knuddels', '💋', 'social', 'knuddels.de'],
  ['ometv', 'Zufalls-Videochat', '🎲', 'social', 'ome.tv chatroulette.com monkey.app', 'OmeTV & Zufalls-Videochats'],

  // ── Messenger & Konferenzen ──────────────────────────────────────────────
  ['whatsapp', 'WhatsApp', '💬', 'messenger', 'whatsapp.com whatsapp.net'],
  ['messenger', 'Facebook Messenger', '💭', 'messenger', 'messenger.com'],
  ['telegram', 'Telegram', '✈️', 'messenger', 'telegram.org telegram.me t.me'],
  ['signal', 'Signal', '🔏', 'messenger', 'signal.org whispersystems.org'],
  ['threema', 'Threema', '🔒', 'messenger', 'threema.ch'],
  ['discord', 'Discord', '🕹️', 'messenger', 'discord.com discordapp.com discord.gg discordapp.net'],
  // Microsoft Teams (Betreiber-Vorgabe 21.09.2026: bei diesem Dienst müssen ALLE Teams-Dienste frei sein). Quellen: Microsofts Endpunktliste
  // (endpoints.office.com, IDs 12/27/127) und das echte Protokoll der Teams-Geräte. skype.com ist seit dem Ende von Skype (Mai 2025) nur noch
  // Teams-Infrastruktur (Anrufaufbau, Konfiguration) – der frühere Dienst „Skype“ ist hier aufgegangen. Der Abgleich kennt nur Endungen:
  // Geschwister wie eu-teams.events.data.microsoft.com stehen deshalb einzeln da; events.data.microsoft.com als Ganzes wäre die Telemetrie aller
  // Microsoft-Produkte. Zwischennamen (…trafficmanager.net) fragt macOS direkt nach. Pflege: tmc-g2.tm-4.office.com trägt einen Generationszähler.
  ['teams', 'Microsoft Teams', '👥', 'messenger', 'teams.microsoft.com teams.live.com teams.cloud.microsoft skype.com lync.com skypeassets.com teams.microsoft.net trouter.io mstea.ms'
    + ' teams.office.com ha-teams.office.com ms-acdc-teams.office.com tmc-g2.tm-4.office.com teams-mrc-ww-perf.tm-4.office.com teams.cdn.office.net ml.cdn.office.net bmc.cdn.office.net cosmic.office.net'
    + ' teams.nel.measure.office.net tfl.nel.measure.office.net teams.cdn.live.net teams.public.onecdn.static.microsoft tflteams.public.onecdn.static.microsoft teamsinstaller.public.onecdn.static.microsoft'
    + ' teams.static.microsoft communications.svc.static.microsoft communications.svc.cloud.microsoft enterprisevoice.svc.cloud.microsoft teams.mira.tm.svc.cloud.microsoft teamsforlife.afdcafe.tm.svc.cloud.microsoft'
    + ' teams.events.data.microsoft.com eu-teams.events.data.microsoft.com us-teams.events.data.microsoft.com ic3.events.data.microsoft.com eu-ic3.events.data.microsoft.com us-ic3.events.data.microsoft.com'
    + ' mobile.events.data.microsoft.com eu-mobile.events.data.microsoft.com us-mobile.events.data.microsoft.com teams.pipe.aria.microsoft.com'
    + ' teams-events-data.trafficmanager.net config.teams.trafficmanager.net config.edge.skype.com.trafficmanager.net flightproxy.teams.trafficmanager.net flightproxy-emea-teams.trafficmanager.net relay.teams.trafficmanager.net'
    + ' attend.teams.trafficmanager.net cc-emea-skype.trafficmanager.net asm-api-golocal-geo-eu-teams.trafficmanager.net teams-mrc-ww-acdcatm.trafficmanager.net'
    + ' media.giphy.com media0.giphy.com media1.giphy.com media2.giphy.com media3.giphy.com media4.giphy.com teams.microsoft.com.mcas.ms teams.cloud.microsoft.mcas.ms rooms.microsoft.com adl.windows.com',
    'Chat, Anrufe und Besprechungen – samt Anruf-Infrastruktur (früher Skype), Konfiguration, Diagnosekanal der App, GIFs und Teams-Räumen. Anmeldung und Dateien laufen über „Microsoft-Konto“ und „Microsoft 365“', '',
    'media.giphy.com media0.giphy.com media1.giphy.com media2.giphy.com media3.giphy.com media4.giphy.com cosmic.office.net adl.windows.com mobile.events.data.microsoft.com eu-mobile.events.data.microsoft.com us-mobile.events.data.microsoft.com'],
  ['zoom', 'Zoom', '🎦', 'messenger', 'zoom.us zoom.com'],
  ['googlemeet', 'Google Meet', '🟩', 'messenger', 'meet.google.com'],
  ['slack', 'Slack', '#️⃣', 'messenger', 'slack.com slack-edge.com'],
  ['viber', 'Viber', '☎️', 'messenger', 'viber.com'],
  ['webex', 'Webex', '🌐', 'messenger', 'webex.com'],
  ['element', 'Element / Matrix', '🧮', 'messenger', 'element.io matrix.org'],
  ['wechat', 'WeChat', '🟢', 'messenger', 'wechat.com weixin.qq.com'],

  // ── Spiele ───────────────────────────────────────────────────────────────
  ['steam', 'Steam', '🚂', 'spiele', 'steampowered.com steamcommunity.com steamstatic.com steamcontent.com steamserver.net steamusercontent.com'],
  ['epicgames', 'Epic Games & Fortnite', '🕹️', 'spiele', 'epicgames.com unrealengine.com fortnite.com'],
  ['roblox', 'Roblox', '🟥', 'spiele', 'roblox.com rbxcdn.com'],
  ['minecraft', 'Minecraft', '⛏️', 'spiele', 'minecraft.net mojang.com'],
  ['ea', 'EA', '🎯', 'spiele', 'ea.com origin.com'],
  ['ubisoft', 'Ubisoft', '🌀', 'spiele', 'ubisoft.com ubi.com'],
  ['playstation', 'PlayStation', '🎮', 'spiele', 'playstation.com playstation.net sonyentertainmentnetwork.com'],
  ['xbox', 'Xbox', '🟢', 'spiele', 'xbox.com xboxlive.com'],
  ['nintendo', 'Nintendo', '🍄', 'spiele', 'nintendo.com nintendo.net'],
  ['battlenet', 'Battle.net', '⚔️', 'spiele', 'battle.net blizzard.com'],
  ['riot', 'Riot Games', '🔫', 'spiele', 'riotgames.com'],
  ['supercell', 'Supercell', '🏰', 'spiele', 'supercell.com'],
  ['rockstar', 'Rockstar Games', '⭐', 'spiele', 'rockstargames.com'],
  ['gog', 'GOG', '💾', 'spiele', 'gog.com'],
  ['pokemongo', 'Pokémon GO', '⚪', 'spiele', 'nianticlabs.com nianticstatic.com pokemongolive.com pokemongo.com pokemongo-get.com scopelyexplore.com wayfarer.scopely.com explore.scopely.com scopelyexplore.helpshift.com pokemon.com', 'Pokémon GO (Niantic, seit 2025 Scopely) – ab Werk für alle Geräte freigeschaltet', undefined, 'scopelyexplore.helpshift.com'],
  ['pokeraid', 'PokeRaid', '🥚', 'spiele', 'pokeraid.me poketrade.me', 'PokeRaid & PokeTrade (Fern-Raids und Tausch für Pokémon GO) – ab Werk für alle Geräte freigeschaltet'],
  ['activision', 'Call of Duty', '🎖️', 'spiele', 'callofduty.com activision.com', 'Call of Duty & Activision'],
  ['hoyoverse', 'Genshin Impact', '🌠', 'spiele', 'hoyoverse.com mihoyo.com hoyolab.com', 'HoYoverse (Genshin Impact)'],
  ['nvidia', 'GeForce NOW', '🟩', 'spiele', 'nvidia.com geforcenow.com nvidiagrid.net', 'NVIDIA & GeForce NOW'],
  ['tocaboca', 'Toca Boca', '🧁', 'spiele', 'tocaboca.com'],
  ['lego', 'LEGO', '🧱', 'spiele', 'lego.com'],
  ['browsergames', 'Browserspiele', '👾', 'spiele', 'poki.com crazygames.com spielaffe.de', 'Browserspiele (Poki, CrazyGames, SpielAffe)'],
  ['schach', 'Schach', '♟️', 'spiele', 'chess.com lichess.org', 'Chess.com & Lichess'],

  // ── Shopping ─────────────────────────────────────────────────────────────
  ['amazon', 'Amazon', '📦', 'shopping', 'amazon.de amazon.com media-amazon.com ssl-images-amazon.com'],
  ['ebay', 'eBay', '🔨', 'shopping', 'ebay.de ebay.com ebayimg.com ebaystatic.com'],
  ['otto', 'Otto', '🛍️', 'shopping', 'otto.de'],
  ['zalando', 'Zalando', '👟', 'shopping', 'zalando.de ztat.net'],
  ['aliexpress', 'AliExpress', '🧧', 'shopping', 'aliexpress.com alicdn.com'],
  ['temu', 'Temu', '🟠', 'shopping', 'temu.com'],
  ['shein', 'Shein', '👗', 'shopping', 'shein.com'],
  ['etsy', 'Etsy', '🧶', 'shopping', 'etsy.com'],
  ['idealo', 'idealo', '🔍', 'shopping', 'idealo.de idealo.com'],
  ['mediamarkt', 'MediaMarkt & Saturn', '🛒', 'shopping', 'mediamarkt.de saturn.de'],
  ['ikea', 'IKEA', '🪑', 'shopping', 'ikea.com'],
  ['lidl', 'Lidl & Kaufland', '🟨', 'shopping', 'lidl.de kaufland.de'],
  ['kleinanzeigen', 'Kleinanzeigen', '🏷️', 'shopping', 'kleinanzeigen.de classistatic.de'],
  ['vinted', 'Vinted', '👚', 'shopping', 'vinted.de vinted.com'],
  ['autoboersen', 'Autobörsen', '🚗', 'shopping', 'mobile.de autoscout24.de', 'mobile.de & AutoScout24'],
  ['lieferando', 'Lieferando', '🍕', 'shopping', 'lieferando.de takeaway.com'],
  ['rewe', 'REWE & ALDI', '🥕', 'shopping', 'rewe.de rewe-group.com aldi-sued.de aldi-nord.de'],
  ['drogerie', 'dm & Rossmann', '🧴', 'shopping', 'dm.de rossmann.de'],
  ['check24', 'CHECK24', '✅', 'shopping', 'check24.de'],
  ['aboutyou', 'About You', '👕', 'shopping', 'aboutyou.de'],

  // ── Suche & KI ───────────────────────────────────────────────────────────
  ['google', 'Google Suche', '🔎', 'ki', 'google.com google.de gstatic.com'],
  ['bing', 'Bing', '🅱️', 'ki', 'bing.com'],
  ['duckduckgo', 'DuckDuckGo', '🦆', 'ki', 'duckduckgo.com'],
  ['ecosia', 'Ecosia', '🌳', 'ki', 'ecosia.org'],
  ['chatgpt', 'ChatGPT', '🤖', 'ki', 'openai.com chatgpt.com oaistatic.com sora.com'],
  ['claude', 'Claude', '🟤', 'ki', 'claude.ai anthropic.com claudeusercontent.com'],
  ['gemini', 'Google Gemini', '💎', 'ki', 'gemini.google.com'],
  ['copilot', 'Microsoft Copilot', '🧑‍✈️', 'ki', 'copilot.microsoft.com'],
  ['perplexity', 'Perplexity', '❓', 'ki', 'perplexity.ai'],
  ['characterai', 'Character.AI', '🎭', 'ki', 'character.ai'],
  ['deepseek', 'DeepSeek', '🐋', 'ki', 'deepseek.com'],
  ['mistral', 'Mistral (Le Chat)', '🌬️', 'ki', 'mistral.ai'],
  ['grok', 'Grok (xAI)', '🅧', 'ki', 'x.ai grok.com'],
  ['metaai', 'Meta AI', '♾️', 'ki', 'meta.ai'],
  ['langdock', 'Langdock', '🧠', 'ki', 'langdock.com'],
  ['deepl', 'DeepL', '🌐', 'ki', 'deepl.com'],
  ['bravesuche', 'Brave & Startpage', '🦁', 'ki', 'search.brave.com startpage.com', 'Brave Search & Startpage'],

  // ── Nachrichten ──────────────────────────────────────────────────────────
  ['tagesschau', 'tagesschau', '📰', 'nachrichten', 'tagesschau.de'],
  ['spiegel', 'DER SPIEGEL', '📄', 'nachrichten', 'spiegel.de'],
  ['bild', 'BILD', '🅱', 'nachrichten', 'bild.de'],
  ['welt', 'WELT', '🌍', 'nachrichten', 'welt.de'],
  ['faz', 'FAZ', '📜', 'nachrichten', 'faz.net'],
  ['sueddeutsche', 'Süddeutsche', '🗞️', 'nachrichten', 'sueddeutsche.de'],
  ['zeit', 'ZEIT', '⏱️', 'nachrichten', 'zeit.de'],
  ['stern', 'stern', '✨', 'nachrichten', 'stern.de'],
  ['focus', 'FOCUS', '🎯', 'nachrichten', 'focus.de'],
  ['ntv', 'n-tv', '📡', 'nachrichten', 'n-tv.de'],
  ['heise', 'heise online', '💻', 'nachrichten', 'heise.de'],
  ['golem', 'Golem.de', '🤖', 'nachrichten', 'golem.de'],
  ['tonline', 't-online', '🅣', 'nachrichten', 't-online.de'],
  ['merkur', 'Merkur, tz & idowa', '🥨', 'nachrichten', 'merkur.de tz.de idowa.de'],
  ['handelsblatt', 'Handelsblatt', '📈', 'nachrichten', 'handelsblatt.com'],
  ['kicker', 'kicker', '⚽', 'nachrichten', 'kicker.de'],
  ['wetter', 'Wetter', '🌦️', 'nachrichten', 'wetter.com wetteronline.de wetter.de dwd.de', 'Wetter (wetter.com, WetterOnline, DWD)'],

  // ── Cloud & Arbeit ───────────────────────────────────────────────────────
  ['microsoft365', 'Microsoft 365', '🅼', 'arbeit', 'office.com office.net office365.com officeapps.live.com microsoftonline.com sharepoint.com sharepointonline.com cloud.microsoft static.microsoft usercontent.microsoft onenote.com svc.ms graph.microsoft.com office.events.data.microsoft.com eu-office.events.data.microsoft.com office-events-data.trafficmanager.net eu.aria.events.data.trafficmanager.net dual-s-0005-office.config.skype.com',
    'Word, Excel, PowerPoint, OneNote, SharePoint – auch Dateien und Besprechungsaufzeichnungen in Teams sowie der Diagnosekanal der Office-Apps'],
  ['onedrive', 'OneDrive', '☁️', 'arbeit', 'onedrive.com 1drv.com'],
  ['googledrive', 'Google Drive & Docs', '📂', 'arbeit', 'drive.google.com docs.google.com'],
  ['icloud', 'iCloud', '🍏', 'arbeit', 'icloud.com icloud-content.com apple-cloudkit.com'],
  ['dropbox', 'Dropbox', '📥', 'arbeit', 'dropbox.com dropboxapi.com dropboxusercontent.com'],
  ['notion', 'Notion', '📝', 'arbeit', 'notion.so notion.com'],
  ['atlassian', 'Jira & Confluence', '🧩', 'arbeit', 'atlassian.com atlassian.net atl-paas.net trello.com'],
  ['github', 'GitHub', '🐙', 'arbeit', 'github.com githubusercontent.com githubassets.com'],
  ['canva', 'Canva', '🎨', 'arbeit', 'canva.com'],
  ['wetransfer', 'WeTransfer', '📤', 'arbeit', 'wetransfer.com'],
  ['onepassword', '1Password', '🔑', 'arbeit', '1password.com 1password.eu 1passwordusercontent.com'],
  ['bitwarden', 'Bitwarden', '🛡️', 'arbeit', 'bitwarden.com bitwarden.eu'],
  ['nextcloud', 'Nextcloud', '🌥️', 'arbeit', 'nextcloud.com'],
  ['gitlab', 'GitLab', '🦊', 'arbeit', 'gitlab.com'],
  ['docker', 'Docker', '🐳', 'arbeit', 'docker.io docker.com ghcr.io quay.io', 'Docker & Container-Registries'],
  ['paketquellen', 'npm & PyPI', '📦', 'arbeit', 'npmjs.org npmjs.com pypi.org pythonhosted.org'],
  ['salesforce', 'Salesforce', '🌩️', 'arbeit', 'salesforce.com force.com forceusercontent.com'],
  ['personio', 'Personio', '🧑‍💼', 'arbeit', 'personio.de personio.com'],
  ['adobe', 'Adobe', '🅰️', 'arbeit', 'adobe.com adobe.io adobelogin.com'],
  ['figma', 'Figma & Miro', '🖌️', 'arbeit', 'figma.com miro.com'],
  ['datev', 'DATEV', '🧾', 'arbeit', 'datev.de'],

  // ── E-Mail ───────────────────────────────────────────────────────────────
  ['gmail', 'Gmail', '✉️', 'mail', 'mail.google.com gmail.com googlemail.com'],
  ['outlook', 'Outlook.com', '📧', 'mail', 'outlook.com hotmail.com live.com'],
  ['gmx', 'GMX', '🟦', 'mail', 'gmx.net gmx.de gmx.at gmx.ch'],
  ['webde', 'WEB.DE', '🟨', 'mail', 'web.de'],
  ['yahoo', 'Yahoo Mail', '🟣', 'mail', 'yahoo.com yahoo.de yimg.com'],
  ['proton', 'Proton Mail', '⚛️', 'mail', 'proton.me protonmail.com protonmail.ch'],
  ['posteo', 'Posteo & mailbox.org', '🌱', 'mail', 'posteo.de mailbox.org'],
  ['ionos', 'IONOS', '🔷', 'mail', 'ionos.de ionos.com'],

  // ── Schule & Lernen (geschützt – die Schule muss funktionieren) ───────────
  ['edupage', 'EduPage', '🏫', 'lernen', 'edupage.org'],
  ['bycs', 'mebis / ByCS', '🎒', 'lernen', 'bycs.de mebis.bayern.de', 'mebis / ByCS (Bayern)'],
  ['schulmanager', 'Schulmanager Online', '🗓️', 'lernen', 'schulmanager-online.de'],
  ['webuntis', 'WebUntis', '⏰', 'lernen', 'webuntis.com untis.at', '', 'crash.untis.at'],
  ['iserv', 'IServ & Moodle', '🖧', 'lernen', 'iserv.de iserv.eu moodle.org moodlecloud.com', '', 'statistics.www-marketing.iserv.eu stats.moodle.org'],
  ['classroom', 'Google Classroom', '🧑‍🏫', 'lernen', 'classroom.google.com'],
  ['schulessen', 'Schulessen', '🍽️', 'lernen', 'inetmenue.de mensamax.de', 'Schulessen (iNet-Menue, MensaMax)'],
  ['anton', 'ANTON', '🟢', 'lernen', 'anton.app'],
  ['antolin', 'Antolin', '📚', 'lernen', 'antolin.de westermann.de', 'Antolin & Westermann', 'track.westermann.de'],
  ['sofatutor', 'Lernvideos', '🛋️', 'lernen', 'sofatutor.com simpleclub.com studyflix.de bettermarks.com', 'sofatutor & simpleclub', 'sst.simpleclub.com'],
  ['duolingo', 'Duolingo', '🦉', 'lernen', 'duolingo.com', '', 'zombie.duolingo.com excess.duolingo.com excess-ga.duolingo.com'],
  ['khan', 'Khan Academy', '🌱', 'lernen', 'khanacademy.org kastatic.org'],
  ['wikipedia', 'Wikipedia', '📖', 'lernen', 'wikipedia.org wikimedia.org wiktionary.org', '', 'analytics.wikimedia.org intake-analytics.wikimedia.org intake-logging.wikimedia.org piwik.wikimedia.org'],
  ['woerterbuch', 'Wörterbücher', '🔤', 'lernen', 'leo.org dict.cc pons.com', 'LEO, dict.cc & PONS', 'advert.leo.org'],
  ['kindersuche', 'Kindersuche', '🔦', 'lernen', 'fragfinn.de blinde-kuh.de helles-koepfchen.de', 'Kinder-Suchmaschinen (fragFINN, Blinde Kuh)', 'matomo.fragfinn.de'],
  ['scratch', 'Scratch', '🐱', 'lernen', 'scratch.mit.edu', '', 'telemetry.scratch.mit.edu'],

  // ── Finanzen, Behörden & Gesundheit (geschützt) ───────────────────────────
  ['bezahlen', 'Bezahldienste', '💳', 'finanzen', 'paypal.com paypalobjects.com paypal.me stripe.com stripe.network klarna.com adyen.com mollie.com cardinalcommerce.com arcot.com 3dsecure.io', 'Bezahlen in Onlineshops samt Kartenfreigabe (3-D Secure)', 'sgtm.adyen.com'],
  ['sparkasse', 'Sparkasse', '🟥', 'finanzen', 'sparkasse.de starfinanz.de', 'Viele Sparkassen nutzen zusätzlich eine eigene Adresse (z. B. sparkasse-musterstadt.de) – die bei Bedarf als eigene Regel freigeben'],
  ['vrbank', 'VR-Banken', '🟧', 'finanzen', 'vr.de atruvia.de fiducia.de', 'Volks- & Raiffeisenbanken', 'edge.vr.de'],
  ['ing', 'ING', '🦁', 'finanzen', 'ing.de'],
  ['dkb', 'DKB', '🔹', 'finanzen', 'dkb.de'],
  ['commerzbank', 'Commerzbank', '🟡', 'finanzen', 'commerzbank.de commerzbank.com comdirect.de', 'Commerzbank & comdirect'],
  ['deutschebank', 'Deutsche Bank', '🏦', 'finanzen', 'deutsche-bank.de db.com postbank.de norisbank.de', 'Deutsche Bank, Postbank & norisbank', 'ads.db.com mit.db.com aa.norisbank.de at.norisbank.de edge.norisbank.de'],
  ['hypovereinsbank', 'HypoVereinsbank', '🔴', 'finanzen', 'hypovereinsbank.de unicredit.de', '', 'sucmetrics.hypovereinsbank.de'],
  ['consorsbank', 'Consorsbank & Co.', '🏛️', 'finanzen', 'consorsbank.de santander.de targobank.de', 'Consorsbank, Santander & Targobank'],
  ['n26', 'N26', '◼️', 'finanzen', 'n26.com tech26.de number26.de'],
  ['c24', 'C24, Revolut, Wise', '💠', 'finanzen', 'c24.de revolut.com wise.com transferwise.com', 'C24 & Revolut & Wise', 'sentry.c24.de statistics.c24.de growth-performance.revolut.com gtm.wise.com sst.wise.com ablink.info.wise.com'],
  ['traderepublic', 'Trade Republic', '📊', 'finanzen', 'traderepublic.com scalable.capital', 'Trade Republic & Scalable', 'sst.de.scalable.capital sentry.traderepublic.com'],
  ['krypto', 'Krypto-Börsen', '🪙', 'finanzen', 'coinbase.com bitpanda.com binance.com kraken.com coinmarketcap.com', 'Krypto-Börsen (Coinbase, Bitpanda, Binance, Kraken)', 'cca-lite.coinbase.com fdt.kraken.com'],
  ['behoerden', 'ELSTER & Behörden', '🦅', 'finanzen', 'elster.de bund.de bayern.de bayernportal.de', '', 'piwik.bayern.de matomo.warnung.bund.de'],
  ['gesundheit', 'Gesundheit', '🏥', 'finanzen', 'doctolib.de tk.de aok.de barmer.de dak.de gematik.de', 'Gesundheit (Doctolib, Krankenkassen, E-Rezept)', 'mail-analytics.by.aok.de mail-analytics.plus.aok.de sentry.bconnect.barmer.de events-logs.doctolib.de metrics.doctolib.de crashreporter.tk.de tk-babyzeit-matomo.tk.de tk-doc-matomo.tk.de'],

  // ── Reisen & Mobilität ───────────────────────────────────────────────────
  ['bahn', 'Deutsche Bahn', '🚆', 'reisen', 'bahn.de bahn.com'],
  ['nahverkehr', 'MVV & MVG', '🚋', 'reisen', 'mvv-muenchen.de mvg.de'],
  ['flixbus', 'FlixBus', '🚌', 'reisen', 'flixbus.de flixbus.com'],
  ['lufthansa', 'Lufthansa', '✈️', 'reisen', 'lufthansa.com eurowings.com', 'Lufthansa & Eurowings'],
  ['billigflieger', 'Ryanair & easyJet', '🛫', 'reisen', 'ryanair.com easyjet.com'],
  ['booking', 'Booking.com', '🏨', 'reisen', 'booking.com bstatic.com'],
  ['airbnb', 'Airbnb', '🏠', 'reisen', 'airbnb.de airbnb.com muscache.com'],
  ['tripadvisor', 'Tripadvisor & TUI', '🏖️', 'reisen', 'tripadvisor.de tripadvisor.com tacdn.com tui.com'],
  ['googlemaps', 'Google Maps', '🗺️', 'reisen', 'maps.google.com maps.googleapis.com maps.gstatic.com'],
  ['fahrdienste', 'Fahrdienste', '🚕', 'reisen', 'uber.com bolt.eu free-now.com', 'Uber, Bolt & FREENOW'],
  ['mietwagen', 'Sixt & Europcar', '🚙', 'reisen', 'sixt.de sixt.com europcar.de'],
  ['adac', 'ADAC', '🛟', 'reisen', 'adac.de'],
  ['komoot', 'Komoot', '🥾', 'reisen', 'komoot.de komoot.com'],
  ['tesla', 'Tesla', '⚡', 'reisen', 'tesla.com teslamotors.com'],

  // ── Telefon & Internet ───────────────────────────────────────────────────
  ['vodafone', 'Vodafone', '🔴', 'telko', 'vodafone.de vodafone.com'],
  ['telekom', 'Telekom', '🩷', 'telko', 'telekom.de telekom.com t-mobile.de'],
  ['o2', 'O2 / Telefónica', '🔵', 'telko', 'o2online.de telefonica.de'],
  ['einsundeins', '1&1', '1️⃣', 'telko', '1und1.de 1und1.net'],
  ['discounter', 'congstar & Co.', '📱', 'telko', 'congstar.de alditalk.de', 'congstar & ALDI TALK'],
  ['sipgate', 'sipgate & CLINQ', '☎️', 'telko', 'sipgate.de sipgate.com sipgate.net clinq.com'],

  // ── Dating (zum Sperren im Kinder-Profil) ─────────────────────────────────
  ['tinder', 'Tinder', '🔥', 'dating', 'tinder.com gotinder.com'],
  ['bumble', 'Bumble & Badoo', '🐝', 'dating', 'bumble.com badoo.com'],
  ['lovoo', 'LOVOO', '💜', 'dating', 'lovoo.com'],
  ['parship', 'Parship', '💞', 'dating', 'parship.de elitepartner.de', 'Parship & ElitePartner'],
  ['hinge', 'Hinge & OkCupid', '💌', 'dating', 'hinge.co okcupid.com'],
  ['grindr', 'Grindr', '🟡', 'dating', 'grindr.com'],

  // ── VPN & Umgehung (zum Sperren im Kinder-Profil – sonst wird der Filter einfach umgangen) ──
  ['nordvpn', 'NordVPN & Surfshark', '🧭', 'vpn', 'nordvpn.com surfshark.com'],
  ['protonvpn', 'Proton VPN', '🛰️', 'vpn', 'protonvpn.com protonvpn.net'],
  ['expressvpn', 'ExpressVPN', '🚀', 'vpn', 'expressvpn.com cyberghostvpn.com', 'ExpressVPN & CyberGhost'],
  ['mullvad', 'Weitere VPNs', '🐻', 'vpn', 'mullvad.net windscribe.com tunnelbear.com hide.me', 'Mullvad, Windscribe & TunnelBear'],
  ['warp', 'Cloudflare WARP', '🟠', 'vpn', 'cloudflareclient.com one.one.one.one', 'Cloudflare WARP (1.1.1.1-App)'],
  ['tor', 'Tor & Psiphon', '🧅', 'vpn', 'torproject.org psiphon.ca psiphon3.com'],
  ['webproxys', 'Web-Proxys', '🕳️', 'vpn', 'croxyproxy.com proxysite.com hidester.com kproxy.com', 'Web-Proxys (CroxyProxy, ProxySite …)'],

  // ── Smart Home & Geräte (geschützt) ───────────────────────────────────────
  ['alexa', 'Alexa & Echo', '🔵', 'smarthome', 'amazonalexa.com alexa.amazon.de alexa.amazon.com', 'Amazon Alexa & Echo'],
  ['googlehome', 'Google Home & Nest', '🏠', 'smarthome', 'nest.com home.google.com'],
  ['hue', 'Philips Hue & WiZ', '💡', 'smarthome', 'meethue.com philips-hue.com wiz.world wizconnected.com', '', 'data.info.philips-hue.com smetrics.marketing.philips-hue.com'],
  ['tuya', 'Tuya / Smart Life', '🔌', 'smarthome', 'tuya.com tuyaeu.com tuyaus.com tuyacn.com', '', 'sentry.tuyaeu.com sentry.tuyaus.com'],
  ['shelly', 'Shelly', '🔲', 'smarthome', 'shelly.cloud shelly.com', '', 'trk.shelly.cloud'],
  ['tado', 'Heizung & Zentrale', '🌡️', 'smarthome', 'tado.com homematic.com bosch-smarthome.com', 'tado°, Homematic IP & Bosch Smart Home', 'sst.tado.com'],
  ['avm', 'FRITZ!Box', '📡', 'smarthome', 'avm.de myfritz.net', 'FRITZ!Box & MyFRITZ', 'piwik.avm.de track.avm.de'],
  ['unifi', 'UniFi (Ubiquiti)', '🛜', 'smarthome', 'ui.com ubnt.com', '', 'trace.svc.ui.com'],
  ['nas', 'NAS-Hersteller', '🗄️', 'smarthome', 'ugnas.com ug.link synology.com quickconnect.to qnap.com myqnapcloud.com', 'NAS (UGREEN, Synology, QNAP)', 'analytics.api.myqnapcloud.com qcenter-metrics-device.api.myqnapcloud.com sentry.monitoring.ugnas.com'],
  ['saugroboter', 'Saugroboter', '🤖', 'smarthome', 'roborock.com ecovacs.com irobot.com', 'Saugroboter (Roborock, Ecovacs, iRobot)', 'metrics.store.irobot.com'],
  ['sonos', 'Sonos', '🔊', 'smarthome', 'sonos.com', '', 'crash-upload.ws.sonos.com msmetrics.ws.sonos.com analytics.sonos.com click.email.sonos.com'],
  ['kameras', 'Kameras & Klingel', '🚪', 'smarthome', 'ring.com eufylife.com reolink.com', 'Ring, Eufy & Reolink', 'log.eufylife.com crashtracking.prod.ring.com'],
  ['drucker', 'Drucker', '🖨️', 'smarthome', 'brother.com hp.com hpsmart.com hpconnected.com epson.com epsonconnect.com', 'Drucker (Brother, HP, Epson)', 'avatar.ext.hp.com met2.hp.com'],
  ['wearables', 'Uhren & Tracker', '⌚', 'smarthome', 'garmin.com fitbit.com withings.com withings.net polar.com', 'Garmin, Fitbit, Withings & Polar', 'web-metrics.fitbit.com matomo.garmin.com'],
  ['huawei', 'Huawei Health', '🌸', 'smarthome', 'dbankcloud.com dbankcloud.eu hicloud.com', 'Huawei-Uhren und -Handys finden darüber ihre Server (Abgleich von Gesundheits- und Sportdaten)', 'dt.dbankcloud.com op.dbankcloud.com logservice*.dbankcloud.com logservice*.platform.dbankcloud.com dt.hicloud.com op.hicloud.com data.hicloud.com logservice*.platform.hicloud.com logservice*.hicloud.com logbak.hicloud.com'],
  ['xiaomihome', 'Xiaomi Home', '🟠', 'smarthome', 'io.mi.com home.mi.com'],
  ['eingabegeraete', 'Elgato & Logitech', '🎛️', 'smarthome', 'elgato.com logitech.com logi.com logitech.io', '', 'webanalytics.logitech.com webtags.logitech.com'],

  // ── Geräte & System (immer geschützt lassen) ─────────────────────────────
  // Betreiber-Vorgabe 21.09.2026: gilt für ALLE Smart-TVs. Domains je Hersteller aus den „SmartTV“-Sperrlisten (Perflyst, hkamran80)
  // abgeleitet – genau das, was solche Listen sperren würden; Werbung, Sehverhaltens-Erkennung (ACR) und Nutzungsstatistik bleiben Ausnahmen.
  ['smarttv', 'Smart-TV-Grundfunktionen', '🖥️', 'system',
    'samsungcloudsolution.com samsungcloudsolution.net samsungqbe.com samsungcloud.tv samsungcloudcdn.com samsungapps.com samsungotn.net samsungnyc.com samsungconsent.com internetat.tv samsungrm.net pavv.co.kr'
    + ' lgtvsdp.com lgappstv.com nextlgsdp.com lgtvcommon.com ngfts.lge.com aic-ngfts.lge.com snu.lge.com lgtvonline.lge.com'
    + ' ndmdhs.com internet.sony.tv bravia.dl.playstation.net myhomescreen.tv vieraconnect.com hismarttv.com vidaa.com nettvservices.com tclclouds.com roku.com'
    + ' ntp-fireos.com fireoscaptiveportal.com arcus-uswest.amazon.com dp-gw-na.amazon.com dcape-na.amazon.com softwareupdates.amazon.com'
    + ' androidtvchannels-pa.googleapis.com androidtvlauncherxfe-pa.googleapis.com androidtvwatsonfe-pa.googleapis.com',
    'Alle Hersteller – Samsung, LG, Sony, Panasonic, Philips, Hisense, TCL, Roku, Fire TV, Android TV/Google TV: Verbindungsprüfung, Uhrzeit, Startbildschirm, App-Store, Firmware. Ohne meldet der Fernseher „kein Internet“ oder Apps starten nicht',
    'acr-*.samsungcloud.tv ureca.samsungapps.com log.internetat.tv ad.lgappstv.com ibis.lgappstv.com ibs.lgappstv.com rdx2.lgtvsdp.com cdpbeacon.lgtvcommon.com collect*.myhomescreen.tv usage*.myhomescreen.tv ad.nettvservices.com rdx2.nextlgsdp.com ad-cmp.hismarttv.com api-logsdk.hismarttv.com api-shoppingguider.hismarttv.com logapi*.bda.ndmdhs.com'
    + ' logs.roku.com acr.roku.com analytics.roku.com ads*.roku.com advertising*.roku.com adservices.roku.com delivery.roku.com bdp.roku.com rpay.roku.com rpay.int.roku.com ap.int.roku.com msc.roku.com sr.roku.com web.roku.com data.roku.com'],
  ['lgkonto', 'LG-Konto & ThinQ', '📲', 'system', 'lgthinq.com lgeapi.com lgaccount.com', 'Anmeldung am LG-Konto und ThinQ-App (Fernseher und Hausgeräte per Handy bedienen)'],
  // Fall 19.09.2026: „SmartTV“-Sperrlisten sperrten gld.push.samsungosp.com (Fernseher) und auth2.samsungosp.com (Handy) →
  // Fernseher ließ sich nicht mehr per SmartThings bedienen. Domains aus dem Protokoll von Fernseher und Handy abgeleitet.
  ['samsungkonto', 'Samsung-Konto & SmartThings', '📲', 'system', 'samsungosp.com account.samsung.com smartthings.com samsungiotcloud.com samsungcloud.com aibixby.com', 'Anmeldung am Samsung-Konto, SmartThings (Fernseher und Geräte per Handy bedienen), Samsung Cloud, Bixby'],
  ['verbindung', 'Internet-Verbindungsprüfung', '📶', 'system', 'connectivitycheck.gstatic.com connectivitycheck.android.com clients3.google.com captive.apple.com msftconnecttest.com msftncsi.com detectportal.firefox.com connectivity-check.ubuntu.com nmcheck.gnome.org network-test.debian.org cp.cloudflare.com', 'Android, Apple, Windows, Linux und Firefox prüfen damit, ob Internet da ist'],
  ['zeitserver', 'Uhrzeit (NTP)', '🕒', 'system', 'pool.ntp.org ntp.org time.apple.com time.windows.com time.google.com time.akamai.com time.cloudflare.com time.nist.gov ntp.ubuntu.com', 'Falsche Uhrzeit = keine gültigen Zertifikate, dann geht fast nichts mehr'],
  ['push', 'Push-Benachrichtigungen', '🔔', 'system', 'push.apple.com mtalk.google.com notify.windows.com wns.windows.com fcm.googleapis.com push.services.mozilla.com ntfy.sh', 'Ohne diese Dienste kommen keine Benachrichtigungen auf Handys'],
  ['updates', 'System-Updates', '⬇️', 'system', 'windowsupdate.com update.microsoft.com delivery.mp.microsoft.com mesu.apple.com gs.apple.com swcdn.apple.com', 'Sicherheitsupdates für Windows, macOS und iOS'],
  ['captcha', 'Bot-Schutz (Captcha)', '🧪', 'system', 'recaptcha.net hcaptcha.com challenges.cloudflare.com arkoselabs.com funcaptcha.com awswaf.com', 'Ohne Captcha lassen sich viele Formulare nicht absenden'],
  ['drm', 'Kopierschutz (DRM)', '🔐', 'system', 'widevine.com', 'Widevine – nötig für Streams in Apps und Browsern'],
  ['apple', 'Apple-Geräte', '🍎', 'system', 'apps.apple.com appleid.apple.com idmsa.apple.com gsa.apple.com identity.apple.com albert.apple.com configuration.apple.com ocsp.apple.com ocsp2.apple.com valid.apple.com ls.apple.com smoot.apple.com cdn-apple.com apple-dns.net safebrowsing.apple',
    'Grundfunktionen von iPhone, iPad, Mac und Apple TV: Anmeldung, Aktivierung, App Store, Karten, Zertifikatsprüfung. Bewusst nicht ganz apple.com – darunter liegen auch Werbe- und Mess-Adressen',
    'feedbackws.fe.apple-dns.net feedbackws.fe2.apple-dns.net books-analytics-events.news.apple-dns.net notes-analytics-events.news.apple-dns.net stocks-analytics-events.news.apple-dns.net weather-analytics-events.news.apple-dns.net'],
  ['android', 'Android & Play', '🤖', 'system', 'play.google.com play.googleapis.com android.clients.google.com android.googleapis.com gvt1.com', 'App-Installation und Updates auf Android-Handys, Tablets und Android TV'],
  ['msanmeldung', 'Microsoft-Konto', '🪟', 'system', 'login.live.com login.microsoft.com account.microsoft.com msauth.net msftauth.net msidentity.com', 'Anmeldung an Windows, Office, Xbox und Minecraft'],
  ['linux', 'Linux-Paketquellen', '🐧', 'system', 'ubuntu.com debian.org archlinux.org fedoraproject.org raspberrypi.com raspbian.org', 'Updates für Linux-Rechner, Raspberry Pi und viele Docker-Images', 'errors.ubuntu.com metrics.ubuntu.com'],
  ['zertifikate', 'Zertifikatsprüfung', '📜', 'system', 'lencr.org letsencrypt.org digicert.com pki.goog globalsign.com sectigo.com usertrust.com identrust.com', 'Geräte prüfen damit, ob ein Sicherheitszertifikat noch gültig ist – ohne schlagen verschlüsselte Verbindungen fehl', 'media.globalsign.com'],
  ['wlantelefonie', 'WLAN-Telefonie', '📶', 'system', '3gppnetwork.org telephony.goog', 'Telefonieren über WLAN (VoWiFi) und Chat-Nachrichten des Mobilfunkanbieters'],
  ['cookiebanner', 'Cookie-Banner', '🍪', 'system', 'usercentrics.eu cookiebot.com consentmanager.net onetrust.com cookielaw.org privacy-center.org privacy-mgmt.com didomi.io', 'Ist das Banner gesperrt, bleiben viele Seiten leer oder lassen sich nicht bedienen', 'analytics.consentmanager.net imgsct.cookiebot.com privacy-analytics-proxy.cookiebot.com sst.cookiebot.com analytics.didomi.io history-logs.didomi.io metrics.didomi.io smetrics.onetrust.com'],
];

// Hilfsangebote aus src/daten/kinderschutz.js
ROH.push(...require('./daten/kinderschutz').HILFE.map(([id, name, symbol, domains, hinweis]) => [id, name, symbol, 'hilfe', domains, hinweis]));

const VORGABE = Object.fromEntries(GRUPPEN.map((g) => [g.id, g.vorgabe]));
const FEST = new Set(GRUPPEN.filter((g) => g.fest).map((g) => g.id));
// Einzelne Dienste mit eigener Vorgabe, abweichend von ihrer Rubrik (Betreiber-Vorgabe 15.11.2026: Pokémon GO und PokeRaid sind ab Werk für alle Geräte frei)
const EIGENE_VORGABE = { pokemongo: 'frei', pokeraid: 'frei' };
const DIENSTE = ROH.map(([id, name, symbol, gruppe, domains, hinweis, ausser, mitbenutzt]) => ({ id, name, symbol, gruppe, ...(FEST.has(gruppe) ? { fest: true } : {}), ...(EIGENE_VORGABE[id] === 'frei' && VORGABE[gruppe] !== 'frei' ? { einzelnFrei: true } : {}), vorgabe: EIGENE_VORGABE[id] || VORGABE[gruppe] || 'listen', domains: domains.split(' '), ...(hinweis ? { hinweis } : {}), ...(ausser ? { ausser: ausser.split(' ') } : {}), ...(mitbenutzt ? { mitbenutzt: mitbenutzt.split(' ') } : {}) }));

// Domain-Endung → Dienst
function index(dienste = DIENSTE) {
  const m = new Map();
  for (const d of dienste) for (const dom of d.domains) m.set(dom, d);
  return m;
}

// Ausnahmen aller Dienste: für diese Domains (samt Subdomains) gilt der Dienst NICHT, die Listen entscheiden.
// „vor*.domain“ trifft jeden Host, dessen Name direkt vor „domain“ mit „vor“ beginnt (acr-*.samsungcloud.tv → acr-eu-prd.…).
function ausnahmen(dienste = DIENSTE) {
  const genau = new Set(), vorsilben = new Map();
  for (const a of dienste.flatMap((d) => d.ausser || [])) {
    const stern = a.indexOf('*.');
    if (stern < 0) { genau.add(a); continue; }
    const rest = a.slice(stern + 2), liste = vorsilben.get(rest) || [];
    liste.push(a.slice(0, stern)); vorsilben.set(rest, liste);
  }
  return {
    genau, vorsilben,
    trifft(domain) {
      const teile = domain.split('.');
      for (let i = 0; i < teile.length; i++) {
        const s = teile.slice(i).join('.');
        if (genau.has(s)) return true;
        if (i > 0 && vorsilben.get(s)?.some((v) => teile[i - 1].startsWith(v))) return true;
      }
      return false;
    },
  };
}

// Zustand eines Dienstes: aus den Einstellungen, sonst die Vorgabe der Rubrik
function modusVon(dienst, einstellungen = {}) {
  if (dienst.fest) return { modus: 'frei', geltung: 'alle' };
  const e = einstellungen[dienst.id];
  if (!e) return { modus: dienst.vorgabe, geltung: 'alle' };
  if (e.gesperrt) return { modus: 'sperren', geltung: e.geltung || 'alle' };   // ältere Einstellungen
  return { modus: e.modus === 'frei' || e.modus === 'listen' || e.modus === 'sperren' ? e.modus : dienst.vorgabe, geltung: e.geltung || 'alle' };
}

module.exports = { DIENSTE, GRUPPEN, index, ausnahmen, modusVon };
