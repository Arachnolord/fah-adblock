// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Was ist diese Domain? Eigene, handgepflegte Wissensdatenbank (keine fremden Datensätze – deren
// Lizenzen erlauben die Weitergabe meist nicht) plus Schlüsselwörter im Namen („telemetry“, „logs“ …).
// Läuft im Browser (window.DomainInfo) und in Node (require) – ohne Netz, ohne Abhängigkeiten.
(function (wurzel) {
  'use strict';
  // Domain-Endung(en) | Anbieter | was die Domain macht | Hinweis (optional). Gilt inkl. Subdomains;
  // der genaueste Eintrag gewinnt, fehlende Felder erbt er von der übergeordneten Domain.
  const DATEN = `
google.com,google.de|Google||
googleapis.com|Google|Schnittstellen für Google-Dienste und Apps|
gstatic.com|Google|Skripte, Schriften und Bilder für Google-Dienste|
connectivitycheck.gstatic.com|Google Android|prüft, ob das Internet erreichbar ist|nicht sperren – sonst meldet Android „kein Internet“
mtalk.google.com|Google Android|Push-Benachrichtigungen (Firebase Cloud Messaging)|nicht sperren – sonst kommen keine App-Benachrichtigungen
googleusercontent.com|Google|von Nutzern hochgeladene Inhalte und App-Daten|
gvt1.com,gvt2.com|Google|Downloads und Updates (Chrome, Android)|
doubleclick.net|Google Marketing Platform (DoubleClick)|Werbenetzwerk: Anzeigen ausliefern, Klicks und Käufe messen|
2mdn.net|Google Marketing Platform|Werbemittel ausliefern (Banner, Videoanzeigen)|
googleadservices.com|Google Ads|misst Klicks auf Google-Anzeigen und anschließende Käufe (Conversion-Tracking)|Sperre kann Klicks auf Anzeigen in der Google-Suche ins Leere laufen lassen
adservice.google.com,adservice.google.de|Google Ads|Anzeigenauswahl und Werbemessung|
googlesyndication.com|Google AdSense|Werbebanner auf fremden Webseiten|
googletagservices.com|Google Ad Manager|Skripte für Werbeplätze auf Webseiten|
googletagmanager.com|Google Tag Manager|lädt Tracking- und Statistik-Skripte auf Webseiten|selten: einzelne Seiten oder Formulare funktionieren ohne nicht
google-analytics.com,analytics.google.com|Google Analytics|Besucherstatistik von Webseiten und Apps|
app-measurement.com|Google Analytics for Firebase|Nutzungsstatistik aus Apps|
firebaselogging-pa.googleapis.com|Google Firebase|Nutzungs- und Fehlerdaten aus Apps|
crashlytics.com|Firebase Crashlytics (Google)|Absturzberichte aus Apps|
fundingchoicesmessages.google.com|Google Funding Choices|Cookie-Einwilligungsbanner auf Webseiten|
imasdk.googleapis.com|Google IMA SDK|Videowerbung in Playern und Apps|
admob.com|Google AdMob|Werbung in Apps|
recaptcha.net|Google reCAPTCHA|Bot-Schutz in Formularen|nicht sperren – sonst lassen sich Formulare nicht absenden
use-application-dns.net|Firefox (Prüf-Domain)|Firefox fragt, ob es sein eigenes verschlüsseltes DNS abschalten soll – FAH-Adblock antwortet absichtlich „gibt es nicht“, damit Firefox gefiltert bleibt|
dns.google|Google Public DNS|DNS-Auflösung (8.8.8.8), auch verschlüsselt|Geräte können darüber am Blocker vorbei auflösen
youtube.com|YouTube (Google)|Videoplattform|
s.youtube.com|YouTube (Google)|Wiedergabestatistik: was wie lange angesehen wurde|
ytimg.com|YouTube (Google)|Vorschaubilder und Skripte|
googlevideo.com|YouTube (Google)|Videostreams|nicht sperren – sonst laufen YouTube-Videos nicht
play.googleapis.com|Google Play|Play-Dienste auf Android-Geräten|

microsoft.com|Microsoft||
data.microsoft.com|Microsoft|Telemetrie: Nutzungs- und Diagnosedaten|
events.data.microsoft.com|Microsoft|Telemetrie: Nutzungs- und Diagnosedaten (Windows, Office, Teams, Edge)|
teams.events.data.microsoft.com,eu-teams.events.data.microsoft.com|Microsoft Teams|Telemetrie: Nutzungs- und Diagnosedaten der Teams-App|
mobile.events.data.microsoft.com|Microsoft (Handy-Apps)|Telemetrie aus Microsoft-Apps auf dem Handy|
vortex.data.microsoft.com|Windows|Telemetrie: Diagnosedaten von Windows|
settings-win.data.microsoft.com|Windows|lädt Einstellungen für Telemetrie und Funktionen|Sperre kann einzelne Windows-Funktionen stören
telemetry.microsoft.com|Microsoft|Telemetrie|
watson.telemetry.microsoft.com|Windows-Fehlerberichterstattung|Absturz- und Fehlerberichte an Microsoft|
aria.microsoft.com|Microsoft|Telemetrie (Aria-Analyse)|
smartscreen.microsoft.com|Microsoft Defender SmartScreen|prüft Downloads und Webseiten auf Schadsoftware|nicht sperren – schützt vor Schadsoftware
update.microsoft.com,windowsupdate.com|Windows Update|Updates für Windows|nicht sperren – sonst keine Sicherheitsupdates
delivery.mp.microsoft.com|Windows Update / Microsoft Store|Download von Updates und Apps|nicht sperren – sonst keine Updates
msftconnecttest.com,msftncsi.com|Windows|prüft, ob das Internet erreichbar ist|nicht sperren – sonst meldet Windows „kein Internet“
notify.windows.com|Windows|Push-Benachrichtigungen (Windows Notification Service)|
windows.net|Microsoft Azure|Cloud-Speicher und -Dienste vieler Firmen|
azureedge.net,azurefd.net|Microsoft Azure|Auslieferung von Inhalten (CDN)|
trafficmanager.net|Microsoft Azure|Lastverteilung für Cloud-Dienste|
live.com|Microsoft|Microsoft-Konto, Outlook.com, OneDrive|
officeapps.live.com|Microsoft Office|Office-Onlinedienste (Dokumente, Vorlagen, Einstellungen)|
office.com|Microsoft 365||
office.net|Microsoft 365|Inhalte für Office-Apps (CDN)|
ecs.office.com|Microsoft 365|Funktionsschalter und Einstellungen für Office und Teams|nicht sperren – Teams/Office starten sonst unzuverlässig
teams.microsoft.com|Microsoft Teams|Teams-Dienst|nicht sperren
microsoftonline.com|Microsoft Entra ID|Anmeldung mit Microsoft-/Firmenkonto|nicht sperren – sonst keine Anmeldung bei Microsoft 365
sharepoint.com|Microsoft SharePoint / OneDrive|Dateiablage von Microsoft 365|
onedrive.com,1drv.com|Microsoft OneDrive|Cloud-Speicher|
msn.com|MSN (Microsoft)|Nachrichtenportal, Startseite von Edge und Windows-Widgets|
browser.events.data.msn.com|Microsoft Edge / MSN|Nutzungsdaten von Edge-Startseite und Widgets|
bing.com|Bing (Microsoft)|Suchmaschine|
bat.bing.com|Microsoft Advertising|misst Anzeigenklicks und Käufe (UET-Tag)|
clarity.ms|Microsoft Clarity|zeichnet Klicks und Mausbewegungen auf Webseiten auf (Heatmaps, Sitzungswiedergabe)|
appcenter.ms|Visual Studio App Center (Microsoft)|Absturzberichte und Nutzungsstatistik aus Apps|
xboxlive.com|Xbox (Microsoft)|Xbox-Netzwerkdienste|
skype.com|Microsoft Teams|Anrufaufbau und Konfiguration von Teams (früher Skype)|nicht sperren
linkedin.com|LinkedIn (Microsoft)||
licdn.com|LinkedIn|Bilder und Skripte (CDN)|
px.ads.linkedin.com|LinkedIn Ads|misst Werbeanzeigen (Insight Tag)|
snap.licdn.com|LinkedIn Insight Tag|Besucher-Tracking für LinkedIn-Werbung|

apple.com|Apple||
icloud.com|Apple iCloud||
mzstatic.com|Apple|Inhalte für App Store und iTunes|
aaplimg.com|Apple|Auslieferung von Inhalten (CDN)|
apple-dns.net|Apple|Lastverteilung der Apple-Dienste|
xp.apple.com|Apple|Nutzungs- und Diagnosedaten (Analyse)|
metrics.icloud.com|Apple iCloud|Nutzungsstatistik|
iadsdk.apple.com|Apple Search Ads|misst Werbung im App Store|
api-adservices.apple.com|Apple Search Ads|ordnet App-Installationen der Werbung zu|
captive.apple.com|Apple|prüft, ob das Internet erreichbar ist (WLAN-Anmeldeseiten)|nicht sperren – sonst meldet das Gerät „kein Internet“
push.apple.com|Apple Push|Push-Benachrichtigungen für iPhone, iPad und Mac|nicht sperren – sonst kommen keine Benachrichtigungen
gs.apple.com,mesu.apple.com|Apple|Software-Updates (iOS, macOS)|nicht sperren – sonst keine Updates

amazon.com,amazon.de|Amazon||
media-amazon.com|Amazon|Bilder und Inhalte des Shops|
amazon-adsystem.com|Amazon Ads|Werbenetzwerk von Amazon (Anzeigen auf Webseiten, in Apps und auf Fire TV)|
device-metrics-us.amazon.com,device-metrics-us-2.amazon.com|Amazon (Echo, Fire TV, Kindle)|Nutzungs- und Diagnosedaten der Geräte|
unagi.amazon.com,unagi.amazon.de,unagi-eu.amazon.com|Amazon|Nutzungsdaten von Webseite und Apps|
fls-eu.amazon.de,fls-eu.amazon.com,fls-na.amazon.com|Amazon|Nutzungs- und Leistungsdaten von Webseite und Apps|
amazonaws.com|Amazon Web Services (AWS)|Cloud-Server – dahinter stecken viele verschiedene Firmen|
cloudfront.net|Amazon CloudFront|Auslieferung von Inhalten (CDN) für viele Webseiten|
primevideo.com,amazonvideo.com,aiv-cdn.net|Amazon Prime Video|Videostreaming|

facebook.com|Facebook (Meta)||
meta.com|Meta||
facebook.net|Meta|Skripte von Facebook auf fremden Webseiten|
connect.facebook.net|Meta Pixel / Facebook SDK|Tracking von Webseiten-Besuchen für Facebook-Werbung, „Mit Facebook anmelden“|Sperre kann „Mit Facebook anmelden“ stören
graph.facebook.com|Facebook|Schnittstelle für Apps: Anmeldung, Teilen, App-Statistik|Sperre kann Facebook- und Instagram-Funktionen in Apps stören
an.facebook.com|Meta Audience Network|Werbung in fremden Apps|
fbcdn.net|Meta|Bilder und Videos von Facebook und Instagram|nicht sperren – sonst laden Bilder in Facebook/Instagram nicht
fbsbx.com|Meta|Dateien und Anhänge (Messenger)|
instagram.com|Instagram (Meta)||
cdninstagram.com|Instagram (Meta)|Bilder und Videos|
whatsapp.com,whatsapp.net|WhatsApp (Meta)|Messenger|nicht sperren

tiktok.com|TikTok||
analytics.tiktok.com|TikTok Pixel|Tracking von Webseiten-Besuchen für TikTok-Werbung|
ads.tiktok.com|TikTok Ads|Werbeplattform von TikTok|
tiktokv.com|TikTok|App-Schnittstellen und Videos|
tiktokcdn.com,ibytedtos.com|TikTok (ByteDance)|Videos und Bilder (CDN)|
byteoversea.com|ByteDance (TikTok)|Schnittstellen und Protokolldaten der TikTok-Apps|
pangle.io,pangleglobal.com|Pangle (ByteDance)|Werbenetzwerk in Apps|
twitter.com,x.com|X (Twitter)||
twimg.com|X (Twitter)|Bilder und Videos|
t.co|X (Twitter)|Kurzlinks aus Beiträgen|Sperre bricht Links aus X/Twitter
ads-twitter.com|X Ads|Tracking-Pixel für X/Twitter-Werbung|
analytics.twitter.com|X (Twitter)|misst Werbeanzeigen|
pinterest.com|Pinterest||
ct.pinterest.com|Pinterest Tag|Tracking für Pinterest-Werbung|
snapchat.com|Snapchat||
tr.snapchat.com|Snap Pixel|Tracking für Snapchat-Werbung|
sc-static.net|Snapchat|Skripte, u. a. das Snap Pixel|
reddit.com|Reddit||
redditstatic.com|Reddit|Skripte und Bilder|
alb.reddit.com|Reddit Ads|Tracking-Pixel für Reddit-Werbung|
discord.com,discordapp.com,discord.gg|Discord|Chat und Sprachkanäle|
telegram.org|Telegram|Messenger|
signal.org|Signal|Messenger|

netflix.com|Netflix||
ichnaea.netflix.com|Netflix|Nutzungs- und Wiedergabedaten|
nflxvideo.net|Netflix|Videostreams|nicht sperren – sonst läuft Netflix nicht
nflxext.com,nflximg.net,nflxso.net|Netflix|Bilder und Skripte|
spotify.com|Spotify||
scdn.co|Spotify|Musik und Bilder (CDN)|
spclient.wg.spotify.com|Spotify|Schnittstelle der App|nicht sperren – sonst funktioniert Spotify nicht
adeventtracker.spotify.com|Spotify|misst Werbung in Spotify Free|
plex.tv|Plex|Mediaserver: Anmeldung und Verbindungsaufbau|nicht sperren – sonst funktioniert Plex nicht
plex.direct|Plex|direkte, verschlüsselte Verbindung zum eigenen Plex-Server|nicht sperren – sonst funktioniert Plex nicht
waipu.tv|waipu.tv|Fernsehen über das Internet|nicht sperren
disneyplus.com,dssott.com,bamgrid.com|Disney+|Videostreaming|
dazn.com|DAZN|Sport-Streaming|
joyn.de|Joyn|Mediathek|
twitch.tv|Twitch|Live-Streaming|
ttvnw.net|Twitch|Videostreams|
fwmrm.net|FreeWheel (Comcast)|Videowerbung in Mediatheken und Streaming-Apps|
innovid.com|Innovid|Videowerbung und deren Messung|
spotxchange.com,spotx.tv|SpotX (Magnite)|Videowerbung|
springserve.com|SpringServe (Magnite)|Videowerbung auf Smart-TVs|
imrworldwide.com|Nielsen|Reichweitenmessung: wer schaut oder liest was|
scorecardresearch.com|comScore|Reichweitenmessung von Webseiten und Videos|
ioam.de,iocnt.net|INFOnline (IVW)|Reichweitenmessung deutscher Webseiten und Apps|

samsung.com|Samsung||
samsungads.com|Samsung Ads|Werbung auf Samsung-Fernsehern und -Handys|
samsungacr.com|Samsung ACR|erkennt, was auf dem Fernseher läuft (Automatic Content Recognition) – für Werbung|
samsungcloudsolution.com,samsungcloudsolution.net|Samsung|Cloud-Dienste der Smart-TVs (Verbindungsprüfung, Uhrzeit, Apps)|Sperre: Fernseher meldet „kein Internet“
samsungqbe.com|Samsung|Smart Hub und App-Store der Fernseher|Sperre: Apps und Smart Hub laden nicht
samsungosp.com|Samsung-Konto|Anmeldung am Samsung-Konto und Push-Kanal der Geräte|Sperre verhindert die Bedienung des Fernsehers per Handy (SmartThings)
smartthings.com,samsungiotcloud.com|SmartThings (Samsung)|Fernseher und Hausgeräte per Handy bedienen|Sperre kann die Bedienung per Handy stören
samsungcloud.com|Samsung Cloud|Sicherung und Abgleich von Samsung-Geräten|
samsungcloud.tv|Samsung|Cloud-Dienste der Smart-TVs|
acr-eu-prd.samsungcloud.tv,acr-us-prd.samsungcloud.tv,acr-au-prd.samsungcloud.tv,acr-br-prd.samsungcloud.tv,acr-ca-prd.samsungcloud.tv,acr-in-prd.samsungcloud.tv,acr-kr-prd.samsungcloud.tv,acr-mx-prd.samsungcloud.tv,acr-nz-prd.samsungcloud.tv|Samsung ACR|meldet, was auf dem Fernseher läuft (Sehverhalten, für Werbung) – hat mit „Samsung Cloud“ nichts zu tun, der Fernseher läuft ohne|
aibixby.com|Samsung Bixby|Sprachassistent der Samsung-Geräte|
samsungotn.net|Samsung|Firmware-Updates für Smart-TVs|Sperre verhindert Updates des Fernsehers
lgtvsdp.com,nextlgsdp.com,lgtvcommon.com,lgappstv.com|LG|Dienste der LG-Smart-TVs (webOS): Startbildschirm, App-Store, Verbindungsprüfung|Sperre: Fernseher meldet „kein Internet“, Apps laden nicht
hismarttv.com,vidaa.com|Hisense (VIDAA)|Dienste der Hisense-Smart-TVs: Anmeldung, Startbildschirm, Updates|Sperre: Startbildschirm und Apps des Fernsehers laden nicht
ndmdhs.com,internet.sony.tv|Sony|Dienste der Sony-Bravia-Fernseher (Einrichtung, Updates)|
myhomescreen.tv|Panasonic|Startbildschirm und Apps der Panasonic-Fernseher|
nettvservices.com|Philips (TP Vision)|Smart-TV-Portal der Philips-Fernseher|
ntp-fireos.com,fireoscaptiveportal.com|Amazon Fire TV|Uhrzeit und Verbindungsprüfung von Fire TV und Echo|Sperre: Fire TV meldet „keine Verbindung“
dbankcloud.com,dbankcloud.eu,hicloud.com|Huawei|Huawei Mobile Services: Serversuche, Abgleich von Gesundheits- und Sportdaten|Sperre kann den Abgleich von Huawei-Uhren stören
lgsmartad.com|LG Ads|Werbung auf LG-Fernsehern|
xiaomi.com,miui.com|Xiaomi||
api.ad.xiaomi.com|Xiaomi|Werbung in MIUI/HyperOS|
data.mistat.xiaomi.com|Xiaomi|Nutzungsstatistik der Handys|
tracking.intl.miui.com|Xiaomi (MIUI)|Tracking von Nutzungsdaten|
hicloud.com|Huawei|Cloud-Dienste von Huawei|
metrics.data.hicloud.com|Huawei|Nutzungsstatistik|
nintendo.com|Nintendo||
nintendo.net|Nintendo|Online-Dienste der Switch|nicht sperren – sonst funktioniert die Switch online nicht
playstation.com,playstation.net,sonyentertainmentnetwork.com|PlayStation (Sony)|Online-Dienste der PlayStation|
ui.com|Ubiquiti (UniFi)|Dienste der UniFi-Geräte|nicht sperren
tplinkcloud.com|TP-Link|Cloud der Kasa-/Tapo-Geräte|
tuya.com,tuyaeu.com|Tuya|Cloud für Smart-Home-Geräte|
meethue.com|Philips Hue|Smart-Home-Beleuchtung|
sonos.com|Sonos|Lautsprecher-Dienste|
ring.com|Ring (Amazon)|Türklingeln und Kameras|

criteo.com,criteo.net|Criteo|personalisierte Werbung (Retargeting: zeigt zuletzt angesehene Produkte erneut)|
taboola.com|Taboola|Werbe- und „Das könnte Sie interessieren“-Artikel unter Nachrichten|
outbrain.com|Outbrain|Werbe- und „Das könnte Sie interessieren“-Artikel unter Nachrichten|
plista.com|plista|Empfehlungs- und Werbeartikel auf Nachrichtenseiten|
adnxs.com|Xandr (Microsoft)|Werbebörse: versteigert Werbeplätze in Echtzeit|
rubiconproject.com|Magnite|Werbebörse: versteigert Werbeplätze in Echtzeit|
pubmatic.com|PubMatic|Werbebörse: versteigert Werbeplätze in Echtzeit|
openx.net|OpenX|Werbebörse: versteigert Werbeplätze in Echtzeit|
casalemedia.com|Index Exchange|Werbebörse: versteigert Werbeplätze in Echtzeit|
bidswitch.net|BidSwitch|Vermittlung zwischen Werbebörsen|
3lift.com|TripleLift|Werbebörse für eingebettete Anzeigen|
lijit.com|Sovrn|Werbebörse|
360yield.com|Improve Digital|Werbebörse|
contextweb.com|PulsePoint|Werbebörse|
sharethrough.com|Sharethrough|Werbebörse für eingebettete Anzeigen|
media.net|Media.net|Kontextwerbung|
gumgum.com|GumGum|kontextbasierte Werbung|
seedtag.com|Seedtag|kontextbasierte Werbung|
smartadserver.com|Equativ (Smart AdServer)|Werbeserver und Werbebörse|
adform.net|Adform|Werbeplattform: Anzeigen ausliefern und messen|
adition.com|ADITION (Virtual Minds)|Werbeserver|
yieldlab.net|Yieldlab (Ströer)|Werbebörse|
yieldlove.com|Yieldlove|Werbevermarktung für Webseiten|
uimserv.net|United Internet Media|Werbung und Tracking (GMX, WEB.DE)|
teads.tv|Teads|Videowerbung in Artikeln|
adsrvr.org|The Trade Desk|Werbe-Einkaufsplattform (personalisierte Anzeigen)|
mathtag.com|MediaMath|Werbe-Einkaufsplattform (personalisierte Anzeigen)|
moatads.com|Moat (Oracle)|misst, ob Werbung gesehen wurde|
doubleverify.com|DoubleVerify|prüft und misst Werbeanzeigen|
adsafeprotected.com|Integral Ad Science|prüft und misst Werbeanzeigen|
meetrics.net|Meetrics|misst die Sichtbarkeit von Werbung|
quantserve.com|Quantcast|Besucher- und Zielgruppenmessung für Werbung|
rlcdn.com|LiveRamp|gleicht Nutzerprofile zwischen Werbefirmen ab|
crwdcntrl.net|Lotame|Datenplattform für Werbe-Zielgruppen|
id5-sync.com|ID5|Werbe-ID, um Nutzer ohne Cookies wiederzuerkennen|
theadex.com|The ADEX (Virtual Minds)|Datenplattform für Werbe-Zielgruppen|
emetriq.de|emetriq|Zielgruppendaten für Werbung|
xplosion.de|Xplosion|Zielgruppendaten für Werbung|
demdex.net|Adobe Audience Manager|Datenplattform für Werbe-Zielgruppen|
omtrdc.net,2o7.net|Adobe Analytics|Besucherstatistik großer Webseiten|
adobedtm.com|Adobe Experience Platform|lädt Tracking-Skripte auf Webseiten (Tag Manager)|
everesttech.net|Adobe Advertising|Werbemessung|
bluekai.com|Oracle BlueKai|Datenplattform für Werbe-Zielgruppen (eingestellt)|
addthis.com|AddThis (Oracle)|Teilen-Knöpfe mit Tracking (eingestellt)|
krxd.net|Salesforce (Krux)|Datenplattform für Werbe-Zielgruppen|
yahoo.com|Yahoo||
ads.yahoo.com|Yahoo Advertising|Werbeplattform|
analytics.yahoo.com|Yahoo|Werbemessung|
advertising.com|Yahoo Advertising (ehem. AOL)|Werbenetzwerk|
awin1.com,zanox.com|Awin|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten
tradedoubler.com|Tradedoubler|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten
belboon.com|belboon|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten
adcell.de|ADCELL|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten
financeads.net|financeAds|Partnerlinks für Finanzprodukte|Sperre bricht Links von Vergleichsseiten
linksynergy.com|Rakuten Advertising|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten
emjcd.com,dpbolvw.net,anrdoezrs.net|CJ Affiliate|Partnerlinks: Provision für Seiten, die auf Shops verlinken|Sperre bricht Links von Gutschein- und Vergleichsseiten

branch.io,app.link|Branch|Deeplinks und Zuordnung von App-Installationen zu Werbung|Sperre kann Links aus Mails und Apps brechen
adjust.com,adjust.io|Adjust|ordnet App-Installationen Werbekampagnen zu|
appsflyer.com|AppsFlyer|ordnet App-Installationen Werbekampagnen zu|
onelink.me|AppsFlyer|Deeplinks in Apps|Sperre kann Links aus Mails und Apps brechen
kochava.com|Kochava|ordnet App-Installationen Werbekampagnen zu|
singular.net|Singular|ordnet App-Installationen Werbekampagnen zu|
onesignal.com|OneSignal|Push-Benachrichtigungen für Apps und Webseiten|
braze.com,appboy.com|Braze|Marketing-Nachrichten in Apps und Nutzungsanalyse|
unity3d.com|Unity|Spiele-Engine|
unityads.unity3d.com|Unity Ads|Werbung in Spielen|
config.uca.cloud.unity3d.com,cdp.cloud.unity3d.com|Unity|Nutzungsstatistik von Spielen|
applovin.com,applvn.com|AppLovin|Werbung in Apps und Spielen|
supersonicads.com|ironSource (Unity)|Werbung in Spielen|
vungle.com|Vungle (Liftoff)|Videowerbung in Spielen|
chartboost.com|Chartboost|Werbung in Spielen|
inmobi.com|InMobi|Werbung in Apps|
mintegral.com,rayjump.com|Mintegral|Werbung in Apps|
startappservice.com|Start.io|Werbung und Datensammlung in Apps|

mixpanel.com|Mixpanel|Nutzungsanalyse von Apps und Webseiten: welche Funktionen genutzt werden|
segment.io,segment.com|Segment (Twilio)|sammelt Nutzungsdaten und verteilt sie an Analyse-Dienste|
amplitude.com|Amplitude|Nutzungsanalyse von Apps|
heapanalytics.com|Heap|Nutzungsanalyse: zeichnet Klicks auf|
hotjar.com,hotjar.io|Hotjar|zeichnet Klicks, Scrollen und Mausbewegungen auf (Heatmaps)|
mouseflow.com|Mouseflow|zeichnet Klicks, Scrollen und Mausbewegungen auf (Heatmaps)|
fullstory.com|FullStory|Sitzungsaufzeichnung: spielt nach, was Besucher auf einer Seite tun|
smartlook.com|Smartlook|Sitzungsaufzeichnung von Webseiten und Apps|
logrocket.com,lr-ingest.io|LogRocket|Sitzungsaufzeichnung und Fehleranalyse|
crazyegg.com|Crazy Egg|Heatmaps von Webseiten|
statcounter.com|StatCounter|Besucherstatistik|
etracker.com,etracker.de|etracker|Besucherstatistik (deutscher Anbieter)|
webtrekk.net,wt-safetag.com|Mapp (ehem. Webtrekk)|Besucherstatistik|
chartbeat.com,chartbeat.net|Chartbeat|Echtzeit-Leserstatistik für Nachrichtenseiten|
parsely.com,parse.ly|Parse.ly|Leserstatistik für Nachrichtenseiten|
cxense.com|Piano (ehem. Cxense)|Leser-Analyse von Nachrichtenseiten|
piano.io,tinypass.com|Piano|Paywalls, Abos und Leser-Analyse|Sperre kann den Abo-Login auf Nachrichtenseiten stören
optimizely.com|Optimizely|A/B-Tests: Seiten zeigen Besuchern verschiedene Varianten|
visualwebsiteoptimizer.com|VWO|A/B-Tests: Seiten zeigen Besuchern verschiedene Varianten|
abtasty.com|AB Tasty|A/B-Tests: Seiten zeigen Besuchern verschiedene Varianten|
kameleoon.com,kameleoon.eu|Kameleoon|A/B-Tests: Seiten zeigen Besuchern verschiedene Varianten|
dynamicyield.com|Dynamic Yield|Personalisierung von Online-Shops|
qualtrics.com|Qualtrics|Umfragen und Feedback|
cloudflareinsights.com|Cloudflare Web Analytics|Besucherstatistik (datensparsam)|
go-mpulse.net,akstat.io|Akamai mPulse|misst die Ladezeit von Webseiten bei Besuchern|
nr-data.net|New Relic|Leistungs- und Fehlerdaten aus Browsern und Apps|
newrelic.com|New Relic|Überwachung von Apps und Webseiten|
datadoghq.com,datadoghq.eu|Datadog|Überwachung von Apps und Servern (Protokolle, Fehler, Leistung)|
browser-intake-datadoghq.com,browser-intake-datadoghq.eu|Datadog|Leistungs- und Fehlerdaten aus dem Browser|
instana.io|IBM Instana|Überwachung der Leistung von Apps und Webseiten|
dynatrace.com|Dynatrace|Überwachung der Leistung von Apps und Webseiten|
appdynamics.com,eum-appdynamics.com|AppDynamics (Cisco)|Überwachung der Leistung von Apps und Webseiten|
sentry.io,sentry-cdn.com|Sentry|Fehler- und Absturzberichte aus Apps und Webseiten|
bugsnag.com|Bugsnag|Fehler- und Absturzberichte aus Apps|
raygun.io|Raygun|Fehlerberichte|
rollbar.com|Rollbar|Fehlerberichte|
instabug.com|Instabug|Fehlerberichte und Feedback aus Apps|
embrace.io|Embrace|Absturz- und Leistungsdaten aus Apps|
launchdarkly.com|LaunchDarkly|Funktionsschalter für Apps|Sperre kann Apps stören
intercom.io,intercomcdn.com|Intercom|Chat-Fenster und Support auf Webseiten|
zendesk.com,zdassets.com|Zendesk|Kundensupport und Chat|
hubspot.com,hs-analytics.net,hs-scripts.com,hsforms.com|HubSpot|Marketing: Formulare, E-Mail-Tracking, Besucherstatistik|
marketo.com,marketo.net,mktoresp.com|Marketo (Adobe)|Marketing-Automatisierung und Besucher-Tracking|
pardot.com|Salesforce Pardot|Marketing-Automatisierung und Besucher-Tracking|
exacttarget.com|Salesforce Marketing Cloud|Marketing-E-Mails und deren Öffnungs- und Klickmessung|
list-manage.com|Mailchimp|Newsletter-Links und Öffnungsmessung|Sperre bricht Links in Newslettern
mailchimp.com|Mailchimp|Newsletter-Dienst|
sendgrid.net|SendGrid (Twilio)|Klickmessung in E-Mails|Sperre bricht Links in E-Mails
klaviyo.com|Klaviyo|E-Mail-Marketing für Online-Shops|
usercentrics.eu|Usercentrics|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
cookiebot.com|Cookiebot (Usercentrics)|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
cookielaw.org,onetrust.com|OneTrust|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
trustarc.com|TrustArc|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
privacy-center.org,didomi.io|Didomi|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
privacy-mgmt.com|Sourcepoint|Cookie-Einwilligungsbanner|Sperre kann Seiten blockieren, die auf die Einwilligung warten
consensu.org|IAB Europe (TCF)|Einwilligungsrahmen für Werbung (veraltet)|

akamai.net,akamaihd.net,akamaized.net,akamaiedge.net,edgekey.net,edgesuite.net|Akamai|Auslieferung von Inhalten (CDN) für viele Firmen|
cloudflare.com|Cloudflare|Netzwerk- und Sicherheitsdienste für viele Webseiten|
challenges.cloudflare.com|Cloudflare Turnstile|Bot-Schutz auf Webseiten|nicht sperren – sonst lassen sich Seiten und Formulare nicht nutzen
cloudflare-dns.com|Cloudflare DNS|DNS-Auflösung (1.1.1.1), auch verschlüsselt|Geräte können darüber am Blocker vorbei auflösen
quad9.net|Quad9|DNS-Auflösung (9.9.9.9), auch verschlüsselt|Geräte können darüber am Blocker vorbei auflösen
fastly.net,fastly.com|Fastly|Auslieferung von Inhalten (CDN) für viele Webseiten|
jsdelivr.net|jsDelivr|Bibliotheken für Webseiten (CDN)|
hcaptcha.com|hCaptcha|Bot-Schutz in Formularen|nicht sperren – sonst lassen sich Formulare nicht absenden
paypal.com|PayPal|Bezahldienst|nicht sperren
paypalobjects.com|PayPal|Skripte und Bilder|nicht sperren – sonst funktioniert „Mit PayPal zahlen“ nicht
klarna.com|Klarna|Bezahldienst|
stripe.com,stripe.network|Stripe|Zahlungsabwicklung für Online-Shops|nicht sperren – sonst scheitern Zahlungen
github.com,githubusercontent.com|GitHub|Code-Plattform|
wikipedia.org,wikimedia.org|Wikipedia|Online-Lexikon|
mozilla.org,mozilla.com,mozilla.net|Mozilla (Firefox)||
incoming.telemetry.mozilla.org|Mozilla Firefox|Telemetrie: Nutzungs- und Diagnosedaten|
brave.com|Brave|Webbrowser|
opera.com|Opera|Webbrowser|
avast.com,avcdn.net|Avast|Virenschutz: Updates und Cloud-Prüfung|
kaspersky.com,kaspersky-labs.com|Kaspersky|Virenschutz: Updates und Cloud-Prüfung|
zoom.us|Zoom|Videokonferenzen|
slack.com,slack-edge.com|Slack|Team-Chat|
dropbox.com,dropboxapi.com|Dropbox|Cloud-Speicher|
steampowered.com,steamcommunity.com,steamstatic.com,steamcontent.com|Steam (Valve)|Spieleplattform|
epicgames.com|Epic Games|Spieleplattform|
roblox.com,rbxcdn.com|Roblox|Spieleplattform|
minecraft.net,mojang.com|Minecraft (Microsoft)|Spiel|
battle.net,blizzard.com|Blizzard|Spieleplattform|
duckduckgo.com|DuckDuckGo|Suchmaschine|
ecosia.org|Ecosia|Suchmaschine|
gmx.net,web.de|GMX / WEB.DE|E-Mail und Portal|
t-online.de|t-online|Nachrichtenportal und E-Mail|
ebay.com,ebay.de,ebayimg.com|eBay|Online-Marktplatz|
spiegel.de|DER SPIEGEL|Nachrichten|
heise.de|heise online|Technik-Nachrichten|
tagesschau.de|tagesschau (ARD)|Nachrichten|
`;

  // Schlüsselwörter in Teilen des Namens (links vom bekannten Teil) → was dieser Rechner genau macht
  const WORTE = [
    [['telemetry', 'telem', 'diagnostics', 'diag', 'vortex', 'watson'], 'Telemetrie: Nutzungs- und Diagnosedaten', /Telemetrie|Diagnose/],
    [['crash', 'crashes', 'crashlytics', 'crashreport', 'crashreports', 'minidump'], 'Absturzberichte', /Absturz/],
    [['log', 'logs', 'logging', 'logger', 'syslog'], 'Übermittlung von Protokoll- und Fehlerdaten', /Protokoll/],
    [['rum', 'eum', 'apm', 'perf', 'performance'], 'Leistungsmessung direkt beim Nutzer', /Leistung|Ladezeit/],
    [['ads', 'ad', 'adserver', 'adservice', 'adsystem', 'advertising', 'adx', 'banner', 'banners', 'sponsored'], 'Werbung ausliefern oder messen', /Werb|Anzeige/],
    [['pixel', 'beacon', 'beacons', 'track', 'tracking', 'tracker', 'trk'], 'Tracking: meldet Besuche und Aktionen', /Tracking|Pixel/],
    [['analytics', 'analytic', 'stats', 'stat', 'statistics', 'metrics', 'metric', 'measure', 'measurement', 'insights'], 'Nutzungsstatistik und Analyse', /Statistik|Analyse|Messung|misst/],
    [['events', 'event', 'collector', 'collect', 'intake', 'ingest', 'ingestion'], 'Erfassung von Nutzungsereignissen', /Nutzungs|Telemetrie/],
    [['consent', 'cmp', 'cookieconsent'], 'Cookie-Einwilligungsbanner', /Einwilligung/],
    [['push', 'notify', 'notification', 'notifications'], 'Push-Benachrichtigungen', /Benachrichtigung/],
    [['update', 'updates', 'upgrade', 'ota', 'firmware'], 'Software-Updates', /Update/],
  ];
  const WORT = new Map(); WORTE.forEach(([worte, text, schon], rang) => worte.forEach((w) => WORT.set(w, { text, schon, rang })));
  // Microsoft-Produkte im Namen (z. B. euc-excel-telemetry.officeapps.live.com)
  const PRODUKTE = { teams: 'Microsoft Teams', excel: 'Microsoft Excel', word: 'Microsoft Word', powerpoint: 'Microsoft PowerPoint', outlook: 'Microsoft Outlook', onenote: 'Microsoft OneNote', onedrive: 'Microsoft OneDrive', edge: 'Microsoft Edge', xbox: 'Xbox', skype: 'Skype', bing: 'Bing', windows: 'Windows' };
  // Zweiteilige Endungen, damit „x.co.uk“ nicht als Firma „co.uk“ gilt
  const ZWEITEILIG = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.jp', 'ne.jp', 'com.br', 'com.cn', 'com.tr', 'co.at', 'or.at', 'gv.at', 'co.nz', 'co.za', 'com.mx', 'co.in', 'co.kr', 'com.tw', 'com.hk', 'com.sg']);

  const KARTE = new Map();
  for (const zeile of DATEN.split('\n')) {
    if (!zeile.trim()) continue;
    const [domains, anbieter, zweck, hinweis] = zeile.split('|').map((s) => (s || '').trim());
    for (const d of domains.split(',')) KARTE.set(d.trim().toLowerCase(), { anbieter: anbieter || null, zweck: zweck || null, hinweis: hinweis || null });
  }

  const cache = new Map();
  function beschreibe(eingabe) {
    const domain = String(eingabe || '').trim().toLowerCase().replace(/\.$/, '');
    if (!domain || !domain.includes('.')) return null;
    if (cache.has(domain)) return cache.get(domain);
    const teile = domain.split('.');
    let anbieter = null, zweck = null, hinweis = null, genau = -1;
    for (let i = 0; i < teile.length; i++) {
      const e = KARTE.get(teile.slice(i).join('.'));
      if (!e) continue;
      if (genau < 0) genau = i;
      anbieter = anbieter || e.anbieter; zweck = zweck || e.zweck; hinweis = hinweis || e.hinweis;
    }
    // Teile links vom bekannten Namen – bei Unbekanntem alles vor der Hauptdomain
    let links;
    if (genau >= 0) links = teile.slice(0, genau);
    else { const n = ZWEITEILIG.has(teile.slice(-2).join('.')) ? 3 : 2; links = teile.slice(0, Math.max(0, teile.length - n)); }
    const woerter = links.flatMap((t) => t.split(/[-_]/)).filter(Boolean);
    let wort = null;
    for (const w of woerter) { const x = WORT.get(w); if (x && (!wort || x.rang < wort.rang)) wort = x; }
    if (anbieter && /^Microsoft$|^Microsoft Office$|^Microsoft 365$/.test(anbieter)) {
      const p = woerter.map((w) => PRODUKTE[w]).find(Boolean); if (p) anbieter = p;
    }
    const hier = wort && !(zweck && wort.schon.test(zweck)) ? wort.text : null;
    let ergebnis = null;
    if (anbieter || zweck || hier) {
      const text = anbieter
        ? `${anbieter}${zweck ? ` – ${zweck}` : ''}${hier ? `${zweck ? ' · hier: ' : ' · '}${hier}` : ''}`
        : `${hier || zweck} · Anbieter unbekannt`;
      ergebnis = { domain, anbieter, zweck, hier, hinweis, bekannt: genau >= 0, text };
    }
    if (cache.size > 5000) cache.clear();
    cache.set(domain, ergebnis);
    return ergebnis;
  }

  const api = { beschreibe, anzahl: KARTE.size };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else wurzel.DomainInfo = api;
})(typeof window !== 'undefined' ? window : globalThis);
