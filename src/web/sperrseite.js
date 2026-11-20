// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung ist untersagt.
// ============================================================================
'use strict';
// Hinweisseite für gesperrte Seiten: FAH-Proxy leitet die gesperrte Domain hierher und nennt sie im Kopf X-Sperr-Domain.

const esc = (t) => String(t).replace(/[&<>"']/g, (z) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[z]));

/** Nur ein gültiger Hostname aus dem Kopf (ohne Port), sonst leer. */
function domainAusKopf(wert) {
  const d = String(wert || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d) && d.length <= 253 ? d : '';
}

/** Lesbarer Grund aus der Filter-Entscheidung. */
function grundText(e, kategorien) {
  if (!e) return '';
  if (e.dienstName) return `Dienst: ${e.dienstName}`;
  if (e.grund === 'Eigene Regel') return 'Eigene Regel';
  const k = kategorien.find((x) => x.id === (e.seiteKategorie || e.kategorie));
  return k ? k.name : '';
}

function sperrseiteHtml({ domain, grund }) {
  const seite = domain ? `<p class="domain">${esc(domain)}</p>` : '';
  const warum = grund ? `<p class="grund">Grund: ${esc(grund)}</p>` : '';
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Seite gesperrt · FAH-Adblock</title><style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e7eaee;font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:440px;padding:32px 24px;text-align:center}
.marke{font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#40e0a0}
svg{width:56px;height:56px;margin:18px 0 6px;color:#40e0a0}
h1{font-size:24px;margin:6px 0 10px}
.domain{font:600 15px ui-monospace,SFMono-Regular,Menlo,monospace;background:#161b22;border:1px solid #2a313c;border-radius:8px;padding:9px 12px;margin:0 0 14px;word-break:break-all}
p{color:#9aa3ae;margin:0 0 8px}.grund{color:#e7eaee}
</style></head><body><main><div class="marke">FAH-Adblock</div>
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.6-2.9 8.1-7 10-4.1-1.9-7-5.4-7-10V6z"/><path d="M9 9l6 6M15 9l-6 6"/></svg>
<h1>Diese Seite ist gesperrt</h1>${seite}<p>FAH-Adblock hat den Aufruf in diesem Netzwerk blockiert.</p>${warum}</main></body></html>`;
}

module.exports = { sperrseiteHtml, domainAusKopf, grundText };
