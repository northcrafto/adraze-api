// AdRaze Kolla (doxing, systemd --user adraze-kolla, 127.0.0.1:8493, nås via api.adraze.app/kolla/* som konto-API:et skickar vidare)
// Klistra in en länk: vi kollar den mot ett gäng säkerhetslistor och DNS-filter (som VirusTotal, fast öppet),
// öppnar sidan i en riktig webbläsare två gånger, utan och med AdRaze-tillägget, och mäter skillnaden.
// All trafik från webbläsaren går genom en egen proxy som vägrar privata adresser, så skannern kan inte nå doxings nät.
'use strict';
const http = require('node:http');
const net = require('node:net');
const dns = require('node:dns');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright-core');

const DIR = __dirname;
const PORT = Number(process.env.KOLLA_PORT || 8493);
const EXE = process.env.CHROME || path.join(os.homedir(), '.cache/ms-playwright/chromium-1234/chrome-linux64/chrome');
const TILLAGG = path.join(DIR, 'extension');
const RESULTAT = path.join(DIR, 'resultat');
const SAMTIDIGA = 2; // skanningar åt gången (varje skanning = två webbläsare efter varandra)
const CACHE_MS = 30 * 60_000; // samma länk inom en halvtimme får samma resultat
const SPARA_DAGAR = 30;
fs.mkdirSync(RESULTAT, { recursive: true });

// ---------- adresser vi aldrig får ansluta till ----------
const privata = new net.BlockList();
for (const [n, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]]) privata.addSubnet(n, p, 'ipv4');
for (const [n, p] of [['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['64:ff9b::', 96], ['2001:db8::', 32]]) privata.addSubnet(n, p, 'ipv6');
function arPrivat(ip) {
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) ip = m[1];
  return privata.check(ip, net.isIPv6(ip) ? 'ipv6' : 'ipv4') || (net.isIPv6(ip) && /^::ffff:/i.test(ip));
}
const TILLATNA_PORTAR = new Set([80, 443]);
// Slår upp värden och ger en publik adress, annars fel (tas fram på nytt vid varje anslutning: ingen DNS-rebinding)
async function publikAdress(host) {
  host = host.replace(/^\[|\]$/g, '');
  const adresser = net.isIP(host) ? [{ address: host }] : await dns.promises.lookup(host, { all: true, verbatim: true });
  if (!adresser.length || adresser.some((a) => arPrivat(a.address))) throw new Error('privat adress');
  return adresser[0].address;
}

// ---------- proxyn som webbläsaren måste gå igenom ----------
const proxy = http.createServer(async (req, res) => {
  // Vanlig http (https går via CONNECT nedan)
  try {
    const u = new URL(req.url);
    const port = Number(u.port || 80);
    if (u.protocol !== 'http:' || !TILLATNA_PORTAR.has(port)) throw new Error('port');
    const ip = await publikAdress(u.hostname);
    const ut = http.request({ host: ip, port, method: req.method, path: u.pathname + u.search, headers: { ...req.headers, host: u.host }, timeout: 20_000 }, (svar) => {
      res.writeHead(svar.statusCode, svar.headers);
      svar.pipe(res);
    });
    ut.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    ut.on('timeout', () => ut.destroy());
    req.pipe(ut);
  } catch {
    res.writeHead(403); res.end();
  }
});
proxy.on('connect', async (req, klient, huvud) => {
  try {
    const [host, portText] = req.url.split(/:(?=\d+$)/);
    const port = Number(portText);
    if (!TILLATNA_PORTAR.has(port)) throw new Error('port');
    const ip = await publikAdress(host);
    const ut = net.connect({ host: ip, port, timeout: 20_000 }, () => {
      klient.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (huvud?.length) ut.write(huvud);
      ut.pipe(klient); klient.pipe(ut);
    });
    ut.on('timeout', () => ut.destroy());
    ut.on('error', () => klient.destroy());
    klient.on('error', () => ut.destroy());
  } catch {
    klient.end('HTTP/1.1 403 Forbidden\r\n\r\n');
  }
});
let PROXY_PORT = 0;
proxy.listen(0, '127.0.0.1', () => { PROXY_PORT = proxy.address().port; });

// ---------- listorna (motorerna) ----------
// typ: 'sakerhet' räknas in i omdömet "farlig", 'reklam' visas för sig
const MOTORER = [
  { id: 'adraze', namn: 'AdRaze', typ: 'sakerhet', kalla: 'regler' },
  { id: 'urlhaus', namn: 'URLhaus (abuse.ch)', typ: 'sakerhet', url: 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt' },
  { id: 'phishfilter', namn: 'Phishing Filter', typ: 'sakerhet', url: 'https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt' },
  { id: 'openphish', namn: 'OpenPhish', typ: 'sakerhet', url: 'https://openphish.com/feed.txt' },
  { id: 'phishdb', namn: 'Phishing.Database', typ: 'sakerhet', url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt' },
  { id: 'phisharmy', namn: 'Phishing Army', typ: 'sakerhet', url: 'https://phishing.army/download/phishing_army_blocklist.txt' },
  { id: 'hagezi', namn: 'HaGeZi Threat Intelligence', typ: 'sakerhet', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt' },
  { id: 'quad9', namn: 'Quad9', typ: 'sakerhet', dns: '9.9.9.9' },
  { id: 'cloudflare', namn: 'Cloudflare Security DNS', typ: 'sakerhet', dns: '1.1.1.2' },
  { id: 'cleanbrowsing', namn: 'CleanBrowsing Security', typ: 'sakerhet', dns: '185.228.168.9' },
  { id: 'controld', namn: 'Control D Malware', typ: 'sakerhet', dns: '76.76.2.1' },
  { id: 'adraze_reklam', namn: 'AdRaze reklam', typ: 'reklam', kalla: 'regler' },
  { id: 'adraze_sparare', namn: 'AdRaze spårare', typ: 'reklam', kalla: 'regler' },
  { id: 'adguard', namn: 'AdGuard DNS', typ: 'reklam', dns: '94.140.14.14' },
];
const listor = new Map(); // id -> Set av domäner

function lasDomaner(text) {
  const s = new Set();
  for (let rad of text.split('\n')) {
    rad = rad.trim();
    if (!rad || rad[0] === '#' || rad[0] === '!') continue;
    if (/^https?:\/\//i.test(rad)) { try { rad = new URL(rad).hostname; } catch { continue; } } // OpenPhish ger hela länkar
    rad = rad.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').replace(/^\*\./, '').split(/\s/)[0].toLowerCase();
    if (rad.includes('.')) s.add(rad);
  }
  return s;
}
// Listorna sparas på disk, så att de finns direkt efter en omstart och bara hämtas om när de är äldre än 12 timmar
const LISTMAPP = path.join(DIR, 'listor');
fs.mkdirSync(LISTMAPP, { recursive: true });
async function hamtaListor(tvinga) {
  for (const m of MOTORER) {
    if (!m.url) continue;
    const fil = path.join(LISTMAPP, `${m.id}.txt`);
    const alder = fs.existsSync(fil) ? Date.now() - fs.statSync(fil).mtimeMs : Infinity;
    if (!listor.has(m.id) && alder < Infinity) {
      const s = lasDomaner(fs.readFileSync(fil, 'utf8'));
      if (s.size) { listor.set(m.id, s); m.antal = s.size; m.uppdaterad = fs.statSync(fil).mtimeMs; }
    }
    if (!tvinga && alder < 12 * 3_600_000) continue;
    try {
      const r = await fetch(m.url, { signal: AbortSignal.timeout(120_000) });
      if (!r.ok) throw new Error(r.status);
      const text = await r.text();
      const s = lasDomaner(text);
      if (s.size) { listor.set(m.id, s); m.antal = s.size; m.uppdaterad = Date.now(); fs.writeFileSync(fil, text); }
    } catch (e) { console.error('lista', m.id, e.message); }
  }
  console.log('listor:', MOTORER.filter((m) => m.url).map((m) => `${m.id}=${listor.get(m.id)?.size ?? 0}`).join(' '));
}

// ---------- AdRaze-reglerna (samma som tillägget använder) ----------
// Varje förfrågan sidan gör prövas mot tilläggets DNR-regler, så att vi kan säga vad som är reklam och spårare
const KATEGORI = { ads: 'reklam', privacy: 'sparare', security: 'farlig' };
let regler = null;
function dnrRegex(f, skiftlage) {
  // DNR-syntax: ||värd, | ankare, * jokertecken, ^ avgränsare
  let r = '';
  let i = 0;
  if (f.startsWith('||')) { r = '^[a-z]+:\\/\\/([^/]*\\.)?'; i = 2; } else if (f.startsWith('|')) { r = '^'; i = 1; }
  const slut = f.endsWith('|') && !f.endsWith('||');
  const kropp = f.slice(i, slut ? -1 : undefined);
  for (const c of kropp) r += c === '*' ? '.*' : c === '^' ? '(?:[^\\w.%-]|$)' : c.replace(/[.+?${}()|[\]\\/]/g, '\\$&');
  if (slut) r += '$';
  try { return new RegExp(r, skiftlage ? '' : 'i'); } catch { return null; }
}
const VARD_RE = /^\|\|([a-z0-9.-]+)(\^|\/|$)/i;
function laddaRegler() {
  const index = { domaner: new Map(), perVard: new Map(), allmanna: [] };
  for (const [fil, kat] of Object.entries(KATEGORI)) {
    for (const r of JSON.parse(fs.readFileSync(path.join(TILLAGG, 'rules', `${fil}.json`), 'utf8'))) {
      const typ = r.action.type;
      if (typ !== 'block' && typ !== 'allow' && typ !== 'redirect') continue;
      const c = r.condition;
      const regel = { kat, blockera: typ !== 'allow', prio: r.priority || 1, c };
      if (c.urlFilter) regel.re = dnrRegex(c.urlFilter, c.isUrlFilterCaseSensitive);
      else if (c.regexFilter) { try { regel.re = new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? '' : 'i'); } catch { continue; } }
      if (c.requestDomains) {
        for (const d of c.requestDomains) { if (!index.domaner.has(d)) index.domaner.set(d, []); index.domaner.get(d).push(regel); }
        continue;
      }
      const m = c.urlFilter && VARD_RE.exec(c.urlFilter);
      if (m) { const v = m[1].toLowerCase(); if (!index.perVard.has(v)) index.perVard.set(v, []); index.perVard.get(v).push(regel); } else index.allmanna.push(regel);
    }
  }
  // Rena värdregler ("||doubleclick.net^") används också som listor i motortabellen
  const domanerFor = (kat) => {
    const s = new Set();
    for (const [d, rs] of index.domaner) if (rs.some((x) => x.kat === kat && x.blockera && !x.c.initiatorDomains)) s.add(d);
    for (const [d, rs] of index.perVard) if (rs.some((x) => x.kat === kat && x.blockera && !x.c.initiatorDomains && /^\|\|[^/*]+\^?$/.test(x.c.urlFilter))) s.add(d);
    return s;
  };
  listor.set('adraze', domanerFor('farlig'));
  listor.set('adraze_reklam', domanerFor('reklam'));
  listor.set('adraze_sparare', domanerFor('sparare'));
  for (const id of ['adraze', 'adraze_reklam', 'adraze_sparare']) { const m = MOTORER.find((x) => x.id === id); m.antal = listor.get(id).size; m.uppdaterad = fs.statSync(path.join(TILLAGG, 'rules', 'ads.json')).mtimeMs; }
  regler = index;
}
const foraldrar = (host) => { const delar = host.split('.'); const ut = []; for (let i = 0; i < delar.length - 1; i++) ut.push(delar.slice(i).join('.')); return ut; };
const ingarI = (host, lista) => lista.some((d) => host === d || host.endsWith('.' + d));
function passar(regel, f) {
  const c = regel.c;
  if (c.resourceTypes && !c.resourceTypes.includes(f.typ)) return false;
  if (c.excludedResourceTypes && c.excludedResourceTypes.includes(f.typ)) return false;
  if (c.domainType === 'thirdParty' && !f.tredje) return false;
  if (c.domainType === 'firstParty' && f.tredje) return false;
  if (c.initiatorDomains && !ingarI(f.fran, c.initiatorDomains)) return false;
  if (c.excludedInitiatorDomains && ingarI(f.fran, c.excludedInitiatorDomains)) return false;
  if (c.excludedRequestDomains && ingarI(f.host, c.excludedRequestDomains)) return false;
  if (regel.re && !regel.re.test(f.url)) return false;
  return true;
}
// Ger 'reklam' | 'sparare' | 'farlig' | null, med samma företräde som Chrome (högst prioritet vinner, allow vinner vid lika)
function klassa(f) {
  const kandidater = [];
  for (const v of foraldrar(f.host)) {
    kandidater.push(...(regler.domaner.get(v) || []), ...(regler.perVard.get(v) || []));
  }
  kandidater.push(...regler.allmanna);
  let blockera = null, tillat = 0;
  for (const r of kandidater) {
    if (!passar(r, f)) continue;
    if (r.blockera) { if (!blockera || r.prio > blockera.prio) blockera = r; } else tillat = Math.max(tillat, r.prio);
  }
  return blockera && blockera.prio > tillat ? blockera.kat : null;
}
// Video/ljud, även HLS/DASH-bitar som hämtas med XHR
const arVideo = (f) => f.typ === 'Media' || /^(video|audio)\/|mpegurl|dash\+xml|mp2t/i.test(f.mime || '') || /\.(m3u8|m4s|ts|mpd)(\?|$)/i.test(f.url);
const REQ_TYP = { Document: 'sub_frame', Stylesheet: 'stylesheet', Image: 'image', Media: 'media', Font: 'font', Script: 'script', XHR: 'xmlhttprequest', Fetch: 'xmlhttprequest', Ping: 'ping', WebSocket: 'websocket', CSPViolationReport: 'csp_report' };
// Grov "registrerbar domän" (räcker för tredjepartskoll): sista två delarna, tre för t.ex. co.uk / com.au
function bas(host) {
  const d = host.split('.');
  return d.length > 2 && /^(co|com|org|net|gov|ac|edu)$/.test(d[d.length - 2]) && d[d.length - 1].length === 2 ? d.slice(-3).join('.') : d.slice(-2).join('.');
}

// ---------- kolla mot listor + DNS-filter ----------
async function dnsSvar(server, host) {
  const r = new dns.promises.Resolver({ timeout: 3000, tries: 1 });
  r.setServers([server]);
  try { return await r.resolve4(host); } catch (e) { return e.code; }
}
async function kollaMotorer(host) {
  const referens = await dnsSvar('1.1.1.1', host);
  const finnsHost = Array.isArray(referens);
  return Promise.all(MOTORER.map(async (m) => {
    const ut = { id: m.id, namn: m.namn, typ: m.typ };
    if (m.dns) {
      if (!finnsHost) return { ...ut, resultat: 'okand' };
      const svar = await dnsSvar(m.dns, host);
      // Blockerat = filtret svarar 0.0.0.0 / NXDOMAIN fast vanlig DNS hittar adressen
      const stopp = svar === 'ENOTFOUND' || (Array.isArray(svar) && svar.some((a) => a === '0.0.0.0' || a.startsWith('127.') || a === '94.140.14.33' || a === '146.112.61.104'));
      return { ...ut, resultat: Array.isArray(svar) || svar === 'ENOTFOUND' ? (stopp ? 'flaggad' : 'ren') : 'okand' };
    }
    const s = listor.get(m.id);
    if (!s) return { ...ut, resultat: 'okand' };
    return { ...ut, resultat: foraldrar(host).some((d) => s.has(d)) ? 'flaggad' : 'ren' };
  }));
}

// ---------- webbläsaren ----------
// Kakrutan klickas bort med "Godkänn" i körningen utan AdRaze, så som de flesta gör. Annars laddas ofta ingen reklam alls.
// Knappar som börjar med ett ja-ord; nej-/inställningsknappar hoppas över, och "alla"-knappar väljs först
const GODKANN = /^(okej|okay|ok|jag förstår|förstått|godkänn|acceptera|jag godkänner|jag accepterar|tillåt|accept|i accept|i agree|agree|allow|got it|continue|alle akzeptieren|akzeptieren|zustimmen|einverstanden|tout accepter|accepter|j'accepte|aceptar|acepto|accetta|accetto|aceitar|aceito|godta|godkend|hyväksy|zaakceptuj|akceptuj|přijmout|souhlasím|elfogad|accept toate|kabul)(?=$|[\s!,.&:])/i;
const NEJ = /nödvändig|necessary|essential|endast|bara |only|neka|avvisa|avböj|reject|decline|refuse|inställning|setting|anpassa|customi|manage|hantera|preferen|options|nur |notwendig|ablehnen|einstellung|seulement|refuser|paramètr|solo|rechaz|rifiut|configur|kun |afvis|vain |odrzu|odmítn|elutasít|reddet/i;
const ALLA = /\b(alla|all|alle|tout|todo|todas|tutto|tutti|kaikki|wszystk|vše|összes|toate|tümü)\b/i;
async function klickaGodkann(sida) {
  for (let forsok = 0; forsok < 2; forsok++) {
    for (const ram of sida.frames()) {
      try {
        const traff = await ram.evaluate(([ja, nej, alla]) => {
          const [JA, NEJ, ALLA] = [ja, nej, alla].map((k) => new RegExp(k, 'i'));
          const text = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim();
          const synlig = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'; };
          const kandidater = [...document.querySelectorAll('button, a[role=button], [role=button], a[href="#"], input[type=button], input[type=submit]')]
            .filter((el) => { const t = text(el); return t.length <= 45 && JA.test(t) && !NEJ.test(t) && synlig(el); });
          const k = kandidater.find((el) => ALLA.test(text(el))) || kandidater[0];
          if (k) { k.click(); return true; }
          return false;
        }, [GODKANN.source, NEJ.source, ALLA.source]);
        if (traff) return true;
      } catch {}
    }
    await vanta(1500);
  }
  return false;
}
const vanta = (ms) => new Promise((r) => setTimeout(r, ms));

async function korWebblasare(adress, medAdraze, sidhost) {
  const profil = fs.mkdtempSync(path.join(os.tmpdir(), 'kolla-'));
  const args = ['--headless=new', '--no-first-run', '--disable-gpu', '--disable-quic', '--mute-audio', '--disable-dev-shm-usage',
    `--proxy-server=http://127.0.0.1:${PROXY_PORT}`, '--proxy-bypass-list=<-loopback>',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--webrtc-ip-handling-policy=disable_non_proxied_udp'];
  if (medAdraze) args.push(`--disable-extensions-except=${TILLAGG}`, `--load-extension=${TILLAGG}`);
  let ctx;
  try {
    ctx = await chromium.launchPersistentContext(profil, {
      executablePath: EXE, headless: false, args, viewport: { width: 1280, height: 800 }, locale: 'sv-SE', timezoneId: 'Europe/Stockholm',
      acceptDownloads: false, ignoreDefaultArgs: ['--disable-extensions'],
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
    });
    if (medAdraze) {
      if (!ctx.serviceWorkers().length) await ctx.waitForEvent('serviceworker', { timeout: 15_000 });
      await vanta(2500); // reglerna laddas när tillägget startar
    }
    const sida = ctx.pages()[0] || await ctx.newPage();
    // Nya flikar (popunders) räknas men stängs
    let popups = 0;
    ctx.on('page', (p) => { if (p !== sida) { popups++; p.close().catch(() => {}); } });
    const cdp = await ctx.newCDPSession(sida);
    await cdp.send('Network.enable');
    const forfr = new Map();
    let blockerade = 0;
    cdp.on('Network.requestWillBeSent', (e) => {
      if (forfr.has(e.requestId)) return;
      let host = ''; try { host = new URL(e.request.url).hostname.toLowerCase(); } catch {}
      forfr.set(e.requestId, { url: e.request.url, host, typ: e.type, start: e.timestamp });
    });
    cdp.on('Network.loadingFinished', (e) => { const f = forfr.get(e.requestId); if (f) { f.klar = true; f.bytes = e.encodedDataLength; } });
    cdp.on('Network.responseReceived', (e) => { const f = forfr.get(e.requestId); if (f) f.mime = e.response.mimeType || ''; });
    // Strömmad video räknas för sig: utan reklam hinner sajtens egna klipp börja spelas, och det är inte skräp
    cdp.on('Network.dataReceived', (e) => { const f = forfr.get(e.requestId); if (f) f.mottaget = (f.mottaget || 0) + e.encodedDataLength; });
    cdp.on('Network.loadingFailed', (e) => { const f = forfr.get(e.requestId); if (f && /BLOCKED_BY_CLIENT/.test(e.errorText)) { f.blockerad = true; blockerade++; } });
    const t0 = Date.now();
    let fel = null;
    const svar = await sida.goto(adress, { waitUntil: 'load', timeout: 25_000 }).catch((e) => { fel = e.message; return null; });
    const laddtid = Date.now() - t0;
    if (!svar && fel && !/Timeout/i.test(fel)) throw Object.assign(new Error('gick inte att öppna'), { kod: 'oppna' });
    let godkande = false;
    if (!medAdraze) { await vanta(1500); godkande = await klickaGodkann(sida); }
    await vanta(3000);
    await sida.mouse.wheel(0, 2500).catch(() => {});
    await vanta(3000);
    await sida.mouse.wheel(0, -2500).catch(() => {});
    await vanta(1500);
    const bild = await sida.screenshot({ type: 'jpeg', quality: 62, timeout: 10_000 }).catch(() => null);
    const kakor = (await ctx.cookies().catch(() => [])).length;
    // Räkna upp: reklam och spårare som faktiskt laddades (blockerade räknas inte, de nådde aldrig nätet)
    const raknat = { reklam: 0, sparare: 0, farlig: 0 };
    const tredjeVardar = new Set();
    const exempel = { reklam: new Set(), sparare: new Set() };
    const huvud = bas(sidhost);
    let bytes = 0;
    const perTyp = {};
    for (const f of forfr.values()) {
      const b = f.bytes ?? f.mottaget ?? 0;
      perTyp[f.typ] = (perTyp[f.typ] || 0) + b;
      if (!arVideo(f)) bytes += b;
    }
    for (const f of forfr.values()) {
      if (!f.host || !/^https?:/.test(f.url)) continue;
      const tredje = bas(f.host) !== huvud;
      if (tredje) tredjeVardar.add(bas(f.host));
      if (f.blockerad || f.typ === 'Document' && f.url === adress) continue;
      const kat = klassa({ url: f.url, host: f.host, typ: REQ_TYP[f.typ] || 'other', tredje, fran: sidhost });
      if (kat) { raknat[kat]++; if (exempel[kat] && exempel[kat].size < 12) exempel[kat].add(f.host); }
    }
    return {
      laddtid, bytes, perTyp, forfragningar: forfr.size, blockerade, kakor, popups, godkande, tredjeparter: tredjeVardar.size,
      ...raknat, exempel: { reklam: [...exempel.reklam], sparare: [...exempel.sparare] }, slutadress: sida.url(), bild,
    };
  } finally {
    await ctx?.close().catch(() => {});
    fs.rmSync(profil, { recursive: true, force: true });
  }
}

// ---------- jobb ----------
const jobb = new Map(); // id -> { status, steg, adress, ... }
const ko = [];
let igang = 0;
const nyttId = () => crypto.randomBytes(8).toString('base64url').replace(/[-_]/g, '').slice(0, 10).toLowerCase();
const giltigtId = (id) => /^[a-z0-9]{6,12}$/.test(id);

function betyg(r) {
  const n = r.reklam + r.sparare;
  return n <= 2 ? 'A' : n <= 10 ? 'B' : n <= 25 ? 'C' : n <= 50 ? 'D' : n <= 100 ? 'E' : 'F';
}
function spara(j) {
  const mapp = path.join(RESULTAT, j.id);
  fs.mkdirSync(mapp, { recursive: true });
  const { bilder, ...rest } = j;
  for (const [namn, b] of Object.entries(bilder || {})) if (b) fs.writeFileSync(path.join(mapp, `${namn}.jpg`), b);
  fs.writeFileSync(path.join(mapp, 'r.json'), JSON.stringify(rest));
}
function offentlig(j) {
  const { bilder, ip, ...rest } = j;
  if (j.status === 'ko') rest.plats = ko.indexOf(j.id) + 1;
  return rest;
}

async function kor(j) {
  igang++;
  try {
    j.status = 'kor';
    j.steg = 'listor';
    const host = new URL(j.adress).hostname.toLowerCase();
    j.motorer = await kollaMotorer(host);
    j.flaggad = j.motorer.filter((m) => m.typ === 'sakerhet' && m.resultat === 'flaggad').length;
    j.antalSakerhet = j.motorer.filter((m) => m.typ === 'sakerhet' && m.resultat !== 'okand').length;
    if (j.flaggad) {
      // Flaggade sidor öppnar vi inte, inte ens på servern
      j.status = 'klar'; j.steg = 'klar'; j.oppnad = false;
      return;
    }
    j.steg = 'utan';
    const utan = await korWebblasare(j.adress, false, host);
    j.steg = 'med';
    const med = await korWebblasare(j.adress, true, host).catch((e) => { console.error('med', j.adress, e.message); return null; });
    j.bilder = { utan: utan.bild, med: med?.bild };
    delete utan.bild; if (med) delete med.bild;
    j.utan = utan; j.med = med; j.oppnad = true;
    j.betyg = betyg(utan);
    j.slutadress = utan.slutadress;
    j.status = 'klar'; j.steg = 'klar';
  } catch (e) {
    j.status = 'fel'; j.fel = e.kod || 'okant';
    if (!e.kod) console.error('kolla', j.adress, e);
  } finally {
    j.klar = Date.now();
    igang--;
    try { spara(j); } catch (e) { console.error('spara', e.message); }
    delete j.bilder;
    nasta();
  }
}
function nasta() {
  while (igang < SAMTIDIGA && ko.length) { const j = jobb.get(ko.shift()); if (j) kor(j); }
}
function hamtaJobb(id) {
  if (jobb.has(id)) return jobb.get(id);
  const fil = path.join(RESULTAT, id, 'r.json');
  if (!fs.existsSync(fil)) return null;
  const j = JSON.parse(fs.readFileSync(fil, 'utf8'));
  jobb.set(id, j);
  return j;
}
// Gamla resultat städas bort, minnet töms på färdiga jobb efter en timme
setInterval(() => {
  const grans = Date.now() - SPARA_DAGAR * 86_400_000;
  for (const id of fs.readdirSync(RESULTAT)) {
    try { if (fs.statSync(path.join(RESULTAT, id)).mtimeMs < grans) fs.rmSync(path.join(RESULTAT, id), { recursive: true, force: true }); } catch {}
  }
  for (const [id, j] of jobb) if (j.klar && Date.now() - j.klar > 3_600_000) jobb.delete(id);
}, 3_600_000).unref();

// ---------- in-adressen ----------
function stadaAdress(text) {
  text = String(text || '').trim();
  if (!text || text.length > 2000) return null;
  if (!/^[a-z]+:\/\//i.test(text)) text = 'https://' + text;
  let u;
  try { u = new URL(text); } catch { return null; }
  if (!/^https?:$/.test(u.protocol) || u.username || u.password) return null;
  if (u.port && !TILLATNA_PORTAR.has(Number(u.port))) return null;
  const h = u.hostname.toLowerCase();
  if (!h.includes('.') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.ts.net') || h === 'localhost') return null;
  if (net.isIP(h.replace(/^\[|\]$/g, '')) && arPrivat(h.replace(/^\[|\]$/g, ''))) return null;
  u.hash = '';
  return u.toString();
}

// ---------- gränser ----------
const traffar = new Map();
function begransad(nyckel, max, fonsterMs) {
  const t = Date.now();
  const lista = (traffar.get(nyckel) || []).filter((x) => t - x < fonsterMs);
  const over = lista.length >= max;
  if (!over) lista.push(t);
  traffar.set(nyckel, lista);
  return over;
}
setInterval(() => { const t = Date.now(); for (const [k, v] of traffar) if (!v.some((x) => t - x < 86_400_000)) traffar.delete(k); }, 600_000).unref();
const senaste = new Map(); // adress -> id, för cachen

// ---------- http ----------
function skicka(res, status, kropp) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(kropp));
}
function lasJson(req) {
  return new Promise((resolve) => {
    let n = 0; const bitar = [];
    req.on('data', (c) => { n += c.length; if (n <= 8192) bitar.push(c); });
    req.on('end', () => { try { resolve(n > 8192 ? null : JSON.parse(Buffer.concat(bitar).toString('utf8') || '{}')); } catch { resolve(null); } });
    req.on('error', () => resolve(null));
  });
}

http.createServer(async (req, res) => {
  const sokvag = new URL(req.url, 'http://x').pathname;
  const ip = String(req.headers['cf-connecting-ip'] || req.socket.remoteAddress);
  try {
    if (req.method === 'POST' && sokvag === '/kolla') {
      const b = await lasJson(req);
      const adress = stadaAdress(b?.url);
      if (!adress) return skicka(res, 400, { ok: false, fel: 'adress' });
      const tidigare = senaste.get(adress);
      const gammal = tidigare && hamtaJobb(tidigare);
      if (gammal && gammal.status !== 'fel' && Date.now() - gammal.skapad < CACHE_MS) return skicka(res, 200, { ok: true, id: gammal.id });
      if (begransad(`m:${ip}`, 6, 10 * 60_000) || begransad(`d:${ip}`, 40, 86_400_000)) return skicka(res, 429, { ok: false, fel: 'for_manga' });
      if (ko.length >= 30) return skicka(res, 503, { ok: false, fel: 'full' });
      try { await publikAdress(new URL(adress).hostname); } catch (e) { return skicka(res, 400, { ok: false, fel: e.code === 'ENOTFOUND' ? 'finns_inte' : 'adress' }); }
      const j = { id: nyttId(), adress, host: new URL(adress).hostname, status: 'ko', steg: 'ko', skapad: Date.now() };
      jobb.set(j.id, j); senaste.set(adress, j.id); ko.push(j.id);
      nasta();
      return skicka(res, 200, { ok: true, id: j.id });
    }
    let m;
    if (req.method === 'GET' && (m = /^\/kolla\/r\/([a-z0-9]+)$/.exec(sokvag))) {
      const j = giltigtId(m[1]) && hamtaJobb(m[1]);
      if (!j) return skicka(res, 404, { ok: false, fel: 'finns_inte' });
      return skicka(res, 200, { ok: true, ...offentlig(j) });
    }
    if (req.method === 'GET' && (m = /^\/kolla\/bild\/([a-z0-9]+)\/(utan|med)\.jpg$/.exec(sokvag))) {
      const fil = giltigtId(m[1]) && path.join(RESULTAT, m[1], `${m[2]}.jpg`);
      if (!fil || !fs.existsSync(fil)) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': 'image/jpeg', 'cache-control': 'public, max-age=86400', 'x-content-type-options': 'nosniff', 'cross-origin-resource-policy': 'cross-origin' });
      return fs.createReadStream(fil).pipe(res);
    }
    if (req.method === 'GET' && sokvag === '/kolla/motorer') {
      return skicka(res, 200, { ok: true, motorer: MOTORER.map(({ id, namn, typ, antal, uppdaterad }) => ({ id, namn, typ, antal, uppdaterad })) });
    }
    skicka(res, 404, { ok: false, fel: 'finns_inte' });
  } catch (e) {
    console.error(req.method, sokvag, e);
    skicka(res, 500, { ok: false, fel: 'okant' });
  }
}).listen(PORT, '127.0.0.1', () => console.log(`adraze-kolla på 127.0.0.1:${PORT}`));

laddaRegler();
hamtaListor();
setInterval(() => hamtaListor(true), 12 * 3_600_000).unref();
// Tillägget synkas hit vid varje release: läs om reglerna om de ändrats
fs.watch(path.join(TILLAGG, 'rules'), { persistent: false }, () => { try { laddaRegler(); } catch {} });
