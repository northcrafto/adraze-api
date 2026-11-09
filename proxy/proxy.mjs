// AdRaze Proxy: surfa via proxy.adraze.app med AdRazes adblocker inbyggd.
//
// Så funkar det:
//  - Sidan (webb/, byggd av ~/adraze/site/bygg.py) registrerar en service worker (Scramjet) som skriver om
//    sidorna så att allt de hämtar går genom proxyn.
//  - Två lägen som besökaren väljer:
//    * Fullt krypterad (standard): TLS görs i webbläsaren av transport/krypterad.wasm (Go + uTLS, samma
//      handskakning som Chrome, källkod i krypterad/) genom en Wisp-websocket hit, och servern öppnar bara
//      TCP-anslutningen. Vi kan alltså inte läsa sidorna, bara se värdnamnen.
//    * Lätt (serverhamtning.mjs): servern hämtar sidan själv med en Chrome-lik anslutning (impit), som de flesta
//      webbproxyer. Trafiken är då okrypterad på servern medan den passerar (den loggas eller sparas inte).
//    Sajter som TikTok avvisar allt utan Chromes TLS-handskakning, därför ser båda lägena ut som Chrome.
//    Websockets går i båda lägena genom libcurl.js (TLS i webbläsaren).
//  - Adblockern sitter i tre lager: 1) servern vägrar ansluta till reklam-/spårar-/farliga värdar,
//    2) service workern prövar varje förfrågan mot tilläggets regler med full adress, 3) sidorna får tilläggets
//    kosmetiska CSS (/adraze/k.css) som döljer annonsytor och kakrutor.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import net from 'node:net';
import util from 'node:util';
import dnsP from 'node:dns/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { server as wisp, logging } from '@mercuryworkshop/wisp-js/server';
import { skapaServerhamtning } from './serverhamtning.mjs';

const require = createRequire(import.meta.url);
const F = require('./filtermotor.cjs');
const { WebSocketServer } = require('ws');   // samma ws som wisp-js själv använder
const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PROXY_PORT || 8495);
const HOST = process.env.PROXY_HOST || '127.0.0.1';
const WEBB = path.join(DIR, 'webb');
const TILLAGG = path.join(DIR, 'extension');
const NM = path.join(DIR, 'node_modules', '@mercuryworkshop');
const MAX_WS_PER_IP = Number(process.env.PROXY_MAX_WS_PER_IP || 12);
const MAX_WS_TOTALT = Number(process.env.PROXY_MAX_WS || 400);

logging.set_level(logging.WARN);

// ---------- reglerna ----------
let regler = null; // { version, json, gz, server: Matchare, kos, kak }
function laddaRegler() {
  const las = (f) => JSON.parse(fs.readFileSync(path.join(TILLAGG, f), 'utf8'));
  const k = F.kompilera({ ads: las('rules/ads.json'), privacy: las('rules/privacy.json'), security: las('rules/security.json') });
  // Samma undantag som tilläggets dynamiska regler: YouTubes kvitto på att reklamen "visats" måste släppas igenom
  k.regler.push(['r', 0, 100000, { urlFilter: '||youtube.com/pagead/adview' }]);
  const json = JSON.stringify(k.regler);
  const version = crypto.createHash('sha256').update(json).digest('hex').slice(0, 12);
  const kos = las('data/cosmetic.json');
  kos.genericHide = new Set(kos.genericHideExceptions || []);
  const kak = las('data/kakor.json');
  const nya = {
    version, sida: byggSidskript(), json, gz: zlib.gzipSync(json, { level: 9 }), br: zlib.brotliCompressSync(json),
    server: new F.Matchare([], k.vardar), kos, kak, css: new Map(), cssJobb: new Map(),
    genericCss: cssAv(kos.generic), kakGenericCss: cssAv(kak.generic),
  };
  // Värdar som reglerna inte nämner (de allra flesta, och alla påhittade) får samma färdigkomprimerade post
  nya.cssStandard = komprimeraSynk(byggCss(nya, []));
  regler = nya;
  console.log(`regler ${version}: ${k.regler.length} till workern, värdar på servern`, Object.fromEntries(Object.entries(k.vardar).map(([a, b]) => [a, b.length])));
}
let reglernasTid = 0;
function kollaRegler() {
  try {
    const t = fs.statSync(path.join(TILLAGG, 'rules', 'ads.json')).mtimeMs;
    if (t !== reglernasTid) { reglernasTid = t; laddaRegler(); }
  } catch (e) { console.error('regler', e.message); }
}

// ---------- sidskripten (tilläggets content scripts, körda inne i de proxade sidorna) ----------
// Skripten laddas av sidan själv (SW:n lägger in en <script>-tagg) och skrivs inte om av Scramjet, så de ser
// proxyns riktiga adress. De får därför en egen "location" som pekar på den proxade sidan, och en låtsas-chrome
// som svarar på det tilläggets bakgrund annars svarar på.
const KAK_DOLJ = {
  sourcepoint: '[id^="sp_message_container"]{display:none!important}html.sp-message-open,html.sp-message-open body{overflow:auto!important}html.sp-message-open body{position:static!important}',
  didomi: '#didomi-host{display:none!important}body.didomi-popup-open,html.didomi-popup-open{overflow:auto!important}',
};
function byggSidskript() {
  const las = (f) => fs.readFileSync(path.join(TILLAGG, 'content', f), 'utf8');
  const kor = (src, villkor = 'true') => `if (${villkor}) try { (function (location, chrome) {\n${src}\n})(L, C); } catch (e) { console.warn('AdRaze', e); }\n`;
  return `// AdRaze Proxy: tilläggets sidskript (kakrutor, popup-vakt, YouTube) för den proxade sidan
(() => {
  if (window.__adrazeProxySida) return;
  window.__adrazeProxySida = true;
  const PREFIX = '/s/';
  const riktig = window.location;
  const proxad = () => { try { return new URL(decodeURIComponent(riktig.pathname.slice(PREFIX.length)) + riktig.hash); } catch (e) { return new URL('about:blank'); } };
  if (!riktig.pathname.startsWith(PREFIX)) return;
  const L = {};
  for (const k of ['href', 'hostname', 'host', 'origin', 'pathname', 'search', 'hash', 'protocol', 'port']) Object.defineProperty(L, k, { get: () => proxad()[k] });
  L.toString = () => proxad().href;
  const KAK_DOLJ = ${JSON.stringify(KAK_DOLJ)};
  // Översta proxade ramen (skalet med adressfältet ligger utanför /s/)
  function toppDok() {
    let w = window;
    try { while (w.parent !== w && w.parent.location.pathname.startsWith(PREFIX)) w = w.parent; } catch (e) {}
    return w.document;
  }
  const C = { runtime: { sendMessage(m) {
    if (m && m.typ === 'kakor') return Promise.resolve({ pa: true });
    if (m && m.typ === 'kak-dolj' && KAK_DOLJ[m.cmp]) {
      try { const d = toppDok(); const s = d.createElement('style'); s.textContent = KAK_DOLJ[m.cmp]; (d.head || d.documentElement).appendChild(s); } catch (e) {}
    }
    return Promise.resolve();
  } } };
  const host = L.hostname;
${kor(las('guard.js'))}${kor(las('kakor.js'))}${kor(las('youtube.js'), "/(^|\\.)youtube(-nocookie)?\\.com$/.test(host)")}})();
`;
}

// ---------- kosmetik (samma logik som tilläggets background.js) ----------
function cssAv(selektorer) {
  let css = '';
  for (let i = 0; i < selektorer.length; i += 100) css += selektorer.slice(i, i + 100).join(',\n') + '{display:none!important}\n';
  return css;
}
// Reglerna är vanliga objekt från JSON: slå bara upp egna nycklar, så att t.ex. h=constructor inte når Object.prototype
const har = (o, n) => !!o && Object.hasOwn(o, n);
function stilCss(k, nivaer, undantag) {
  let css = '';
  for (const n of nivaer) if (har(k.styles, n)) for (const [sel, decl] of k.styles[n]) if (!undantag.has(`${sel}:style(${decl})`)) css += `${sel}{${decl}}\n`;
  return css;
}
const KAK_UPPLAS = `html.sp-message-open,body.didomi-popup-open,html.didomi-popup-open,body.qc-cmp-ui-showing,html.qc-cmp-ui-showing,
body.cmp-modal-open,body.cookie-consent-open,body.onetrust-consent-sdk-open,html.cookiebot-open,body.CybotCookiebotDialogActive,
body.cky-modal-open,html.cmpbox-open,body.cmplz-cookiebanner-open{overflow:auto!important}
html.sp-message-open body{overflow:auto!important;position:static!important}\n`;
function delCss(k, nivaer, generic, genericCss, medGeneric) {
  const undantag = new Set();
  for (const n of nivaer) if (har(k.exceptions, n)) for (const s of k.exceptions[n]) undantag.add(s);
  const specifika = [];
  for (const n of nivaer) if (har(k.specific, n)) for (const s of k.specific[n]) if (!undantag.has(s)) specifika.push(s);
  let css = (specifika.length ? cssAv(specifika) : '') + stilCss(k, nivaer, undantag);
  if (medGeneric) css += undantag.size ? cssAv(generic.filter((s) => !undantag.has(s))) : genericCss;
  return css;
}
function byggCss(r, nivaer) {
  return delCss(r.kos, nivaer, r.kos.generic, r.genericCss, !nivaer.some((n) => r.kos.genericHide.has(n)))
    + delCss(r.kak, nivaer, r.kak.generic, r.kakGenericCss, true) + KAK_UPPLAS;
}
// Bara nivåer som reglerna nämner påverkar CSS:en. De är cachenyckeln, så ett slumpat värdnamn kostar ett uppslag
// i stället för en egen komprimering och en egen post i minnet.
function cssNivaer(r, host) {
  return F.foraldrar(host).filter((n) => r.kos.genericHide.has(n) || [r.kos, r.kak].some((k) => har(k.specific, n) || har(k.exceptions, n) || har(k.styles, n)));
}
const etagAv = (css) => '"' + crypto.createHash('sha1').update(css).digest('hex').slice(0, 16) + '"';
const BR5 = { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } };
const komprimeraSynk = (css) => ({ gz: zlib.gzipSync(css), br: zlib.brotliCompressSync(css, BR5), etag: etagAv(css) });
const gzipAsync = util.promisify(zlib.gzip), brotliAsync = util.promisify(zlib.brotliCompress);
const CSS_CACHE_MAX = 300, KOMPRIMERINGAR_MAX = 2;
let komprimeringar = 0;
// Ger posten direkt eller ett löfte om den. Komprimeringen görs i trådpoolen, högst två åt gången; är det fullt
// skickas CSS:en okomprimerad och utan cache, så att händelseloopen aldrig väntar på en komprimering.
function cssFor(host) {
  const r = regler;
  const nivaer = cssNivaer(r, host);
  if (!nivaer.length) return r.cssStandard;
  const nyckel = nivaer.join(',');
  const klar = r.css.get(nyckel) || r.cssJobb.get(nyckel);
  if (klar) return klar;
  const css = byggCss(r, nivaer);
  if (komprimeringar >= KOMPRIMERINGAR_MAX) return { raw: Buffer.from(css), etag: etagAv(css), tillfallig: true };
  komprimeringar++;
  const jobb = Promise.all([gzipAsync(css), brotliAsync(css, BR5)]).then(([gz, br]) => {
    const post = { gz, br, etag: etagAv(css) };
    r.css.set(nyckel, post);
    if (r.css.size > CSS_CACHE_MAX) r.css.delete(r.css.keys().next().value);
    return post;
  }).finally(() => { komprimeringar--; r.cssJobb.delete(nyckel); });
  r.cssJobb.set(nyckel, jobb);
  return jobb;
}

// ---------- Wisp: servern ansluter bara dit vi tillåter ----------
const EGNA = /(^|\.)(proxy\.adraze\.app|localhost|ts\.net|local|internal|lan|home\.arpa)$/i;
const statistik = { stoppade: 0, anslutningar: 0, start: Date.now() };
// Samma kontroll för Wisp och läget "Lätt"
function vardStoppad(host) {
  // Samma namn med avslutande punkt ("proxy.adraze.app.") eller versaler ska stoppas likadant
  host = String(host).toLowerCase().replace(/\.+$/, '');
  if (EGNA.test(host)) return true;
  const kat = regler?.server.vard(host);
  if (kat) { statistik.stoppade++; return true; }
  return false;
}
wisp.options.hostname_blacklist = [{ test: vardStoppad }];
wisp.options.port_whitelist = [80, 443];
wisp.options.allow_udp_streams = false;
wisp.options.allow_direct_ip = false;     // annars går värdlistan att kringgå med en IP-adress
wisp.options.allow_private_ips = false;
wisp.options.allow_loopback_ips = false;
wisp.options.stream_limit_total = 300;
wisp.options.stream_limit_per_host = 40;
// Egen namnupplösning (samma som wisp-js 'resolve' med ipv4first) som bara släpper igenom publika adresser,
// både IPv4 och IPv6 (där bara global unicast). Både filtret och själva anslutningen slår upp namnet här, så
// adressen som kontrolleras är alltid den som används.
const ICKE_PUBLIK = new net.BlockList();
for (const [nat, bitar] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]]) ICKE_PUBLIK.addSubnet(nat, bitar, 'ipv4');
for (const [nat, bitar] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) ICKE_PUBLIK.addSubnet(nat, bitar, 'ipv6');
function arPublik(ip) {
  ip = String(ip || '');
  if (net.isIPv4(ip)) return !ICKE_PUBLIK.check(ip, 'ipv4');
  if (!net.isIPv6(ip) || ip.includes('%')) return false;
  // IPv6: bara global unicast (2000::/3), utom delarna ovan som är reserverade eller pekar vidare mot IPv4
  if ((parseInt(ip.split(':')[0] || '0', 16) & 0xe000) !== 0x2000) return false;
  try { return !ICKE_PUBLIK.check(ip, 'ipv6'); } catch { return false; }
}
const DNS = new dnsP.Resolver();
DNS.setServers(['1.1.1.2', '1.0.0.2']);  // Cloudflares DNS med skadeprogramsfilter
async function slaUppPublik(host) {
  let adr;
  try { adr = (await DNS.resolve4(host))[0]; if (!adr) throw new Error('ingen A-post'); }
  catch { adr = (await DNS.resolve6(host))[0]; if (!adr) throw new Error('address not resolved'); }
  if (!arPublik(adr)) throw new Error('blocked_address');
  return adr;
}
wisp.options.dns_method = slaUppPublik;
wisp.options.parse_real_ip_from = ['127.0.0.1', '::1'];
wisp.options.wisp_motd = 'AdRaze Proxy';
const serverhamtning = skapaServerhamtning({ vardStoppad, slaUppPublik, ipAv: (req) => ipAv(req) });

// ---------- HTTP ----------
const TYPER = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.cjs': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.woff2': 'font/woff2', '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.ico': 'image/x-icon', '.map': 'application/json' };
// Motorns filer, serverade under /motor/
const MOTOR = {
  scram: path.join(NM, 'scramjet', 'dist'),
  baremux: path.join(NM, 'bare-mux', 'dist'),
  libcurl: path.join(NM, 'libcurl-transport', 'dist'),
  adraze: path.join(DIR, 'transport'),
};
const SAKERHET = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'interest-cohort=()',
};
const ipAv = (req) => String(req.headers['cf-connecting-ip'] || req.socket.remoteAddress || '');

function inom(bas, del) {
  const p = path.resolve(bas, '.' + path.posix.normalize('/' + del));
  return p.startsWith(bas + path.sep) || p === bas ? p : null;
}
function skickaFil(req, res, fil, extra = {}) {
  fs.stat(fil, (fel, st) => {
    if (fel || !st.isFile()) return skickaFel(req, res, 404);
    const typ = TYPER[path.extname(fil).toLowerCase()] || 'application/octet-stream';
    const etag = `"${st.size.toString(36)}-${Math.floor(st.mtimeMs).toString(36)}"`;
    const huvud = { 'Content-Type': typ, ETag: etag, ...SAKERHET, ...extra };
    // Sidan och dess eget js/css har inga versionsnummer i adressen: fråga alltid servern (ETag), annars
    // ligger gamla skript kvar i Cloudflare och webbläsaren i timmar efter en ändring
    if (!huvud['Cache-Control']) huvud['Cache-Control'] = /^text\/(html|css|javascript)/.test(typ) ? 'no-cache' : 'public, max-age=3600';
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, huvud); return res.end(); }
    huvud['Content-Length'] = st.size;
    res.writeHead(200, huvud);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(fil).pipe(res);
  });
}
function skickaFel(req, res, kod) {
  const sida = path.join(WEBB, '404.html');
  res.writeHead(kod, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', ...SAKERHET });
  res.end(kod === 404 && fs.existsSync(sida) ? fs.readFileSync(sida) : `<!doctype html><title>${kod}</title><p>${kod}</p>`);
}
function skickaKomprimerat(req, res, typ, data, huvud) {
  const ae = String(req.headers['accept-encoding'] || '');
  const h = { 'Content-Type': typ, Vary: 'Accept-Encoding', ...SAKERHET, ...huvud };
  if (huvud.ETag && req.headers['if-none-match'] === huvud.ETag) { res.writeHead(304, h); return res.end(); }
  if (/\bbr\b/.test(ae) && data.br) { h['Content-Encoding'] = 'br'; res.writeHead(200, h); return res.end(data.br); }
  if (/\bgzip\b/.test(ae) && data.gz) { h['Content-Encoding'] = 'gzip'; res.writeHead(200, h); return res.end(data.gz); }
  res.writeHead(200, h);
  res.end(data.gz ? zlib.gunzipSync(data.gz) : data.raw);
}


// Krypterade lägets motor (~13 MB, ~2,5 MB med brotli): förkomprimerad av krypterad/bygg.sh, läses in en gång
let wasmPost = null;
function skickaWasm(req, res) {
  try {
    const bas = path.join(DIR, 'transport', 'krypterad.wasm');
    const st = fs.statSync(bas);
    if (!wasmPost || wasmPost.mtime !== st.mtimeMs) {
      wasmPost = { mtime: st.mtimeMs, etag: `"w${st.size.toString(36)}-${Math.floor(st.mtimeMs).toString(36)}"`,
        br: fs.readFileSync(bas + '.br'), gz: fs.readFileSync(bas + '.gz') };
    }
  } catch { return skickaFel(req, res, 404); }
  return skickaKomprimerat(req, res, 'application/wasm', { br: wasmPost.br, gz: wasmPost.gz }, { ETag: wasmPost.etag, 'Cache-Control': 'no-cache' });
}

// ---------- bilder till ny flik-sidan ----------
// Bakgrundsfoton (Pexels) och genvägsikoner (DuckDuckGo) hämtas av servern, så att besökarens IP aldrig når dem.
// Bara foton i vår egen lista och vanliga värdnamn, högst 6 MB/400 kB, sparas på disk utanför koden.
const EXTCACHE = path.join(os.homedir(), '.cache', 'adraze-proxy');
fs.mkdirSync(path.join(EXTCACHE, 'bild'), { recursive: true });
fs.mkdirSync(path.join(EXTCACHE, 'ikon'), { recursive: true });
let bildIds = new Set(), bildLista = [];
function lasBildlista() {
  try { bildLista = JSON.parse(fs.readFileSync(path.join(WEBB, 'bakgrunder.json'), 'utf8')); } catch { bildLista = []; }
  bildIds = new Set(bildLista.map((b) => String(b[0]) + '/' + b[1]));
}
const bildPost = (b) => ({ id: b[0], fil: b[1], namn: b[2], farg: b[3] });
// /adraze/bakgrund -> ett slumpat foto, ?dag=2026-11-04 -> dagens (samma för alla den dagen), ?galleri -> ett urval
function bakgrund(u) {
  if (!bildLista.length) return null;
  if (u.searchParams.has('galleri')) return bildLista.filter((_, i) => i % Math.max(1, Math.floor(bildLista.length / 24)) === 0).slice(0, 24).map(bildPost);
  const dag = u.searchParams.get('dag');
  if (dag && /^\d{4}-\d{2}-\d{2}$/.test(dag)) return bildPost(bildLista[crypto.createHash('sha1').update(dag).digest().readUInt32BE(0) % bildLista.length]);
  return bildPost(bildLista[crypto.randomInt(bildLista.length)]);
}
lasBildlista();
setInterval(lasBildlista, 3_600_000).unref();
const BREDDER = new Set(['320', '640', '1280', '1600', '1920', '2560', '3840']);
const pagaende = new Map();
async function hamtaTillCache(fil, kalla, max, typer) {
  if (pagaende.has(fil)) return pagaende.get(fil);
  const jobb = (async () => {
    const r = await fetch(kalla, { redirect: 'follow', signal: AbortSignal.timeout(15000), headers: { 'User-Agent': 'AdRaze-Proxy/1.0 (+https://proxy.adraze.app)' } });
    const typ = (r.headers.get('content-type') || '').split(';')[0].trim();
    if (!r.ok || !typer.test(typ)) throw new Error('svar ' + r.status + ' ' + typ);
    if (Number(r.headers.get('content-length')) > max) throw new Error('för stor');
    const data = Buffer.from(await r.arrayBuffer());
    if (data.length > max) throw new Error('för stor');
    fs.writeFileSync(fil + '.tmp', data); fs.renameSync(fil + '.tmp', fil);
    fs.writeFileSync(fil + '.typ', typ);
  })().finally(() => pagaende.delete(fil));
  pagaende.set(fil, jobb);
  return jobb;
}
async function skickaExtern(req, res, fil, kalla, max, typer, livstid, vidMiss) {
  let st;
  try { st = fs.statSync(fil, { throwIfNoEntry: false }); } catch { return skickaFel(req, res, 404); }
  if (!st || Date.now() - st.mtimeMs > livstid * 1000) {
    try { await hamtaTillCache(fil, kalla, max, typer); if (!st) vidMiss?.(true); }
    catch { if (!st) { vidMiss?.(false); return skickaFel(req, res, 404); } }   // gammal kopia duger
  }
  try {
    const typ = fs.readFileSync(fil + '.typ', 'utf8');
    const data = fs.readFileSync(fil);
    res.writeHead(200, { 'Content-Type': typ, 'Content-Length': data.length, 'Cache-Control': `public, max-age=${livstid}`, ...SAKERHET });
    res.end(req.method === 'HEAD' ? undefined : data);
  } catch { skickaFel(req, res, 404); }
}

// Genvägsikoner: högst IKON_MAX värdar på disk (de äldsta tas bort), inget som inte hämtats om på 30 dygn,
// misslyckade värdar frågas inte om på en timme, och varje IP får högst 120 nya hämtningar per 10 minuter.
const IKONDIR = path.join(EXTCACHE, 'ikon');
const IKON_MAX = 5000, IKON_ALDER = 30 * 86_400_000, IKON_MISS_TTL = 3_600_000;
const ikonMiss = new Map();
let ikonAntal = 0;
function rensaIkoner(behall) {
  const filer = [];
  for (const f of fs.readdirSync(IKONDIR)) {
    if (f.endsWith('.typ')) continue;
    try { filer.push([f, fs.statSync(path.join(IKONDIR, f)).mtimeMs]); } catch {}
  }
  filer.sort((a, b) => a[1] - b[1]);
  const gammal = Date.now() - IKON_ALDER;
  let i = 0;
  for (; i < filer.length && (filer.length - i > behall || filer[i][1] < gammal || filer[i][0].endsWith('.tmp')); i++) {
    for (const f of [filer[i][0], filer[i][0] + '.typ']) try { fs.unlinkSync(path.join(IKONDIR, f)); } catch {}
  }
  ikonAntal = filer.length - i;
}
try { rensaIkoner(IKON_MAX); } catch (e) { console.error('ikoner', e.message); }
setInterval(() => { try { rensaIkoner(IKON_MAX); } catch (e) { console.error('ikoner', e.message); } }, 6 * 3_600_000).unref();
const traffar = new Map();
function begransad(nyckel, max, ms) {
  const t = Date.now(), lista = (traffar.get(nyckel) || []).filter((x) => t - x < ms);
  const over = lista.length >= max;
  if (!over) lista.push(t);
  traffar.set(nyckel, lista);
  return over;
}
setInterval(() => { const t = Date.now(); for (const [k, v] of traffar) if (!v.some((x) => t - x < 3_600_000)) traffar.delete(k); }, 600_000).unref();
async function skickaIkon(req, res, vard) {
  const fil = path.join(IKONDIR, vard);
  if (!fs.existsSync(fil)) {
    const miss = ikonMiss.get(vard);
    if (miss && Date.now() - miss < IKON_MISS_TTL) return skickaFel(req, res, 404);
    if (begransad('ikon:' + ipAv(req), 120, 600_000)) return skickaFel(req, res, 429);
    if (pagaende.size >= 16) return skickaFel(req, res, 503);
  }
  return skickaExtern(req, res, fil, `https://icons.duckduckgo.com/ip3/${vard}.ico`, 400 << 10, /^image\//, 7 * 86400, (ok) => {
    if (!ok) {
      ikonMiss.set(vard, Date.now());
      if (ikonMiss.size > 10_000) ikonMiss.delete(ikonMiss.keys().next().value);
    } else if (++ikonAntal > IKON_MAX) rensaIkoner(Math.floor(IKON_MAX * 0.9));
  });
}

// Ett fel i en enskild förfrågan ska aldrig ta ned hela proxyn: logga och svara (eller stäng) bara den
function misslyckad(req, res, kod = 404) {
  return (e) => {
    if (kod >= 500) console.error('förfrågan', req.method, String(req.url).slice(0, 200), e?.message || e);
    try { if (!res.headersSent) skickaFel(req, res, kod); else res.destroy(); } catch { res.destroy(); }
  };
}
const server = http.createServer((req, res) => {
  try { hantera(req, res); } catch (e) { misslyckad(req, res, 500)(e); }
});
function hantera(req, res) {
  let u, p;
  try { u = new URL(req.url, 'http://x'); p = decodeURIComponent(u.pathname); } catch { return skickaFel(req, res, 400); }
  if (p === '/adraze/hamta' && req.method === 'POST') return void serverhamtning.hamta(req, res).catch(misslyckad(req, res, 500));
  if (req.method !== 'GET' && req.method !== 'HEAD') return skickaFel(req, res, 405);

  if (p === '/sw.js') return skickaFil(req, res, path.join(WEBB, 'sw.js'), { 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' });
  if (p === '/adraze/sida.js') {
    const etag = `"s${regler.version}"`;
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, { ETag: etag }); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', ETag: etag, 'Cache-Control': 'public, max-age=3600', ...SAKERHET });
    return res.end(regler.sida);
  }
  if (p === '/adraze/filtermotor.js') return skickaFil(req, res, path.join(DIR, 'filtermotor.cjs'), { 'Cache-Control': 'no-cache' });
  if (p === '/adraze/regler.json') {
    return skickaKomprimerat(req, res, 'application/json', { gz: regler.gz, br: regler.br }, { ETag: `"${regler.version}"`, 'Cache-Control': 'public, max-age=3600', 'X-Regler': regler.version });
  }
  if (p === '/adraze/k.css') {
    const host = String(u.searchParams.get('h') || '').toLowerCase();
    if (!/^[a-z0-9.-]{1,253}$/.test(host)) return skickaFel(req, res, 400);
    const svara = (c) => skickaKomprimerat(req, res, 'text/css; charset=utf-8', c, { ETag: c.etag, 'Cache-Control': c.tillfallig ? 'no-cache' : 'public, max-age=86400', 'Access-Control-Allow-Origin': '*' });
    const c = cssFor(host);
    if (typeof c.then === 'function') return void c.then(svara).catch(misslyckad(req, res, 500));
    return svara(c);
  }
  if (p.startsWith('/adraze/stubbar/')) {
    const fil = inom(path.join(TILLAGG, 'stubbar'), p.slice('/adraze/stubbar/'.length));
    return fil ? skickaFil(req, res, fil, { 'Cache-Control': 'public, max-age=86400' }) : skickaFel(req, res, 404);
  }
  if (p === '/adraze/bakgrund') {
    const b = bakgrund(u);
    if (!b) return skickaFel(req, res, 404);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': u.searchParams.has('dag') || u.searchParams.has('galleri') ? 'public, max-age=3600' : 'no-store', ...SAKERHET });
    return res.end(JSON.stringify(b));
  }
  const bm = /^\/adraze\/bild\/(\d{1,12})\/(pexels-photo-\d{1,12}\.(?:jpe?g|png))$/.exec(p);
  if (bm) {
    const w = String(u.searchParams.get('w') || '1920');
    if (!bildIds.has(bm[1] + '/' + bm[2]) || !BREDDER.has(w)) return skickaFel(req, res, 404);
    return void skickaExtern(req, res, path.join(EXTCACHE, 'bild', `${bm[1]}-${w}`), `https://images.pexels.com/photos/${bm[1]}/${bm[2]}?auto=compress&cs=tinysrgb&w=${w}`, 6 << 20, /^image\/(jpeg|png|webp)$/, 30 * 86400)
      .catch(misslyckad(req, res));
  }
  const im = /^\/adraze\/ikon\/([a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,6})$/.exec(p.toLowerCase());
  // Värdnamnet blir filnamn på disken, och med .typ/.tmp måste det rymmas inom filsystemets 255 tecken
  if (im) return im[1].length > 250 ? skickaFel(req, res, 404) : void skickaIkon(req, res, im[1]).catch(misslyckad(req, res));
  if (p === '/adraze/status') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...SAKERHET });
    return res.end(JSON.stringify({ ok: true, regler: regler.version, anslutna: aktiva.totalt, serverhamtning: serverhamtning.aktiva.totalt, stoppade: statistik.stoppade, sedan: statistik.start }));
  }
  if (p === '/motor/adraze/krypterad.wasm') return skickaWasm(req, res);
  const m = /^\/motor\/(scram|baremux|libcurl|adraze)\/(.+)$/.exec(p);
  if (m) {
    const fil = inom(MOTOR[m[1]], m[2]);
    return fil ? skickaFil(req, res, fil, { 'Cache-Control': 'public, max-age=86400' }) : skickaFel(req, res, 404);
  }
  // Scramjets adresser (/s/…) ska bara besvaras av service workern. Kommer de hit saknas workern: tillbaka till starten.
  if (p.startsWith('/s/')) {
    res.writeHead(302, { Location: '/?u=' + encodeURIComponent(p.slice(3) + u.search), 'Cache-Control': 'no-store' });
    return res.end();
  }
  // Sajten: / -> index.html, /en/ -> en/index.html, /om -> om.html
  let fil = inom(WEBB, p);
  if (!fil) return skickaFel(req, res, 404);
  if (p.endsWith('/')) fil = path.join(fil, 'index.html');
  else if (!path.extname(fil)) {
    if (fs.existsSync(fil + '.html')) fil += '.html';
    else if (fs.existsSync(path.join(fil, 'index.html'))) { res.writeHead(308, { Location: p + '/' + u.search }); return res.end(); }
  }
  const html = fil.endsWith('.html');
  skickaFil(req, res, fil, html ? {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; worker-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
  } : {});
}

// ---------- websockets: begränsa per IP ----------
// Egen websocket-server för /wisp/ (i stället för wisp-js routeRequest), så att vi själva bestämmer största
// ramstorlek. Wisp-ramar är i praktiken några kB.
const wsServer = new WebSocketServer({ noServer: true, maxPayload: 1 << 20 });
async function korWisp(ws, req) {
  ws.binaryType = 'arraybuffer';
  // Ett fel på en enskild anslutning (t.ex. för stor ram) ska bara stänga just den
  ws.on('error', () => {});
  const wisp_version = req.headers['sec-websocket-protocol'] && wisp.options.wisp_version === 2 ? 2 : 1;
  const conn = new wisp.ServerConnection(ws, '/wisp/', { wisp_version });
  try { await conn.setup(); await conn.run(); } catch (e) {
    try { ws.close(); } catch {}
    if (!/^(HandshakeError|AccessDeniedError)$/.test(e?.constructor?.name || '')) console.error('wisp', e?.message || e);
  }
}
const aktiva = { perIp: new Map(), totalt: 0 };
server.on('upgrade', (req, socket, head) => {
  const p = (req.url || '').split('?')[0];
  if (p !== '/wisp/') { socket.destroy(); return; }
  const ursprung = String(req.headers.origin || '');
  // Bara sidor från samma värd får öppna Wisp (annars kunde vilken sajt som helst använda proxyn som sin egen)
  const vard = String(req.headers.host || '');
  if (ursprung && ursprung !== `https://${vard}` && ursprung !== `http://${vard}`) { socket.destroy(); return; }
  const ip = ipAv(req);
  const n = aktiva.perIp.get(ip) || 0;
  if (n >= MAX_WS_PER_IP || aktiva.totalt >= MAX_WS_TOTALT) {
    socket.end('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n');
    return;
  }
  aktiva.perIp.set(ip, n + 1); aktiva.totalt++; statistik.anslutningar++;
  let klar = false;
  const slut = () => {
    if (klar) return; klar = true;
    const k = (aktiva.perIp.get(ip) || 1) - 1;
    if (k <= 0) aktiva.perIp.delete(ip); else aktiva.perIp.set(ip, k);
    aktiva.totalt--;
  };
  socket.on('close', slut);
  socket.on('error', slut);
  wsServer.handleUpgrade(req, socket, head, (ws) => { korWisp(ws, req); });
});

kollaRegler();
setInterval(kollaRegler, 10 * 60_000).unref();
if (!regler) { console.error('kunde inte läsa reglerna i', TILLAGG); process.exit(1); }

server.keepAliveTimeout = 65_000;
server.listen(PORT, HOST, () => {
  console.log(`AdRaze Proxy på http://${HOST}:${PORT}`);
  // Ett löfte som ingen fångar ska bara loggas, inte ta ned proxyn för alla (läggs in först när servern är uppe)
  process.on('unhandledRejection', (e) => console.error('Ohanterat avvisat löfte:', e?.message || e));
});
for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => { server.close(); process.exit(0); });
