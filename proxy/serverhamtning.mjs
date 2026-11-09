// Läget "Lätt" (som CroxyProxy): servern hämtar sidan själv med en anslutning som ser ut som Chrome (impit),
// i stället för att webbläsaren gör TLS genom Wisp. Behövs för sajter som TikTok, som avvisar allt som inte har
// Chromes TLS-handskakning. Priset: trafiken i det här läget är okrypterad på servern (vi loggar den inte).
//
// Säkerhet: impit får aldrig ansluta själv. Allt går genom en lokal CONNECT-vakt som gör samma kontroller som
// Wisp (bara port 443, inga IP-adresser, inga egna/interna namn, adblockerns värdlista, bara publika adresser
// efter namnuppslag), så läget kan inte användas för att nå interna tjänster.
import http from 'node:http';
import net from 'node:net';
import { Readable } from 'node:stream';
import { Impit } from 'impit';

const MAX_PER_IP = Number(process.env.SERVER_MAX_PER_IP || 32);
const MAX_TOTALT = Number(process.env.SERVER_MAX || 600);
const MAX_KROPP = 32 << 20;      // största förfrågningskropp (uppladdningar o.d.)
const TIDSGRANS = 60_000;
// Huvuden som hör till själva anslutningen och inte ska skickas vidare åt något håll
const HOPP = new Set(['host', 'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'content-length', 'expect']);
const UT_BORT = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'content-encoding', 'trailer', 'upgrade', 'proxy-authenticate']);

export function skapaServerhamtning({ vardStoppad, slaUppPublik, ipAv }) {
  // ---------- vakten ----------
  const vakt = http.createServer((req, res) => { res.writeHead(405); res.end(); });
  vakt.on('connect', async (req, sock, head) => {
    sock.on('error', () => {});
    try {
      const m = /^([a-z0-9.-]{1,253}):(\d{1,5})$/i.exec(String(req.url || ''));
      if (!m || Number(m[2]) !== 443 || net.isIP(m[1]) || vardStoppad(m[1])) throw new Error('stoppad');
      const ip = await slaUppPublik(m[1]);
      const ut = net.connect(443, ip);
      ut.setTimeout(120_000, () => ut.destroy());
      ut.on('error', () => sock.destroy());
      ut.on('close', () => sock.destroy());
      sock.on('close', () => ut.destroy());
      ut.once('connect', () => {
        sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head?.length) ut.write(head);
        ut.pipe(sock); sock.pipe(ut);
      });
    } catch { sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); }
  });
  let impit = null;
  const klar = new Promise((ok) => vakt.listen(0, '127.0.0.1', () => {
    // chrome151: den senaste profilen. Den äldre standardprofilen ("chrome") godtas inte längre av TikTok.
    impit = new Impit({ browser: 'chrome151', proxyUrl: `http://127.0.0.1:${vakt.address().port}`, followRedirects: false, timeout: TIDSGRANS });
    ok();
  }));

  const aktiva = { perIp: new Map(), totalt: 0 };

  function fel(res, kod, text) {
    if (res.headersSent) return res.destroy();
    res.writeHead(kod, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(text);
  }
  function lasKropp(req) {
    return new Promise((ok, nej) => {
      const delar = []; let n = 0;
      req.on('data', (d) => { n += d.length; if (n > MAX_KROPP) { nej(new Error('för stor')); req.destroy(); } else delar.push(d); });
      req.on('end', () => ok(Buffer.concat(delar)));
      req.on('error', nej);
    });
  }

  // POST /adraze/hamta  med huvudet x-adraze-mal = base64(JSON {url, method, headers: [[k, v], …]}) och kroppen som kropp.
  // Svaret: 200 med x-adraze-svar = base64(JSON {s: status, t: statusText, h: [[k, v], …]}) och sidans kropp.
  async function hamta(req, res) {
    // Bara proxyns egna sidor (annars kunde vilken sajt som helst använda servern som sin proxy)
    const ursprung = String(req.headers.origin || ''), vard = String(req.headers.host || '');
    if (ursprung !== `https://${vard}` && ursprung !== `http://${vard}`) return fel(res, 403, 'origin');
    let mal;
    try { mal = JSON.parse(Buffer.from(String(req.headers['x-adraze-mal'] || ''), 'base64').toString('utf8')); } catch { return fel(res, 400, 'mal'); }
    let url;
    try { url = new URL(mal.url); } catch { return fel(res, 400, 'url'); }
    if (url.protocol !== 'https:' || (url.port && url.port !== '443') || url.username || url.password) return fel(res, 400, 'url');
    const method = String(mal.method || 'GET').toUpperCase();
    if (!/^[A-Z]{3,10}$/.test(method) || method === 'CONNECT' || method === 'TRACE') return fel(res, 400, 'metod');
    if (net.isIP(url.hostname.replace(/^\[|\]$/g, '')) || vardStoppad(url.hostname)) return fel(res, 403, 'stoppad');
    const headers = [];
    if (Array.isArray(mal.headers)) for (const [k, v] of mal.headers) {
      const n = String(k).toLowerCase();
      if (!HOPP.has(n) && /^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(n)) headers.push([n, String(v)]);
    }

    const ip = ipAv(req);
    const n = aktiva.perIp.get(ip) || 0;
    if (n >= MAX_PER_IP || aktiva.totalt >= MAX_TOTALT) return fel(res, 429, 'för många');
    aktiva.perIp.set(ip, n + 1); aktiva.totalt++;
    let slut = false;
    const sluta = () => {
      if (slut) return; slut = true;
      const k = (aktiva.perIp.get(ip) || 1) - 1;
      if (k <= 0) aktiva.perIp.delete(ip); else aktiva.perIp.set(ip, k);
      aktiva.totalt--;
    };
    const ac = new AbortController();
    res.on('close', () => { sluta(); if (!res.writableFinished) ac.abort(); });

    try {
      const kropp = method === 'GET' || method === 'HEAD' ? undefined : await lasKropp(req);
      await klar;
      const svar = await impit.fetch(url.href, { method, headers, body: kropp?.length ? kropp : undefined, signal: ac.signal, redirect: 'manual', timeout: TIDSGRANS });
      const h = [];
      for (const [k, v] of svar.headers) if (k !== 'set-cookie' && !UT_BORT.has(k)) h.push([k, v]);
      for (const c of svar.headers.getSetCookie?.() || []) h.push(['set-cookie', c]);
      const meta = Buffer.from(JSON.stringify({ s: svar.status, t: svar.statusText || '', h })).toString('base64');
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Adraze-Svar': meta, 'X-Content-Type-Options': 'nosniff' });
      if (method === 'HEAD' || !svar.body) return res.end();
      const strom = Readable.fromWeb(svar.body);
      strom.on('error', () => res.destroy());
      strom.pipe(res);
    } catch (e) {
      if (ac.signal.aborted) return;
      fel(res, 502, String(e?.message || e).slice(0, 200));
    }
  }
  return { hamta, aktiva };
}
