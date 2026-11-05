// Falks webbsökning: sök via vår SearXNG (vaka-sok på doxing) och läs sidor som ren text.
// Sidhämtningen släpper bara igenom publika adresser (samma SSRF-skydd som chattens förhandsvisning).
const _dns = require('dns'), _net = require('net'), _http = require('http'), _https = require('https');

const SOK_URL = process.env.FALK_SOK_URL || 'http://127.0.0.1:8890/search';
// Bara Google CSE ger vettiga svar från vår instans (Bing ger skräp, resten blockeras/CAPTCHA)
const SOK_MOTORER = process.env.FALK_SOK_MOTORER || 'google cse';

// IPv6: bara global unicast (2000::/3) räknas som publik, och inte de delar av den som bär eller pekar på
// en annan adress (Teredo, 6to4) eller är IETF-/dokumentationsadresser. Allt annat (::/8 med ::a.b.c.d,
// fc00::/7, fe80::/10, fec0::/10, 64:ff9b::/96, multicast …) nekas.
const ICKE_PUBLIK6 = new _net.BlockList();
for (const [nat, bitar] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) ICKE_PUBLIK6.addSubnet(nat, bitar, 'ipv6');
function isPublicIp(ip) {
  ip = String(ip || '');
  if (_net.isIPv4(ip)) {
    const [a, b2] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b2 >= 64 && b2 <= 127) return false;       // CGNAT / tailnet
    if (a === 169 && b2 === 254) return false;
    if (a === 172 && b2 >= 16 && b2 <= 31) return false;
    if (a === 192 && (b2 === 168 || ip.startsWith('192.0.0.') || ip.startsWith('192.0.2.'))) return false;
    if (a === 198 && (b2 === 18 || b2 === 19)) return false;
    return true;
  }
  if (!_net.isIPv6(ip) || ip.includes('%')) return false;
  const l = ip.toLowerCase();
  const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return isPublicIp(m[1]);
  if ((parseInt(l.split(':')[0] || '0', 16) & 0xe000) !== 0x2000) return false;
  try { return !ICKE_PUBLIK6.check(l, 'ipv6'); } catch { return false; }
}
function safeLookup(host, opts, cb) {
  _dns.lookup(host, { all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = (addrs || []).filter((a) => isPublicIp(a.address));
    if (!ok.length || ok.length !== addrs.length) return cb(new Error('blocked_address'));
    if (opts && opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}
function safeGet(urlStr, maxBytes, hops = 0) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(urlStr); } catch { return reject(new Error('bad_url')); }
    if (!/^https?:$/.test(u.protocol)) return reject(new Error('bad_proto'));
    if (u.port && !['80', '443'].includes(u.port)) return reject(new Error('bad_port'));
    if (u.username || u.password) return reject(new Error('bad_url'));
    const bare = u.hostname.replace(/^\[|\]$/g, '');
    if (_net.isIP(bare) && !isPublicIp(bare)) return reject(new Error('blocked_address'));
    const mod = u.protocol === 'https:' ? _https : _http;
    const r = mod.request(u, { method: 'GET', lookup: safeLookup, timeout: 8000, agent: false, headers: {
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36',
      Accept: 'text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5', 'Accept-Language': 'sv,en;q=0.8' } }, (svar) => {
      if ([301, 302, 303, 307, 308].includes(svar.statusCode) && svar.headers.location) {
        svar.resume();
        if (hops >= 4) return reject(new Error('too_many_redirects'));
        let nx; try { nx = new URL(svar.headers.location, u).href; } catch { return reject(new Error('bad_redirect')); }
        return safeGet(nx, maxBytes, hops + 1).then(resolve, reject);
      }
      if (svar.statusCode !== 200) { svar.resume(); return reject(new Error('status_' + svar.statusCode)); }
      const chunks = []; let n = 0;
      svar.on('data', (c) => { n += c.length; chunks.push(c); if (n > maxBytes) svar.destroy(); });
      svar.on('close', () => resolve({ url: u.href, type: String(svar.headers['content-type'] || '').toLowerCase(), body: Buffer.concat(chunks).subarray(0, maxBytes) }));
      svar.on('error', reject);
    });
    r.on('timeout', () => r.destroy(new Error('timeout')));
    r.on('error', reject);
    r.end();
  });
}
function decodeEntities(t) {
  return String(t).replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (m, e) => {
    const l = e.toLowerCase();
    if (l[0] === '#') { const cp = l[1] === 'x' ? parseInt(l.slice(2), 16) : parseInt(l.slice(1), 10); try { return String.fromCodePoint(cp); } catch { return ''; } }
    return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[l];
  });
}
// HTML → text i linjär tid. Varje steg letar framåt från där förra träffen slutade och ger upp så fort
// det inte kan finnas fler träffar, så trasig eller fientlig HTML (t.ex. tusentals "<a" eller "<script"
// utan slut) inte kan låsa servern. Resultatet är detsamma som med de enkla regexarna.
const BLOCK_START = /<(script|style|noscript|svg|template|iframe|head)\b/gi;
const BLOCK_SLUT = {};
for (const n of ['script', 'style', 'noscript', 'svg', 'template', 'iframe', 'head']) BLOCK_SLUT[n] = new RegExp(`</${n}>`, 'gi');
const RADBRYT_START = /<(?:br|\/p|\/div|\/li|\/tr|\/h[1-6]|\/section|\/article|\/table)\b/gi;
function utanBlock(s) {
  let ut = '', fran = 0, m;
  const utanSlut = new Set();
  BLOCK_START.lastIndex = 0;
  while ((m = BLOCK_START.exec(s))) {
    const namn = m[1].toLowerCase();
    if (utanSlut.has(namn)) continue;
    const slut = BLOCK_SLUT[namn];
    slut.lastIndex = BLOCK_START.lastIndex;
    const e = slut.exec(s);
    if (!e) { utanSlut.add(namn); continue; }   // inget slut efter här, alltså inte heller efter senare starter
    ut += s.slice(fran, m.index) + ' ';
    fran = BLOCK_START.lastIndex = e.index + e[0].length;
  }
  return ut + s.slice(fran);
}
function utanKommentarer(s) {
  let ut = '', fran = 0;
  for (;;) {
    const a = s.indexOf('<!--', fran); if (a < 0) break;
    const b = s.indexOf('-->', a + 4); if (b < 0) break;
    ut += s.slice(fran, a) + ' '; fran = b + 3;
  }
  return ut + s.slice(fran);
}
// Taggar vars start matchar re ersätts (till och med första '>') med med
function ersattTaggar(s, re, med) {
  let ut = '', fran = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(s))) {
    const gt = s.indexOf('>', re.lastIndex);
    if (gt < 0) break;
    ut += s.slice(fran, m.index) + med;
    fran = re.lastIndex = gt + 1;
  }
  return ut + s.slice(fran);
}
function utanTaggar(s) {
  let ut = '', fran = 0, i = 0;
  for (;;) {
    const lt = s.indexOf('<', i); if (lt < 0) break;
    const gt = s.indexOf('>', lt + 1); if (gt < 0) break;
    if (gt === lt + 1) { i = lt + 1; continue; }   // "<>" är ingen tagg
    ut += s.slice(fran, lt) + ' ';
    fran = i = gt + 1;
  }
  return ut + s.slice(fran);
}
function titelAv(s) {
  const m = /<title/i.exec(s); if (!m) return '';
  const gt = s.indexOf('>', m.index + 6); if (gt < 0) return '';
  const slut = /<\/title>/gi; slut.lastIndex = gt + 1;
  const e = slut.exec(s);
  return e ? s.slice(gt + 1, e.index) : '';
}
function htmlTillText(html) {
  const titel = titelAv(html).trim();
  const t = utanTaggar(ersattTaggar(utanKommentarer(utanBlock(html)), RADBRYT_START, '\n').replace(/<\/t[dh]>/gi, ' | '));
  const text = decodeEntities(t).replace(/[ \t ]+/g, ' ').replace(/ *\n[\s\n]*/g, '\n').trim();
  return { titel: decodeEntities(titel).replace(/\s+/g, ' '), text };
}

async function sok(fraga, antal = 8) {
  const u = new URL(SOK_URL);
  u.searchParams.set('q', String(fraga).slice(0, 300)); u.searchParams.set('format', 'json');
  u.searchParams.set('engines', SOK_MOTORER);
  const r = await fetch(u, { signal: AbortSignal.timeout(12_000) });
  if (!r.ok) throw new Error('sok_' + r.status);
  const d = await r.json();
  return (d.results || []).filter((x) => /^https?:\/\//.test(x.url || '')).slice(0, antal)
    .map((x) => ({ titel: String(x.title || '').slice(0, 200), url: x.url, utdrag: String(x.content || '').replace(/\s+/g, ' ').slice(0, 400), datum: x.publishedDate || undefined }));
}

// Så mycket av sidan som tolkas. Texten kortas ändå till maxTecken, och taket gör tolkningen billig även för
// enorma sidor (allt sker på API:ts enda tråd).
const TOLKA_TECKEN = 1_000_000;
async function lasSida(url, maxTecken = 14_000) {
  const r = await safeGet(url, 3_000_000);
  if (r.type && !/text\/(html|plain)|xhtml|json|xml/.test(r.type)) throw new Error('inte_text');
  const raw = r.body.toString('utf8').slice(0, TOLKA_TECKEN);
  const { titel, text } = /html|xml/.test(r.type) || /<html|<body/i.test(raw.slice(0, 2000)) ? htmlTillText(raw) : { titel: '', text: raw };
  return { url: r.url, titel, text: text.slice(0, maxTecken) + (text.length > maxTecken ? '\n…(sidan kortad)' : '') };
}

module.exports = { sok, lasSida, isPublicIp };
