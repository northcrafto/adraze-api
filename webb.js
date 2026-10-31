// Falks webbsökning: sök via vår SearXNG (vaka-sok på doxing) och läs sidor som ren text.
// Sidhämtningen släpper bara igenom publika adresser (samma SSRF-skydd som chattens förhandsvisning).
const _dns = require('dns'), _net = require('net'), _http = require('http'), _https = require('https');

const SOK_URL = process.env.FALK_SOK_URL || 'http://127.0.0.1:8890/search';
// Bara Google CSE ger vettiga svar från vår instans (Bing ger skräp, resten blockeras/CAPTCHA)
const SOK_MOTORER = process.env.FALK_SOK_MOTORER || 'google cse';

function isPublicIp(ip) {
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
  const l = ip.toLowerCase();
  if (l === '::' || l === '::1' || /^fe[89ab]/.test(l) || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('ff')) return false;
  const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return isPublicIp(m[1]);
  if (l.startsWith('::ffff:') || l.startsWith('64:ff9b:')) return false;
  return true;
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
function htmlTillText(html) {
  const titel = ((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').trim();
  const t = html
    .replace(/<(script|style|noscript|svg|template|iframe|head)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(br|\/p|\/div|\/li|\/tr|\/h[1-6]|\/section|\/article|\/table)\b[^>]*>/gi, '\n')
    .replace(/<\/t[dh]>/gi, ' | ')
    .replace(/<[^>]+>/g, ' ');
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

async function lasSida(url, maxTecken = 14_000) {
  const r = await safeGet(url, 3_000_000);
  if (r.type && !/text\/(html|plain)|xhtml|json|xml/.test(r.type)) throw new Error('inte_text');
  const raw = r.body.toString('utf8');
  const { titel, text } = /html|xml/.test(r.type) || /<html|<body/i.test(raw.slice(0, 2000)) ? htmlTillText(raw) : { titel: '', text: raw };
  return { url: r.url, titel, text: text.slice(0, maxTecken) + (text.length > maxTecken ? '\n…(sidan kortad)' : '') };
}

module.exports = { sok, lasSida, isPublicIp };
