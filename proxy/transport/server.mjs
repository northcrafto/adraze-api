// AdRaze Proxy, läget "Lätt": https-sidor hämtas av servern (/adraze/hamta) med en Chrome-lik anslutning.
// Websockets och vanlig http går som förut, krypterat genom Wisp med libcurl.js.
import LibcurlClient from '/motor/libcurl/index.mjs';

// libcurl.js laddar sin wasm i bakgrunden efter importen, och init() kastar fel tills den är klar
async function initLibcurl(lib) {
  for (let i = 0; ; i++) {
    try { return await lib.init(); } catch (e) { if (i > 300) throw e; await new Promise((ok) => setTimeout(ok, 50)); }
  }
}

const b64 = (s) => { const b = new TextEncoder().encode(s); let t = ''; for (let i = 0; i < b.length; i += 0x8000) t += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(t); };
const fran64 = (s) => new TextDecoder().decode(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)));

export default class AdRazeServer {
  constructor(opt) {
    this.lib = new LibcurlClient({ wisp: opt.wisp });
    this.server = opt.server || '/adraze/hamta';
    this.ready = false;
  }
  async init() { await initLibcurl(this.lib); this.ready = true; }
  async meta() {}
  async request(remote, method, body, headers, signal) {
    if (remote.protocol !== 'https:') return this.lib.request(remote, method, body, headers, signal);
    const h = [];
    for (const [k, v] of Object.entries(headers || {})) for (const x of [].concat(v)) h.push([k, String(x)]);
    const kropp = body == null || method === 'GET' || method === 'HEAD' ? undefined : await new Response(body).arrayBuffer();
    const r = await fetch(this.server, {
      method: 'POST', body: kropp, signal, cache: 'no-store', credentials: 'omit',
      headers: { 'x-adraze-mal': b64(JSON.stringify({ url: remote.href, method, headers: h })) },
    });
    const meta = r.headers.get('x-adraze-svar');
    if (!r.ok || !meta) throw new TypeError('AdRaze: ' + r.status + ' ' + (await r.text().catch(() => '')).slice(0, 200));
    const m = JSON.parse(fran64(meta));
    const rh = {};
    for (const [k, v] of m.h) (rh[k] ||= []).push(v);
    return { body: r.body || new ArrayBuffer(0), headers: rh, status: m.s, statusText: m.t };
  }
  connect(...a) { return this.lib.connect(...a); }
}
