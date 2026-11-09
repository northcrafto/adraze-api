// AdRaze Proxy, krypterade läget: TLS görs här i webbläsaren av krypterad.wasm (Go + uTLS, samma handskakning
// som Chrome) över TCP-strömmar genom Wisp. Servern ser bara krypterade bytes och värdnamnet.
// Websockets går som förut genom libcurl.js (också krypterat i webbläsaren).
import '/motor/adraze/wasm_exec.js';
import LibcurlClient from '/motor/libcurl/index.mjs';

// libcurl.js laddar sin wasm i bakgrunden efter importen, och init() kastar fel tills den är klar
async function initLibcurl(lib) {
  for (let i = 0; ; i++) {
    try { return await lib.init(); } catch (e) { if (i > 300) throw e; await new Promise((ok) => setTimeout(ok, 50)); }
  }
}

// ---------- Wisp v1 (bara TCP) ----------
const T_CONNECT = 1, T_DATA = 2, T_CONTINUE = 3, T_CLOSE = 4;
const MAX_DATA = 64 << 10;

class Wisp {
  constructor(adress) { this.adress = adress; this.ws = null; this.oppen = null; this.strommar = new Map(); this.nasta = 1; }
  anslut() {
    if (this.oppen) return this.oppen;
    this.oppen = new Promise((ok, nej) => {
      const ws = new WebSocket(this.adress);
      ws.binaryType = 'arraybuffer';
      let klar = false;
      ws.onmessage = (e) => {
        const d = new Uint8Array(e.data);
        const v = new DataView(e.data);
        const typ = d[0], id = v.getUint32(1, true);
        if (id === 0 && typ === T_CONTINUE) {
          if (!klar) { klar = true; ok(); }
          return;
        }
        const s = this.strommar.get(id);
        if (!s) return;
        if (typ === T_DATA) s.ondata(d.subarray(5));
        else if (typ === T_CLOSE) this.stang(id, false);
      };
      const nere = () => {
        if (this.ws === ws) { this.ws = null; this.oppen = null; }
        for (const id of [...this.strommar.keys()]) this.stang(id, false);
        if (!klar) { klar = true; nej(new Error('wisp')); }
      };
      ws.onclose = nere;
      ws.onerror = nere;
      this.ws = ws;
    });
    return this.oppen;
  }
  paket(typ, id, nyttolast) {
    const b = new Uint8Array(5 + nyttolast.length);
    b[0] = typ; new DataView(b.buffer).setUint32(1, id, true); b.set(nyttolast, 5);
    this.ws?.send(b);
  }
  async dial(host, port, ondata, onclose) {
    await this.anslut();
    const id = this.nasta++;
    const namn = new TextEncoder().encode(host);
    const p = new Uint8Array(3 + namn.length);
    p[0] = 1; p[1] = port & 0xff; p[2] = port >> 8; p.set(namn, 3);
    // Ingen paketräkning: wisp-js (0.5.x) skickar aldrig CONTINUE för TCP-strömmar utan bromsar via websocketen,
    // så en klient som väntar på CONTINUE fastnar efter de första 128 paketen.
    const s = { ondata, onclose };
    this.strommar.set(id, s);
    this.paket(T_CONNECT, id, p);
    return {
      send: (u8) => { for (let i = 0; i < u8.length; i += MAX_DATA) this.paket(T_DATA, id, u8.subarray(i, i + MAX_DATA)); },
      close: () => this.stang(id, true),
    };
  }
  stang(id, skicka) {
    const s = this.strommar.get(id);
    if (!s) return;
    this.strommar.delete(id);
    if (skicka) this.paket(T_CLOSE, id, new Uint8Array([2]));
    try { s.onclose(); } catch {}
  }
}

// ---------- motorn ----------
let motor = null;
function laddaMotor(wasmAdress) {
  return motor ||= (async () => {
    const go = new globalThis.Go();
    const klar = new Promise((ok) => { globalThis.adrazeTlsKlar = ok; });
    const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmAdress), go.importObject);
    go.run(instance);
    await klar;
    return globalThis.adrazeTls;
  })();
}

let nastaReq = 1;
export default class AdRazeKrypterad {
  constructor(opt) {
    this.lib = new LibcurlClient({ wisp: opt.wisp });
    this.wisp = new Wisp(opt.wisp);
    this.wasm = opt.wasm || '/motor/adraze/krypterad.wasm';
    this.ready = false;
  }
  async init() {
    globalThis.adrazeNat = { dial: (h, p, d, c) => this.wisp.dial(h, p, d, c) };
    await Promise.all([initLibcurl(this.lib), laddaMotor(this.wasm)]);
    this.ready = true;
  }
  async meta() {}
  async request(remote, method, body, headers, signal) {
    const tls = await laddaMotor(this.wasm);
    const h = [];
    for (const [k, v] of Object.entries(headers || {})) for (const x of [].concat(v)) h.push([k, String(x)]);
    const kropp = body == null || method === 'GET' || method === 'HEAD' ? null : new Uint8Array(await new Response(body).arrayBuffer());
    const rid = nastaReq++;
    const avbryt = () => tls.abort(rid);
    if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    signal?.addEventListener('abort', avbryt, { once: true });
    let svar;
    try { svar = await tls.fetch(remote.href, method, h, kropp, rid); } catch (e) { avbryt(); throw new TypeError('AdRaze: ' + e.message); }
    const id = svar.body;
    const strom = new ReadableStream({
      async pull(c) {
        try {
          for (;;) {
            const bit = await tls.read(id);
            if (bit === null) { c.close(); avbryt(); return; }
            if (bit.length) { c.enqueue(bit); return; }
          }
        } catch (e) { c.error(e); avbryt(); }
      },
      cancel() { tls.cancel(id); avbryt(); },
    }, { highWaterMark: 2 });
    const rh = {};
    for (const [k, v] of svar.headers) (rh[k] ||= []).push(v);
    const tom = method === 'HEAD' || [101, 204, 205, 304].includes(svar.status);
    if (tom) strom.cancel();
    return { body: tom ? new ArrayBuffer(0) : strom, headers: rh, status: svar.status, statusText: svar.statusText };
  }
  connect(...a) { return this.lib.connect(...a); }
}
