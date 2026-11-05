// Låtsas-Stripe för test/pro-test.mjs: fångar fetch mot api.stripe.com och svarar ur STRIPE_MOCK (JSON-fil som testet skriver).
import fs from 'node:fs';
const FIL = process.env.STRIPE_MOCK;
const orig = globalThis.fetch;
globalThis.fetch = async (url, opt = {}) => {
  const u = String(url);
  if (!u.startsWith('https://api.stripe.com/')) return orig(url, opt);
  const st = JSON.parse(fs.readFileSync(FIL, 'utf8'));
  const m = u.match(/subscriptions\/([^?]+)/);
  st.anrop = (st.anrop || []).concat([`${opt.method || 'GET'} ${u.replace('https://api.stripe.com/v1/', '')}`]);
  let svar = { error: { message: 'okänt' } }, kod = 404;
  if (m && st.subs[decodeURIComponent(m[1])]) {
    const s = st.subs[decodeURIComponent(m[1])];
    if (opt.method === 'DELETE') { if (st.felVidDelete) { kod = 500; svar = { error: { message: 'nere' } }; } else { s.status = 'canceled'; kod = 200; svar = s; } }
    else { kod = 200; svar = s; }
  }
  fs.writeFileSync(FIL, JSON.stringify(st));
  return new Response(JSON.stringify(svar), { status: kod, headers: { 'content-type': 'application/json' } });
};
