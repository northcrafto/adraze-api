// AdRaze Pro: prenumeration via Stripe (Payment Element i webbläsarens Falk-panel) och Falks AI.
// Pro gäller till users.pro_until (ms). Förnyelser läses från Stripe när perioden gått ut,
// så ingen webhook behövs.
module.exports = ({ rutt, q, db, fel, kravInloggad, begransad, now }) => {
  const KEY = process.env.STRIPE_SECRET_KEY || '';
  const PK = process.env.STRIPE_PUBLISHABLE_KEY || '';
  const AI_BASE = process.env.AI_CHAT_BASE || '';
  const AI_KEY = process.env.AI_CHAT_KEY || '';
  const AI_MODEL = process.env.AI_CHAT_MODEL || '';
  const AI_PER_DYGN = 300;

  for (const [kol, typ] of [['stripe_customer', 'TEXT'], ['pro_sub', 'TEXT'], ['pro_until', 'INTEGER']]) {
    if (!q(`SELECT 1 FROM pragma_table_info('users') WHERE name='${kol}'`).get()) db.exec(`ALTER TABLE users ADD COLUMN ${kol} ${typ}`);
  }

  const PLANER = {
    pro_month: { lookup: 'adraze_pro_month', belopp: 7900, intervall: 'month' },
    pro_year: { lookup: 'adraze_pro_year', belopp: 109000, intervall: 'year' },
  };

  // Låst API-version: prenumerationen har current_period_end och fakturan payment_intent.
  async function stripe(metod, sokvag, falt) {
    const r = await fetch(`https://api.stripe.com/v1/${sokvag}`, {
      method: metod,
      headers: { authorization: `Bearer ${KEY}`, 'content-type': 'application/x-www-form-urlencoded', 'stripe-version': '2024-06-20' },
      body: falt ? new URLSearchParams(falt).toString() : undefined,
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { console.error('Stripe pro', r.status, d.error?.message); throw fel(502, 'Betalningen kunde inte startas just nu. Försök igen om en stund.'); }
    return d;
  }

  // Produkt och priser skapas första gången och hittas sedan via lookup_key.
  const prisCache = {};
  async function prisFor(plan) {
    const p = PLANER[plan];
    if (prisCache[plan]) return prisCache[plan];
    const finns = await stripe('GET', `prices?active=true&lookup_keys[]=${p.lookup}`);
    let pris = finns.data?.[0];
    if (!pris) {
      pris = await stripe('POST', 'prices', {
        currency: 'sek', unit_amount: String(p.belopp), 'recurring[interval]': p.intervall, lookup_key: p.lookup,
        'product_data[name]': 'AdRaze Pro', 'metadata[app]': 'adraze',
      });
    }
    return (prisCache[plan] = pris);
  }

  const arPro = (u) => !!(u.pro_until && u.pro_until > now());

  async function kundFor(u) {
    if (u.stripe_customer) return u.stripe_customer;
    const k = await stripe('POST', 'customers', { email: u.email, 'metadata[adraze_user]': String(u.id) });
    q('UPDATE users SET stripe_customer=? WHERE id=?').run(k.id, u.id);
    return k.id;
  }

  // Läser prenumerationen från Stripe och sparar hur länge Pro gäller.
  async function lasPrenumeration(u, subId) {
    const s = await stripe('GET', `subscriptions/${encodeURIComponent(subId)}`);
    if (s.customer !== u.stripe_customer) throw fel(400, 'Okänd prenumeration.');
    const aktiv = s.status === 'active' || s.status === 'trialing';
    const tills = aktiv ? s.current_period_end * 1000 + 3_600_000 : null;   // en timmes marginal för förnyelsen
    q('UPDATE users SET pro_sub=?, pro_until=? WHERE id=?').run(s.id, tills, u.id);
    return { aktiv, tills, slutar: !!s.cancel_at_period_end };
  }

  // Anropas från GET /me: har perioden gått ut kollar vi om Stripe förnyat den.
  const senastKoll = new Map();
  async function uppdatera(u) {
    if (!KEY || !u.pro_sub || arPro(u)) return u;
    if (now() - (senastKoll.get(u.id) || 0) < 600_000) return u;
    senastKoll.set(u.id, now());
    try { await lasPrenumeration(u, u.pro_sub); } catch {}
    return q('SELECT * FROM users WHERE id=?').get(u.id);
  }

  rutt('POST', '/pro/intent', async (req, res, b) => {
    const u = kravInloggad(req);
    if (!KEY || !PK) throw fel(503, 'Betalning är inte igång just nu.');
    if (arPro(u)) throw Object.assign(fel(409, 'Du har redan Pro.'), { kropp: { ok: false, error: 'already_pro', message: 'Du har redan Pro på det här kontot.' } });
    if (!PLANER[b.plan]) throw fel(400, 'Okänd plan.');
    if (begransad(`pro:${u.id}`, 20, 3_600_000)) throw fel(429, 'För många försök. Vänta en stund.');
    const [pris, kund] = await Promise.all([prisFor(b.plan), kundFor(u)]);
    // Gamla ofullbordade försök städas, så kunden inte får flera obetalda prenumerationer
    const gamla = await stripe('GET', `subscriptions?customer=${kund}&status=incomplete&limit=10`);
    await Promise.all((gamla.data || []).map((s) => stripe('DELETE', `subscriptions/${s.id}`).catch(() => {})));
    const s = await stripe('POST', 'subscriptions', {
      customer: kund, 'items[0][price]': pris.id, payment_behavior: 'default_incomplete',
      'payment_settings[save_default_payment_method]': 'on_subscription', 'payment_settings[payment_method_types][0]': 'card',
      'expand[0]': 'latest_invoice.payment_intent', 'metadata[app]': 'adraze', 'metadata[plan]': b.plan,
    });
    const pi = s.latest_invoice?.payment_intent;
    if (!pi?.client_secret) throw fel(502, 'Betalningen kunde inte startas just nu. Försök igen om en stund.');
    return { client_secret: pi.client_secret, publishable_key: PK, amount: pi.amount, currency: pi.currency, kind: 'subscription', interval: PLANER[b.plan].intervall, subscription: s.id };
  });

  rutt('POST', '/pro/confirm', async (req, res, b) => {
    const u = kravInloggad(req);
    if (!/^sub_[A-Za-z0-9]{8,64}$/.test(b.subscription || '')) throw fel(400, 'Okänd prenumeration.');
    if (!u.stripe_customer) throw fel(400, 'Okänd prenumeration.');
    // Stripe kan behöva en kort stund på sig efter kortbetalningen
    let r = { aktiv: false };
    for (let i = 0; i < 4 && !r.aktiv; i++) {
      if (i) await new Promise((ok) => setTimeout(ok, 1500));
      r = await lasPrenumeration(u, b.subscription);
    }
    return { pro: r.aktiv, until: r.tills };
  });

  // Status för inställningarna: hur länge Pro gäller och om prenumerationen är uppsagd
  rutt('GET', '/pro/status', async (req) => {
    const u = await uppdatera(kravInloggad(req));
    const svar = { pro: arPro(u), until: u.pro_until || null, prenumeration: null };
    if (KEY && u.pro_sub) {
      try {
        const s = await stripe('GET', `subscriptions/${encodeURIComponent(u.pro_sub)}`);
        if (s.customer === u.stripe_customer) {
          const pris = s.items?.data?.[0]?.price;
          svar.prenumeration = { status: s.status, slutar: !!s.cancel_at_period_end, periodSlut: s.current_period_end * 1000,
            intervall: pris?.recurring?.interval || null, belopp: pris?.unit_amount ?? null, valuta: pris?.currency || null };
        }
      } catch {}
    }
    return svar;
  });

  // Säg upp: Pro gäller perioden ut och förnyas sedan inte
  rutt('POST', '/pro/cancel', async (req) => {
    const u = kravInloggad(req);
    if (!u.pro_sub) throw fel(400, 'Du har ingen prenumeration.');
    const nu = await stripe('GET', `subscriptions/${encodeURIComponent(u.pro_sub)}`);
    if (nu.customer !== u.stripe_customer) throw fel(400, 'Okänd prenumeration.');
    if (nu.status !== 'active' && nu.status !== 'trialing') throw fel(400, 'Prenumerationen är redan avslutad.');
    const s = await stripe('POST', `subscriptions/${encodeURIComponent(u.pro_sub)}`, { cancel_at_period_end: 'true' });
    return { until: s.current_period_end * 1000 };
  });

  // Ångra uppsägningen innan perioden gått ut
  rutt('POST', '/pro/resume', async (req) => {
    const u = kravInloggad(req);
    if (!u.pro_sub) throw fel(400, 'Du har ingen prenumeration.');
    const nu = await stripe('GET', `subscriptions/${encodeURIComponent(u.pro_sub)}`);
    if (nu.customer !== u.stripe_customer) throw fel(400, 'Okänd prenumeration.');
    if (nu.status !== 'active' && nu.status !== 'trialing') throw fel(400, 'Prenumerationen har redan tagit slut. Skaffa Pro igen i Falk.');
    const s = await stripe('POST', `subscriptions/${encodeURIComponent(u.pro_sub)}`, { cancel_at_period_end: 'false' });
    return { until: s.current_period_end * 1000 };
  });

  // Falk: AI-assistenten, bara för Pro
  rutt.max('/falk/chat', 1_400_000);   // bifogade filer/mappar och projektfiler (klienten håller sig under ~60k + 100k tecken)
  rutt('POST', '/falk/chat', async (req, res, b) => {
    const u = await uppdatera(kravInloggad(req));
    if (!arPro(u)) throw Object.assign(fel(402, 'Falk ingår i AdRaze Pro.'), { kropp: { ok: false, error: 'no_pro', message: 'Falk ingår i AdRaze Pro.' } });
    if (!AI_BASE || !AI_KEY) throw fel(503, 'Falk är inte igång just nu.');
    if (begransad(`falk:${u.id}`, AI_PER_DYGN, 86_400_000)) throw fel(429, 'Du har ställt väldigt många frågor i dag. Försök igen i morgon.');
    const msgs = (Array.isArray(b.messages) ? b.messages : []).slice(-16)
      .filter((m) => m && ['user', 'assistant', 'system'].includes(m.role) && typeof m.content === 'string')
      .map((m) => ({ role: m.role, content: m.content.slice(0, 120_000) }));
    if (!msgs.length) throw fel(400, 'Skriv en fråga.');
    // Totalt tak: blir det för mycket kortas de äldsta meddelandena först (instruktionerna först i listan och din senaste fråga behålls)
    let tot = msgs.reduce((a, m) => a + m.content.length, 0);
    for (let i = 2; tot > 280_000 && i < msgs.length - 1; i++) { tot -= msgs[i].content.length; msgs[i].content = msgs[i].content.slice(0, 2000) + '\n…(äldre meddelande kortat)'; tot += msgs[i].content.length; }
    const r = await fetch(AI_BASE, {
      method: 'POST', signal: AbortSignal.timeout(60_000),
      headers: { authorization: `Bearer ${AI_KEY}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model: AI_MODEL, messages: msgs, max_tokens: 4000, temperature: 0.4, reasoning_effort: 'none' }),
    }).catch(() => null);
    const d = r ? await r.json().catch(() => ({})) : {};
    const svar = d.choices?.[0]?.message?.content;
    if (!r?.ok || !svar) { console.error('Falk', r?.status, d.error?.message); throw fel(502, 'Falk kunde inte svara just nu. Försök igen om en stund.'); }
    return { reply: svar };
  });

  return { arPro, uppdatera };
};
