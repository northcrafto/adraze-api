// Test: Falks kvoter (gratis 50 000 tokens + 2 sökfrågor per 14 dagar, Pro 2 miljoner per 30 dagar) och nödbromsarna
// som skyddar mot höga AI-kostnader. Kör mot en låtsas-AI och låtsas-sökning: inga riktiga anrop, inga kostnader.
// Kör: node test/falk-kvot-test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite'; import { fileURLToPath } from 'node:url';
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18531, AI_PORT = 18532, SOK_PORT = 18533, BAS = `http://127.0.0.1:${PORT}`;

// Låtsas-AI (OpenAI-format). Läget styrs av testet: 'svar' svarar direkt, 'sok' ber om en webbsökning först.
const ai = { anrop: [], lage: 'svar', usage: 1000, vanta: 0 };
const aiSrv = http.createServer((req, res) => {
  let kropp = ''; req.on('data', (d) => { kropp += d; });
  req.on('end', async () => {
    const b = JSON.parse(kropp || '{}'); ai.anrop.push({ model: b.model, max_tokens: b.max_tokens, tecken: JSON.stringify(b.messages).length, verktyg: (b.tools || []).length, val: b.tool_choice });
    if (ai.vanta) await new Promise((r) => setTimeout(r, ai.vanta));
    const harVerktygssvar = (b.messages || []).some((m) => m.role === 'tool');
    const message = ai.lage === 'sok' && !harVerktygssvar && b.tool_choice !== 'none'
      ? { role: 'assistant', content: '', tool_calls: [{ id: 'c1', type: 'function', function: { name: 'web_search', arguments: JSON.stringify({ query: 'test' }) } }] }
      : { role: 'assistant', content: 'Svar från låtsas-AI.' };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message }], usage: { total_tokens: ai.usage } }));
  });
});
const sok = { anrop: 0 };
const sokSrv = http.createServer((req, res) => { sok.anrop++; res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ results: [{ url: 'https://exempel.se/', title: 'Exempel', content: 'utdrag' }] })); });
await new Promise((r) => aiSrv.listen(AI_PORT, '127.0.0.1', r));
await new Promise((r) => sokSrv.listen(SOK_PORT, '127.0.0.1', r));

const tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'adraze-falk-kvot-'));
for (const f of fs.readdirSync(REPO)) if (f.endsWith('.js')) fs.copyFileSync(path.join(REPO, f), path.join(tmp, f));
const ENV = { PATH: process.env.PATH, HOME: tmp, PORT: String(PORT), MAIL_LOGG: '1', BREVO_API_KEY: '', CHATT_HOTLISTOR: '0', CLAMD_PORT: '1',
  CHATT_NYCKEL: crypto.randomBytes(32).toString('hex'), SUPPORT_SECRET: crypto.randomBytes(32).toString('hex'),
  STRIPE_SECRET_KEY: '', AI_CHAT_BASE: `http://127.0.0.1:${AI_PORT}/v1/chat/completions`, AI_CHAT_KEY: 'lats', AI_CHAT_MODEL: 'deepseek/deepseek-v4-flash-0731',
  FALK_SOK_URL: `http://127.0.0.1:${SOK_PORT}/search`, FALK_DAG_TAK: '400000', FALK_MINUT_TAK: '1000' };
let logg = ''; const srv = spawn(process.execPath, [path.join(tmp, 'server.js')], { cwd: tmp, env: ENV, stdio: ['ignore', 'pipe', 'pipe'] });
srv.stdout.on('data', (d) => { logg += d; }); srv.stderr.on('data', (d) => { logg += d; });
process.on('exit', () => { try { srv.kill(); } catch {} aiSrv.close(); sokSrv.close(); fs.rmSync(tmp, { recursive: true, force: true }); });
for (let i = 0; i < 100 && !logg.includes('adraze-api på'); i++) await new Promise((r) => setTimeout(r, 50));
const db = new DatabaseSync(path.join(tmp, 'adraze.db'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
let n = 0;
function konto(pro) {
  n++;
  const id = Number(db.prepare('INSERT INTO users(email,pass,verified,created_at,pro_until) VALUES(?,?,1,?,?)')
    .run(`falk${n}@test.invalid`, 'x:y', Date.now(), pro ? Date.now() + 20 * 86400_000 : null).lastInsertRowid);
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)').run(sha(token), id, Date.now() + 86400_000);
  return { id, token };
}
const fraga = async (v, text = 'Hej Falk', extra = {}) => {
  const r = await fetch(BAS + '/falk/chat', { method: 'POST', headers: { 'cf-connecting-ip': '10.8.0.' + v.id, authorization: 'Bearer ' + v.token, 'content-type': 'application/json' },
    body: JSON.stringify({ messages: [{ role: 'system', content: 'Du är Falk.' }, { role: 'user', content: text }], ...extra }) });
  let j = null; try { j = await r.json(); } catch {} return { s: r.status, j };
};
let ok = 0, fel = 0; const koll = (namn, v, info) => { if (v) { ok++; console.log('  ok  ', namn); } else { fel++; console.log('  FEL ', namn, JSON.stringify(info ?? '').slice(0, 400)); } };
const rad = (id) => db.prepare('SELECT * FROM falk_kvot WHERE user_id=?').get(id);

// 1) Gratis: Falk svarar med den mindre modellen och visar kvoten
let g = konto(false); ai.lage = 'svar'; ai.usage = 1000;
let r = await fraga(g);
koll('gratis: Falk svarar (ingen Pro-vägg)', r.s === 200 && r.j?.reply === 'Svar från låtsas-AI.', r);
koll('gratis: Qwen-modellen och kort svarslängd', ai.anrop.at(-1)?.model === 'qwen/qwen3.7-flash' && ai.anrop.at(-1)?.max_tokens === 1500, ai.anrop.at(-1));
koll('gratis: kvoten visas (50 000, 2 sökfrågor, 14 dagar)', r.j?.kvot?.plan === 'gratis' && r.j.kvot.tak === 50_000 && r.j.kvot.anvant === 1000 && r.j.kvot.sokKvar === 2
  && Math.abs(r.j.kvot.fyllsPa - (rad(g.id).start + 14 * 86400_000)) < 5, r.j?.kvot);
r = await fetch(BAS + '/falk/kvot', { headers: { authorization: 'Bearer ' + g.token } }).then((x) => x.json());
koll('GET /falk/kvot', r.kvot?.anvant === 1000 && r.kvot?.kvar === 49_000, r);

// 2) Gratis: tokens tar slut → 429 och AI:n anropas inte alls
ai.usage = 30_000; await fraga(g); await fraga(g);
let fore = ai.anrop.length;
r = await fraga(g);
koll('gratis: slut på tokens → 429 kvot_slut med datum', r.s === 429 && r.j?.error === 'kvot_slut' && /fylls på/.test(r.j?.message || '') && r.j?.kvot?.kvar === 0, r);
koll('gratis: AI:n anropas inte när kvoten är slut', ai.anrop.length === fore, ai.anrop.length - fore);

// 3) Perioden fylls på efter 14 dagar
db.prepare('UPDATE falk_kvot SET start=? WHERE user_id=?').run(Date.now() - 15 * 86400_000, g.id);
ai.usage = 1000; r = await fraga(g);
koll('gratis: efter 14 dagar fylls kvoten på', r.s === 200 && r.j?.kvot?.anvant === 1000 && r.j.kvot.sokKvar === 2, r.j?.kvot);

// 4) Gratis: två frågor med webbsökning, sedan svarar Falk utan sökning och ber om Pro
ai.lage = 'sok'; let s0 = sok.anrop;
r = await fraga(g, 'Vad är vädret?'); koll('gratis: sökfråga 1 söker', r.s === 200 && sok.anrop === s0 + 1 && r.j?.kvot?.sokKvar === 1, { s: sok.anrop - s0, k: r.j?.kvot });
r = await fraga(g, 'Vad är vädret i morgon?'); koll('gratis: sökfråga 2 söker', r.s === 200 && sok.anrop === s0 + 2 && r.j?.kvot?.sokKvar === 0, { s: sok.anrop - s0, k: r.j?.kvot });
r = await fraga(g, 'Och på söndag?');
koll('gratis: tredje sökfrågan söker inte', sok.anrop === s0 + 2, sok.anrop - s0);
koll('gratis: svaret säger uppgradera=sok (Pro-rutan)', r.s === 200 && r.j?.uppgradera === 'sok' && !!r.j?.reply, r.j);
koll('gratis: vanliga frågor fungerar fortfarande', (ai.lage = 'svar', (await fraga(g)).s === 200));

// 5) Gratis: stora inklistringar kortas så en fråga inte kan bränna hela kvoten
const g2 = konto(false); ai.usage = 500;
await fraga(g2, 'x'.repeat(110_000));
koll('gratis: inmatningen kortas till ~60 000 tecken', ai.anrop.at(-1).tecken < 75_000, ai.anrop.at(-1).tecken);

// 6) Pro: större modell, stor kvot, fler sökningar
const p = konto(true); ai.usage = 1000;
r = await fraga(p);
koll('pro: DeepSeek och 4000 i svarslängd', ai.anrop.at(-1)?.model === 'deepseek/deepseek-v4-flash-0731' && ai.anrop.at(-1)?.max_tokens === 4000, ai.anrop.at(-1));
koll('pro: kvoten 2 miljoner per 30 dagar, inga sökfrågegränser', r.j?.kvot?.plan === 'pro' && r.j.kvot.tak === 2_000_000 && r.j.kvot.sokKvar === null
  && Math.abs(r.j.kvot.fyllsPa - (rad(p.id).start + 30 * 86400_000)) < 5, r.j?.kvot);
db.prepare('UPDATE falk_kvot SET tokens=? WHERE user_id=?').run(2_000_000, p.id); fore = ai.anrop.length;
r = await fraga(p);
koll('pro: slut på kvoten → 429 utan AI-anrop', r.s === 429 && r.j?.error === 'kvot_slut' && ai.anrop.length === fore, r);

// 7) Byte gratis → Pro ger Pro-kvoten direkt
db.prepare('UPDATE users SET pro_until=? WHERE id=?').run(Date.now() + 20 * 86400_000, g.id);
r = await fraga(g); koll('uppgradering: Pro-kvoten gäller direkt', r.s === 200 && r.j?.kvot?.plan === 'pro' && r.j.kvot.anvant === 1000, r.j?.kvot);

// 8) En fråga i taget per konto (skript som skickar massor samtidigt)
const s = konto(false); ai.vanta = 400; ai.usage = 100;
const samtidigt = await Promise.all([fraga(s), fraga(s), fraga(s), fraga(s), fraga(s)]);
ai.vanta = 0;
koll('samtidiga frågor: bara en går igenom, resten 429', samtidigt.filter((x) => x.s === 200).length === 1 && samtidigt.filter((x) => x.s === 429).length === 4, samtidigt.map((x) => x.s));

// 9) Utan inloggning: ingen AI
fore = ai.anrop.length;
r = await fetch(BAS + '/falk/chat', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messages: [{ role: 'user', content: 'hej' }] }) });
koll('utan inloggning: 401 och inget AI-anrop', r.status === 401 && ai.anrop.length === fore, r.status);

// 10) Nödbromsen för hela servern: dygnstaket (400 000 i testet) stoppar alla
const m = konto(true); ai.usage = 150_000;
for (let i = 0; i < 4; i++) await fraga(m);
fore = ai.anrop.length;
const ny = konto(false); ai.usage = 100;
r = await fraga(ny);
koll('dygnstaket: 503 för alla och inget AI-anrop', r.s === 503 && ai.anrop.length === fore, r);
console.log(logg.includes('dygnstaket nått') ? '  (servern loggade att dygnstaket nåddes)' : '');

console.log(`\n${ok} ok, ${fel} fel`);
process.exit(fel ? 1 : 0);
