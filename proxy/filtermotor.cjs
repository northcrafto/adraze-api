// AdRaze filtermotor: samma regler som tillägget (DNR-JSON), men matchade i JavaScript.
// Körs på två ställen i proxyn:
//  - servern (proxy.mjs): delar upp reglerna i rena värdregler (stoppas redan vid anslutningen) och resten
//  - service workern (sw.js): prövar varje förfrågan sidan gör mot resten av reglerna med full adress
// Fungerar både som CommonJS-modul och som vanligt skript (importScripts).
(function (g) {
  'use strict';
  const FILER = { ads: 'reklam', privacy: 'sparare', security: 'farlig' };
  const VILLKOR_SOM_BEGRANSAR = ['initiatorDomains', 'excludedInitiatorDomains', 'resourceTypes', 'excludedResourceTypes', 'domainType', 'excludedRequestDomains', 'regexFilter', 'requestMethods', 'excludedRequestMethods', 'tabIds'];
  const REN_VARD = /^\|\|([a-z0-9.-]+)\^?$/i;
  const VARD_RE = /^\|\|([a-z0-9.-]+)(\^|\/|\*|$)/i;

  // a.b.example.se -> ["a.b.example.se", "b.example.se", "example.se"]
  function foraldrar(host) {
    const delar = host.split('.');
    const ut = [];
    for (let i = 0; i < delar.length - 1; i++) ut.push(delar.slice(i).join('.'));
    if (!ut.length) ut.push(host);
    return ut;
  }
  const ingarI = (host, lista) => lista.some((d) => host === d || host.endsWith('.' + d));
  // Grov "registrerbar domän" (räcker för tredjepartskoll)
  function bas(host) {
    const d = host.split('.');
    return d.length > 2 && /^(co|com|org|net|gov|ac|edu|or|ne|go)$/.test(d[d.length - 2]) && d[d.length - 1].length === 2 ? d.slice(-3).join('.') : d.slice(-2).join('.');
  }

  // ---------- serversidan: dela upp ----------
  // regelfiler = { ads: [...], privacy: [...], security: [...] } (tilläggets rules/*.json)
  // Ger { vardar: { reklam: [...], sparare: [...], farlig: [...] }, regler: [kompakta regler för service workern] }
  // En värd stoppas bara på servern om ingen tillåt-regel nämner värden, en förälder eller en underdomän.
  function kompilera(regelfiler) {
    const tillatVardar = new Set();
    for (const fil of Object.keys(FILER)) {
      for (const r of regelfiler[fil] || []) {
        if (r.action.type !== 'allow' && r.action.type !== 'allowAllRequests') continue;
        const c = r.condition;
        for (const d of c.requestDomains || []) tillatVardar.add(d.toLowerCase());
        const m = c.urlFilter && VARD_RE.exec(c.urlFilter);
        if (m) tillatVardar.add(m[1].toLowerCase());
      }
    }
    const tillatBas = new Set([...tillatVardar].map(bas));
    const krockar = (h) => tillatBas.has(bas(h)) && [...tillatVardar].some((t) => t === h || t.endsWith('.' + h) || h.endsWith('.' + t));

    const vardar = { reklam: new Set(), sparare: new Set(), farlig: new Set() };
    const regler = [];
    for (const [fil, kat] of Object.entries(FILER)) {
      for (const r of regelfiler[fil] || []) {
        const typ = r.action.type;
        if (typ !== 'block' && typ !== 'allow' && typ !== 'redirect') continue;
        const c = r.condition;
        const ren = typ === 'block' && !VILLKOR_SOM_BEGRANSAR.some((k) => k in c);
        if (ren && c.requestDomains && !c.urlFilter) {
          const kvar = [];
          for (const d of c.requestDomains) { const h = d.toLowerCase(); if (krockar(h)) kvar.push(h); else vardar[kat].add(h); }
          if (kvar.length) regler.push(kompakt(kat, r, { ...c, requestDomains: kvar }));
          continue;
        }
        const m = ren && !c.requestDomains && c.urlFilter && REN_VARD.exec(c.urlFilter);
        if (m && !krockar(m[1].toLowerCase())) { vardar[kat].add(m[1].toLowerCase()); continue; }
        regler.push(kompakt(kat, r, c));
      }
    }
    return { vardar: Object.fromEntries(Object.entries(vardar).map(([k, s]) => [k, [...s]])), regler };
  }
  // [kategori, blockera(1)/tillåt(0), prio, villkor, omdirigering]
  function kompakt(kat, r, c) {
    const v = {};
    for (const k of ['urlFilter', 'regexFilter', 'isUrlFilterCaseSensitive', 'requestDomains', 'excludedRequestDomains', 'initiatorDomains', 'excludedInitiatorDomains', 'resourceTypes', 'excludedResourceTypes', 'domainType']) if (c[k] !== undefined) v[k] = c[k];
    const ut = [kat[0], r.action.type === 'allow' ? 0 : 1, r.priority || 1, v];
    if (r.action.type === 'redirect' && r.action.redirect && r.action.redirect.extensionPath) ut.push(r.action.redirect.extensionPath);
    return ut;
  }

  // ---------- matchningen ----------
  function dnrRegex(f, skiftlage) {
    // DNR-syntax: ||värd, | ankare, * jokertecken, ^ avgränsare
    let r = '';
    let i = 0;
    if (f.startsWith('||')) { r = '^[a-z]+:\\/\\/([^/]*\\.)?'; i = 2; } else if (f.startsWith('|')) { r = '^'; i = 1; }
    const slut = f.endsWith('|') && !f.endsWith('||');
    const kropp = f.slice(i, slut ? -1 : undefined);
    for (const ch of kropp) r += ch === '*' ? '.*' : ch === '^' ? '(?:[^\\w.%-]|$)' : ch.replace(/[.+?${}()|[\]\\/]/g, '\\$&');
    if (slut) r += '$';
    try { return new RegExp(r, skiftlage ? '' : 'i'); } catch (e) { return null; }
  }
  const KAT = { r: 'reklam', s: 'sparare', f: 'farlig' };

  class Matchare {
    // kompakta = regler från kompilera(); varor = valfria värdlistor (servern skickar dem inte till workern)
    constructor(kompakta, varor) {
      this.domaner = new Map();
      this.perVard = new Map();
      this.allmanna = [];
      this.varor = new Map();
      for (const [kat, lista] of Object.entries(varor || {})) for (const h of lista) this.varor.set(h, kat);
      for (const k of kompakta) {
        const c = k[3];
        const regel = { kat: KAT[k[0]], blockera: k[1] === 1, prio: k[2], c, stubb: k[4] || null, re: null, kompilerad: false };
        if (c.requestDomains) {
          for (const d of c.requestDomains) { const h = d.toLowerCase(); if (!this.domaner.has(h)) this.domaner.set(h, []); this.domaner.get(h).push(regel); }
          continue;
        }
        const m = c.urlFilter && VARD_RE.exec(c.urlFilter);
        if (m) { const v = m[1].toLowerCase(); if (!this.perVard.has(v)) this.perVard.set(v, []); this.perVard.get(v).push(regel); } else this.allmanna.push(regel);
      }
    }
    // Värdkoll (servern): ger kategori eller null
    vard(host) {
      for (const v of foraldrar(host.toLowerCase())) { const k = this.varor.get(v); if (k) return k; }
      return null;
    }
    static passar(regel, f) {
      const c = regel.c;
      if (c.resourceTypes && !c.resourceTypes.includes(f.typ)) return false;
      if (c.excludedResourceTypes && c.excludedResourceTypes.includes(f.typ)) return false;
      if (c.domainType === 'thirdParty' && !f.tredje) return false;
      if (c.domainType === 'firstParty' && f.tredje) return false;
      if (c.initiatorDomains && !(f.fran && ingarI(f.fran, c.initiatorDomains))) return false;
      if (c.excludedInitiatorDomains && f.fran && ingarI(f.fran, c.excludedInitiatorDomains)) return false;
      if (c.excludedRequestDomains && ingarI(f.host, c.excludedRequestDomains)) return false;
      if (!regel.kompilerad) {
        regel.kompilerad = true;
        if (c.urlFilter) regel.re = dnrRegex(c.urlFilter, c.isUrlFilterCaseSensitive);
        else if (c.regexFilter) { try { regel.re = new RegExp(c.regexFilter, c.isUrlFilterCaseSensitive ? '' : 'i'); } catch (e) { regel.re = /(?!)/; } }
      }
      if (regel.re && !regel.re.test(f.url)) return false;
      return true;
    }
    // f = { url, typ (DNR-resurstyp), fran (sidans värd eller null) }
    // Ger { kat, stubb } eller null. Samma företräde som Chrome: högst prioritet vinner, tillåt vinner vid lika.
    klassa(f) {
      let u;
      try { u = new URL(f.url); } catch (e) { return null; }
      if (u.protocol !== 'http:' && u.protocol !== 'https:' && u.protocol !== 'ws:' && u.protocol !== 'wss:') return null;
      f.host = u.hostname.toLowerCase();
      f.tredje = !!f.fran && bas(f.host) !== bas(f.fran);
      const vk = this.vard(f.host);
      if (vk && f.typ !== 'main_frame') return { kat: vk, stubb: null };
      const kandidater = [];
      for (const v of foraldrar(f.host)) {
        const a = this.domaner.get(v); if (a) for (const r of a) kandidater.push(r);
        const b = this.perVard.get(v); if (b) for (const r of b) kandidater.push(r);
      }
      let blockera = null, tillat = 0;
      const prova = (r) => {
        if (r.blockera ? (blockera && r.prio <= blockera.prio) : r.prio <= tillat) return;
        if (!Matchare.passar(r, f)) return;
        if (r.blockera) blockera = r; else tillat = r.prio;
      };
      for (const r of kandidater) prova(r);
      for (const r of this.allmanna) prova(r);
      if (vk === 'farlig' && f.typ === 'main_frame') return { kat: vk, stubb: null };
      return blockera && blockera.prio > tillat ? { kat: blockera.kat, stubb: blockera.stubb } : null;
    }
  }

  const api = { kompilera, Matchare, foraldrar, bas };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else g.AdRazeFilter = api;
})(typeof self !== 'undefined' ? self : this);
