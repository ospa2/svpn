import { RU_V4, RU_V6 } from "./ruRanges";

// geo codes
export const GEO_PENDING = 0,
   GEO_RU = 1,
   GEO_OTHER = 2,
   GEO_UNKNOWN = 3;

// ── Range tables (decoded once, lazily) ──
function decode(b64) {
   const bin = atob(b64);
   const starts = [],
      ends = [];
   let pos = 0,
      prev = 0;
   const varint = () => {
      let n = 0,
         mul = 1,
         b;
      do {
         b = bin.charCodeAt(pos++);
         n += (b & 127) * mul; // Number math: v6 keys are 48-bit, bit ops would overflow
         mul *= 128;
      } while (b >= 128);
      return n;
   };
   while (pos < bin.length) {
      const s = prev + varint();
      const e = s + varint();
      starts.push(s);
      ends.push(e);
      prev = e;
   }
   return { starts: Float64Array.from(starts), ends: Float64Array.from(ends) };
}
let T4 = null,
   T6 = null;

function inRanges(t, x) {
   let lo = 0,
      hi = t.starts.length - 1;
   while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (x < t.starts[mid]) hi = mid - 1;
      else if (x > t.ends[mid]) lo = mid + 1;
      else return true;
   }
   return false;
}

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
export const isIPv4 = (h) => V4_RE.test(h);
export const isIPv6 = (h) => h.includes(":");
const stripBrackets = (h) => h.replace(/^\[|\]$/g, "");

function v6Top48(s) {
   const [h, t] = s.toLowerCase().split("::");
   const hs = h ? h.split(":") : [];
   const ts = t ? t.split(":") : [];
   const fill = s.includes("::") ? Math.max(0, 8 - hs.length - ts.length) : 0;
   const g = [...hs, ...Array(fill).fill("0"), ...ts].map((x) =>
      parseInt(x || "0", 16),
   );
   if (g.length < 3 || g.slice(0, 3).some(Number.isNaN)) return null;
   return (g[0] * 65536 + g[1]) * 65536 + g[2];
}

export function isRuIp(ip) {
   ip = stripBrackets(ip);
   const m = V4_RE.exec(ip);
   if (m) {
      const o = m.slice(1).map(Number);
      if (o.some((x) => x > 255)) return null;
      return inRanges(
         (T4 ??= decode(RU_V4)),
         ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3],
      );
   }
   if (isIPv6(ip)) {
      const k = v6Top48(ip);
      return k == null ? null : inRanges((T6 ??= decode(RU_V6)), k);
   }
   return null; // not an IP literal
}

// ── DoH resolution (browser-friendly, CORS enabled) ──
const DOH = [
   (n, t) =>
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
   (n, t) =>
      `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
];
const dnsCache = new Map(); // host -> Promise<string[]>

async function dohQuery(name, type, timeoutMs = 4000) {
   for (const mk of DOH) {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
         const r = await fetch(mk(name, type), {
            headers: { accept: "application/dns-json" },
            signal: ctrl.signal,
         });
         if (!r.ok) continue;
         const j = await r.json();
         const want = type === "A" ? 1 : 28;
         return (j.Answer || [])
            .filter((a) => a.type === want)
            .map((a) => a.data);
      } catch {
         /* try next resolver */
      } finally {
         clearTimeout(tid);
      }
   }
   return null; // all resolvers failed
}

function resolveHost(host) {
   let p = dnsCache.get(host);
   if (!p) {
      p = (async () => {
         const a = await dohQuery(host, "A");
         if (a && a.length) return a;
         const aaaa = await dohQuery(host, "AAAA");
         return aaaa ?? a; // null if both failed
      })();
      dnsCache.set(host, p);
   }
   return p;
}

// Returns Uint8Array of geo codes aligned with `hosts`.
// Each unique hostname is resolved once; IP literals need no network at all.
// A domain counts as RU if ANY of its resolved IPs is in a Russian range.
export async function classifyHosts(
   hosts,
   { concurrency = 30, onTick, isStale } = {},
) {
   const out = new Uint8Array(hosts.length);
   const byHost = new Map(); // host -> indices
   hosts.forEach((h, i) => {
      const k = stripBrackets(h || "");
      (byHost.get(k) ?? byHost.set(k, []).get(k)).push(i);
   });

   const set = (idxs, code) => idxs.forEach((i) => (out[i] = code));
   const domains = [];
   for (const [h, idxs] of byHost) {
      const lit = isRuIp(h);
      if (lit === true) set(idxs, GEO_RU);
      else if (lit === false) set(idxs, GEO_OTHER);
      else if (isIPv4(h) || isIPv6(h)) set(idxs, GEO_UNKNOWN);
      else domains.push([h, idxs]);
   }
   onTick?.();

   let cursor = 0,
      last = 0;
   const worker = async () => {
      while (cursor < domains.length && !isStale?.()) {
         const [h, idxs] = domains[cursor++];
         const ips = await resolveHost(h);
         if (!ips || !ips.length) set(idxs, GEO_UNKNOWN);
         else
            set(
               idxs,
               ips.some((ip) => isRuIp(ip) === true) ? GEO_RU : GEO_OTHER,
            );
         if (Date.now() - last > 250) {
            last = Date.now();
            onTick?.();
         }
      }
   };
   await Promise.all(
      Array.from({ length: Math.min(concurrency, domains.length) }, worker),
   );
   onTick?.();
   return out;
}
