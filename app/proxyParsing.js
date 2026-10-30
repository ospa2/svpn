// Проверка структуры ссылок. Не проверяет доступность серверов,
// результаты DNS и полную совместимость конфигурации с Xray.

const PARSE_CHUNK = 1500;

const UNSAFE_PORTS = new Set([
   1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
   87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
   139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
   540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
   2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669,
   6679, 6697, 10080,
]);

const fail = (reason) => {
   throw new Error(reason);
};

const record = (x) => x !== null && typeof x === "object" && !Array.isArray(x);

const enabled = (x) => x === true || x === 1 || /^(1|true)$/i.test(String(x));

const base = (proto, host, port, transport, security, sni, path = "/") => ({
   proto,
   host,
   port,
   transport,
   security,
   sni,
   path,
});

function uint(x, min = 0) {
   return (
      (typeof x === "number" || typeof x === "string") &&
      /^\d+$/.test(String(x)) &&
      Number.isSafeInteger(Number(x)) &&
      Number(x) >= min
   );
}

function portOf(x, fallback) {
   if (x === undefined || x === null || x === "") {
      if (fallback === undefined) fail("missing-port");
      return fallback;
   }

   if (!uint(x, 1) || Number(x) > 65535) {
      fail("invalid-port");
   }

   return Number(x);
}

function decode64(s) {
   s = s.replace(/-/g, "+").replace(/_/g, "/");

   if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
      fail("invalid-base64");
   }

   s = s.replace(/=+$/, "");

   const binary = atob(s + "=".repeat((4 - (s.length % 4)) % 4));

   return new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(binary, (c) => c.charCodeAt(0)),
   );
}

function jsonObject(s, label) {
   let j;

   try {
      j = JSON.parse(s);
   } catch {
      fail(`invalid-${label}-json`);
   }

   if (!record(j)) fail(`invalid-${label}-object`);

   return j;
}

function range(a, min) {
   // Строгая политика:
   // [значение], [min, max] или [min, max, шаг].
   return (
      Array.isArray(a) &&
      a.length >= 1 &&
      a.length <= 3 &&
      a.every((x) => uint(x, min)) &&
      (a.length < 2 || Number(a[1]) >= Number(a[0])) &&
      (a.length < 3 || Number(a[2]) > 0)
   );
}

function checkFm(value) {
   const fm = typeof value === "string" ? jsonObject(value, "fm") : value;

   if (!record(fm) || !Object.keys(fm).length) {
      fail("invalid-fm-object");
   }

   for (const [transport, masks] of Object.entries(fm)) {
      if (!["tcp", "udp"].includes(transport) || !Array.isArray(masks)) {
         fail("unsupported-fm-format");
      }

      for (const mask of masks) {
         if (
            !record(mask) ||
            typeof mask.type !== "string" ||
            !mask.type.trim() ||
            !record(mask.settings)
         ) {
            fail("invalid-mask");
         }

         // Другие маски проверяются только структурно.
         if (mask.type !== "fragment") continue;

         const s = mask.settings;

         if (transport !== "tcp") {
            fail("fragment-requires-tcp");
         }

         // Не угадываем смысл старых форматов других клиентов.
         if ("length" in s || "delay" in s) {
            fail("unsupported-fragment-format");
         }

         if (!range(s.lengths, 1)) {
            fail("invalid-fragment-lengths");
         }

         if ("delays" in s && !range(s.delays, 0)) {
            fail("invalid-fragment-delays");
         }

         if ("maxSplit" in s && !uint(s.maxSplit, 0)) {
            fail("invalid-fragment-maxSplit");
         }
      }
   }
}

function checkObjectParams(j) {
   for (const [k, v] of Object.entries(j)) {
      if (
         /^(insecure|allowInsecure|skip-cert-verify)$/i.test(k) &&
         enabled(v)
      ) {
         fail("insecure-tls");
      }
   }

   if ("fm" in j) checkFm(j.fm);

   if ("extra" in j) {
      const extra =
         typeof j.extra === "string" ? jsonObject(j.extra, "extra") : j.extra;

      if (!record(extra)) {
         fail("invalid-extra-object");
      }
   }
}

function readUrl(core) {
   const u = new URL(core);

   const critical = new Set([
      "fm",
      "extra",
      "security",
      "type",
      "sni",
      "host",
      "insecure",
      "allowinsecure",
      "skip-cert-verify",
   ]);

   const allowedCase = new Set([
      "fm",
      "extra",
      "security",
      "type",
      "sni",
      "host",
      "insecure",
      "allowInsecure",
      "skip-cert-verify",
   ]);

   const seen = new Set();

   for (const [k] of u.searchParams) {
      const key = k.toLowerCase();

      if (critical.has(key) && seen.has(key)) {
         fail("duplicate-critical-param");
      }

      seen.add(key);

      if (critical.has(key) && !allowedCase.has(k)) {
         fail("unsupported-param-case");
      }
   }

   checkObjectParams(Object.fromEntries(u.searchParams));

   // Строго отклоняем старую неоднозначную форму fragment=...
   if (u.searchParams.has("fragment")) {
      fail("unsupported-legacy-fragment");
   }

   const authority = core
      .slice(core.indexOf("://") + 3)
      .split(/[/?#]/, 1)[0]
      .split("@")
      .pop();

   if (authority.endsWith(":")) {
      fail("empty-port");
   }

   return u;
}

function normalizeHost(input) {
   if (
      typeof input !== "string" ||
      !input ||
      input !== input.trim() ||
      /[\s/?#@%\\]/.test(input)
   ) {
      fail("invalid-host");
   }

   let h = input
      .toLowerCase()
      .replace(/^\[|\]$/g, "")
      .replace(/\.$/, "");

   const u = new URL(`http://${h.includes(":") ? `[${h}]` : h}/`);

   if (u.port || u.username || u.password) {
      fail("invalid-host");
   }

   h = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");

   if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local")) {
      fail("local-host");
   }

   if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
      const [a, b] = h.split(".").map(Number);

      if (
         a === 0 ||
         a === 10 ||
         a === 127 ||
         a >= 224 ||
         (a === 169 && b === 254) ||
         (a === 172 && b >= 16 && b <= 31) ||
         (a === 192 && b === 168) ||
         (a === 100 && b >= 64 && b <= 127)
      ) {
         fail("non-public-ip");
      }
   } else if (h.includes(":")) {
      if (
         h === "::" ||
         h === "::1" ||
         /^(fc|fd|ff)/.test(h) ||
         /^fe[89ab]/.test(h)
      ) {
         fail("non-public-ip");
      }

      // Строгая политика: IPv4-mapped IPv6 не принимаем.
      if (h.startsWith("::ffff:")) {
         fail("ipv4-mapped-ipv6");
      }
   } else if (
      h.length > 253 ||
      !h
         .split(".")
         .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
   ) {
      fail("invalid-host");
   }

   return h;
}

export function repairMangled(raw) {
   const hi = raw.indexOf("#");
   if (hi < 0) return raw;

   let frag;

   try {
      frag = decodeURIComponent(raw.slice(hi + 1));
   } catch {
      return raw;
   }

   if (!/(^|[?&])security=tls(?:&|#|$)/.test(frag)) {
      return raw;
   }

   const s = frag.search(/[?&]/);
   if (s < 0) return raw;

   try {
      const tail = frag.slice(s + 1);
      const inner = new URLSearchParams(tail.split("#")[0]);
      const u = new URL(raw.slice(0, hi));

      for (const k of [
         "security",
         "type",
         "host",
         "sni",
         "fp",
         "alpn",
         "ech",
      ]) {
         if (inner.has(k)) {
            u.searchParams.set(k, inner.get(k));
         }
      }

      if (inner.has("ed")) {
         const path = u.searchParams.get("path") || "/";
         const q = path.indexOf("?");
         const pathname = q < 0 ? path : path.slice(0, q);
         const params = new URLSearchParams(q < 0 ? "" : path.slice(q + 1));

         params.set("ed", inner.get("ed"));

         u.searchParams.set("path", `${pathname}?${params}`);
      }

      const name = frag.includes("#")
         ? frag.slice(frag.lastIndexOf("#") + 1)
         : frag.slice(0, s);

      u.hash = encodeURIComponent(name);

      return u.toString();
   } catch {
      return raw;
   }
}

function vmessObject(core) {
   const j = jsonObject(decode64(core.slice(8)), "vmess");

   checkObjectParams(j);

   if (typeof j.id !== "string" || !j.id.trim()) {
      fail("missing-vmess-id");
   }

   return j;
}

function parseSS(core) {
   const rest = core.slice(5);
   let endpoint;
   let auth;

   if (rest.includes("@")) {
      const u = readUrl(core);

      if (u.password) {
         auth =
            `${decodeURIComponent(u.username)}:` +
            decodeURIComponent(u.password);
      } else {
         auth = decode64(decodeURIComponent(u.username));
      }

      endpoint = {
         host: u.hostname,
         port: portOf(u.port),
      };
   } else {
      const decoded = decode64(rest);
      const at = decoded.lastIndexOf("@");

      if (at < 1) fail("invalid-ss");

      auth = decoded.slice(0, at);

      const u = readUrl(`ss://${decoded.slice(at + 1)}`);

      endpoint = {
         host: u.hostname,
         port: portOf(u.port),
      };
   }

   const colon = auth.indexOf(":");

   if (colon < 1 || colon === auth.length - 1) {
      fail("invalid-ss-auth");
   }

   // Поддержка конкретного шифра зависит от целевого ядра.
   return base(
      "ss",
      endpoint.host,
      endpoint.port,
      "tcp",
      "none",
      endpoint.host,
   );
}

function parseUri(core) {
   const scheme = core.slice(0, core.indexOf("://")).toLowerCase();

   if (scheme === "vmess") {
      const j = vmessObject(core);

      return base(
         "vmess",
         j.add,
         portOf(j.port),
         j.net || "tcp",
         j.tls === "tls" ? "tls" : "none",
         j.sni || j.host || j.add,
         j.path || "/",
      );
   }

   if (scheme === "ss") {
      return parseSS(core);
   }

   const defaults = {
      vless: 443,
      trojan: 443,
      hysteria: 443,
      hysteria2: 443,
      hy2: 443,
      tuic: 443,
      socks: 1080,
      socks5: 1080,
      socks4: 1080,
      http: 80,
      https: 443,
   };

   if (!(scheme in defaults)) {
      fail("unsupported-protocol");
   }

   const u = readUrl(core);
   const p = Object.fromEntries(u.searchParams);
   const port = portOf(u.port, defaults[scheme]);

   if (
      ["vless", "trojan", "hysteria2", "hy2", "tuic"].includes(scheme) &&
      !u.username
   ) {
      fail("missing-auth");
   }

   if (scheme === "tuic" && !u.password) {
      fail("missing-tuic-password");
   }

   decodeURIComponent(u.username);
   decodeURIComponent(u.password);

   if (scheme === "vless" || scheme === "trojan") {
      return base(
         scheme,
         u.hostname,
         port,
         p.type || "tcp",
         p.security || (scheme === "trojan" ? "tls" : "none"),
         p.sni || p.host || u.hostname,
         p.path || "/",
      );
   }

   if (["hysteria", "hysteria2", "hy2"].includes(scheme)) {
      return base(
         scheme === "hy2" ? "hysteria2" : scheme,
         u.hostname,
         port,
         "udp",
         "tls",
         p.sni || u.hostname,
      );
   }

   if (scheme === "tuic") {
      return base(scheme, u.hostname, port, "quic", "tls", p.sni || u.hostname);
   }

   return base(
      scheme,
      u.hostname,
      port,
      "tcp",
      scheme === "https" ? "tls" : "none",
      u.hostname,
      u.pathname || "/",
   );
}

function parsePlain(core, proto) {
   if (!["socks", "socks4", "socks5", "http", "https"].includes(proto)) {
      fail("invalid-plain-protocol");
   }

   let host;
   let port;
   let login = null;
   let password = null;

   if (core.includes("@")) {
      const at = core.lastIndexOf("@");
      const auth = core.slice(0, at);
      const colon = auth.indexOf(":");

      if (colon < 1) fail("invalid-plain-auth");

      login = auth.slice(0, colon);
      password = auth.slice(colon + 1);

      const authority = core.slice(at + 1);
      const u = readUrl(`${proto}://${authority}`);

      host = u.hostname;

      const m = authority.match(/:(\d+)$/);

      if (!m) fail("missing-port");

      port = portOf(m[1]);
   } else if (core.startsWith("[")) {
      const m = core.match(/^\[([^\]]+)\]:(\d+)$/);

      if (!m) fail("invalid-plain-ipv6");

      [, host, port] = m;
      port = portOf(port);
   } else {
      const parts = core.split(":");

      if (parts.length === 2) {
         [host, port] = parts;
      } else if (parts.length === 4) {
         const [a, b, c, d] = parts;

         // Сохраняем прежний приоритет login:pass:host:port.
         if (/^\d+$/.test(d)) {
            [login, password, host, port] = [a, b, c, d];
         } else if (/^\d+$/.test(b)) {
            [host, port, login, password] = parts;
         } else {
            fail("invalid-plain");
         }
      } else {
         fail("invalid-plain");
      }

      port = portOf(port);
   }

   if (login !== null && (!login || !password)) {
      fail("invalid-plain-auth");
   }

   return {
      ...base(
         proto,
         host,
         port,
         "tcp",
         proto === "https" ? "tls" : "none",
         host,
      ),
      login,
      password,
      plain: true,
   };
}


export function canonicalKey(core, fields = null) {
   const f = fields || parseUri(core);

   const endpoint = [f.proto, normalizeHost(f.host), portOf(f.port)];

   // VMess: группируем по адресу и ID.
   if (f.proto === "vmess") {
      const j = vmessObject(core);

      return JSON.stringify(["aggressive", ...endpoint, j.id]);
   }

   // Shadowsocks: учитываем метод шифрования и пароль,
   // независимо от способа их кодирования в ссылке.
   if (f.proto === "ss") {
      const rest = core.slice(5);
      let auth;

      if (rest.includes("@")) {
         const u = readUrl(core);

         auth = u.password
            ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`
            : decode64(decodeURIComponent(u.username));
      } else {
         const decoded = decode64(rest);
         const at = decoded.lastIndexOf("@");

         if (at < 1) fail("invalid-ss");
         auth = decoded.slice(0, at);
      }

      const colon = auth.indexOf(":");

      if (colon < 1 || colon === auth.length - 1) {
         fail("invalid-ss-auth");
      }

      return JSON.stringify([
         "aggressive",
         ...endpoint,
         auth.slice(0, colon),
         auth.slice(colon + 1),
      ]);
   }

   // VLESS, Trojan, TUIC, HTTP, SOCKS и другие URI.
   const u = readUrl(core);

   const username = decodeURIComponent(u.username);
   const password = decodeURIComponent(u.password);

   // У Hysteria реквизиты могут передаваться
   // не в userinfo, а отдельным параметром.
   const queryAuth =
      f.proto === "hysteria" || f.proto === "hysteria2"
         ? [u.searchParams.get("auth"), u.searchParams.get("password")]
         : null;

   return JSON.stringify([
      "aggressive",
      ...endpoint,
      username,
      password,
      queryAuth,
   ]);
}

export function parseProxyDetailed(raw, defaultPlainProto = "socks5") {
   try {
      if (typeof raw !== "string") {
         fail("invalid-input");
      }

      const trimmed = repairMangled(raw.trim());

      if (!trimmed) fail("empty");

      const hash = trimmed.indexOf("#");
      const core = hash < 0 ? trimmed : trimmed.slice(0, hash);

      let name = hash < 0 ? "" : trimmed.slice(hash + 1);

      // Ошибка кодирования имени не делает сервер невалидным.
      try {
         name = decodeURIComponent(name);
      } catch {}

      let fields = core.includes("://")
         ? parseUri(core)
         : parsePlain(core, defaultPlainProto);

      fields = {
         ...fields,
         host: normalizeHost(fields.host),
         port: portOf(fields.port),
      };

      const key = fields.plain
         ? JSON.stringify([
              "plain",
              fields.proto,
              fields.host,
              fields.port,
              fields.login,
              fields.password,
           ])
         : canonicalKey(core, fields);;

      return {
         proxy: {
            ...fields,
            raw: trimmed,
            name: name.trim() || `${fields.host}:${fields.port}`,
            key,
            untestable: UNSAFE_PORTS.has(fields.port),
         },
         reason: null,
      };
   } catch (e) {
      // Не возвращаем URI или реквизиты в диагностике.
      const known =
         /^(missing-|invalid-|unsupported-|duplicate-|insecure-|fragment-|empty|local-host|non-public-ip|ipv4-mapped-ipv6)/;

      return {
         proxy: null,
         reason: known.test(e.message) ? e.message : "invalid-link",
      };
   }
}

export function parseProxy(raw, defaultPlainProto = "socks5") {
   return parseProxyDetailed(raw, defaultPlainProto).proxy;
}

export function toCopyString(p, format = "uri") {
   if (!p.plain) return p.raw;

   const host = p.host.includes(":") ? `[${p.host}]` : p.host;

   if (format === "plain") {
      return p.login != null
         ? `${host}:${p.port}:${p.login}:${p.password}`
         : `${host}:${p.port}`;
   }

   const name = encodeURIComponent(p.name || `${host}:${p.port}`);

   const auth =
      p.login != null
         ? `${encodeURIComponent(p.login)}:${encodeURIComponent(p.password)}@`
         : "";

   return `${p.proto}://${auth}${host}:${p.port}#${name}`;
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

export async function parseAndDedupe(
   text,
   plainProto = "socks5",
   isCancelled = () => false,
) {
   const lines = text.split(/\r?\n/);
   const map = new Map();

   for (let s = 0; s < lines.length; s += PARSE_CHUNK) {
      if (isCancelled()) return null;

      const end = Math.min(s + PARSE_CHUNK, lines.length);

      for (let i = s; i < end; i++) {
         const p = parseProxy(lines[i], plainProto);

         if (!p) continue;

         const ex = map.get(p.key);

         if (ex) {
            ex.merged++;

            if (ex.aliases.length < 50 && !ex.aliases.includes(p.name)) {
               ex.aliases.push(p.name);
            }
         } else {
            map.set(p.key, {
               ...p,
               merged: 1,
               aliases: [p.name],
            });
         }
      }

      if (end < lines.length) {
         await tick();
      }
   }

   return isCancelled() ? null : [...map.values()];
}
