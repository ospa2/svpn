"use client";
import { useState, useCallback, useRef, useMemo, useEffect, memo } from "react";
import { classifyHosts, GEO_RU, GEO_OTHER, GEO_UNKNOWN } from "./geoRu.jsx";
import { parseAndDedupe, toCopyString } from "./proxyParsing.js";
const BG = "#0b0e11";
const BORDER = "#1e2a38";
const GREEN = "#22c55e";
const AMBER = "#f59e0b";
const RED = "#ef4444";
const BLUE = "#38bdf8";
const MUTED = "#4b5a6e";
const TEXT = "#c9d8e8";
const MONO = "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace";

// ─── Tuning ────────────────────────────────────────────────────────────────────
const ROW_H = 34; // fixed row height (virtualization relies on it)
const VIEW_H = 560; // visible table body height
const OVERSCAN = 12; // extra rows rendered above/below viewport
const FLUSH_MS = 250; // how often check results are pushed into React state

// status codes (typed arrays instead of an object-of-objects)
const ST_NONE = 0,
   ST_CHECKING = 1,
   ST_ONLINE = 2,
   ST_TIMEOUT = 3,
   ST_ERROR = 4,
   ST_UNTESTABLE = 5; // <- add
const ST_CODE = {
   checking: ST_CHECKING,
   online: ST_ONLINE,
   timeout: ST_TIMEOUT,
   error: ST_ERROR,
   untestable: ST_UNTESTABLE, // <- add
};

const COLS =
   "44px minmax(160px,1.4fr) 190px 52px 90px 90px 80px minmax(100px,1fr) 110px 110px 60px";
const HEADERS = [
   "#",
   "Название",
   "Хост : Порт",
   "Geo",
   "Протокол",
   "Транспорт",
   "Security",
   "SNI",
   "Auth",
   "Статус",
   "",
];

// ─── Colors ────────────────────────────────────────────────────────────────────
const PROTO_COLORS = {
   vless: { bg: "#0d1f38", text: "#38bdf8" },
   vmess: { bg: "#1a1038", text: "#a78bfa" },
   trojan: { bg: "#1f1010", text: "#f87171" },
   ss: { bg: "#0f2818", text: "#4ade80" },
   shadowsocks: { bg: "#0f2818", text: "#4ade80" },
   hysteria: { bg: "#1f1a08", text: "#fbbf24" },
   hysteria2: { bg: "#1f1a08", text: "#fcd34d" },
   hy2: { bg: "#1f1a08", text: "#fcd34d" },
   tuic: { bg: "#0d2020", text: "#2dd4bf" },
   socks: { bg: "#181818", text: "#9ca3af" },
   socks5: { bg: "#181818", text: "#9ca3af" },
   http: { bg: "#181818", text: "#9ca3af" },
};
const TRANSPORT_COLORS = {
   ws: { bg: "#1a0c3b", text: "#a78bfa" },
   httpupgrade: { bg: "#0c1f3b", text: "#38bdf8" },
   grpc: { bg: "#0c3b3b", text: "#34d399" },
   tcp: { bg: "#161616", text: "#6b7280" },
   udp: { bg: "#1a1008", text: "#f59e0b" },
   quic: { bg: "#0d1f10", text: "#4ade80" },
   h2: { bg: "#0c1f3b", text: "#60a5fa" },
};
const SEC_COLORS = {
   tls: { bg: "#0c3b2e", text: "#22c55e" },
   reality: { bg: "#0c1f3b", text: "#38bdf8" },
   none: { bg: "#2a1a0a", text: "#f59e0b" },
};

// ─── Connectivity check ────────────────────────────────────────────────────────
// `inflight` holds an abort fn per running check so [stop] can cancel everything
// instantly. Every check always releases its socket (fetch abort / ws.close).
function checkProxy(proxy, timeoutMs, inflight) {
   if (proxy.untestable)
      return Promise.resolve({ status: "untestable", latency: null }); // <- add
   return new Promise((resolve) => {
      const start = performance.now();
      const elapsed = () => Math.round(performance.now() - start);
      let finished = false;
      let cleanup = () => {};

      const finish = (status, latency = null) => {
         if (finished) return;
         finished = true;
         clearTimeout(tid);
         inflight.delete(abort);
         try {
            cleanup();
         } catch {}
         resolve({ status, latency });
      };
      const abort = () => finish("aborted");
      const tid = setTimeout(() => finish("timeout"), timeoutMs);
      inflight.add(abort);

      const transport = proxy.transport?.toLowerCase();
      const isUDP =
         transport === "udp" ||
         transport === "quic" ||
         ["hysteria", "hysteria2", "tuic"].includes(proxy.proto);

      if (!isUDP && (transport === "ws" || transport === "httpupgrade")) {
         const tls = proxy.security === "tls";
         const addr = tls ? proxy.sni || proxy.host : proxy.host;
         try {
            const ws = new WebSocket(
               `${tls ? "wss" : "ws"}://${addr}:${proxy.port}${proxy.path || "/"}`,
            );
            cleanup = () => {
               ws.onopen = ws.onerror = ws.onclose = null;
               ws.close();
            };
            ws.onopen = () => finish("online", elapsed());
            ws.onerror = () => finish("error");
            ws.onclose = () => finish("error");
         } catch {
            finish("error");
         }
         return;
      }

      // TCP / UDP-ish → fetch no-cors. A fast failure means something answered on the port.
      const ctrl = new AbortController();
      cleanup = () => ctrl.abort();
      const fastLimit = timeoutMs - (isUDP ? 500 : 300);
      fetch(
         `${proxy.security === "tls" ? "https" : "http"}://${proxy.host}:${proxy.port}`,
         {
            mode: "no-cors",
            signal: ctrl.signal,
            cache: "no-store",
            credentials: "omit",
         },
      )
         .then(() => finish("online", elapsed()))
         .catch((error) => {
            // Отмена уже обрабатывается через finish() или таймаут.
            if (error?.name === "AbortError") return;

            finish("error");
         });
   });
}

// Worker pool. Stops launching new checks as soon as ctx.stopped is set.
async function runChecks(proxies, indices, concurrency, timeoutMs, ctx) {
   let cursor = 0;
   const worker = async () => {
      while (!ctx.stopped) {
         const k = cursor++;
         if (k >= indices.length) return;
         const i = indices[k];
         ctx.onResult(i, "checking", null);
         const r = await checkProxy(proxies[i], timeoutMs, ctx.inflight);
         if (ctx.stopped) return;
         ctx.onResult(i, r.status, r.latency);
      }
   };
   await Promise.all(
      Array.from({ length: Math.min(concurrency, indices.length) }, worker),
   );
}

// ─── Small components ──────────────────────────────────────────────────────────
const Badge = ({ colors, fallback, children, upper }) => {
   const c = colors ?? fallback;
   return (
      <span
         style={{
            background: c.bg,
            color: c.text,
            fontSize: 10,
            padding: "2px 7px",
            borderRadius: 4,
            fontFamily: MONO,
            letterSpacing: "0.04em",
            textTransform: upper ? "uppercase" : "none",
         }}
      >
         {children}
      </span>
   );
};

const statusColor = (s) =>
   ({
      [ST_ONLINE]: GREEN,
      [ST_TIMEOUT]: AMBER,
      [ST_ERROR]: RED,
      [ST_CHECKING]: BLUE,
      [ST_UNTESTABLE]: MUTED, // <- add
   })[s] ?? MUTED;
const statusLabel = (s, lat) => {
   if (s === ST_ONLINE) return lat >= 0 ? `✓ ${lat}ms` : "✓ online";
   if (s === ST_TIMEOUT) return "⏱ timeout";
   if (s === ST_ERROR) return "✗ error";
   if (s === ST_CHECKING) return "… checking";
   if (s === ST_UNTESTABLE) return "– blocked port"; // <- add
   return "–";
};

const cell = {
   padding: "0 12px",
   overflow: "hidden",
   whiteSpace: "nowrap",
   textOverflow: "ellipsis",
};

// Memoized: status, latency, copy-state and selection are passed per row.
const Row = memo(function Row({
   p,
   row,
   idx,
   geo,
   status,
   latency,
   copied,
   selected,
   copyFormat,
   onCopy,
}) {
   return (
      <div
         className="prow"
         data-result-row={row}
         data-selected={selected ? "true" : "false"}
         style={{
            position: "absolute",
            top: row * ROW_H,
            left: 0,
            right: 0,
            height: ROW_H,
            display: "grid",
            gridTemplateColumns: COLS,
            alignItems: "center",
            borderBottom: "1px solid #0e161f",
            background: selected ? "#153452" : undefined,
            boxShadow: selected ? `inset 3px 0 ${BLUE}` : undefined,
            fontSize: 11,
         }}
      >
         <div style={{ ...cell, color: MUTED }}>{idx + 1}</div>
         <div
            style={{ ...cell, display: "flex", alignItems: "center", gap: 6 }}
         >
            <span
               title={p.name}
               style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  color: TEXT,
               }}
            >
               {p.name}
            </span>
            {p.merged > 1 && (
               <span
                  title={`Объединено ${p.merged} дубликатов:\n${p.aliases.join("\n")}`}
                  style={{
                     background: "#2a1a0a",
                     color: AMBER,
                     fontSize: 9,
                     padding: "1px 6px",
                     borderRadius: 10,
                     flexShrink: 0,
                     cursor: "help",
                  }}
               >
                  ×{p.merged}
               </span>
            )}
         </div>
         <div style={cell}>
            <span style={{ color: TEXT }}>{p.host}</span>
            <span style={{ color: MUTED }}>:{p.port}</span>
         </div>
         <div style={cell}>
            {geo === GEO_RU ? (
               <Badge colors={{ bg: "#2b0c0c", text: RED }}>RU</Badge>
            ) : geo === GEO_OTHER ? (
               <span style={{ color: GREEN, fontSize: 10 }}>non-RU</span>
            ) : (
               <span style={{ color: MUTED, fontSize: 10 }}>
                  {geo === GEO_UNKNOWN ? "?" : "…"}
               </span>
            )}
         </div>
         <div style={cell}>
            <Badge
               upper
               colors={PROTO_COLORS[p.proto?.toLowerCase()]}
               fallback={{ bg: "#1a1a1a", text: "#9ca3af" }}
            >
               {p.proto === "shadowsocks" ? "ss" : p.proto}
            </Badge>
         </div>
         <div style={cell}>
            <Badge
               colors={TRANSPORT_COLORS[p.transport?.toLowerCase()]}
               fallback={TRANSPORT_COLORS.tcp}
            >
               {p.transport || "tcp"}
            </Badge>
         </div>
         <div style={cell}>
            <Badge
               colors={SEC_COLORS[p.security?.toLowerCase()]}
               fallback={SEC_COLORS.none}
            >
               {p.security || "none"}
            </Badge>
         </div>
         <div style={{ ...cell, color: MUTED, fontSize: 10 }} title={p.sni}>
            {p.sni || "—"}
         </div>
         <div
            style={{ ...cell, color: MUTED, fontSize: 10 }}
            title={p.login ? `${p.login}:${p.password}` : ""}
         >
            {p.login ? `${p.login}:••••` : "—"}
         </div>
         <div style={{ ...cell, color: statusColor(status) }}>
            {statusLabel(status, latency)}
         </div>
         <div style={{ padding: "0 8px" }}>
            <button
               onClick={() => onCopy(toCopyString(p, copyFormat), idx)}
               title={
                  copyFormat === "uri"
                     ? "скопировать как URI"
                     : "скопировать как ip:port:login:pass"
               }
               style={{
                  padding: "4px 10px",
                  fontSize: 10,
                  background: copied ? "#0c2b14" : "transparent",
                  color: copied ? GREEN : MUTED,
                  border: `1px solid ${copied ? "#1a5c2a" : BORDER}`,
                  borderRadius: 6,
               }}
            >
               {copied ? "✓" : "copy"}
            </button>
         </div>
      </div>
   );
});

function Stat({ label, value, color }) {
   return (
      <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
         <span style={{ fontSize: 9, color: MUTED, letterSpacing: "0.1em" }}>
            {label}
         </span>
         <span style={{ fontSize: 20, fontWeight: 600, color, lineHeight: 1 }}>
            {value}
         </span>
      </div>
   );
}

function Pill({ label, active, onClick, color = BLUE, wide }) {
   return (
      <button
         onClick={onClick}
         style={{
            padding: wide ? "5px 12px" : "4px 11px",
            fontSize: wide ? 11 : 10,
            borderRadius: wide ? 6 : 20,
            border: `1px solid ${active ? color : BORDER}`,
            background: active ? color + "18" : "transparent",
            color: active ? color : MUTED,
         }}
      >
         {label}
      </button>
   );
}

const PLACEHOLDER = `vless://uuid@1.2.3.4:443?type=ws&security=tls&sni=example.com#MyVless
vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJuZXQiOiJ3cyIsInRscyI6InRscyIsInBhdGgiOiIvIn0=
trojan://password@1.2.3.4:443?sni=example.com#MyTrojan
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#MySS
hysteria2://password@1.2.3.4:443?sni=example.com#MyHy2
tuic://uuid:password@1.2.3.4:443?sni=example.com#MyTuic
1.2.3.4:1080:login:password`;

const SUPPORTED = [
   "vless",
   "vmess",
   "trojan",
   "ss",
   "hysteria",
   "hysteria2",
   "hy2",
   "tuic",
   "socks",
   "socks5",
   "http",
   "https",
   "ip:port[:login:pass]",
];

// Selection uses proxy indices, not mounted DOM rows, so virtualization is safe.
function useRowSelection(liveOrder, proxies, copyFormat) {
   const [selected, setSelected] = useState(() => new Set());
   const [dragOrder, setDragOrder] = useState(null);
   const [copyMessage, setCopyMessage] = useState("");
   const viewportRef = useRef(null);
   const selectedRef = useRef(selected);
   const dragRef = useRef(null);
   const anchorRef = useRef(null);
   const rafRef = useRef(null);
   const order = dragOrder ?? liveOrder;

   const commit = useCallback((next) => {
      selectedRef.current = next;
      setSelected(next);
      setCopyMessage("");
   }, []);
   const clear = useCallback(() => {
      commit(new Set());
      anchorRef.current = null;
   }, [commit]);
   useEffect(() => {
      // An asynchronously loaded replacement list invalidates all old indices.
      const pointerId = dragRef.current?.pointerId;
      dragRef.current = null;
      cancelAnimationFrame(rafRef.current);
      setDragOrder(null);
      clear();
      const el = viewportRef.current;
      if (pointerId !== undefined && el?.hasPointerCapture(pointerId)) {
         el.releasePointerCapture(pointerId);
      }
   }, [proxies, clear]);
   useEffect(() => () => cancelAnimationFrame(rafRef.current), []);

   const updateRange = useCallback(() => {
      const drag = dragRef.current;
      const el = viewportRef.current;
      if (!drag || !el) return;
      const rect = el.getBoundingClientRect();
      const y = Math.max(0, Math.min(el.clientHeight - 1, drag.y - rect.top));
      const last = Math.max(
         0,
         Math.min(
            drag.order.length - 1,
            Math.floor((el.scrollTop + y) / ROW_H),
         ),
      );
      if (last === drag.last) return;
      drag.last = last;
      const next = new Set(drag.base);
      const lo = Math.min(drag.anchor, last);
      const hi = Math.max(drag.anchor, last);
      for (let row = lo; row <= hi; row++) next.add(drag.order[row]);
      commit(next);
   }, [commit]);

   const onPointerDown = useCallback(
      (e) => {
         if (
            e.button !== 0 ||
            (e.pointerType !== "mouse" && e.pointerType !== "pen")
         )
            return;
         if (e.target.closest("button, a, input, textarea, select")) return;
         const rowEl = e.target.closest("[data-result-row]");
         if (!rowEl || !liveOrder.length) return;
         const el = e.currentTarget;
         const row = Number(rowEl.dataset.resultRow);
         let anchor = e.shiftKey ? liveOrder.indexOf(anchorRef.current) : row;
         if (anchor < 0) anchor = row;
         if (!e.shiftKey || anchorRef.current === null)
            anchorRef.current = liveOrder[anchor];
         // Freeze ordering only during the gesture; checks continue in the background.
         const snapshot = liveOrder.slice();
         dragRef.current = {
            pointerId: e.pointerId,
            y: e.clientY,
            order: snapshot,
            anchor,
            last: -1,
            base:
               e.ctrlKey || e.metaKey
                  ? new Set(selectedRef.current)
                  : new Set(),
         };
         setDragOrder(snapshot);
         e.preventDefault();
         el.focus({ preventScroll: true });
         el.setPointerCapture(e.pointerId);
         updateRange();
         let previousTime = null;
         const autoScroll = (time) => {
            const drag = dragRef.current;
            if (!drag) return;
            const rect = el.getBoundingClientRect();
            const edge = 36;
            const above = Math.max(0, rect.top + edge - drag.y);
            const below = Math.max(
               0,
               drag.y - (rect.top + el.clientHeight - edge),
            );
            const speed = Math.max(-900, Math.min(900, (below - above) * 18));
            const dt =
               previousTime === null ? 16 : Math.min(40, time - previousTime);
            previousTime = time;
            if (speed) el.scrollTop += (speed * dt) / 1000;
            updateRange();
            rafRef.current = requestAnimationFrame(autoScroll);
         };
         rafRef.current = requestAnimationFrame(autoScroll);
      },
      [liveOrder, updateRange],
   );

   const onPointerMove = useCallback(
      (e) => {
         if (dragRef.current?.pointerId !== e.pointerId) return;
         dragRef.current.y = e.clientY;
         updateRange();
      },
      [updateRange],
   );
   const finishDrag = useCallback(
      (e) => {
         if (!dragRef.current || dragRef.current.pointerId !== e.pointerId)
            return;
         if (e.type === "pointerup") {
            dragRef.current.y = e.clientY;
            updateRange();
         }
         dragRef.current = null;
         cancelAnimationFrame(rafRef.current);
         setDragOrder(null);
         if (e.currentTarget.hasPointerCapture(e.pointerId)) {
            e.currentTarget.releasePointerCapture(e.pointerId);
         }
      },
      [updateRange],
   );

   const selectedCount = order.reduce(
      (n, idx) => n + Number(selected.has(idx)),
      0,
   );
   const getCopyText = () =>
      order
         .filter((idx) => selectedRef.current.has(idx))
         .map((idx) => toCopyString(proxies[idx], copyFormat))
         .join("\n");
   const onCopy = (e) => {
      const text = getCopyText();
      if (!text) return;
      e.preventDefault();
      e.clipboardData.setData("text/plain", text);
   };
   const copySelected = async () => {
      const text = getCopyText();
      if (!text) return;
      try {
         await navigator.clipboard.writeText(text);
         setCopyMessage("Скопировано");
      } catch {
         setCopyMessage(
            "Нет доступа к буферу: выделите строки и нажмите Ctrl+C / ⌘C",
         );
      }
   };
   const onKeyDown = (e) => {
      // Leave keyboard interaction with per-row copy buttons unchanged.
      if (e.target !== e.currentTarget) return;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") {
         e.preventDefault();
         commit(new Set(order));
      } else if (e.key === "Escape") {
         e.preventDefault();
         clear();
      }
   };
   return {
      order,
      selected,
      selectedCount,
      copyMessage,
      copySelected,
      clear,
      viewportRef,
      onPointerDown,
      onPointerMove,
      finishDrag,
      onCopy,
      onKeyDown,
      updateRange,
   };
}

// ─── Main component ────────────────────────────────────────────────────────────
export default function ProxyChecker() {
   const [input, setInput] = useState("");
   const [proxies, setProxies] = useState([]);
   const [version, setVersion] = useState(0); // bumped on each batched flush
   const [running, setRunning] = useState(false);
   const [parsing, setParsing] = useState(false);
   const [sortMode, setSortMode] = useState("latency");
   const [concurrency, setConcurrency] = useState(150);
   const [timeoutMs, setTimeoutMs] = useState(2000);
   const [filterProto, setFilterProto] = useState("all");
   const [onlyOnline, setOnlyOnline] = useState(false);
   const [ruMode, setRuMode] = useState("hide"); // "hide" | "all" | "only"
   const [geoBusy, setGeoBusy] = useState(false);
   const [plainProto, setPlainProto] = useState("socks5");
   const [copyFormat, setCopyFormat] = useState("uri");
   const [copied, setCopied] = useState(null);
   const [copiedAll, setCopiedAll] = useState(false);
   const [autoMode, setAutoMode] = useState(true);
   const [clipError, setClipError] = useState(null);
   const [firstRow, setFirstRow] = useState(0);

   // Results live OUTSIDE React state: typed arrays mutated in place by workers.
   const statusRef = useRef(new Uint8Array(0));
   const latencyRef = useRef(new Int32Array(0));
   const proxiesRef = useRef([]);
   const geoRef = useRef(new Uint8Array(0));
   const geoPromiseRef = useRef(Promise.resolve());
   const ruModeRef = useRef("hide");
   ruModeRef.current = ruMode;
   const ctxRef = useRef(null);
   const flushTimer = useRef(null);
   const parseToken = useRef(0);

   const flush = useCallback(() => setVersion((v) => v + 1), []);
   useEffect(
      () => () => {
         ctxRef.current && (ctxRef.current.stopped = true);
         clearInterval(flushTimer.current);
      },
      [],
   );

   const setList = useCallback(
      (list) => {
         proxiesRef.current = list;
         statusRef.current = new Uint8Array(list.length);
         latencyRef.current = new Int32Array(list.length).fill(-1);
         geoRef.current = new Uint8Array(list.length);
         setProxies(list);
         setFirstRow(0);
         flush();
      },
      [flush],
   );

   // Offline range lookup for IP hosts; one DoH query per unique domain.
   const runGeo = useCallback(
      (list) => {
         setGeoBusy(true);
         const stale = () => proxiesRef.current !== list;
         const p = classifyHosts(
            list.map((x) => x.host),
            { onTick: flush, isStale: stale },
         ).then((codes) => {
            if (stale()) return;
            geoRef.current = codes;
            setGeoBusy(false);
            flush();
         });
         geoPromiseRef.current = p;
         return p;
      },
      [flush],
   );

   const stopCheck = useCallback(() => {
      const ctx = ctxRef.current;
      if (!ctx) return;
      ctx.stopped = true;
      [...ctx.inflight].forEach((abort) => abort()); // frees sockets immediately
      const st = statusRef.current;
      for (let i = 0; i < st.length; i++)
         if (st[i] === ST_CHECKING) st[i] = ST_NONE;
      clearInterval(flushTimer.current);
      ctxRef.current = null;
      setRunning(false);
      flush();
   }, [flush]);

   // indices === undefined → check everything
   const startCheck = useCallback(
      async (indices) => {
         const list = proxiesRef.current;
         if (!list.length) return;
         if (ctxRef.current) stopCheck();
         if (ruModeRef.current === "hide") await geoPromiseRef.current; // need geo before deciding what to skip
         if (proxiesRef.current !== list) return;
         let idx = indices ?? Array.from({ length: list.length }, (_, i) => i);
         if (ruModeRef.current === "hide")
            idx = idx.filter((i) => geoRef.current[i] !== GEO_RU); // RU proxies never hit the network
         if (!idx.length) return;

         for (const i of idx) {
            statusRef.current[i] = ST_NONE;
            latencyRef.current[i] = -1;
         }
         const ctx = {
            stopped: false,
            inflight: new Set(),
            onResult: (i, status, latency) => {
               statusRef.current[i] = ST_CODE[status] ?? ST_ERROR;
               latencyRef.current[i] = latency ?? -1;
            },
         };
         ctxRef.current = ctx;
         setRunning(true);
         clearInterval(flushTimer.current);
         flushTimer.current = setInterval(flush, FLUSH_MS);

         await runChecks(list, idx, concurrency, timeoutMs, ctx);

         if (ctxRef.current === ctx) {
            clearInterval(flushTimer.current);
            ctxRef.current = null;
            setRunning(false);
            flush();
         }
      },
      [concurrency, timeoutMs, flush, stopCheck],
   );
   const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
   const load = useCallback(
      async (text, autoCheck) => {
         if (!text?.trim()) return 0;
         stopCheck();
         const token = ++parseToken.current;
         setParsing(true);
         await tick(); // let "parsing…" paint first
         const parsed = await parseAndDedupe(
            text,
            plainProto,
            () => token !== parseToken.current,
         );
         if (!parsed || token !== parseToken.current) return 0;
         setParsing(false);
         setList(parsed);
         runGeo(parsed);
         setFilterProto("all");
         setSortMode(autoCheck ? "index" : "latency");
         if (autoCheck && parsed.length) startCheck();
         return parsed.length;
      },
      [plainProto, setList, runGeo, startCheck, stopCheck],
   );

   const handlePaste = useCallback(
      (e) => {
         if (!autoMode) return;
         const pasted = e.clipboardData?.getData("text");
         if (!pasted?.trim()) return;
         e.preventDefault();
         setInput(pasted);
         load(pasted, true);
      },
      [autoMode, load],
   );

   const pasteFromClipboard = useCallback(async () => {
      setClipError(null);
      try {
         const text = await navigator.clipboard.readText();
         if (!text?.trim()) return setClipError("буфер обмена пуст");
         setInput(text);
         const n = await load(text, true);
         if (!n) setClipError("в буфере нет распознанных прокси-строк");
      } catch {
         setClipError("нет доступа к буферу — разрешите вставку в браузере");
      }
   }, [load]);

   const copyUri = useCallback((uri, idx) => {
      navigator.clipboard.writeText(uri).then(() => {
         setCopied(idx);
         setTimeout(() => setCopied((c) => (c === idx ? null : c)), 1500);
      });
   }, []);

   // ── Derived data (recomputed only on flush / filter / sort changes) ──
   const {
      counts,
      protoCounts,
      visible: liveVisible,
   } = useMemo(() => {
      const st = statusRef.current,
         lat = latencyRef.current;
      const n = proxies.length;
      const geo = geoRef.current;
      const c = { checked: 0, online: 0, failed: 0, ru: 0 };
      const pc = {};
      const idx = [];
      for (let i = 0; i < n; i++) {
         const s = st[i];
         if (s === ST_ONLINE) {
            c.checked++;
            c.online++;
         } else if (s === ST_TIMEOUT || s === ST_ERROR) {
            c.checked++;
            c.failed++;
         }
         const isRu = geo[i] === GEO_RU;
         if (isRu) c.ru++;
         if ((ruMode === "hide" && isRu) || (ruMode === "only" && !isRu))
            continue;
         const proto = proxies[i].proto;
         pc[proto] = (pc[proto] || 0) + 1;
         if (filterProto !== "all" && proto !== filterProto) continue;
         if (onlyOnline && s !== ST_ONLINE) continue;
         idx.push(i);
      }
      if (sortMode === "latency") {
         idx.sort(
            (a, b) =>
               (lat[a] < 0 ? 1e9 : lat[a]) - (lat[b] < 0 ? 1e9 : lat[b]) ||
               a - b,
         );
      } else if (sortMode === "status") {
         const order = [9, 1, 0, 2, 3, 4]; // was [9, 1, 0, 2, 3]
         idx.sort((a, b) => order[st[a]] - order[st[b]] || a - b);
      }
      return { counts: c, protoCounts: pc, visible: idx };
      // eslint-disable-next-line react-hooks/exhaustive-deps
   }, [proxies, version, sortMode, filterProto, onlyOnline, ruMode]);

   const selection = useRowSelection(liveVisible, proxies, copyFormat);
   const visible = selection.order;

   const copyAllWorking = () => {
      const st = statusRef.current;
      const out = [];
      for (let i = 0; i < proxies.length; i++)
         if (
            st[i] === ST_ONLINE &&
            !(ruMode === "hide" && geoRef.current[i] === GEO_RU)
         )
            out.push(toCopyString(proxies[i], copyFormat));
      if (!out.length) return;
      navigator.clipboard.writeText(out.join("\n")).then(() => {
         setCopiedAll(true);
         setTimeout(() => setCopiedAll(false), 2000);
      });
   };

   const recheckFailed = () => {
      const st = statusRef.current;
      const idx = [];
      for (let i = 0; i < proxies.length; i++)
         if (st[i] !== ST_ONLINE) idx.push(i);
      startCheck(idx);
   };

   const mergedCount = useMemo(
      () => proxies.reduce((a, p) => a + (p.merged - 1), 0),
      [proxies],
   );
   const availableProtos = Object.keys(protoCounts);
   const progress = proxies.length ? counts.checked / proxies.length : 0;

   // ── Virtual window ──
   const start = Math.max(0, firstRow - OVERSCAN);
   const end = Math.min(
      visible.length,
      firstRow + Math.ceil(VIEW_H / ROW_H) + OVERSCAN,
   );
   const st = statusRef.current,
      lat = latencyRef.current;
   const onScroll = (e) => {
      const r = Math.floor(e.currentTarget.scrollTop / ROW_H);
      setFirstRow((prev) => (prev === r ? prev : r)); // re-render only when crossing a row boundary
      selection.updateRange();
   };

   return (
      <div
         style={{
            background: BG,
            minHeight: "100vh",
            fontFamily: MONO,
            color: TEXT,
            padding: "24px 20px",
         }}
      >
         <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0b0e11; }
        ::-webkit-scrollbar-thumb { background: #1e2a38; border-radius: 3px; }
        textarea, input[type=number] { background: #080b0e !important; color: ${TEXT} !important; border: 1px solid ${BORDER} !important; border-radius: 8px !important; font-family: ${MONO} !important; outline: none !important; resize: vertical; }
        textarea:focus, input[type=number]:focus { border-color: #2d4a6b !important; }
        button { cursor: pointer; font-family: ${MONO}; }
        .prow:hover { background: #0f1822; }
      `}</style>

         <div style={{ maxWidth: 1200, margin: "0 auto" }}>
            <div style={{ marginBottom: 20 }}>
               <div
                  style={{
                     display: "flex",
                     alignItems: "baseline",
                     gap: 12,
                     marginBottom: 4,
                  }}
               >
                  <span
                     style={{
                        fontSize: 11,
                        color: MUTED,
                        letterSpacing: "0.15em",
                     }}
                  >
                     //
                  </span>
                  <h1
                     style={{
                        margin: 0,
                        fontSize: 18,
                        fontWeight: 600,
                        color: TEXT,
                        letterSpacing: "-0.02em",
                     }}
                  >
                     proxy checker
                  </h1>
               </div>
               <p style={{ margin: 0, fontSize: 11, color: MUTED }}>
                  поддерживает: {SUPPORTED.join(" · ")}
               </p>
            </div>

            <div style={{ marginBottom: 16 }}>
               <button
                  onClick={pasteFromClipboard}
                  disabled={running || parsing}
                  style={{
                     display: "flex",
                     alignItems: "center",
                     gap: 10,
                     padding: "12px 20px",
                     background: "linear-gradient(135deg, #0a1f10, #0c2b14)",
                     color: GREEN,
                     border: "1px solid #1a5c2a",
                     borderRadius: 10,
                     fontSize: 13,
                     fontWeight: 500,
                     opacity: running || parsing ? 0.5 : 1,
                     width: "100%",
                     justifyContent: "center",
                  }}
               >
                  <span style={{ fontSize: 16 }}>📋</span>
                  {parsing
                     ? "[ парсинг... ]"
                     : "[ вставить из буфера и проверить ]"}
               </button>
               {clipError && (
                  <p
                     style={{
                        marginTop: 6,
                        fontSize: 11,
                        color: AMBER,
                        textAlign: "center",
                     }}
                  >
                     ⚠ {clipError}
                  </p>
               )}
            </div>

   

            <div
               style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto",
                  gap: 12,
                  alignItems: "start",
                  marginBottom: 8,
               }}
            >
               
               <div
                  style={{
                     display: "flex",
                     flexDirection: "column",
                     gap: 8,
                     minWidth: 160,
                  }}
               >
                  <label
                     style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 10,
                        color: MUTED,
                        cursor: "pointer",
                        marginBottom: 2,
                     }}
                  >
                     <input
                        type="checkbox"
                        checked={autoMode}
                        onChange={(e) => setAutoMode(e.target.checked)}
                        style={{
                           width: 13,
                           height: 13,
                           accentColor: GREEN,
                           cursor: "pointer",
                        }}
                     />
                     авто-парсинг + чек при вставке
                  </label>
                  <button
                     onClick={() => load(input, false)}
                     disabled={!input.trim() || parsing}
                     style={{
                        padding: "9px 16px",
                        background: "#0c1f38",
                        color: BLUE,
                        border: "1px solid #1a3a5c",
                        borderRadius: 8,
                        fontSize: 12,
                        fontWeight: 500,
                        opacity: !input.trim() ? 0.4 : 1,
                     }}
                  >
                     [ parse ]
                  </button>
                  <button
                     onClick={() => startCheck()}
                     disabled={!proxies.length || running}
                     style={{
                        padding: "9px 16px",
                        background: "#0c2b14",
                        color: running ? MUTED : GREEN,
                        border: `1px solid ${running ? MUTED : "#1a5c2a"}`,
                        borderRadius: 8,
                        fontSize: 12,
                        fontWeight: 500,
                        opacity: !proxies.length ? 0.4 : 1,
                     }}
                  >
                     {running ? "[ running... ]" : "[ check all ]"}
                  </button>
                  {running ? (
                     <button
                        onClick={stopCheck}
                        style={{
                           padding: "9px 16px",
                           background: "#2b0c0c",
                           color: RED,
                           border: "1px solid #5c1a1a",
                           borderRadius: 8,
                           fontSize: 12,
                        }}
                     >
                        [ stop ]
                     </button>
                  ) : (
                     <button
                        onClick={recheckFailed}
                        disabled={!counts.failed}
                        style={{
                           padding: "9px 16px",
                           background: "#1f1a08",
                           color: AMBER,
                           border: "1px solid #5c4a1a",
                           borderRadius: 8,
                           fontSize: 12,
                           opacity: counts.failed ? 1 : 0.4,
                        }}
                     >
                        [ recheck failed ]
                     </button>
                  )}
                  <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                     <div style={{ flex: 1 }}>
                        <label
                           style={{
                              fontSize: 10,
                              color: MUTED,
                              display: "block",
                              marginBottom: 4,
                           }}
                        >
                           потоков
                        </label>
                        <input
                           type="number"
                           min={1}
                           max={500}
                           value={concurrency}
                           disabled={running}
                           onChange={(e) =>
                              setConcurrency(
                                 Math.max(
                                    1,
                                    Math.min(500, +e.target.value || 1),
                                 ),
                              )
                           }
                           style={{
                              width: "100%",
                              padding: "7px 10px",
                              fontSize: 12,
                           }}
                        />
                     </div>
                     <div style={{ flex: 1 }}>
                        <label
                           style={{
                              fontSize: 10,
                              color: MUTED,
                              display: "block",
                              marginBottom: 4,
                           }}
                        >
                           таймаут, мс
                        </label>
                        <input
                           type="number"
                           min={200}
                           max={10000}
                           step={100}
                           value={timeoutMs}
                           disabled={running}
                           onChange={(e) =>
                              setTimeoutMs(
                                 Math.max(
                                    200,
                                    Math.min(10000, +e.target.value || 1000),
                                 ),
                              )
                           }
                           style={{
                              width: "100%",
                              padding: "7px 10px",
                              fontSize: 12,
                           }}
                        />
                     </div>
                  </div>
               </div>
            </div>

            <div
               style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 8,
                  flexWrap: "wrap",
               }}
            >
               <span style={{ fontSize: 10, color: MUTED }}>
                  строки без схемы (ip:port:login:pass) — считать как:
               </span>
               {["socks5", "http"].map((p) => (
                  <Pill
                     key={p}
                     label={p}
                     active={plainProto === p}
                     onClick={() => setPlainProto(p)}
                  />
               ))}
            </div>

            <div
               style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 16,
                  flexWrap: "wrap",
               }}
            >
               <span style={{ fontSize: 10, color: MUTED }}>
                  формат копирования:
               </span>
               <Pill
                  label="URI — для v2rayN"
                  color={GREEN}
                  active={copyFormat === "uri"}
                  onClick={() => setCopyFormat("uri")}
               />
               <Pill
                  label="ip:port:login:pass"
                  color={GREEN}
                  active={copyFormat === "plain"}
                  onClick={() => setCopyFormat("plain")}
               />
            </div>

            {proxies.length > 0 && (
               <div style={{ marginBottom: 16 }}>
                  <div
                     style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 16,
                        marginBottom: 10,
                        flexWrap: "wrap",
                     }}
                  >
                     <div style={{ display: "flex", gap: 20 }}>
                        <Stat
                           label="всего"
                           value={proxies.length}
                           color={TEXT}
                        />
                        {mergedCount > 0 && (
                           <Stat
                              label="склеено"
                              value={mergedCount}
                              color={AMBER}
                           />
                        )}
                        <Stat
                           label="проверено"
                           value={counts.checked}
                           color={BLUE}
                        />
                        <Stat
                           label="доступно"
                           value={counts.online}
                           color={GREEN}
                        />
                        <Stat
                           label="недоступно"
                           value={counts.failed}
                           color={RED}
                        />
                        <Stat
                           label={geoBusy ? "RU (резолв…)" : "RU"}
                           value={counts.ru}
                           color={AMBER}
                        />
                     </div>
                     <div
                        style={{
                           marginLeft: "auto",
                           display: "flex",
                           gap: 8,
                           flexWrap: "wrap",
                        }}
                     >
                        {[
                           ["hide", "hide RU"],
                           ["all", "show RU"],
                           ["only", "only RU"],
                        ].map(([m, l]) => (
                           <Pill
                              wide
                              key={m}
                              label={l}
                              color={AMBER}
                              active={ruMode === m}
                              onClick={() => setRuMode(m)}
                           />
                        ))}
                        <Pill
                           wide
                           label="only online"
                           active={onlyOnline}
                           color={GREEN}
                           onClick={() => setOnlyOnline((v) => !v)}
                        />
                        {["index", "status", "latency"].map((m) => (
                           <Pill
                              wide
                              key={m}
                              label={m}
                              active={sortMode === m}
                              onClick={() => setSortMode(m)}
                           />
                        ))}
                        <button
                           onClick={copyAllWorking}
                           disabled={!counts.online}
                           style={{
                              padding: "5px 14px",
                              fontSize: 11,
                              borderRadius: 6,
                              border: `1px solid ${counts.online ? "#1a5c2a" : BORDER}`,
                              background: copiedAll
                                 ? "#0c2b14"
                                 : counts.online
                                   ? "#0a1f10"
                                   : "transparent",
                              color: counts.online ? GREEN : MUTED,
                              opacity: counts.online ? 1 : 0.4,
                           }}
                        >
                           {copiedAll
                              ? `✓ скопировано ${counts.online}`
                              : `[ copy ${counts.online} working ]`}
                        </button>
                     </div>
                  </div>

                  {availableProtos.length > 1 && (
                     <div
                        style={{
                           display: "flex",
                           gap: 6,
                           flexWrap: "wrap",
                           marginBottom: 10,
                        }}
                     >
                        <Pill
                           label={`all · ${proxies.length}`}
                           active={filterProto === "all"}
                           onClick={() => setFilterProto("all")}
                        />
                        {availableProtos.map((proto) => (
                           <Pill
                              key={proto}
                              label={`${proto} · ${protoCounts[proto]}`}
                              active={filterProto === proto}
                              color={PROTO_COLORS[proto]?.text}
                              onClick={() => setFilterProto(proto)}
                           />
                        ))}
                     </div>
                  )}

                  {running && (
                     <div
                        style={{
                           height: 3,
                           background: BORDER,
                           borderRadius: 2,
                           overflow: "hidden",
                           marginBottom: 12,
                        }}
                     >
                        <div
                           style={{
                              height: "100%",
                              width: `${progress * 100}%`,
                              background: GREEN,
                              transition: "width 0.3s",
                              borderRadius: 2,
                           }}
                        />
                     </div>
                  )}

                  <div
                     style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        flexWrap: "wrap",
                        marginBottom: 10,
                        fontSize: 11,
                     }}
                  >
                     <span style={{ color: MUTED }}>
                        Тяните мышью по строкам → Ctrl+C / ⌘C. Shift — диапазон,
                        Ctrl / ⌘ — добавить, Ctrl+A / ⌘A — все, Esc — снять.
                     </span>
                     <span aria-live="polite">
                        Выделено: {selection.selectedCount}
                     </span>
                     <button
                        disabled={!selection.selectedCount}
                        onClick={selection.copySelected}
                        style={{
                           padding: "5px 10px",
                           background: "#0c1f38",
                           color: BLUE,
                           border: `1px solid ${BORDER}`,
                           borderRadius: 6,
                           opacity: selection.selectedCount ? 1 : 0.4,
                        }}
                     >
                        Копировать выделенные
                     </button>
                     <button
                        onClick={selection.clear}
                        style={{
                           padding: "5px 10px",
                           background: "transparent",
                           color: MUTED,
                           border: `1px solid ${BORDER}`,
                           borderRadius: 6,
                        }}
                     >
                        Снять выделение
                     </button>
                     <span role="status" style={{ color: GREEN }}>
                        {selection.copyMessage}
                     </span>
                  </div>

                  {/* Virtualized table: only ~60 rows exist in the DOM regardless of list size */}
                  <div
                     style={{
                        overflowX: "auto",
                        border: `1px solid ${BORDER}`,
                        borderRadius: 10,
                     }}
                  >
                     <div style={{ minWidth: 1160 }}>
                        <div
                           style={{
                              display: "grid",
                              gridTemplateColumns: COLS,
                              height: 32,
                              alignItems: "center",
                              borderBottom: `1px solid ${BORDER}`,
                              paddingRight: 6,
                           }}
                        >
                           {HEADERS.map((h, i) => (
                              <div
                                 key={i}
                                 style={{
                                    ...cell,
                                    color: MUTED,
                                    fontSize: 10,
                                    letterSpacing: "0.08em",
                                 }}
                              >
                                 {h}
                              </div>
                           ))}
                        </div>
                        <div
                           ref={selection.viewportRef}
                           tabIndex={0}
                           role="region"
                           aria-label="Результаты тестов: выделение строк и копирование"
                           onScroll={onScroll}
                           onPointerDown={selection.onPointerDown}
                           onPointerMove={selection.onPointerMove}
                           onPointerUp={selection.finishDrag}
                           onPointerCancel={selection.finishDrag}
                           onLostPointerCapture={selection.finishDrag}
                           onCopy={selection.onCopy}
                           onKeyDown={selection.onKeyDown}
                           style={{
                              userSelect: "none",
                              WebkitUserSelect: "none",
                              height: VIEW_H,
                              overflowY: "auto",
                              position: "relative",
                           }}
                        >
                           <div
                              style={{
                                 height: visible.length * ROW_H,
                                 position: "relative",
                              }}
                           >
                              {Array.from(
                                 { length: Math.max(0, end - start) },
                                 (_, k) => {
                                    const row = start + k;
                                    const i = visible[row];
                                    return (
                                       <Row
                                          key={i}
                                          p={proxies[i]}
                                          row={row}
                                          idx={i}
                                          geo={geoRef.current[i]}
                                          status={st[i]}
                                          latency={lat[i]}
                                          copied={copied === i}
                                          selected={selection.selected.has(i)}
                                          copyFormat={copyFormat}
                                          onCopy={copyUri}
                                       />
                                    );
                                 },
                              )}
                              {visible.length === 0 && (
                                 <div
                                    style={{
                                       padding: 24,
                                       textAlign: "center",
                                       color: MUTED,
                                       fontSize: 11,
                                    }}
                                 >
                                    нет строк под текущий фильтр
                                 </div>
                              )}
                           </div>
                        </div>
                     </div>
                  </div>

                  <p style={{ marginTop: 10, fontSize: 10, color: MUTED }}>
                     * WS/HTTPUpgrade → WebSocket. TCP/HTTP → fetch no-cors.
                     UDP/QUIC (Hysteria, TUIC) → HTTP ping. Браузер не может
                     делать raw TCP/UDP и не умеет ходить через
                     SOCKS5/HTTP-прокси с авторизацией — для ip:port:login:pass
                     проверяется только доступность порта, не сама авторизация.
                     <br />* В режиме «URI» строки ip:port:login:pass
                     конвертируются в socks://BASE64(login:pass)@host:port или
                     http://login:pass@host:port; если v2rayN не примет ссылку,
                     переключитесь на ip:port:login:pass.
                     <br />* Geo: офлайн-таблица RU-диапазонов (RIR, IPv4 + IPv6
                     до /48); домены резолвятся через DoH (Cloudflare → Google),
                     RU если любой из A/AAAA попал в диапазон. «?» — не удалось
                     резолвить, такие не скрываются. Это страна регистрации IP,
                     а не гарантия физического расположения (CDN, relay).
                     <br />* Дубликаты (отличаются только названием, spx,
                     headerType=none и т.п.) склеиваются; бейдж ×N — число
                     склеенных строк.
                  </p>
               </div>
            )}

            {!proxies.length && (
               <div
                  style={{
                     border: `1px dashed ${BORDER}`,
                     borderRadius: 10,
                     padding: "40px 24px",
                     textAlign: "center",
                     color: MUTED,
                     fontSize: 12,
                  }}
               >
                  <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.4 }}>
                     ⬡
                  </div>
                  <div style={{ marginBottom: 8 }}>
                     {parsing
                        ? "парсинг..."
                        : "вставьте прокси URI выше и нажмите [ parse ]"}
                  </div>
                  <div style={{ fontSize: 10, color: "#2d3d4e" }}>
                     {SUPPORTED.join("  ·  ")}
                  </div>
               </div>
            )}
         </div>
      </div>
   );
}
