import { connect } from "cloudflare:sockets";

/*
 * Privacy-first VLESS over WebSocket worker.
 *
 * No Trojan, no external fetches, no KV, no Telegram, no hidden fallback.
 * Configure all credentials and endpoints with Worker environment variables.
 *
 * Required:
 *   UUID = one UUID or comma-separated UUIDs
 *
 * Optional:
 *   DEFAULT_ROUTE = direct | proxyip | socks5 | http
 *   PROXYIP_POOL = host[:port],host[:port]
 *   SOCKS5_URL = socks5://user:pass@host:port
 *   HTTP_PROXY_URL = http://user:pass@host:port
 *   ROUTE_RULES = JSON array, for example:
 *     [{"match":"*.google.com","via":"socks5"},
 *      {"match":"speedtest.net","via":"direct"},
 *      {"match":"*.example.com","via":"proxyip"}]
 *   WS_PATH = / or /ws
 *   CONNECT_TIMEOUT_MS = 15000
 *   IDLE_TIMEOUT_MS = 300000
 *
 * Route semantics:
 *   direct  : Worker connects to the VLESS destination.
 *   socks5  : Worker connects to SOCKS5_URL and issues CONNECT destination.
 *   http    : Worker connects to HTTP_PROXY_URL and issues HTTP CONNECT destination.
 *   proxyip : Worker connects to a configured ProxyIP host. The destination
 *             port is retained unless the pool entry includes an explicit port.
 *
 * IMPORTANT: only use ProxyIP/SOCKS5/HTTP endpoints that you own or are
 * explicitly authorized to use. A hostname alone does not prove that it is
 * a working proxy endpoint.
 */

const DEFAULT_WS_PATH = "/";
const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;
const DEFAULT_IDLE_TIMEOUT_MS = 300_000;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_EARLY_DATA_BYTES = 8 * 1024;

export default {
  async fetch(request, env) {
    const config = loadConfig(env);
    const url = new URL(request.url);

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      if (url.pathname !== config.wsPath) {
        return new Response("Bad WebSocket path", { status: 404 });
      }
      return handleWebSocket(request, config);
    }

    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
      });
    }

    // Deliberately do not expose UUIDs, proxy endpoints, route rules, or links.
    return new Response("VLESS WebSocket endpoint", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" }
    });
  }
};

function loadConfig(env) {
  const uuids = String(env.UUID || env.UUIDS || "")
    .split(",")
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  if (!uuids.length || uuids.some((x) => !isValidUUID(x))) {
    throw new Error("UUID environment variable is missing or invalid");
  }

  const proxyPool = String(env.PROXYIP_POOL || env.PROXYIP || "")
    .split(/[\n,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

  let routeRules = [];
  if (env.ROUTE_RULES) {
    try {
      const parsed = JSON.parse(env.ROUTE_RULES);
      if (!Array.isArray(parsed)) throw new Error("ROUTE_RULES must be an array");
      routeRules = parsed.map(normalizeRule).filter(Boolean);
    } catch (error) {
      throw new Error(`Invalid ROUTE_RULES: ${error.message}`);
    }
  }

  const defaultRoute = String(env.DEFAULT_ROUTE || "direct").toLowerCase();
  if (!["direct", "proxyip", "socks5", "http"].includes(defaultRoute)) {
    throw new Error("DEFAULT_ROUTE must be direct, proxyip, socks5, or http");
  }

  const socks5 = parseProxyURL(env.SOCKS5_URL || env.SOCKS5);
  const httpProxy = parseProxyURL(env.HTTP_PROXY_URL || env.HTTP_PROXY);

  if (routeRules.some((r) => r.via === "proxyip") && !proxyPool.length) {
    throw new Error("A proxyip route exists but PROXYIP_POOL is empty");
  }
  if (routeRules.some((r) => r.via === "socks5") && !socks5) {
    throw new Error("A socks5 route exists but SOCKS5_URL is empty");
  }
  if (routeRules.some((r) => r.via === "http") && !httpProxy) {
    throw new Error("An http route exists but HTTP_PROXY_URL is empty");
  }

  return {
    uuids,
    proxyPool,
    socks5,
    httpProxy,
    routeRules,
    defaultRoute,
    wsPath: normalizePath(env.WS_PATH || DEFAULT_WS_PATH),
    connectTimeoutMs: boundedNumber(env.CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS, 1_000, 120_000),
    idleTimeoutMs: boundedNumber(env.IDLE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, 10_000, 1_800_000)
  };
}

function normalizeRule(rule) {
  if (!rule || typeof rule !== "object") return null;
  const match = String(rule.match || rule.host || "").trim().toLowerCase();
  const via = String(rule.via || "").trim().toLowerCase();
  if (!match || !["direct", "proxyip", "socks5", "http"].includes(via)) return null;
  return { match, via };
}

function normalizePath(path) {
  const value = String(path || "/").trim();
  return value.startsWith("/") ? value : `/${value}`;
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

function isValidUUID(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function handleWebSocket(request, config) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  const abort = new AbortController();
  let closed = false;
  let remote = null;
  let remoteWriter = null;
  let firstPacket = true;
  let pending = new Uint8Array(0);

  const close = (code = 1000, reason = "") => {
    if (closed) return;
    closed = true;
    try { abort.abort(reason); } catch (_) {}
    try { remoteWriter?.releaseLock(); } catch (_) {}
    remoteWriter = null;
    try { remote?.close(); } catch (_) {}
    try { if (server.readyState === 1 || server.readyState === 2) server.close(code, reason); } catch (_) {}
  };

  const readable = new ReadableStream({
    start(controller) {
      const onMessage = (event) => {
        if (closed) return;
        const bytes = toBytes(event.data);
        if (!bytes) return close(1003, "Binary frames only");
        controller.enqueue(bytes);
      };
      server.addEventListener("message", onMessage);
      server.addEventListener("close", () => { try { controller.close(); } catch (_) {} close(); });
      server.addEventListener("error", (event) => { try { controller.error(event); } catch (_) {} close(1011, "WebSocket error"); });

      const early = decodeEarlyData(request.headers.get("sec-websocket-protocol") || "", MAX_EARLY_DATA_BYTES);
      if (early) controller.enqueue(early);
    },
    cancel() { close(); }
  });

  const consume = readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (closed) return;
      pending = concatBytes(pending, chunk);

      if (firstPacket) {
        const parsed = parseVlessHeader(pending, config.uuids);
        if (!parsed) {
          if (pending.byteLength > MAX_HEADER_BYTES) throw new Error("Invalid or oversized VLESS header");
          return;
        }
        firstPacket = false;
        pending = new Uint8Array(0);
        const route = selectRoute(parsed.host, config);
        remote = await openRoute(route, parsed.host, parsed.port, config);
        remoteWriter = remote.writable.getWriter();
        if (parsed.payload.byteLength) await remoteWriter.write(parsed.payload);
        startRemoteToWebSocket(remote, server, parsed.responseHeader, close, config);
        return;
      }

      if (!remoteWriter) throw new Error("Remote connection is unavailable");
      await remoteWriter.write(chunk);
    },
    close() { close(); },
    abort() { close(1011, "Stream aborted"); }
  })).catch(() => close(1002, "Invalid VLESS request"));

  request.signal?.addEventListener("abort", () => close());
  void consume;
  return new Response(null, { status: 101, webSocket: client });
}

function parseVlessHeader(buffer, allowedUUIDs) {
  if (buffer.byteLength < 24) return null;
  try {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const version = bytes[0];
    const uuid = bytesToUUID(bytes.subarray(1, 17));
    if (!allowedUUIDs.includes(uuid)) throw new Error("Invalid UUID");

    const optionLength = bytes[17];
    const commandIndex = 18 + optionLength;
    if (commandIndex + 4 > bytes.length) return null;
    const command = bytes[commandIndex];
    if (command !== 1) throw new Error("Only VLESS TCP is supported");

    const portIndex = commandIndex + 1;
    const port = (bytes[portIndex] << 8) | bytes[portIndex + 1];
    const addressType = bytes[portIndex + 2];
    let cursor = portIndex + 3;
    let host = "";

    if (addressType === 1) {
      if (cursor + 4 > bytes.length) return null;
      host = Array.from(bytes.subarray(cursor, cursor + 4)).join(".");
      cursor += 4;
    } else if (addressType === 2) {
      if (cursor + 1 > bytes.length) return null;
      const length = bytes[cursor++];
      if (cursor + length > bytes.length) return null;
      host = new TextDecoder().decode(bytes.subarray(cursor, cursor + length));
      cursor += length;
    } else if (addressType === 3) {
      if (cursor + 16 > bytes.length) return null;
      const view = new DataView(bytes.buffer, bytes.byteOffset + cursor, 16);
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(view.getUint16(i * 2).toString(16));
      host = `[${parts.join(":")}]`;
      cursor += 16;
    } else {
      throw new Error("Unsupported address type");
    }

    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid destination");
    return {
      host,
      port,
      payload: bytes.slice(cursor),
      responseHeader: new Uint8Array([version, 0])
    };
  } catch (error) {
    // A complete but invalid first packet must fail; an incomplete packet returns null above.
    if (buffer.byteLength >= MAX_HEADER_BYTES) throw error;
    throw error;
  }
}

function selectRoute(host, config) {
  const normalized = stripIPv6Brackets(String(host).toLowerCase().replace(/\.$/, ""));
  for (const rule of config.routeRules) {
    if (hostMatches(normalized, rule.match)) return rule.via;
  }
  return config.defaultRoute;
}

function hostMatches(host, pattern) {
  const p = pattern.toLowerCase().replace(/\.$/, "");
  if (p === host) return true;
  if (p.startsWith("*.")) return host.endsWith(`.${p.slice(2)}`);
  if (p.startsWith(".")) return host.endsWith(p);
  return false;
}

async function openRoute(route, destinationHost, destinationPort, config) {
  if (route === "direct") return connectWithTimeout(destinationHost, destinationPort, config.connectTimeoutMs);
  if (route === "proxyip") {
    if (!config.proxyPool.length) throw new Error("No ProxyIP configured");
    const entry = config.proxyPool[Math.floor(Math.random() * config.proxyPool.length)];
    const endpoint = parseHostPort(entry, destinationPort);
    return connectWithTimeout(endpoint.host, endpoint.port, config.connectTimeoutMs);
  }
  if (route === "socks5") {
    if (!config.socks5) throw new Error("No SOCKS5 endpoint configured");
    return openSocks5(config.socks5, destinationHost, destinationPort, config.connectTimeoutMs);
  }
  if (route === "http") {
    if (!config.httpProxy) throw new Error("No HTTP proxy endpoint configured");
    return openHttpConnect(config.httpProxy, destinationHost, destinationPort, config.connectTimeoutMs);
  }
  throw new Error("Unknown route");
}

async function connectWithTimeout(host, port, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // cloudflare:sockets currently accepts hostname/port; the AbortController is
    // still used to bound the surrounding operation where supported by runtime.
    const socket = connect({ hostname: stripIPv6Brackets(host), port });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => controller.signal.addEventListener("abort", () => reject(new Error("Connect timeout")), { once: true }))
    ]);
    return socket;
  } finally {
    clearTimeout(timer);
  }
}

async function openSocks5(proxy, destinationHost, destinationPort, timeoutMs) {
  const socket = await connectWithTimeout(proxy.host, proxy.port, timeoutMs);
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    const authMethods = proxy.username ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
    await writer.write(authMethods);
    let response = await readExactly(reader, 2);
    if (response[0] !== 5 || response[1] === 255) throw new Error("SOCKS5 authentication unavailable");

    if (response[1] === 2) {
      if (!proxy.username) throw new Error("SOCKS5 username/password required");
      const user = new TextEncoder().encode(proxy.username);
      const pass = new TextEncoder().encode(proxy.password || "");
      if (user.length > 255 || pass.length > 255) throw new Error("SOCKS5 credentials too long");
      await writer.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
      response = await readExactly(reader, 2);
      if (response[1] !== 0) throw new Error("SOCKS5 authentication failed");
    } else if (response[1] !== 0) {
      throw new Error("Unsupported SOCKS5 method");
    }

    const target = encodeSocksAddress(destinationHost);
    await writer.write(new Uint8Array([5, 1, 0, ...target, destinationPort >> 8, destinationPort & 255]));
    const head = await readExactly(reader, 4);
    if (head[0] !== 5 || head[1] !== 0) throw new Error(`SOCKS5 CONNECT failed: ${head[1]}`);
    const replyLength = head[3] === 1 ? 4 : head[3] === 4 ? 16 : (await readExactly(reader, 1))[0];
    await readExactly(reader, replyLength + 2);
    return socket;
  } finally {
    writer.releaseLock();
    reader.releaseLock();
  }
}

async function openHttpConnect(proxy, destinationHost, destinationPort, timeoutMs) {
  const socket = await connectWithTimeout(proxy.host, proxy.port, timeoutMs);
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  try {
    const authority = `${stripIPv6Brackets(destinationHost)}:${destinationPort}`;
    let request = `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nConnection: keep-alive\r\n`;
    if (proxy.username) {
      request += `Proxy-Authorization: Basic ${btoa(`${proxy.username}:${proxy.password || ""}`)}\r\n`;
    }
    request += `\r\n`;
    await writer.write(new TextEncoder().encode(request));
    const response = await readUntilHeaderEnd(reader);
    const status = new TextDecoder().decode(response).match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
    if (!status || status[1] !== "200") throw new Error(`HTTP CONNECT failed: ${status ? status[1] : "invalid response"}`);
    return socket;
  } finally {
    writer.releaseLock();
    reader.releaseLock();
  }
}

async function startRemoteToWebSocket(socket, webSocket, responseHeader, close, config) {
  let header = responseHeader;
  let lastData = Date.now();
  const timer = setInterval(() => {
    if (Date.now() - lastData > config.idleTimeoutMs) close(1000, "Idle timeout");
  }, Math.min(10_000, config.idleTimeoutMs));

  try {
    await socket.readable.pipeTo(new WritableStream({
      write(chunk) {
        lastData = Date.now();
        if (webSocket.readyState !== 1) throw new Error("WebSocket closed");
        if (header) {
          webSocket.send(concatBytes(header, toBytes(chunk)));
          header = null;
        } else {
          webSocket.send(chunk);
        }
      }
    }));
  } catch (_) {
    close(1000, "Remote connection closed");
  } finally {
    clearInterval(timer);
    close();
  }
}

function parseProxyURL(value) {
  if (!value) return null;
  try {
    const url = new URL(String(value).includes("://") ? value : `socks5://${value}`);
    const scheme = url.protocol.replace(":", "").toLowerCase();
    if (!["socks5", "socks5h", "http", "https"].includes(scheme)) throw new Error("Unsupported proxy scheme");
    if (!url.hostname || !url.port) throw new Error("Proxy port is required");
    return {
      scheme: scheme.startsWith("socks5") ? "socks5" : "http",
      host: url.hostname,
      port: Number(url.port),
      username: url.username ? decodeURIComponent(url.username) : "",
      password: url.password ? decodeURIComponent(url.password) : ""
    };
  } catch (error) {
    throw new Error(`Invalid proxy URL: ${error.message}`);
  }
}

function parseHostPort(value, defaultPort) {
  const raw = String(value).trim();
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    if (end < 0) throw new Error("Invalid ProxyIP IPv6 endpoint");
    return { host: raw.slice(1, end), port: raw.slice(end + 1).startsWith(":") ? Number(raw.slice(end + 2)) : defaultPort };
  }
  const lastColon = raw.lastIndexOf(":");
  if (lastColon > -1 && /^\d+$/.test(raw.slice(lastColon + 1))) {
    return { host: raw.slice(0, lastColon), port: Number(raw.slice(lastColon + 1)) };
  }
  return { host: raw, port: defaultPort };
}

function encodeSocksAddress(host) {
  const clean = stripIPv6Brackets(host);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) return new Uint8Array([1, ...clean.split(".").map(Number)]);
  if (clean.includes(":")) {
    const parts = clean.split(":");
    const expanded = expandIPv6(parts);
    return new Uint8Array([4, ...expanded.flatMap((x) => [x >> 8, x & 255])]);
  }
  const bytes = new TextEncoder().encode(clean);
  if (bytes.length > 255) throw new Error("Destination hostname too long");
  return new Uint8Array([3, bytes.length, ...bytes]);
}

function expandIPv6(parts) {
  const index = parts.indexOf("");
  if (index >= 0) {
    const missing = 8 - (parts.filter(Boolean).length);
    parts = [...parts.slice(0, index), ...Array(missing).fill("0"), ...parts.slice(index + 1)];
  }
  return parts.slice(0, 8).map((x) => parseInt(x || "0", 16));
}

async function readExactly(reader, length) {
  const output = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const { done, value } = await reader.read();
    if (done) throw new Error("Proxy closed during handshake");
    const bytes = toBytes(value);
    if (!bytes) throw new Error("Invalid proxy response");
    const take = Math.min(bytes.length, length - offset);
    output.set(bytes.subarray(0, take), offset);
    offset += take;
    if (take < bytes.length) throw new Error("Unexpected buffered proxy data");
  }
  return output;
}

async function readUntilHeaderEnd(reader) {
  let result = new Uint8Array(0);
  while (result.length <= MAX_HEADER_BYTES) {
    const { done, value } = await reader.read();
    if (done) throw new Error("Proxy closed during HTTP handshake");
    const bytes = toBytes(value);
    result = concatBytes(result, bytes);
    const text = new TextDecoder().decode(result);
    if (text.includes("\r\n\r\n")) return result;
  }
  throw new Error("HTTP proxy headers too large");
}

function decodeEarlyData(value, maxBytes) {
  if (!value) return null;
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(normalized);
    if (decoded.length > maxBytes) return null;
    return Uint8Array.from(decoded, (c) => c.charCodeAt(0));
  } catch (_) {
    return null;
  }
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

function concatBytes(a, b) {
  const left = toBytes(a) || new Uint8Array(0);
  const right = toBytes(b) || new Uint8Array(0);
  const output = new Uint8Array(left.length + right.length);
  output.set(left, 0);
  output.set(right, left.length);
  return output;
}

function stripIPv6Brackets(host) {
  const value = String(host);
  return value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
}

function bytesToUUID(bytes) {
  if (bytes.length !== 16) throw new Error("Invalid UUID bytes");
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`.toLowerCase();
}
