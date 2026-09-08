export function parseXrayLink(value: string): any {
  if (value.startsWith("vmess://")) {
    const data = JSON.parse(decodeBase64(value.slice(8)));
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Некорректная VMess-ссылка");
    requireText(data.add, "В ссылке нет сервера");
    requireText(data.id, "В ссылке нет идентификатора пользователя");
    const port = parsePort(data.port);
    const alterId = Number(data.aid || 0);
    if (!Number.isInteger(alterId) || alterId < 0) throw new Error("Некорректный alterId");
    const outbound: any = { protocol: "vmess", settings: { vnext: [{ address: data.add, port, users: [{ id: data.id, alterId, security: data.scy || "auto" }] }] } };
    outbound.streamSettings = streamSettings(data.net || "tcp", data.tls || "none", { host: data.host, path: data.path, sni: data.sni, serviceName: data.path, fingerprint: data.fp });
    return outbound;
  }
  if (value.startsWith("ss://") && !value.slice(5).includes("@")) {
    const decoded = decodeBase64(value.slice(5).split("#")[0]);
    const at = decoded.lastIndexOf("@");
    if (at < 1) throw new Error("Некорректная Shadowsocks-ссылка");
    return shadowsocksOutbound(decoded.slice(0, at), decoded.slice(at + 1));
  }
  const url = new URL(value);
  requireText(url.hostname, "В ссылке нет сервера");
  const port = parsePort(url.port);
  if (url.protocol === "ss:") {
    const credentials = decodeBase64(decodeURIComponent(url.username));
    return shadowsocksOutbound(credentials, `${url.hostname}:${port}`);
  }
  const protocol = url.protocol.slice(0, -1);
  if (protocol !== "vless" && protocol !== "trojan") throw new Error("Поддерживаются vless://, vmess://, trojan:// и ss://");
  const user = decodeURIComponent(url.username);
  requireText(user, "В ссылке нет идентификатора пользователя или пароля");
  const server: any = { address: url.hostname, port };
  if (protocol === "vless") server.users = [{ id: user, encryption: url.searchParams.get("encryption") || "none", ...(url.searchParams.get("flow") ? { flow: url.searchParams.get("flow") } : {}) }];
  else server.password = user;
  const settings = protocol === "vless" ? { vnext: [server] } : { servers: [server] };
  return { protocol, settings, streamSettings: streamSettings(url.searchParams.get("type") || "tcp", url.searchParams.get("security") || "none", {
    host: url.searchParams.get("host"), path: url.searchParams.get("path"), sni: url.searchParams.get("sni"),
    serviceName: url.searchParams.get("serviceName"), fingerprint: url.searchParams.get("fp"),
    publicKey: url.searchParams.get("pbk"), shortId: url.searchParams.get("sid"), spiderX: url.searchParams.get("spx"),
  }) };
}

function streamSettings(network: string, security: string, options: any): any {
  const out: any = { network, security };
  if (network === "ws") out.wsSettings = { path: options.path || "/", headers: options.host ? { Host: options.host } : {} };
  if (network === "grpc") out.grpcSettings = { serviceName: options.serviceName || "" };
  if (network === "xhttp") out.xhttpSettings = { path: options.path || "/", host: options.host || "" };
  if (security === "tls") out.tlsSettings = { serverName: options.sni || options.host || "", fingerprint: options.fingerprint || "chrome" };
  if (security === "reality") out.realitySettings = { serverName: options.sni || "", fingerprint: options.fingerprint || "chrome", password: options.publicKey || "", shortId: options.shortId || "", spiderX: options.spiderX || "" };
  return out;
}

function shadowsocksOutbound(credentials: string, endpoint: string): any {
  const split = credentials.indexOf(":");
  const lastColon = endpoint.lastIndexOf(":");
  if (split < 1 || lastColon < 1) throw new Error("Некорректная Shadowsocks-ссылка");
  const method = credentials.slice(0, split), password = credentials.slice(split + 1), address = endpoint.slice(0, lastColon);
  requireText(method, "В ссылке нет метода шифрования");
  requireText(password, "В ссылке нет пароля");
  requireText(address, "В ссылке нет сервера");
  const port = parsePort(endpoint.slice(lastColon + 1));
  return { protocol: "shadowsocks", settings: { servers: [{ method, password, address, port }] } };
}

function requireText(value: unknown, message: string): asserts value is string {
  if (typeof value !== "string" || !value.trim()) throw new Error(message);
}

function parsePort(value: unknown): number {
  if ((typeof value !== "number" && typeof value !== "string") || !/^\d+$/.test(String(value))) {
    throw new Error("Порт должен быть целым числом от 1 до 65535");
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Порт должен быть от 1 до 65535");
  return port;
}

function decodeBase64(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

