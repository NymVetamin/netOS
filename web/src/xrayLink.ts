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
    outbound.streamSettings = streamSettings(data.net || "tcp", data.tls || "none", { host: data.host, path: data.path, sni: data.sni, serviceName: data.path, fingerprint: data.fp, pcs: data.pcs, vcn: data.vcn });
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
  if (url.protocol === "hysteria2:" || url.protocol === "hy2:") return hysteriaOutbound(url);
  if (url.protocol === "socks5:" || url.protocol === "http:") {
    const user = decodeURIComponent(url.username), pass = decodeURIComponent(url.password);
    requireText(user, "В ссылке нет логина");
    requireText(pass, "В ссылке нет пароля");
    const port = parsePort(url.port || (url.protocol === "http:" ? "80" : "1080"));
    return { protocol: url.protocol === "socks5:" ? "socks" : "http", settings: { servers: [{
      address: url.hostname.replace(/^\[|\]$/g, ""), port, users: [{ user, pass }],
    }] } };
  }
  const port = parsePort(url.port);
  if (url.protocol === "ss:") {
    const credentials = decodeBase64(decodeURIComponent(url.username));
    return shadowsocksOutbound(credentials, `${url.hostname}:${port}`);
  }
  const protocol = url.protocol.slice(0, -1);
  if (protocol !== "vless" && protocol !== "trojan") throw new Error("Поддерживаются vless://, vmess://, trojan://, ss://, hysteria2://, hy2://, socks5:// и http://");
  const user = decodeURIComponent(url.username);
  requireText(user, "В ссылке нет идентификатора пользователя или пароля");
  if (protocol === "vless" && !isUUID(user)) throw new Error("Идентификатор пользователя VLESS должен быть UUID");
  const server: any = { address: url.hostname, port };
  if (protocol === "vless") server.users = [{ id: user, encryption: url.searchParams.get("encryption") || "none", ...(url.searchParams.get("flow") ? { flow: url.searchParams.get("flow") } : {}) }];
  else server.password = user;
  const settings = protocol === "vless" ? { vnext: [server] } : { servers: [server] };
  return { protocol, settings, streamSettings: streamSettings(url.searchParams.get("type") || "tcp", url.searchParams.get("security") || "none", {
    host: url.searchParams.get("host"), path: url.searchParams.get("path"), sni: url.searchParams.get("sni"),
    serviceName: url.searchParams.get("serviceName"), fingerprint: url.searchParams.get("fp"),
    publicKey: url.searchParams.get("pbk"), shortId: url.searchParams.get("sid"), spiderX: url.searchParams.get("spx"),
    mode: url.searchParams.get("mode"), extra: url.searchParams.get("extra"), alpn: url.searchParams.get("alpn"),
    pcs: url.searchParams.get("pcs"), vcn: url.searchParams.get("vcn"),
  }) };
}

function hysteriaOutbound(url: URL): any {
  const auth = decodeURIComponent(url.username + (url.password ? `:${url.password}` : ""));
  requireText(auth, "В ссылке нет пароля Hysteria 2");
  const query = url.searchParams;
  const tls: any = { serverName: query.get("sni") || url.hostname };
  const insecure = query.get("insecure");
  if (insecure !== null && insecure !== "0" && insecure !== "1") throw new Error("Параметр insecure должен быть 0 или 1");
  const pin = query.get("pinSHA256");
  if (pin !== null) {
    const normalized = pin.replace(/:/g, "");
    if (!/^[a-f0-9]{64}$/i.test(normalized)) throw new Error("pinSHA256 должен содержать SHA-256 сертификата");
    tls.pinnedPeerCertSha256 = normalized;
  }
  if (insecure === "1" && !pin) throw new Error("Для insecure=1 укажите pinSHA256: Xray требует закреплённый сертификат");
  if (query.has("alpn")) {
    tls.alpn = query.get("alpn")!.split(",").map(value => value.trim()).filter(Boolean);
    if (!tls.alpn.length) throw new Error("Параметр alpn не должен быть пустым");
  }
  const stream: any = { method: "hysteria", security: "tls", tlsSettings: tls, hysteriaSettings: { version: 2, auth } };
  if (query.has("fm")) {
    let mask: any;
    try { mask = JSON.parse(query.get("fm")!); }
    catch { throw new Error("Параметр fm должен содержать корректный JSON-объект"); }
    if (!mask || typeof mask !== "object" || Array.isArray(mask)) throw new Error("Параметр fm должен быть JSON-объектом");
    if (mask.udp !== undefined && (!Array.isArray(mask.udp) || mask.udp.some((item: any) => !item || typeof item !== "object" || Array.isArray(item) || typeof item.type !== "string"))) {
      throw new Error("Параметр fm.udp должен содержать массив UDP-масок");
    }
    stream.finalmask = mask;
  }
  const obfs = query.get("obfs");
  if (obfs) {
    if (obfs !== "salamander") throw new Error("Поддерживается obfs=salamander; другие маски задайте через fm или outbound JSON");
    const password = query.get("obfs-password");
    requireText(password, "В ссылке нет obfs-password");
    // Share links may describe the same mask twice. Applying it twice breaks the wire format.
    const masks = stream.finalmask?.udp;
    if (masks?.length) {
      if (!masks.some((item: any) => item.type === "salamander" && item.settings?.password === password)) {
        throw new Error("Параметры obfs и fm задают разные UDP-маски");
      }
    } else {
      stream.finalmask = { ...stream.finalmask, udp: [{ type: "salamander", settings: { password } }] };
    }
  }
  return { protocol: "hysteria", settings: { version: 2, address: url.hostname, port: parsePort(url.port || "443") }, streamSettings: stream };
}

function streamSettings(network: string, security: string, options: any): any {
  const out: any = { network, security };
  if (network === "ws") out.wsSettings = { path: options.path || "/", headers: options.host ? { Host: options.host } : {} };
  if (network === "grpc") out.grpcSettings = { serviceName: options.serviceName || "" };
  if (network === "xhttp") {
    out.xhttpSettings = { path: options.path || "/", host: options.host || "" };
    if (options.mode) out.xhttpSettings.mode = options.mode;
    if (options.extra != null) {
      let extra: unknown;
      try { extra = JSON.parse(options.extra); }
      catch { throw new Error("Параметр XHTTP extra должен содержать корректный JSON-объект"); }
      if (!extra || typeof extra !== "object" || Array.isArray(extra)) throw new Error("Параметр XHTTP extra должен быть JSON-объектом");
      out.xhttpSettings.extra = extra;
    }
  }
  if (security === "tls") out.tlsSettings = { serverName: options.sni || options.host || "", fingerprint: options.fingerprint || "chrome" };
  if (security === "tls" && options.alpn) out.tlsSettings.alpn = options.alpn.split(",").map((value: string) => value.trim()).filter(Boolean);
  if (security === "tls" && options.pcs) out.tlsSettings.pinnedPeerCertSha256 = options.pcs;
  if (security === "tls" && options.vcn) out.tlsSettings.verifyPeerCertByName = options.vcn;
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

function isUUID(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
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

