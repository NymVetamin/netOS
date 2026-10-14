// Используем те же данные, что сервер выдаёт для ссылки и QR-кода.
export function realityClientConfig(link: string) {
  const url = new URL(link);
  const q = url.searchParams;
  if (url.protocol !== "vless:" || q.get("security") !== "reality") throw new Error("Некорректный профиль Reality");
  return {
    log: { loglevel: "warning" },
    inbounds: [{ tag: "socks", listen: "127.0.0.1", port: 10808, protocol: "socks", settings: { auth: "noauth", udp: true } }],
    outbounds: [{
      tag: "proxy", protocol: "vless",
      settings: { vnext: [{ address: url.hostname.replace(/^\[|\]$/g, ""), port: Number(url.port), users: [{
        id: decodeURIComponent(url.username), encryption: "none", ...(q.get("flow") ? { flow: q.get("flow") } : {}),
      }] }] },
      streamSettings: { network: "tcp", security: "reality", realitySettings: {
        serverName: q.get("sni"), fingerprint: q.get("fp") || "chrome", password: q.get("pbk"), shortId: q.get("sid"),
      } },
    }],
  };
}
