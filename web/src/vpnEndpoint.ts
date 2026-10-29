// Port belongs to the VPN protocol, never to the management panel.
export function newVPNEndpoint(server: {type: string; port?: number; config?: {listen?: string}}, publicHost: string): string {
  const listen = server.config?.listen;
  const host = listen && listen !== "0.0.0.0" && listen !== "::" ? listen : publicHost;
  if (!host) return "";
  if (server.type === "ikev2" || server.type === "l2tp") return host;
  const port = server.port || (server.type === "wireguard" ? 51820 : 443);
  return `${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${port}`;
}
