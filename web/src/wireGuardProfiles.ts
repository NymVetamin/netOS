export type WireGuardProfile = { use_router_dns: boolean; dns: string[]; allowed_ips: string[] };

export function newWireGuardProfile(): WireGuardProfile {
  return { use_router_dns: true, dns: [], allowed_ips: ["0.0.0.0/0"] };
}

export function effectiveWireGuardProfile(server: any, peer: any): WireGuardProfile {
  // Preserve old exports until the client is explicitly edited.
  const profile = peer.wireguard_profile || {
    use_router_dns: false,
    dns: server.config?.client_dns || [],
    allowed_ips: server.config?.client_allowed_ips?.length ? server.config.client_allowed_ips : ["0.0.0.0/0"],
  };
  return {
    use_router_dns: !!profile.use_router_dns,
    dns: profile.use_router_dns ? [String(server.subnet || "").split("/")[0]] : [...(profile.dns || [])],
    allowed_ips: [...(profile.allowed_ips || [])],
  };
}

export function wireGuardClientConfig(server: any, peer: any, privateKey: string, serverPublicKey: string, presharedKey?: string) {
  const profile = effectiveWireGuardProfile(server, peer);
  const dns = profile.dns.length ? `DNS = ${profile.dns.join(", ")}\n` : "";
  const mtu = server.config?.mtu ? `MTU = ${server.config.mtu}\n` : "";
  const allowed = profile.allowed_ips;
  const address = String(peer.address || "").includes("/") ? peer.address : `${peer.address}/32`;
  const preshared = (peer.credentials?.preshared_key || presharedKey)
    ? `PresharedKey = ${peer.credentials?.preshared_key || presharedKey}\n`
    : "";
  return `[Interface]\nPrivateKey = ${privateKey}\nAddress = ${address}\n${dns}${mtu}\n[Peer]\nPublicKey = ${serverPublicKey}\n${preshared}Endpoint = ${server.config?.public_endpoint || ""}\nAllowedIPs = ${allowed.join(", ")}\nPersistentKeepalive = 25\n`;
}
