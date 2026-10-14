export type VPNMapPeer = { id: string; name: string; address: string; state: string; label: string; endpoint: string; handshake: number; received: number; sent: number; trafficKnown: boolean; peer: any };
export type VPNMapServer = { id: string; name: string; type: string; enabled: boolean; subnet: string; peers: VPNMapPeer[]; server: any };

export function vpnMapServers(config: any, telemetry: Record<string, any[]>): VPNMapServer[] {
  return (config.vpn_servers || []).map((server: any) => ({
    id: server.id, name: server.name || server.id, type: server.type, enabled: !!server.enabled,
    subnet: server.subnet || "", server,
    peers: (server.peers || []).map((peer: any) => {
      const live = (telemetry[server.id] || []).find(row => row.id === peer.id &&
        (!peer.credentials?.public_key || row.public_key === peer.credentials.public_key));
      const state = !server.enabled ? "server_disabled" : !peer.enabled ? "disabled" : live?.state || "unknown";
      const labels: Record<string, string> = { online: "онлайн", offline: "оффлайн", recent: "недавно на связи", idle: "давно нет handshake", never: "ещё не подключался", disabled: "доступ запрещён", server_disabled: "сервер выключен", unknown: "состояние неизвестно" };
      return { id: peer.id, name: peer.name || peer.id, address: peer.address || "", state, label: labels[state] || labels.unknown,
        endpoint: live?.endpoint || "", handshake: live?.last_seen || live?.last_handshake || 0, trafficKnown: live?.traffic_known ?? !!live?.last_handshake, received: live?.received || 0, sent: live?.sent || 0, peer };
    }),
  }));
}
