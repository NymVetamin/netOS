export const channelComponents = [
  { type: "wireguard", id: "wireguard", title: "WireGuard" },
  { type: "amneziawg", id: "amneziawg", title: "AmneziaWG" },
  { type: "openconnect", id: "openconnect", title: "OpenConnect" },
  { type: "xray", id: "xray", title: "Xray" },
  { type: "ikev2", id: "strongswan", title: "IKEv2 (strongSwan)" },
  { type: "l2tp", id: "l2tp", title: "L2TP" },
] as const;

// An AmneziaWG channel is stored as a WireGuard channel with obfuscation
// parameters; its kind decides the component, label and icon.
export function channelKind(channel: any): string {
  return channel?.type === "wireguard" && !channel.wireguard_peer && channel.config?.amneziawg ? "amneziawg" : channel?.type;
}

// A checkbox in the draft is not proof that the installation succeeded.
export function channelComponentReady(config: any, installed: Record<string, boolean> | null, type: string): boolean {
  const component = channelComponents.find(item => item.type === type);
  return !!component && installed?.[component.id] === true &&
    (config.components || []).some((item: any) => item.id === component.id && item.installed === true);
}
