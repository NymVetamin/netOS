export type AutomaticNAT = { id: string; name: string; iface: string; kind: "wan" | "channel" };

// Условия и порядок соответствуют builder.nat в subsys/firewall/ruleset.go.
// Это представление черновика, а не чтение действующего ruleset ОС.
export function automaticNAT(config: any): AutomaticNAT[] {
  const result: AutomaticNAT[] = [];
  const covered = new Set<string>((config.firewall?.nat || [])
    .filter((n: any) => n.direction !== "destination" && n.interface && !n.source && !n.to_source)
    .map((n: any) => n.interface));
  for (const wan of config.wans || []) {
    const iface = ["pppoe", "l2tp"].includes(wan.proto) ? `ppp-${wan.id}`
      : (config.interfaces || []).find((i: any) => i.id === wan.interface)?.name || "";
    if (wan.enabled && !covered.has(iface)) {
      covered.add(iface);
      result.push({ id: `auto-wan-${wan.id}`, name: `NAT аплинка «${wan.name}»`, iface, kind: "wan" });
    }
  }
  const prefixes: Record<string, string> = { wireguard: "wg", openconnect: "tun", xray: "tun", l2tp: "ppp", ikev2: "xfrm" };
  for (const channel of config.channels || []) {
    if (channel.enabled && prefixes[channel.type]) result.push({
      id: `auto-channel-${channel.id}`, name: `NAT канала «${channel.name}»`,
      iface: `${prefixes[channel.type]}-ch${channel.index || 0}`, kind: "channel",
    });
  }
  return result;
}
