export function networkInterfaceView(config: any) {
  const interfaces: any[] = config.interfaces || [];
  const masters = new Map<string, any>();
  const wans = new Map<string, any>();
  const networks = new Map<string, any>();
  const vlans = new Map<string, string[]>();
  const labels = new Map<string, string>();
  for (const iface of interfaces) {
    if (iface.type === "bridge" || iface.type === "bond") {
      for (const member of iface.members || []) if (!masters.has(member)) masters.set(member, iface);
    }
    if (iface.type === "vlan") {
      let names = vlans.get(iface.parent);
      if (!names) vlans.set(iface.parent, names = []);
      names.push(iface.name);
    }
  }
  for (const wan of config.wans || []) if (!wans.has(wan.interface)) wans.set(wan.interface, wan);
  for (const net of config.networks || []) if (!networks.has(net.interface)) networks.set(net.interface, net);
  for (const iface of interfaces) {
    const parts: string[] = [];
    const master = masters.get(iface.id), wan = wans.get(iface.id), net = networks.get(iface.id);
    if (master) parts.push((master.type === "bond" ? "в агрегации " : "в мосту ") + master.name);
    if (wan) parts.push("аплинк «" + wan.name + "»");
    if (net) parts.push("сегмент «" + net.name + "»");
    const children = vlans.get(iface.id);
    if (children?.length) parts.push("VLAN " + children.join(", "));
    labels.set(iface.id, parts.join(", "));
  }
  return {
    usage: (iface: any): string => labels.get(iface.id) || "",
    // Keep a selected subordinate port visible, as in an incomplete draft.
    options: (selected: string): any[] => interfaces.filter(iface => iface.id === selected || !masters.has(iface.id)),
  };
}
