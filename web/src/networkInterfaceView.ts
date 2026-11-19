export function networkInterfaceView(config: any) {
  const interfaces: any[] = config.interfaces || [];
  const firstByName = new Map<string, any>();
  const parents: any[] = [];
  const byID = new Map<string, any>();
  const masters = new Map<string, any>();
  const wans = new Map<string, any>();
  const networks = new Map<string, any>();
  const vlans = new Map<string, string[]>();
  const labels = new Map<string, string>();
  for (const iface of interfaces) {
    if (!firstByName.has(iface.name)) firstByName.set(iface.name, iface);
    if (!byID.has(iface.id)) byID.set(iface.id, iface);
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
    if (!master && iface.type !== "vlan") parents.push(iface);
    if (master) parts.push((master.type === "bond" ? "в агрегации " : "в мосту ") + master.name);
    if (wan) parts.push("аплинк «" + wan.name + "»");
    if (net) parts.push("сегмент «" + net.name + "»");
    const children = vlans.get(iface.id);
    if (children?.length) parts.push("VLAN " + children.join(", "));
    labels.set(iface.id, parts.join(", "));
  }
  return {
    vlanParents: (exceptID: string): any[] => parents.filter(iface => iface.id !== exceptID),
    labelForName: (name: string) => firstByName.get(name)?.label,
    memberBlocker: (id: string, targetID: string): string => {
      const master = masters.get(id);
      if (master && master.id !== targetID) return "уже в " + master.name;
      if (wans.has(id)) return "занят аплинком";
      const net = networks.get(id);
      return net ? "занят сегментом «" + net.name + "»" : "";
    },
    name: (id: string): string | undefined => byID.get(id)?.name,
    displayName: (id: string): string => {
      const iface = byID.get(id);
      return iface ? iface.label ? `${iface.label} (${iface.name})` : iface.name : "не выбран";
    },
    usage: (iface: any): string => labels.get(iface.id) || "",
    // Keep a selected subordinate port visible, as in an incomplete draft.
    options: (selected: string): any[] => interfaces.filter(iface => iface.id === selected || !masters.has(iface.id)),
  };
}

export function vlanParents(config: any, exceptID?: string): any[] {
  const interfaces = config.interfaces || [];
  const members = new Set<string>();
  for (const iface of interfaces) {
    if (iface.type === "bridge" || iface.type === "bond") {
      for (const id of iface.members || []) members.add(id);
    }
  }
  return interfaces.filter((iface: any) =>
    iface.id !== exceptID && iface.type !== "vlan" && !members.has(iface.id));
}

type VlanChoice = { parent: any; vlanID: number } | { reason: "no-parent" | "full" };

export function nextVlan(config: any): VlanChoice {
  const parents = vlanParents(config);
  if (!parents.length) return { reason: "no-parent" };

  const used = new Map<string, Set<number>>();
  for (const iface of config.interfaces) {
    if (iface.type !== "vlan") continue;
    let ids = used.get(iface.parent);
    if (!ids) {
      ids = new Set();
      used.set(iface.parent, ids);
    }
    ids.add(iface.vlan_id);
  }
  for (const parent of parents) {
    const ids = used.get(parent.id);
    for (let vlanID = 100; vlanID <= 4094; vlanID++) {
      if (!ids?.has(vlanID)) return { parent, vlanID };
    }
    for (let vlanID = 1; vlanID < 100; vlanID++) {
      if (!ids?.has(vlanID)) return { parent, vlanID };
    }
  }
  return { reason: "full" };
}
