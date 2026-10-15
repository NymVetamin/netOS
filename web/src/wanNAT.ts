export const wanInterface = (config: any, wan: any): string => ["pppoe", "l2tp"].includes(wan.proto)
  ? `ppp-${wan.id}` : (config.interfaces || []).find((i: any) => i.id === wan.interface)?.name || "";
export const basicMasquerade = (n: any) => n.direction !== "destination" && !n.source && !n.to_source && !!n.interface;
export function wanNAT(config: any, wan: any) {
 const iface = wanInterface(config, wan);
 const rules = (config.firewall?.nat || []).filter((n: any) => basicMasquerade(n) && n.interface === iface);
 return { iface, manual: rules.some((n: any) => !n.system), enabled: rules.length ? rules.some((n: any) => n.enabled) : true };
}
export function setWanNAT(config: any, wan: any, enabled: boolean) {
 const state = wanNAT(config, wan);
 if (!state.iface || state.manual) return;
 config.firewall = config.firewall || {};
 config.firewall.nat = config.firewall.nat || [];
 const rules = config.firewall.nat.filter((n: any) => n.system && basicMasquerade(n) && n.interface === state.iface);
 if (rules.length) rules.forEach((n: any) => { n.enabled = enabled; });
 else config.firewall.nat.push({id:`wan-nat-${wan.id}`, name:`NAT аплинка «${wan.name}»`,system:true,enabled,direction:"source",interface:state.iface});
}
export function managedWanNAT(config: any, rule: any) {
 return !!rule.system && basicMasquerade(rule) && (config.wans || []).some((w: any) => wanInterface(config,w) === rule.interface && !wanNAT(config,w).manual);
}
