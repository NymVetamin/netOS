import { isWireGuardType, wireGuardPrefix } from "./amneziawg";
// Mirrors config normalization so a new exit is immediately selectable in the draft.
export function syncWireGuardPeerChannels(config: any) {
 const sources = new Map<string, any>();
 for (const s of config.vpn_servers || []) {
  if (!isWireGuardType(s.type)) continue;
  for (const p of s.peers || []) if (p.use_as_channel) {
   const id = `wg-exit-${s.id}`;
   if (!sources.has(id)) sources.set(id, {type:s.type,name:p.name, ref:{server_id:s.id,peer_id:p.id,server_index:s.index}});
  }
 }
 const used = new Set<number>((config.channels || []).map((c:any) => c.index));
 const present = new Set<string>();
 const managedNAT = new Map<string,string>();
 config.channels = (config.channels || []).filter((c:any) => {
  const source = sources.get(c.id);
  if (c.wireguard_peer) {
   managedNAT.set(`channel-nat-${c.id}`, source ? `${wireGuardPrefix(source.type)}-srv${source.ref.server_index}` : "");
   if (!source) return false;
   c.wireguard_peer = source.ref; c.type=source.type;
  }
  present.add(c.id);
  return true;
 });
 if (config.firewall?.nat) config.firewall.nat = config.firewall.nat.filter((rule:any) => {
  if (!rule.system || !managedNAT.has(rule.id)) return true;
  const iface = managedNAT.get(rule.id);
  if (!iface) return false;
  rule.interface = iface; return true;
 });
 let index = 1;
 for (const [id,source] of sources) {
  if (present.has(id)) continue;
  while (used.has(index)) index++;
  config.channels.push({id,index,name:source.name,enabled:true,type:source.type,mode:"tun",fail_mode:"block",config:{},wireguard_peer:source.ref,
   probe:{enabled:true,type:"icmp",targets:["1.1.1.1","8.8.8.8"],interval:10,timeout:3,fail_threshold:3,rise_threshold:2}});
  used.add(index);
 }
}
