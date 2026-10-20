import { basicMasquerade } from "./wanNAT";

export function channelNATInterface(channel: any): string {
 if (!channel) return "";
 const prefix: Record<string, string> = {wireguard:"wg-ch", openconnect:"tun-ch", xray:"tun-ch", l2tp:"ppp-ch", ikev2:"xfrm-ch"};
 return prefix[channel.type] && Number.isInteger(channel.index) && channel.index > 0 ? `${prefix[channel.type]}${channel.index}` : "";
}
export function channelNAT(config: any, channel: any) {
 const iface = channelNATInterface(channel);
 const rules = (config.firewall?.nat || []).filter((n: any) => basicMasquerade(n) && n.interface === iface);
 return {iface, manual: rules.some((n: any) => !n.system), enabled: rules.length ? rules.some((n: any) => n.enabled) : true};
}
export function setChannelNAT(config: any, channel: any, enabled: boolean) {
 const state = channelNAT(config, channel);
 if (!state.iface || state.manual) return;
 config.firewall = config.firewall || {};
 config.firewall.nat = config.firewall.nat || [];
 const rules = config.firewall.nat.filter((n: any) => n.system && basicMasquerade(n) && n.interface === state.iface);
 if (rules.length) rules.forEach((n: any) => { n.enabled = enabled; });
 else config.firewall.nat.push({id:`channel-nat-${channel.id}`,name:`NAT канала «${channel.name}»`,system:true,enabled,direction:"source",interface:state.iface});
}
export function managedChannelNAT(config: any, rule: any) {
 return !!rule.system && basicMasquerade(rule) && (config.channels || []).some((c: any) => channelNATInterface(c) === rule.interface && !channelNAT(config,c).manual);
}
export function removeChannelNAT(config: any, id: string) {
 if (config.firewall?.nat) config.firewall.nat = config.firewall.nat.filter((n: any) => !(n.system && n.id === `channel-nat-${id}`));
}
