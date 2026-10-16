// Display only: selectors and configuration must retain the OS interface name.
export function interfaceDisplay(config: any, name: string): string {
 const iface = (config.interfaces || []).find((item: any) => item.name === name);
 const label = String(iface?.label || "").trim();
 return label && label !== name ? `${label} (${name})` : name;
}
