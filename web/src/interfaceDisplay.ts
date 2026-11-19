// Display only: selectors and configuration must retain the OS interface name.
export function interfaceDisplay(config: any, name: string): string {
 const iface = (config.interfaces || []).find((item: any) => item.name === name);
 return interfaceLabel(name, iface?.label);
}

export function interfaceLabel(name: string, value: unknown): string {
 const label = String(value || "").trim();
 return label && label !== name ? `${label} (${name})` : name;
}
