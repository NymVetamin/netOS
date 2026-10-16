import { createContext, useContext } from "react";
import type { AnchorHTMLAttributes, ReactNode } from "react";
import type { Session } from "./api";

export const PermissionContext = createContext<Session | null>(null);
export const PANEL_SECTIONS: Record<string, string> = {
  dashboard: "Сводка", map: "Карта сети", clients: "Клиенты", network: "Сеть",
  routing: "Маршрутизация", channels: "Интернет-каналы", "vpn-servers": "VPN-доступ",
  wifi: "Wi-Fi", traffic: "Скорость и QoS", firewall: "Защита сети", services: "Сетевые службы",
  components: "Компоненты", storage: "Диски и файлы", system: "Система", history: "История", diagnostics: "Диагностика",
};
export function canAccess(session: Session | null, section: string, manage = false): boolean {
  if (!session || session.role === "admin") return true;
  if (session.role === "viewer") return !manage && section !== "diagnostics";
  const level = session.permissions?.[section];
  return level === "manage" || (!manage && level === "view");
}
export function useAccess() {
  const session = useContext(PermissionContext);
  return (section: string, manage = false) => canAccess(session, section, manage);
}

export function SectionLink({ section, children, ...props }: { section: string; children: ReactNode } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href">) {
  const can = useAccess();
  return can(section) ? <a href={`#${section}`} {...props}>{children}</a> : <span className={props.className}>{children}</span>;
}
