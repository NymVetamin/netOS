import { Badge, Card, Empty, Tile } from "../ui";
import { formatBytes } from "../api";

const serviceNames: Record<string, string> = {
  netosd: "Панель netOS", "netos-dnsmasq": "DNS / DHCP · dnsmasq",
  "netos-unbound": "DNS · Unbound", "netos-dnsproxy": "DNS · dnsproxy",
  "netos-kea-dhcp4": "DHCP · Kea", "netos-isc-dhcp": "DHCP · ISC",
  "netos-samba": "Файловый сервер · Samba", "netos-wsdd": "Обнаружение сетевых папок",
  "netos-socks": "SOCKS-прокси", "netos-strongswan": "VPN · IKEv2",
  "netos-maintenance": "Обслуживание системы",
};

function serviceLabel(unit: string, title?: string): string {
  const name = unit.replace(/\.service$/, "");
  return serviceNames[name] || title || name.replace(/^netos-/, "").replace(/^xray-/, "Xray · ").replace(/^ocserv-/, "OpenConnect · ");
}

function serviceState(service: any): { label: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  if (service.state === "failed") return { label: "Ошибка", tone: "danger" };
  if (service.state === "activating" || service.state === "reloading") return { label: "Запускается / обновляется", tone: "warn" };
  if (service.state === "deactivating") return { label: "Останавливается", tone: "warn" };
  if (service.state === "active") return { label: service.substate === "exited" ? "Выполнена" : "Работает", tone: "ok" };
  if (service.state === "inactive") return { label: "Остановлена", tone: "neutral" };
  return { label: "Нет данных", tone: "warn" };
}

export function DashboardHealth({ status }: { status: any }) {
  const r = status.resources;
  const memory = r?.memory_total > 0 && r?.memory_used != null ? 100 * r.memory_used / r.memory_total : null;
  const disk = r?.disk_total > 0 && r?.disk_used != null ? 100 * r.disk_used / r.disk_total : null;
  const services = [...(status.services || [])].sort((a, b) => Number(b.state === "failed") - Number(a.state === "failed") || a.unit.localeCompare(b.unit));
  return <>
    <div className="tiles dashboard-resources" aria-label="Ресурсы роутера">
      <Tile icon="gauge" label="Процессор" value={r?.cpu_percent != null ? `${r.cpu_percent.toFixed(1)} %` : "—"} note={r?.cpu_percent != null ? "Загрузка всех ядер" : "Нет данных о загрузке"} />
      <Tile icon="layers" label="Оперативная память" value={memory != null ? `${memory.toFixed(1)} %` : "—"} note={memory != null ? `${formatBytes(r.memory_used)} из ${formatBytes(r.memory_total)} · без доступного кэша` : "Нет данных о памяти"} />
      <Tile icon="activity" label="Температура CPU" value={r?.cpu_temperature != null ? `${r.cpu_temperature.toFixed(1)} °C` : "—"} note={r?.cpu_temperature != null ? "Максимум по датчикам процессора" : "Датчик недоступен"} />
      <Tile icon="hard-drive" label="Системный диск" value={disk != null ? `${disk.toFixed(1)} %` : "—"} note={disk != null ? `${formatBytes(r.disk_used)} из ${formatBytes(r.disk_total)} · раздел /` : "Нет данных о диске"} />
    </div>
    <Card title="Службы" subtitle="Текущее состояние">
      {!status.services_available ? <Empty>Не удалось получить состояние служб. Повторим при обновлении.</Empty> : !services.length ? <Empty>Службы netOS не найдены</Empty> :
        <div className="dashboard-services">
          {services.map(service => {
            const state = serviceState(service);
            return <div className="dashboard-service" key={service.unit}>
              <div><strong>{serviceLabel(service.unit, service.title)}</strong><div className="faint mono">{service.unit}</div></div>
              <Badge tone={state.tone}><span className="dot" />{state.label}</Badge>
            </div>;
          })}
        </div>}
      <div className="row wrap dashboard-protection">
        <Badge tone={status.firewall_enabled ? "ok" : "warn"}>Файрволл {status.firewall_enabled ? "включён" : "выключен"}</Badge>
        <span className="faint">IPv6 {status.ipv6_mode === "off" ? "выключен" : "разрешён"}</span>
      </div>
    </Card>
  </>;
}
