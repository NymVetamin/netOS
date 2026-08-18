import { useEffect, useState } from "react";
import { api, formatBytes, formatUptime } from "../api";
import { Badge, Card, Empty, Tile, TableWrap } from "../ui";

// Сводка: то, на что администратор смотрит первым делом, когда что-то не
// работает. Поэтому здесь состояние аплинка, клиенты и счётчики интерфейсов,
// а не декоративные графики.
export function Dashboard({ config }: { config: any }) {
  const [status, setStatus] = useState<any>(null);

  useEffect(() => {
    const load = () => api.status().then(setStatus).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const interfaces: any[] = status?.interfaces || [];
  const wanNames = new Set(
    (config.wans || [])
      .filter((w: any) => w.enabled)
      .map((w: any) => interfaceName(config, w.interface)),
  );
  const wan = interfaces.find((i) => wanNames.has(i.name));

  return (
    <>
      <div className="page-head">
        <h1>Сводка</h1>
        <p>Состояние роутера {config.system?.hostname}</p>
      </div>

      <div className="tiles">
        <Tile
          label="Аплинк"
          value={wan ? (wan.up ? "На связи" : "Нет связи") : "Не настроен"}
          note={wan?.name}
          tone={wan?.up ? "ok" : "danger"}
          small
        />
        <Tile
          label="Клиенты"
          value={status ? `${status.clients_online} / ${status.clients_total}` : "—"}
          note="в сети / всего известно"
        />
        <Tile
          label="Соединений"
          value={status?.conntrack_count ?? "—"}
          note="отслеживается ядром"
        />
        <Tile
          label="Время работы"
          value={formatUptime(status?.uptime_seconds)}
          small
        />
      </div>

      <Card title="Сетевые сегменты" subtitle="Локальные сети и их адреса">
        {(config.networks || []).length === 0 ? (
          <Empty>Сегменты не настроены</Empty>
        ) : (
          <div className="stack">
            {config.networks.map((n: any) => {
              const iface = interfaceName(config, n.interface);
              const live = interfaces.find((i) => i.name === iface);
              return (
                <div key={n.id} className="row between wrap">
                  <div className="row">
                    <Badge tone={live?.up ? "ok" : "warn"}>
                      <span className="dot" />
                      {live?.up ? "поднят" : "не поднят"}
                    </Badge>
                    <strong>{n.name}</strong>
                    <span className="mono dim">{n.router_address}</span>
                    <span className="faint">{iface}</span>
                  </div>
                  <div className="row">
                    {n.dhcp_pool?.enabled ? (
                      <span className="faint mono">
                        DHCP {n.dhcp_pool.start} – {n.dhcp_pool.end}
                      </span>
                    ) : (
                      <span className="faint">DHCP выключен</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card title="Интерфейсы" subtitle="Счётчики с момента запуска системы" tight>
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Интерфейс</th>
                <th>Состояние</th>
                <th>MAC</th>
                <th>MTU</th>
                <th>Принято</th>
                <th>Передано</th>
                <th>Ошибки</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((i) => (
                <tr key={i.name}>
                  <td className="mono">{i.name}</td>
                  <td>
                    <Badge tone={i.up ? "ok" : "neutral"}>{i.up ? "up" : "down"}</Badge>
                  </td>
                  <td className="mono faint">{i.mac}</td>
                  <td className="mono">{i.mtu}</td>
                  <td className="mono">{formatBytes(i.rx_bytes)}</td>
                  <td className="mono">{formatBytes(i.tx_bytes)}</td>
                  <td className="mono">
                    {i.rx_errors + i.tx_errors > 0 ? (
                      <span style={{ color: "var(--danger)" }}>
                        {i.rx_errors + i.tx_errors}
                      </span>
                    ) : (
                      <span className="faint">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Card>

      <Card title="Службы">
        <div className="row wrap" style={{ gap: "1.5rem" }}>
          <ServiceInfo label="DHCP" value={config.dhcp?.enabled ? config.dhcp.provider : "выключен"} />
          <ServiceInfo label="DNS" value={config.dns?.enabled ? config.dns.provider : "выключен"} />
          <ServiceInfo
            label="Файрволл"
            value={config.firewall?.enabled ? "включён" : "выключен"}
            tone={config.firewall?.enabled ? "ok" : "danger"}
          />
          <ServiceInfo
            label="IPv6"
            value={config.ipv6?.mode === "off" ? "подавлен" : "разрешён"}
            tone={config.ipv6?.mode === "off" ? "ok" : "warn"}
          />
        </div>
      </Card>
    </>
  );
}

function ServiceInfo({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "ok" | "warn" | "danger";
}) {
  return (
    <div>
      <div className="faint" style={{ fontSize: 12 }}>
        {label}
      </div>
      <div className="row" style={{ marginTop: 2 }}>
        {tone ? <Badge tone={tone}>{value}</Badge> : <strong>{value}</strong>}
      </div>
    </div>
  );
}

export function interfaceName(config: any, id: string): string {
  const iface = (config.interfaces || []).find((i: any) => i.id === id);
  return iface?.name || id;
}
