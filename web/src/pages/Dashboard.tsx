import { useEffect, useState } from "react";
import { api, formatBytes, formatUptime } from "../api";
import { Badge, Card, Empty, Tile, TableWrap } from "../ui";

// Сводка: то, на что администратор смотрит первым делом, когда что-то не
// работает. Поэтому здесь состояние аплинка, клиенты и счётчики интерфейсов,
// а не декоративные графики.
export function Dashboard({ config }: { config: any }) {
  const [status, setStatus] = useState<any>(null);
  const [statistics, setStatistics] = useState<any[]>([]);

  const wanInterfaces = (config.wans || [])
    .filter((w: any) => w.enabled)
    .map((w: any) => wanInterfaceName(config, w));

  useEffect(() => {
    const load = () => {
      api.status().then(setStatus).catch(() => {});
      api.statistics(24, wanInterfaces).then((result) => setStatistics(result.points || [])).catch(() => {});
    };
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [wanInterfaces.join(",")]);

  const interfaces: any[] = status?.interfaces || [];
  const wanNames = new Set(wanInterfaces);
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

      <Card title="Скорость интернета" subtitle="Фактический трафик всех включённых интернет-каналов за 24 часа">
        <TrafficChart points={statistics} interfaces={wanInterfaces} />
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

function wanInterfaceName(config: any, wan: any): string {
  if (wan.proto === "pppoe" || wan.proto === "l2tp") return `ppp-${wan.id}`;
  return interfaceName(config, wan.interface);
}

function TrafficChart({ points, interfaces }: { points: any[]; interfaces: string[] }) {
  const series = points.map((point) => {
    let down = 0;
    let up = 0;
    for (const name of interfaces) {
      down += point.interfaces?.[name]?.rx_bps || 0;
      up += point.interfaces?.[name]?.tx_bps || 0;
    }
    return { at: point.at, down, up };
  });
  if (series.length < 2) return <Empty>История появится после двух замеров — примерно через 30 секунд</Empty>;
  const width = 720;
  const height = 190;
  const pad = 14;
  const peak = Math.max(1, ...series.flatMap((item) => [item.down, item.up]));
  const path = (key: "down" | "up") => series.map((item, index) => {
    const x = pad + (index / Math.max(1, series.length - 1)) * (width - pad * 2);
    const y = height - pad - (item[key] / peak) * (height - pad * 2);
    return `${index ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const last = series[series.length - 1];
  return (
    <div>
      <div className="row wrap" style={{ marginBottom: ".75rem", gap: "1rem" }}>
        <Badge tone="accent">↓ {formatBitrate(last.down)}</Badge>
        <Badge tone="ok">↑ {formatBitrate(last.up)}</Badge>
        <span className="faint">пик {formatBitrate(peak)}</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="График входящей и исходящей скорости" style={{ width: "100%", height: 190, display: "block" }}>
        {[0.25, 0.5, 0.75, 1].map((part) => <line key={part} x1={pad} x2={width - pad} y1={height - pad - part * (height - pad * 2)} y2={height - pad - part * (height - pad * 2)} stroke="var(--border)" strokeWidth="1" />)}
        <path d={path("down")} fill="none" stroke="var(--accent)" strokeWidth="3" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        <path d={path("up")} fill="none" stroke="var(--ok)" strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
      </svg>
    </div>
  );
}

function formatBitrate(value: number): string {
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} Гбит/с`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} Мбит/с`;
  if (value >= 1_000) return `${Math.round(value / 1_000)} Кбит/с`;
  return `${Math.round(value)} бит/с`;
}
