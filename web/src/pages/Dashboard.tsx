import { TrafficMonitor } from "./TrafficMonitor";
import { DashboardHealth } from "./DashboardHealth";
import { linkSpeed } from "./PortLinkSettings";
import { useEffect, useState } from "react";
import { api, formatBytes, formatUptime } from "../api";
import { Badge, Card, Empty, Notice, Tile, TableWrap } from "../ui";
import { Icon } from "../icons";

// Сводка: то, на что администратор смотрит первым делом, когда что-то не
// работает. Поэтому здесь состояние аплинка, клиенты и счётчики интерфейсов,
// а не декоративные графики.
export function Dashboard({ config, patch }: { config: any; patch: (change: (draft: any) => void) => void }) {
  const [status, setStatus] = useState<any>(null);
  const [statusError, setStatusError] = useState(false);

  const wanInterfaces = (config.wans || [])
    .filter((w: any) => w.enabled)
    .map((w: any) => wanInterfaceName(config, w));

  useEffect(() => {
    let cancelled = false;
    let busy = false;
    const load = async () => {
      if (busy) return;
      busy = true;
      await Promise.all([
        api.status(true).then((result) => {
          if (!cancelled) { setStatus(result); setStatusError(false); }
        }).catch(() => { if (!cancelled) setStatusError(true); }),

      ]);
      busy = false;
    };
    load();
    const t = setInterval(load, 5000);
    return () => { cancelled = true; clearInterval(t); };
  }, [wanInterfaces.join(",")]);

  const interfaces: any[] = status?.interfaces || [];
  const wanNames = new Set(wanInterfaces);
  const wan = interfaces.find((i) => wanNames.has(i.name));
  const clients = status?.client_summary;

  return (
    <>
      <div className="page-head">
        <h1><Icon name="layout-dashboard" />Сводка</h1>
        <p>Состояние роутера {config.system?.hostname}</p>
      </div>

      {statusError && (
        <Notice tone="danger" title="Не удалось обновить состояние роутера">
          {status ? "Показаны последние полученные данные. " : ""}
          Повторная попытка выполняется автоматически.
        </Notice>
      )}
      {!status ? (
        statusError ? null : <Empty>Загрузка состояния роутера…</Empty>
      ) : <>
      <div className="tiles">
        <Tile
          icon="globe"
          label="Аплинк"
          value={wan ? (wan.up ? "На связи" : "Нет связи") : "Не настроен"}
          note={wan?.name}
          tone={wan?.up ? "ok" : "danger"}
          small
        />
        <Tile
          icon="users"
          label="Клиенты"
          value={clients ? `${clients.lan_online + clients.vpn_online} / ${clients.lan_total + clients.vpn_total}` : "—"}
          note={clients ? `В сети / всего · LAN ${clients.lan_online}/${clients.lan_total} · VPN ${clients.vpn_online}/${clients.vpn_total}${clients.vpn_unknown ? ` · нет данных: ${clients.vpn_unknown}` : ""}` : "Нет данных о клиентах"}
        />
        <Tile
          icon="activity"
          label="Соединений"
          value={status?.conntrack_count ?? "—"}
          note="отслеживается ядром"
        />
        <Tile
          icon={status?.os_id === "debian" || status?.os_id === "ubuntu" ? status.os_id : "history"}
          label="Время работы"
          value={formatUptime(status?.uptime_seconds)}
          note={status?.os_name || undefined}
          small
        />
      </div>

      <DashboardHealth status={status} />

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

      <Card title="Аплинки и VPN-каналы" subtitle="Текущее состояние применённых подключений">
        <div className="stack">
          {(status?.wans || []).map((wan: any) =>
            <div key={wan.id} className="row between wrap">
              <strong>{wan.name}</strong>
              <span className="mono faint">{wan.interface} {wan.address || ""}</span>
              <Badge tone={wan.up ? "ok" : "warn"}>{wan.probe_down ? "проба не прошла" : wan.up ? "поднят" : "нет связи"}</Badge>
            </div>)}
          {(status?.channels || []).map((channel: any) =>
            <div key={channel.id} className="row between wrap">
              <strong>{channel.name}</strong>
              <span className="mono faint">{channel.interface}</span>
              <Badge tone={channel.up ? "ok" : "warn"}>{channel.probe_down ? "проба не прошла" : channel.up ? "поднят" : "нет связи"}</Badge>
            </div>)}
        </div>
      </Card>

      <TrafficMonitor config={config} patch={patch} interfaces={wanInterfaces} status={status} />

      <Card title="Интерфейсы" subtitle="Счётчики с момента запуска системы" tight>
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Интерфейс</th>
                <th>Состояние</th>
                <th>Линк</th>
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
                  <td>
                    <span className="mono">{i.name}</span>
                    {(config.interfaces || []).find((p:any)=>p.name===i.name)?.label && <div>{(config.interfaces || []).find((p:any)=>p.name===i.name).label}</div>}
                    {i.name.startsWith("ifb-netos-") && (
                      <div className="faint" style={{ fontSize: 12 }}>Служебный интерфейс QoS: входящий трафик</div>
                    )}
                  </td>
                  <td>
                    <Badge tone={i.up ? "ok" : "neutral"}>{i.up ? "up" : "down"}</Badge>
                  </td>
                  <td>{linkSpeed(i) || "—"}</td>
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

      </>}
    </>
  );
}

export function interfaceName(config: any, id: string): string {
  const iface = (config.interfaces || []).find((i: any) => i.id === id);
  return iface?.name || id;
}

export function wanInterfaceName(config: any, wan: any): string {
  if (wan.proto === "pppoe" || wan.proto === "l2tp") return `ppp-${wan.id}`;
  return interfaceName(config, wan.interface);
}
