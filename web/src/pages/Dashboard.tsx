import { TrafficMonitor } from "./TrafficMonitor";
import { useStatusPolling } from "../StatusPollingContext";
import { DashboardHealth } from "./DashboardHealth";
import { linkSpeed } from "./PortLinkSettings";
import { useEffect, useMemo, useState } from "react";
import { formatBytes, formatUptime } from "../api";
import { Badge, Card, Empty, Notice, Tile, TableWrap } from "../ui";
import { Icon } from "../icons";

// Сводка: то, на что администратор смотрит первым делом, когда что-то не
// работает. Поэтому здесь состояние аплинка, клиенты и счётчики интерфейсов,
// а не декоративные графики.
export function Dashboard({ config, patch }: { config: any; patch: (change: (draft: any) => void) => void }) {
  const statusPolling = useStatusPolling();
  const [status, setStatus] = useState<any>(null);
  const [statusError, setStatusError] = useState(false);
  const hasSegments = !!config.networks?.length;
  const { labelsByName, namesByID } = useMemo(() => {
    const labels = new Map<string, string>();
    const names = new Map<string, string>();
    for (const { id, name, label } of config.interfaces || []) {
      if (!labels.has(name)) labels.set(name, label);
      if (hasSegments && !names.has(id)) names.set(id, name);
    }
    return { labelsByName: labels, namesByID: names };
  }, [config.interfaces, hasSegments]);

  const liveByName = useMemo(() => {
    const ports = new Map<string, any>();
    if (hasSegments) {
      for (const port of status?.interfaces || []) {
        if (!ports.has(port.name)) ports.set(port.name, port);
      }
    }
    return ports;
  }, [status?.interfaces, hasSegments]);

  const wanInterfaces = (config.wans || [])
    .filter((w: any) => w.enabled)
    .map((w: any) => wanInterfaceName(config, w));

  useEffect(() => {
    let cancelled = false;
    const unsubscribe = statusPolling.subscribe(5000, true, request => {
      void request.then((result) => {
        if (!cancelled) { setStatus(result); setStatusError(false); }
      }).catch(() => { if (!cancelled) setStatusError(true); });
    });
    return () => { cancelled = true; unsubscribe(); };
  }, [statusPolling, wanInterfaces.join(",")]);

  const interfaces: any[] = status?.interfaces || [];
  const wans = status?.wans;
  const wan = wans?.find((item: any) => item.up) ?? wans?.[0];
  const wanState = wan ? (wan.up ? "На связи" : "Нет связи") : (wans === undefined ? "Нет данных" : "Не настроен");
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
          value={wanState}
          note={wan?.interface}
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
              const iface = namesByID.get(n.interface) || n.interface;
              const live = liveByName.get(iface);
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
              {interfaces.map((i) => {
                const label = labelsByName.get(i.name);
                return <tr key={i.name}>
                  <td>
                    <span className="mono">{i.name}</span>
                    {label && <div>{label}</div>}
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
                </tr>;
              })}
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
