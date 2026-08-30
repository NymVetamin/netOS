import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { Badge, Card, Empty, TableWrap } from "../ui";

// Для каждого клиента можно переопределить канал сегмента. Явные политики
// всё равно стоят выше этой настройки.
export function Clients({
  config,
  patch,
}: {
  config: any;
  patch: (mutate: (draft: any) => void) => void;
}) {
  const [clients, setClients] = useState<any[]>([]);
  const [leases, setLeases] = useState<any[]>([]);

  async function load() {
    const [c, l] = await Promise.all([api.clients(), api.leases()]);
    setClients(c.clients || []);
    setLeases(l.leases || []);
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, []);

  const leaseByMAC = new Map(leases.map((l) => [l.mac, l]));

  // Устройство описывается в конфигурации только когда о нём что-то задали:
  // имя, канал, блокировку. Пустые записи не копим.
  function updateClient(mac: string, changes: Record<string, unknown>) {
    patch((draft) => {
      draft.clients = draft.clients || [];
      const existing = draft.clients.find((c: any) => c.mac === mac);
      if (existing) {
        Object.assign(existing, changes);
        return;
      }
      const live = clients.find((client) => client.mac === mac);
      const detectedNetwork = (config.networks || []).find((network: any) => {
        const iface = (config.interfaces || []).find((item: any) => item.id === network.interface);
        return iface?.name === live?.interface;
      })?.id || "";
      draft.clients.push({
        id: "cl-" + mac.replace(/:/g, ""),
        mac,
        name: "",
        blocked: false,
        down_kbit: 0,
        up_kbit: 0,
        network: detectedNetwork,
        ...changes,
      });
    });
  }

  const known = new Map((config.clients || []).map((c: any) => [c.mac, c]));

  return (
    <>
      <div className="page-head">
        <h1>Клиенты</h1>
        <p>Устройства, которые роутер видит в сети</p>
      </div>

      <Card
        title="Устройства"
        subtitle={`${clients.filter((c) => c.online).length} в сети из ${clients.length}`}
        tight
      >
        {clients.length === 0 ? (
          <Empty>Устройств пока не видно</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Устройство</th>
                  <th>Адрес</th>
                  <th>MAC</th>
                  <th>Интерфейс</th>
                  <th>Источник</th>
                  <th>Аренда до</th>
                  <th>Канал</th>
                  <th>Сегмент</th>
                  <th>Лимит ↓ / ↑, Кбит/с</th>
                  <th>Доступ</th>
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => {
                  const cfgClient: any = known.get(c.mac);
                  const lease = leaseByMAC.get(c.mac);
                  return (
                    <tr key={c.mac}>
                      <td>
                        <div className="row">
                          <Badge tone={c.online ? "ok" : "neutral"}>
                            <span className="dot" />
                            {c.online ? "в сети" : "молчит"}
                          </Badge>
                          <input
                            type="text"
                            aria-label={`Имя устройства ${c.mac}`}
                            style={{ width: 150 }}
                            placeholder={c.hostname || "без имени"}
                            defaultValue={cfgClient?.name || ""}
                            onBlur={(e) => {
                              const v = e.target.value.trim();
                              if (v !== (cfgClient?.name || "")) updateClient(c.mac, { name: v });
                            }}
                          />
                        </div>
                      </td>
                      <td className="mono">{c.ip || "—"}</td>
                      <td className="mono faint">{c.mac}</td>
                      <td className="mono faint">{c.interface || "—"}</td>
                      <td>
                        <Badge tone={c.source === "both" ? "accent" : "neutral"}>
                          {c.source === "dhcp"
                            ? "DHCP"
                            : c.source === "arp"
                              ? "ARP"
                              : "DHCP + ARP"}
                        </Badge>
                      </td>
                      <td className="faint">{lease ? formatTime(lease.expires) : "—"}</td>
                      <td>
                        <select
                          aria-label={`Канал для устройства ${c.mac}`}
                          value={cfgClient?.channel || ""}
                          onChange={(e) => updateClient(c.mac, { channel: e.target.value })}
                        >
                          <option value="">По настройке сегмента</option>
                          {(config.channels || []).filter((channel: any) => channel.enabled).map((channel: any) => (
                            <option key={channel.id} value={channel.id}>{channel.name}</option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <select aria-label={`Сегмент для устройства ${c.mac}`} value={cfgClient?.network || ""} onChange={(e) => updateClient(c.mac, { network: e.target.value })}>
                          <option value="">— не выбран —</option>
                          {(config.networks || []).filter((network: any) => network.enabled).map((network: any) => (
                            <option key={network.id} value={network.id}>{network.name || network.id}</option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <div className="row" style={{ minWidth: 190 }}>
                          <input aria-label="Лимит загрузки" title="Загрузка" type="number" min={0} placeholder="без лимита" style={{ width: 88 }} value={cfgClient?.down_kbit || 0} onChange={(e) => updateClient(c.mac, { down_kbit: Number(e.target.value) })} />
                          <input aria-label="Лимит отдачи" title="Отдача" type="number" min={0} placeholder="без лимита" style={{ width: 88 }} value={cfgClient?.up_kbit || 0} onChange={(e) => updateClient(c.mac, { up_kbit: Number(e.target.value) })} />
                        </div>
                      </td>
                      <td>
                        <button
                          className={`btn sm ${cfgClient?.blocked ? "danger" : ""}`}
                          onClick={() => updateClient(c.mac, { blocked: !cfgClient?.blocked })}
                        >
                          {cfgClient?.blocked ? "Заблокирован" : "Разрешён"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Card
        title="Закреплённые адреса"
        subtitle="Устройство всегда получает один и тот же адрес"
        tight
      >
        {(config.dhcp?.reservations || []).length === 0 ? (
          <Empty>Закреплённых адресов нет</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>MAC</th>
                  <th>Адрес</th>
                  <th>Имя</th>
                  <th>Сеть</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {config.dhcp.reservations.map((r: any) => (
                  <tr key={r.id}>
                    <td className="mono">{r.mac}</td>
                    <td className="mono">{r.ip}</td>
                    <td>{r.hostname || <span className="faint">—</span>}</td>
                    <td className="faint">{r.network}</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost sm"
                        onClick={() =>
                          patch((d) => {
                            d.dhcp.reservations = d.dhcp.reservations.filter(
                              (x: any) => x.id !== r.id,
                            );
                          })
                        }
                      >
                        Убрать
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <AddReservation config={config} patch={patch} clients={clients} />
    </>
  );
}

function AddReservation({
  config,
  patch,
  clients,
}: {
  config: any;
  patch: (mutate: (draft: any) => void) => void;
  clients: any[];
}) {
  const networks = config.networks || [];
  const [mac, setMac] = useState("");
  const [ip, setIp] = useState("");
  const [hostname, setHostname] = useState("");
  const [network, setNetwork] = useState(networks[0]?.id || "");
  const [error, setError] = useState("");

  if (networks.length === 0) return null;

  return (
    <Card title="Закрепить адрес">
      <div className="form-grid">
        <div className="field">
          <label>Устройство</label>
          <select
            value={mac}
            onChange={(e) => {
              setMac(e.target.value);
              const c = clients.find((x) => x.mac === e.target.value);
              if (c?.hostname) setHostname(c.hostname);
              if (c?.ip) setIp(c.ip);
            }}
          >
            <option value="">— выберите или введите MAC ниже —</option>
            {clients.map((c) => (
              <option key={c.mac} value={c.mac}>
                {c.hostname || c.mac} {c.ip ? `(${c.ip})` : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>MAC-адрес</label>
          <input
            type="text"
            className="mono"
            placeholder="aa:bb:cc:dd:ee:ff"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
        </div>
        <div className="field">
          <label>IP-адрес</label>
          <input
            type="text"
            className="mono"
            placeholder="192.168.10.50"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Имя</label>
          <input type="text" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </div>
        <div className="field">
          <label>Сеть</label>
          <select value={network} onChange={(e) => setNetwork(e.target.value)}>
            {networks.map((n: any) => (
              <option key={n.id} value={n.id}>
                {n.name} ({n.router_address})
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="dim" style={{ color: "var(--danger)", marginBottom: "0.6rem" }}>
          {error}
        </div>
      )}

      <button
        className="btn primary"
        disabled={!mac || !ip}
        onClick={() => {
          setError("");
          patch((d) => {
            d.dhcp.reservations = d.dhcp.reservations || [];
            d.dhcp.reservations.push({
              id: "res-" + Date.now(),
              enabled: true,
              mac: mac.toLowerCase(),
              ip,
              hostname,
              network,
            });
          });
          setMac("");
          setIp("");
          setHostname("");
        }}
      >
        Закрепить
      </button>
    </Card>
  );
}
