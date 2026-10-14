import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { localDevices } from "../deviceList";
import { vpnMapServers } from "../mapVPN";
import { newID } from "../id";
import { Badge, Cap, Card, Empty, Notice, Row, Rows } from "../ui";

function ClientChannel({ config, value, inherited, source, label, onChange }: {
  config: any; value: string; inherited?: string; source: string; label: string; onChange: (value: string) => void;
}) {
  const channels = config.channels || [];
  const name = (id: string) => channels.find((c: any) => c.id === id)?.name || (id === "direct" ? "Напрямую" : id);
  return <select className="client-channel" aria-label={label} value={value} onChange={e => onChange(e.target.value)} onClick={e => e.stopPropagation()}>
    <option value="">{source}{inherited ? ` — ${name(inherited)}` : ""}</option>
    {value && !channels.some((c: any) => c.id === value && c.enabled) && <option value={value} disabled>{name(value)} (недоступен)</option>}
    {channels.filter((c: any) => c.enabled).map((c: any) => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
  </select>;
}

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
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      setLoading(true);
      try {
        const [c, l] = await Promise.all([api.clients(), api.leases()]);
        if (stopped) return;
        setClients(c.clients || []);
        setLeases(l.leases || []);
        setLoaded(true);
        setLoadError("");
      } catch (error) {
        if (!stopped) setLoadError(error instanceof Error ? error.message : "Не удалось получить данные");
      } finally {
        if (!stopped) {
          setLoading(false);
          timer = setTimeout(load, 8000);
        }
      }
    }
    load();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [reloadKey]);

  const [manual, setManual] = useState(false);
  const [vpnTelemetry, setVPNTelemetry] = useState<Record<string, any[]>>({});
  const [vpnError, setVPNError] = useState(false);
  const vpnIDs = JSON.stringify((config.vpn_servers || []).map((s: any) => s.id));
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const ids: string[] = JSON.parse(vpnIDs);
    setVPNTelemetry({});
    async function load() {
      const results = await Promise.allSettled(ids.map(id => api.vpnClientStatus(id, controller.signal)));
      if (controller.signal.aborted) return;
      const next: Record<string, any[]> = {};
      results.forEach((r, i) => { if (r.status === "fulfilled") next[ids[i]] = r.value; });
      setVPNTelemetry(next);
      setVPNError(results.some(r => r.status === "rejected"));
      timer = setTimeout(load, 5000);
    }
    void load();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [vpnIDs]);
  const devices = localDevices(clients, config);
  const vpn = vpnMapServers(config, vpnTelemetry);
  const vpnCount = vpn.reduce((n, s) => n + s.peers.length, 0);

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

  // Булавка рядом с адресом: закрепить его за устройством или открепить.
  const pinButton = (c: any) => {
    if (!reserved.has(String(c.mac).toLowerCase()) && (!c.ip || (config.networks || []).length === 0)) return null;
    const pinned: any = reserved.get(String(c.mac).toLowerCase());
    return <button
                            type="button"
                            className={`pin-btn ${pinned ? "on" : ""}`}
                            aria-pressed={!!pinned}
                            aria-label={pinned ? `Открепить адрес устройства ${c.mac}` : `Закрепить адрес за устройством ${c.mac}`}
                            title={pinned ? `Адрес ${pinned.ip} закреплён за устройством. Нажмите, чтобы открепить` : "Закрепить этот адрес за устройством"}
                            onClick={(event) => { event.preventDefault(); togglePin(c); }}
                          >
                            <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor" aria-hidden="true"><path d="M10.2 1.3 14.7 5.8l-1.1 1.1-.9-.2-2.4 2.4.2 2.6-1.2 1.2-2.6-2.6L3 14l-.9-.1L2 13l3.7-3.7L3.1 6.7l1.2-1.2 2.6.2 2.4-2.4-.2-.9z" /></svg>
                          </button>;
  };

  const known = new Map((config.clients || []).map((c: any) => [String(c.mac).toLowerCase(), c]));
  const reserved = new Map((config.dhcp?.reservations || []).map((r: any) => [String(r.mac).toLowerCase(), r]));

  // Закрепить за устройством адрес, который у него сейчас, — одним нажатием в
  // его же строке, включая сохранённое отключённое устройство.
  function togglePin(client: any) {
    const mac = String(client.mac).toLowerCase();
    patch((draft) => {
      draft.dhcp = draft.dhcp || {};
      const list = draft.dhcp.reservations || [];
      if (list.some((r: any) => String(r.mac).toLowerCase() === mac)) {
        draft.dhcp.reservations = list.filter((r: any) => String(r.mac).toLowerCase() !== mac);
        return;
      }
      const network = (draft.networks || []).find((item: any) =>
        (draft.interfaces || []).find((iface: any) => iface.id === item.interface)?.name === client.interface)?.id
        || draft.networks?.[0]?.id || "";
      // Отображаемое имя может содержать пробелы и кириллицу. В DHCP берём
      // только корректное DNS-имя, полученное от самого устройства.
      const hostname = String(client.hostname || "");
      const name = hostname.length <= 253 && hostname.split(".").every(label =>
        label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)
      ) ? hostname : "";
      draft.dhcp.reservations = [...list, { id: newID("res"), enabled: true, mac, ip: client.ip, hostname: name, network }];
    });
  }

  return (
    <>
      <div className="page-head">
        <h1>Клиенты</h1>
        <p>Телефоны, компьютеры и другая техника, которую видит роутер</p>
      </div>

      {manual && <AddReservation config={config} patch={patch} clients={clients} />}
      <Card
        actions={(config.networks || []).length > 0 ? <button className="btn sm" onClick={() => setManual(!manual)}>{manual ? "Закрыть добавление" : "Добавить по MAC"}</button> : undefined}
        title="Клиенты"
        subtitle={`${devices.length} локальных · ${vpnCount} VPN · ${devices.filter(c => c.online && !loadError).length} локальных в сети · ${vpn.reduce((n, s) => n + s.peers.filter(p => ["recent", "online"].includes(p.state)).length, 0)} VPN на связи`}
        tight
      >
        {loadError && (
          <Notice tone="danger" title="Не удалось загрузить данные устройств">
            <p>{loadError}</p>
            <button className="btn sm" disabled={loading} onClick={() => setReloadKey((key) => key + 1)}>Повторить</button>
          </Notice>
        )}
        {vpnError && <Notice tone="warn" title="Состояние VPN-клиентов недоступно">Подключение не подтверждено. Проверка повторится автоматически.</Notice>}
        {!loaded && loading && <Empty>Загрузка локальных устройств…</Empty>}
        {loaded && devices.length + vpnCount === 0 && <Empty>Устройств пока не видно</Empty>}
          <Rows cols={["Устройство", "Адрес", "Канал выхода", "Подключение", "Состояние"]}>
          {devices.map((c) => {
                  const cfgClient: any = known.get(c.mac);
                  const lease = leaseByMAC.get(c.mac);
                  const network = (config.networks || []).find((n: any) => cfgClient?.network ? n.id === cfgClient.network
                    : (config.interfaces || []).find((i: any) => i.id === n.interface)?.name === c.interface);
                  return (
              <Row
                key={`lan:${c.mac}`}
                id={`lan:${c.mac}`}
                cells={[<strong>{cfgClient?.name || c.hostname || "без имени"}</strong>,
                  <span className="mono">{c.ip || "—"}{pinButton(c)}</span>,
                  <ClientChannel config={config} value={cfgClient?.channel || ""} inherited={network?.default_channel || (network ? "direct" : "")}
                    source="По сегменту" label={`Канал для устройства ${c.mac}`} onChange={channel => updateClient(c.mac, { channel })} />,
                  <span className="dim">{[c.interface, c.source === "dhcp" ? "DHCP" : c.source === "arp" ? "ARP" : c.source === "reservation" ? "Закреплённый адрес" : "DHCP + ARP", lease ? `до ${formatTime(lease.expires)}` : ""].filter(Boolean).join(" · ")}</span>,
                  loadError ? <Badge tone="neutral">данные устарели</Badge> : cfgClient?.blocked ? <Badge tone="danger">заблокирован</Badge> : <Badge tone={c.online ? "ok" : "neutral"}>{c.online ? "в сети" : "молчит"}</Badge>]}
              >
                <div className="form-grid">
                  <Cap label="Имя"><input
                            type="text"
                            aria-label={`Имя устройства ${c.mac}`}
                            placeholder={c.hostname || "без имени"}
                            value={cfgClient?.name || ""}
                            onChange={(e) => updateClient(c.mac, { name: e.target.value })}
                          /></Cap>
                  <Cap label="MAC"><span className="mono">{c.mac}</span></Cap>
                  <Cap label="Сегмент"><select aria-label={`Сегмент для устройства ${c.mac}`} value={cfgClient?.network || ""} onChange={(e) => updateClient(c.mac, { network: e.target.value })}>
                          <option value="">— не выбран —</option>
                          {(config.networks || []).filter((network: any) => network.enabled).map((network: any) => (
                            <option key={network.id} value={network.id}>{network.name || network.id}</option>
                          ))}
                        </select></Cap>
                  <Cap label="Лимит загрузки, Кбит/с"><input aria-label="Лимит загрузки" title="Загрузка, Кбит/с" type="number" min={0} max={10000000} placeholder="без лимита" value={cfgClient?.down_kbit || 0} onChange={(e) => updateClient(c.mac, { down_kbit: Number(e.target.value) })} /></Cap>
                  <Cap label="Лимит отдачи, Кбит/с"><input aria-label="Лимит отдачи" title="Отдача, Кбит/с" type="number" min={0} max={10000000} placeholder="без лимита" value={cfgClient?.up_kbit || 0} onChange={(e) => updateClient(c.mac, { up_kbit: Number(e.target.value) })} /></Cap>
                  <Cap label="Комментарий"><input
                          type="text"
                          aria-label={`Комментарий устройства ${c.mac}`}
                          value={cfgClient?.comment || ""}
                          onChange={(e) => updateClient(c.mac, { comment: e.target.value })}
                        /></Cap>
                </div>
                <div className="row-actions end"><button
                          className={`btn sm ${cfgClient?.blocked ? "danger" : ""}`}
                          onClick={() => updateClient(c.mac, { blocked: !cfgClient?.blocked })}
                        >
                          {cfgClient?.blocked ? "Заблокирован" : "Разрешён"}
                        </button></div>
              </Row>
          );
                })}
          {vpn.flatMap(server => server.peers.map(peer => <Row
            key={`vpn:${server.id}:${peer.id}`} id={`vpn:${server.id}:${peer.id}`}
            cells={[<strong>{peer.name}</strong>, <span className="mono">{peer.address || "—"}</span>,
              <ClientChannel config={config} value={peer.peer.channel || ""} inherited={server.server.default_channel || "direct"}
                source="По серверу" label={`Канал VPN-клиента ${server.name} / ${peer.name}`}
                onChange={channel => patch(draft => {
                  const target = (draft.vpn_servers || []).find((s: any) => s.id === server.id)?.peers?.find((p: any) => p.id === peer.id);
                  if (target) target.channel = channel;
                })} />,
              <span>VPN · {server.name} · {server.type === "wireguard" ? "WireGuard" : server.type}</span>,
              <Badge tone={["recent", "online"].includes(peer.state) ? "ok" : peer.state === "disabled" ? "danger" : "neutral"}>{peer.label}</Badge>]}>
            <div className="form-grid">
              <Cap label="VPN-сервер"><span>{server.name}</span></Cap>
              <Cap label="Адрес подключения"><span>{peer.endpoint || "—"}</span></Cap>
              <Cap label={server.type === "wireguard" ? "Последний handshake" : "Последний раз замечен онлайн"}><span>{peer.handshake ? formatTime(new Date(peer.handshake * 1000).toISOString()) : "—"}</span></Cap>
              <Cap label="Получено / отправлено"><span>{peer.trafficKnown ? `${peer.received} / ${peer.sent} байт` : "—"}</span></Cap>
            </div>
            <a className="btn sm" href="#vpn-servers">Настройки VPN-клиента</a>
          </Row>))}
        </Rows>
        <div className="clients-channel-hint hint">Каналы показаны по настройкам черновика. Изменения начнут действовать после применения. Явные правила маршрутизации имеют приоритет.</div>
      </Card>

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
    <Card title="Добавить устройство по MAC" subtitle="Для устройства, которое ещё не подключалось: заранее закрепить адрес DHCP">
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
            d.dhcp = d.dhcp || {};
            d.dhcp.reservations = d.dhcp.reservations || [];
            d.dhcp.reservations.push({
              id: newID("res"),
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
