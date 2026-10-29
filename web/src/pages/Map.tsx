import { useAccess } from "../permissions";
import { useStatusPolling } from "../StatusPollingContext";
import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { api, formatBitrate, formatUptime } from "../api";
import { Badge, Card, Empty, Notice, Speed } from "../ui";
import { Icon } from "../icons";
import { MapViewport } from "../MapViewport";
import { vpnMapServers } from "../mapVPN";
import { interfaceName, wanInterfaceName } from "./Dashboard";

// Карта сети: как роутер связан с провайдерами, каналами и сегментами прямо
// сейчас. Только чтение — настройки узла живут в своих разделах, карта ведёт
// туда и показывает применённое состояние.

const POLL_MS = 5000;

type Rates = Map<string, { down: number; up: number }>;
type NodeID = string; // router | wan:<id> | channel:<id> | segment:<id>

export function MapPage({ config }: { config: any }) {
  const statusPolling = useStatusPolling();
  const [status, setStatus] = useState<any>(null);
  const [clients, setClients] = useState<any[]>([]);
  const [vpnTelemetry, setVPNTelemetry] = useState<Record<string, any[]>>({});
  const [vpnError, setVPNError] = useState(false);
  const vpnIDs = JSON.stringify((config.vpn_servers || []).map((s: any) => s.id));
  const [error, setError] = useState(false);
  const [rates, setRates] = useState<Rates>(new Map());
  const [selected, setSelected] = useState<NodeID>("");
  const previous = useRef<{ at: number; bytes: Map<string, { rx: number; tx: number }> } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async (request: Promise<any>) => {
      try {
        const [next, list] = await Promise.all([request, api.clients()]);
        if (cancelled) return;
        // Скорость — прирост счётчиков между двумя опросами. Первый опрос
        // скорости не даёт: сравнивать не с чем.
        const now = Date.now();
        const bytes = new Map<string, { rx: number; tx: number }>();
        const nextRates: Rates = new Map();
        for (const i of next.interfaces || []) {
          bytes.set(i.name, { rx: i.rx_bytes || 0, tx: i.tx_bytes || 0 });
          const before = previous.current?.bytes.get(i.name);
          const seconds = previous.current ? (now - previous.current.at) / 1000 : 0;
          if (before && seconds > 0) {
            nextRates.set(i.name, {
              down: Math.max(0, ((i.rx_bytes - before.rx) * 8) / seconds),
              up: Math.max(0, ((i.tx_bytes - before.tx) * 8) / seconds),
            });
          }
        }
        previous.current = { at: now, bytes };
        setRates(nextRates);
        setStatus(next);
        setClients(list.clients || []);
        setError(false);
      } catch {
        if (!cancelled) setError(true);
      }
    };
    const unsubscribe = statusPolling.subscribe(POLL_MS, false, request => { void load(request); });
    return () => { cancelled = true; unsubscribe(); };
  }, [statusPolling]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const ids: string[] = JSON.parse(vpnIDs);
    async function loadVPN() {
      const results = await Promise.allSettled(ids.map(id => api.vpnClientStatus(id, controller.signal)));
      if (controller.signal.aborted) return;
      const next: Record<string, any[]> = {};
      results.forEach((result, i) => { if (result.status === "fulfilled") next[ids[i]] = result.value; });
      setVPNTelemetry(next);
      setVPNError(results.some(result => result.status === "rejected"));
      timer = setTimeout(loadVPN, POLL_MS);
    }
    void loadVPN();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [vpnIDs]);

  const graph = useMemo(() => buildGraph(config, status, clients, rates, vpnTelemetry), [config,status,clients,rates,vpnTelemetry]);

  return (
    <>
      <div className="page-head">
        <h1><Icon name="waypoints" />Карта сети</h1>
        <p>Как устроена сеть сейчас. Выберите узел, чтобы увидеть подробности</p>
      </div>
      {error && (
        <Notice tone="danger" title="Не удалось обновить состояние роутера">
          {status ? "Показаны последние полученные данные. " : ""}Повторная попытка выполняется автоматически.
        </Notice>
      )}
      {vpnError && <Notice tone="warn" title="Состояние VPN-клиентов недоступно">Клиенты показаны по конфигурации. Их подключение сейчас не подтверждено; проверка повторится автоматически.</Notice>}
      {!status ? (error ? null : <Empty>Загрузка состояния роутера…</Empty>) : (
        <div className="map-layout">
          <Card
            title="Схема"
            actions={
              <span className="map-legend">
                {LEGEND.map(([kind, state, label]) => (
                  <span key={label}><svg viewBox="0 0 44 12" aria-hidden="true"><Edge kind={kind} state={state} path={["M3,6 H41", null]} /></svg>{label}</span>
                ))}
              </span>
            }
            tight
          >
            <MapSVG graph={graph} selected={selected} onSelect={setSelected} config={config} status={status} overlay={selected?<aside className="map-node-overlay" aria-label="Сведения об узле">
              <button className="map-details-close" aria-label="Закрыть сведения об узле" onClick={()=>setSelected("")}>×</button>
              <NodeDetails graph={graph} id={selected} config={config} status={status} clients={clients}/>
            </aside>:null}/>
          </Card>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Модель схемы
// ---------------------------------------------------------------------------

type WanNode = { id: string; name: string; iface: string; up: boolean; primary: boolean; wan: any; rate?: { down: number; up: number } };
type ChannelNode = { id: string; name: string; type: string; up: boolean; channel: any };
type SegmentNode = { id: string; name: string; iface: string; address: string; online: number; total: number; network: any };

function buildGraph(config: any, status: any, clients: any[], rates: Rates, vpnTelemetry: Record<string, any[]>) {
  const liveWans = new Map<string, any>((status?.wans || []).map((w: any) => [w.id, w]));
  const liveChannels = new Map<string, any>((status?.channels || []).map((c: any) => [c.id, c]));

  const wans: WanNode[] = (config.wans || [])
    .filter((w: any) => w.enabled)
    .map((w: any) => {
      const iface = liveWans.get(w.id)?.interface || wanInterfaceName(config, w);
      return { id: w.id, name: w.name || w.id, iface, up: !!liveWans.get(w.id)?.up, primary: false, wan: w, rate: rates.get(iface) };
    });
  // Основной — живой аплинк с наименьшей метрикой: так выбирает и ядро.
  const primary = wans.filter((w) => w.up).sort((a, b) => (a.wan.metric || 0) - (b.wan.metric || 0))[0];
  if (primary) primary.primary = true;

  const channels: ChannelNode[] = (config.channels || [])
    .filter((c: any) => c.enabled && c.type !== "direct")
    .map((c: any) => ({ id: c.id, name: c.name || c.id, type: channelType(c.type), up: !!liveChannels.get(c.id)?.up, channel: c }));

  const segments: SegmentNode[] = (config.networks || [])
    .filter((n: any) => n.enabled)
    .map((n: any) => {
      const iface = interfaceName(config, n.interface);
      const own = clients.filter((c) => c.interface === iface);
      return { id: n.id, name: n.name || n.id, iface, address: n.router_address, online: own.filter((c) => c.online).length, total: own.length, network: n };
    });

  return { wans, channels, segments, vpn: vpnMapServers(config, vpnTelemetry) };
}

function channelType(type: string): string {
  return ({ wireguard: "WireGuard", xray: "Xray", openconnect: "OpenConnect", ikev2: "IKEv2" } as Record<string, string>)[type] || type;
}

// ---------------------------------------------------------------------------
// Рисунок
// ---------------------------------------------------------------------------

const W = 1000;
const ROW = 80;

function spread(count: number, from: number, to: number): number[] {
  if (count === 1) return [(from + to) / 2];
  return Array.from({ length: count }, (_, i) => from + (i * (to - from)) / (count - 1));
}

type Point = [number, number];
type EdgePath = [string, Point | null]; // кривая и её середина — туда ставится крестик обрыва
type EdgeKind = "uplink" | "channel" | "lan" | "vpn";
type EdgeState = "live" | "idle" | "dead";

const LEGEND: [EdgeKind, EdgeState, string][] = [
  ["uplink", "live", "аплинк"], ["channel", "live", "канал"], ["lan", "live", "сегмент"], ["vpn", "live", "VPN"],
  ["uplink", "idle", "ждёт, резерв"], ["uplink", "dead", "нет связи"],
];

// Кривая симметрична, поэтому её середина — середина отрезка между концами.
function curve(x1: number, y1: number, x2: number, y2: number): EdgePath {
  const m = (x1 + x2) / 2;
  return [`M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`, [m, (y1 + y2) / 2]];
}

// Линия канала спускается сверху; середина — точка кубической кривой при t = 0,5.
function drop(x1: number, y1: number, x2: number, y2: number, bend: number): EdgePath {
  return [`M${x1},${y1} C${x1},${bend} ${x2},${bend} ${x2},${y2}`, [(x1 + x2) / 2, (y1 + 6 * bend + y2) / 8]];
}

function Edge({ kind, state, path: [d, mid], children, ...rest }: { kind: EdgeKind; state: EdgeState; path: EdgePath; children?: ReactNode; "data-vpn-server"?: string }) {
  return (
    <>
      <path className={`edge k-${kind} ${state}`} d={d} {...rest}>{children}</path>
      {kind === "uplink" && state === "live" && <path className="edge-flow" d={d} />}
      {state === "dead" && mid && <g className="edge-mark" transform={`translate(${mid[0]} ${mid[1]})`}><circle r={8} /><path d="M-4,-4 4,4 M4,-4 -4,4" /></g>}
    </>
  );
}

function peerEdgeState(state: string): EdgeState {
  if (["recent", "online"].includes(state)) return "live";
  return state === "disabled" || state === "server_disabled" ? "dead" : "idle";
}

// Включённый сервер, к которому сейчас никто не подключён, ждёт клиентов.
function serverEdgeState(server: { enabled: boolean; peers: { state: string }[] }): EdgeState {
  if (!server.enabled) return "dead";
  return server.peers.some((p) => peerEdgeState(p.state) === "live") ? "live" : "idle";
}

function MapSVG({ graph, selected, onSelect, config, status, overlay }: {
  graph: ReturnType<typeof buildGraph>;
  selected: NodeID;
  onSelect: (id: NodeID) => void;
  config: any;
  status: any;
  overlay: ReactNode;
}) {
  const { wans, channels, segments, vpn } = graph;
  const channelRows = Math.ceil(channels.length / 3);
  const top = channelRows > 0 ? channelRows * 85 + 45 : 40;
  const rightRows = segments.length + vpn.reduce((sum, server) => sum + Math.max(1, server.peers.length), 0);
  const rows = Math.max(wans.length, rightRows, 2);
  const height = top + rows * ROW;
  const bodyTop = top + ROW / 2;
  const bodyBottom = height - ROW / 2;
  const cy = (bodyTop + bodyBottom) / 2;
  const router = { x: 530, y: cy, w: 190, h: 130 };
  const wanY = spread(wans.length, bodyTop, bodyBottom);
  const rightY = spread(rightRows, bodyTop, bodyBottom);
  const segY = rightY.slice(0, segments.length);
  let nextRow = segments.length;
  const vpnLayout = vpn.map(server => {
    const positions = rightY.slice(nextRow, nextRow + Math.max(1, server.peers.length));
    nextRow += positions.length;
    return { server, positions, y: (positions[0] + positions[positions.length - 1]) / 2 };
  });
  const chPos = channels.map((_,i)=>({x:spread(Math.min(3,channels.length-Math.floor(i/3)*3),300,800)[i%3],y:52+Math.floor(i/3)*85}));
  const live = new Map<string, any>((status?.interfaces || []).map((i: any) => [i.name, i]));
  const ports = (config.interfaces || []).filter((i: any) => i.type === "physical").slice(0, 6);

  const node = (id: NodeID, x: number, y: number, w: number, h: number, title: string, sub: string, tone: string) => (
    <g
      key={id}
      className={`node ${selected === id ? "sel" : ""}`}
      tabIndex={0}
      role="button"
      aria-pressed={selected === id}
      aria-label={`${title}: ${sub}`}
      onClick={() => onSelect(id)}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(id); } }}
    >
      <title>{title}: {sub}</title>
      <rect className="nb" x={x - w / 2} y={y - h / 2} width={w} height={h} rx={6} />
      <circle cx={x - w / 2 + 16} cy={y - 8} r={4.5} className={`nd ${tone}`} />
      <text className="nt" x={x - w / 2 + 28} y={y - 3}>{clip(title, 18)}</text>
      <text className="ns" x={x - w / 2 + 16} y={y + 15}>{sub}</text>
    </g>
  );

  return (
    <MapViewport width={vpn.length ? 1240 : W} height={height} overlay={overlay} background={<>
        {wans.map((w, i) => (
          <g key={`e-${w.id}`}>
            <Edge kind="uplink" state={edgeState(w.up, w.primary)} path={curve(122, cy, 205, wanY[i])} />
            <Edge kind="uplink" state={edgeState(w.up, w.primary)} path={curve(375, wanY[i], router.x - router.w / 2, cy)} />
          </g>
        ))}
        {segments.map((s, i) => (
          <Edge key={`e-${s.id}`} kind="lan" state="live" path={curve(router.x + router.w / 2, cy, 755, segY[i])} />
        ))}
        {channels.map((c, i) => (
          <Edge key={`e-${c.id}`} kind="channel" state={c.up ? "live" : "dead"} path={drop(chPos[i].x, chPos[i].y + 30, router.x, router.y - router.h / 2, top - 10)} />
        ))}

        {vpnLayout.map(({server, positions, y}) => <g key={`vpn-lines-${server.id}`}>
          <Edge data-vpn-server={server.id} kind="vpn" state={serverEdgeState(server)} path={curve(router.x + router.w / 2, cy, 755, y)}>
            <title>{!server.enabled ? "VPN-сервер отключён" : serverEdgeState(server) === "live" ? "VPN-сервер включён, клиенты на связи" : "VPN-сервер включён, клиентов на связи нет"}</title>
          </Edge>
          {server.peers.map((peer, i) => <Edge key={peer.id} kind="vpn" state={peerEdgeState(peer.state)} path={curve(925, y, 990, positions[i])} />)}
        </g>)}

        </>}>
        <g>
          <circle cx={80} cy={cy} r={44} className="cloud" />
          <text className="nt" x={80} y={cy + 4} textAnchor="middle">Интернет</text>
        </g>

        {wans.map((w, i) => node(
          `wan:${w.id}`, 290, wanY[i], 170, 56, w.name,
          !w.up ? "нет связи" : w.primary ? (w.rate ? `↓ ${formatBitrate(w.rate.down)}` : w.iface) : `${w.iface} · резерв`,
          !w.up ? "danger" : w.primary ? "ok" : "idle",
        ))}
        {channels.map((c, i) => node(`channel:${c.id}`, chPos[i].x, chPos[i].y, 220, 60, c.name, `${c.type} · ${c.up ? "на связи" : "нет связи"}`, c.up ? "ok" : "danger"))}

        <g
          className={`node ${selected === "router" ? "sel" : ""}`}
          tabIndex={0}
          role="button"
          aria-pressed={selected === "router"}
          aria-label={`Роутер ${config.system?.hostname || ""}`}
          onClick={() => onSelect("router")}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect("router"); } }}
        >
          <rect className="nb core" x={router.x - router.w / 2} y={router.y - router.h / 2} width={router.w} height={router.h} rx={6} />
          <text className="nt inv" x={router.x - 77} y={router.y - 33}>{clip(config.system?.hostname || "netOS", 14)}</text>
          <text className="ns inv" x={router.x - 77} y={router.y - 12}>работает {formatUptime(status?.uptime_seconds)}</text>
          <text className="ns inv" x={router.x - 77} y={router.y + 6}>{status?.conntrack_count ?? "—"} соединений</text>
          {ports.map((p: any, i: number) => {
            const x = router.x - 77 + i * 26;
            return (
              <g key={p.id}>
                <rect x={x} y={router.y + 22} width={18} height={13} rx={1.5} className="rp" />
                <rect x={x + 3} y={router.y + 25} width={5} height={3} className={live.get(p.name)?.up ? "rp-on" : "rp-off"} />
                <text className="ns inv" x={x + 9} y={router.y + 48} textAnchor="middle" style={{ fontSize: 7.5 }}>{p.name.slice(0, 5)}</text>
              </g>
            );
          })}
        </g>

        {segments.map((s, i) => node(`segment:${s.id}`, 840, segY[i], 170, 62, s.name, `${s.address} · ${s.online}/${s.total}`, "ok"))}
        {vpnLayout.map(({server, positions, y}) => <g key={`vpn-nodes-${server.id}`}>
          {node(`vpn:${server.id}`, 840, y, 170, 62, server.name, `${channelType(server.type)} · ${server.enabled ? "включён" : "отключён"}`, serverEdgeState(server) === "live" ? "ok" : "idle")}
          {server.peers.map((peer, i) => node(`peer:${encodeURIComponent(server.id)}:${encodeURIComponent(peer.id)}`, 1105, positions[i], 230, 62, peer.name, clip(`${peer.address} · ${peer.label}`, 35), peerEdgeState(peer.state) === "live" ? "ok" : "idle"))}
        </g>)}
    </MapViewport>
  );
}

function edgeState(up: boolean, primary: boolean): EdgeState {
  if (!up) return "dead";
  return primary ? "live" : "idle";
}

function clip(text: string, max: number) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// ---------------------------------------------------------------------------
// Подробности узла
// ---------------------------------------------------------------------------

function NodeDetails({ graph, id, config, status, clients }: {
  graph: ReturnType<typeof buildGraph>;
  id: NodeID;
  config: any;
  status: any;
  clients: any[];
}) {
  const can = useAccess();
  const [kind, key] = id.split(":");
  let title = "";
  let body: React.ReactNode = null;

  if (kind === "router") {
    const live = new Map<string, any>((status?.interfaces || []).map((i: any) => [i.name, i]));
    title = config.system?.hostname || "netOS";
    body = (
      <>
        <dl className="kv">
          <dt>Работает</dt><dd>{formatUptime(status?.uptime_seconds)}</dd>
          <dt>Соединений</dt><dd className="mono">{status?.conntrack_count ?? "—"}</dd>
          <dt>Версия</dt><dd className="mono">{status?.version || "—"}</dd>
        </dl>
        <div className="mini">
          {(config.interfaces || []).filter((i: any) => i.type === "physical").map((p: any) => (
            <div key={p.id}>
              <span className="mono">{p.name}</span>
              <Badge tone={live.get(p.name)?.up ? "ok" : "neutral"}>{live.get(p.name)?.up ? "линк есть" : "нет линка"}</Badge>
            </div>
          ))}
        </div>
      </>
    );
  }

  const wan = kind === "wan" ? graph.wans.find((w) => w.id === key) : undefined;
  if (wan) {
    title = wan.name;
    body = (
      <dl className="kv">
        <dt>Подключение</dt><dd>{String(wan.wan.proto || "").toUpperCase()}</dd>
        <dt>Интерфейс</dt><dd className="mono">{wan.iface}</dd>
        <dt>Метрика</dt><dd className="mono">{wan.wan.metric}</dd>
        <dt>Состояние</dt><dd><Badge tone={wan.up ? "ok" : "danger"}>{wan.up ? (wan.primary ? "основной" : "резерв, на связи") : "нет связи"}</Badge></dd>
        <dt>Сейчас</dt><dd>{wan.rate ? <Speed down={wan.rate.down} up={wan.rate.up} /> : "—"}</dd>
      </dl>
    );
  }

  const channel = kind === "channel" ? graph.channels.find((c) => c.id === key) : undefined;
  if (channel) {
    title = channel.name;
    body = (
      <dl className="kv">
        <dt>Тип</dt><dd>{channel.type}</dd>
        <dt>Состояние</dt><dd><Badge tone={channel.up ? "ok" : "danger"}>{channel.up ? "на связи" : "нет связи"}</Badge></dd>
        <dt>При отказе</dt><dd>{({ block: "блокировать", fallback: "запасной канал", direct: "напрямую" } as Record<string, string>)[channel.channel.fail_mode] || channel.channel.fail_mode}</dd>
      </dl>
    );
  }

  const segment = kind === "segment" ? graph.segments.find((s) => s.id === key) : undefined;
  if (segment) {
    const own = clients.filter((c) => c.interface === segment.iface);
    const pool = segment.network.dhcp_pool;
    title = `Сегмент «${segment.name}»`;
    body = (
      <>
        <dl className="kv">
          <dt>Интерфейс</dt><dd className="mono">{segment.iface}</dd>
          <dt>Адрес роутера</dt><dd className="mono">{segment.address}</dd>
          <dt>DHCP</dt><dd className="mono">{pool?.enabled ? `${pool.start} – ${pool.end}` : "выключен"}</dd>
          <dt>Изоляция</dt><dd>{segment.network.isolated ? "включена" : "нет"}</dd>
        </dl>
        <div className="mini">
          {own.length === 0 ? <div className="faint">Устройств не видно</div> : own.map((c) => (
            <div key={c.mac}>
              <span>{c.name || c.hostname || c.ip}</span>
              <Badge tone={c.online ? "ok" : "neutral"}>{c.online ? "в сети" : "не в сети"}</Badge>
            </div>
          ))}
        </div>
      </>
    );
  }

  const vpnServer = kind === "vpn" ? graph.vpn.find(s => s.id === key) : kind === "peer" ? graph.vpn.find(s => s.id === decodeURIComponent(key)) : undefined;
  if (vpnServer) {
    const peerID = kind === "peer" ? decodeURIComponent(id.split(":")[2] || "") : "";
    const peer = vpnServer.peers.find(p => p.id === peerID);
    title = peer ? peer.name : vpnServer.name;
    const selectedChannel = peer?.peer.channel || vpnServer.server.default_channel || "direct";
    const channelName = (config.channels || []).find((c: any) => c.id === selectedChannel)?.name || (selectedChannel === "block" ? "Блок" : selectedChannel === "direct" ? "Напрямую" : selectedChannel);
    body = <>
      <dl className="kv">
        <dt>VPN-сервер</dt><dd>{vpnServer.name} · {channelType(vpnServer.type)}</dd>
        <dt>VPN-подсеть</dt><dd className="mono">{vpnServer.subnet || "—"}</dd>
        {peer ? <>
          <dt>VPN-адрес</dt><dd className="mono">{peer.address || "—"}</dd>
          <dt>Состояние</dt><dd>{peer.label}</dd>
          <dt>Адрес подключения</dt><dd className="mono">{peer.endpoint || "—"}</dd>
          <dt>{vpnServer.type === "wireguard" ? "Последний handshake" : "Последний раз замечен онлайн"}</dt><dd>{peer.handshake ? new Date(peer.handshake * 1000).toLocaleString() : "—"}</dd>
          <dt>Получено / отправлено</dt><dd>{peer.trafficKnown ? `${peer.received.toLocaleString()} / ${peer.sent.toLocaleString()} байт` : "—"}</dd>
          <dt>Канал выхода</dt><dd>{channelName}</dd>
        </> : <><dt>Сервер включён</dt><dd>{vpnServer.enabled ? "да" : "нет"}</dd><dt>Клиенты</dt><dd>{vpnServer.peers.length}</dd></>}
      </dl>
      {vpnServer.type === "wireguard" && <p className="hint">Недавний handshake подтверждает обмен с клиентом, но не непрерывное подключение.</p>}
      {can("vpn-servers") && <a href="#vpn-servers">Открыть VPN-серверы</a>}
    </>;
  }

  return (
    <Card title="Узел">
      {body ? <><h3 className="details-title">{title}</h3>{body}</> : <Empty>Узел больше не существует</Empty>}
    </Card>
  );
}
