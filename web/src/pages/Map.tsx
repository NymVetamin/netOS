import { useEffect, useRef, useState } from "react";
import { api, formatBitrate, formatUptime } from "../api";
import { Badge, Card, Empty, Notice, Speed } from "../ui";
import { interfaceName, wanInterfaceName } from "./Dashboard";

// Карта сети: как роутер связан с провайдерами, каналами и сегментами прямо
// сейчас. Только чтение — настройки узла живут в своих разделах, карта ведёт
// туда и показывает применённое состояние.

const POLL_MS = 5000;

type Rates = Map<string, { down: number; up: number }>;
type NodeID = string; // router | wan:<id> | channel:<id> | segment:<id>

export function MapPage({ config }: { config: any }) {
  const [status, setStatus] = useState<any>(null);
  const [clients, setClients] = useState<any[]>([]);
  const [error, setError] = useState(false);
  const [rates, setRates] = useState<Rates>(new Map());
  const [selected, setSelected] = useState<NodeID>("router");
  const previous = useRef<{ at: number; bytes: Map<string, { rx: number; tx: number }> } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [next, list] = await Promise.all([api.status(), api.clients()]);
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
    load();
    const timer = window.setInterval(load, POLL_MS);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, []);

  const graph = buildGraph(config, status, clients, rates);

  return (
    <>
      <div className="page-head">
        <h1>Карта сети</h1>
        <p>Как устроена сеть сейчас. Выберите узел, чтобы увидеть подробности</p>
      </div>
      {error && (
        <Notice tone="danger" title="Не удалось обновить состояние роутера">
          {status ? "Показаны последние полученные данные. " : ""}Повторная попытка выполняется автоматически.
        </Notice>
      )}
      {!status ? (error ? null : <Empty>Загрузка состояния роутера…</Empty>) : (
        <div className="map-layout">
          <Card
            title="Схема"
            actions={
              <span className="map-legend">
                <span><i className="live" />трафик идёт</span>
                <span><i className="idle" />ждёт</span>
                <span><i className="dead" />нет связи</span>
              </span>
            }
            tight
          >
            <MapSVG graph={graph} selected={selected} onSelect={setSelected} config={config} status={status} />
          </Card>
          <NodeDetails graph={graph} id={selected} config={config} status={status} clients={clients} />
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

function buildGraph(config: any, status: any, clients: any[], rates: Rates) {
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

  return { wans, channels, segments };
}

function channelType(type: string): string {
  return ({ wireguard: "WireGuard", xray: "Xray", openconnect: "OpenConnect", ikev2: "IKEv2" } as Record<string, string>)[type] || type;
}

// ---------------------------------------------------------------------------
// Рисунок
// ---------------------------------------------------------------------------

const W = 1000;
const ROW = 110;

function spread(count: number, from: number, to: number): number[] {
  if (count === 1) return [(from + to) / 2];
  return Array.from({ length: count }, (_, i) => from + (i * (to - from)) / (count - 1));
}

function curve(x1: number, y1: number, x2: number, y2: number) {
  const m = (x1 + x2) / 2;
  return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`;
}

function MapSVG({ graph, selected, onSelect, config, status }: {
  graph: ReturnType<typeof buildGraph>;
  selected: NodeID;
  onSelect: (id: NodeID) => void;
  config: any;
  status: any;
}) {
  const { wans, channels, segments } = graph;
  const top = channels.length > 0 ? 130 : 40;
  const rows = Math.max(wans.length, segments.length, 2);
  const height = top + rows * ROW;
  const bodyTop = top + ROW / 2;
  const bodyBottom = height - ROW / 2;
  const cy = (bodyTop + bodyBottom) / 2;
  const router = { x: 530, y: cy, w: 190, h: 130 };
  const wanY = spread(wans.length, bodyTop, bodyBottom);
  const segY = spread(segments.length, bodyTop, bodyBottom);
  const chX = spread(channels.length, 360, 700);
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
      <rect className="nb" x={x - w / 2} y={y - h / 2} width={w} height={h} rx={6} />
      <circle cx={x - w / 2 + 16} cy={y - 8} r={4.5} className={`nd ${tone}`} />
      <text className="nt" x={x - w / 2 + 28} y={y - 3}>{clip(title, 18)}</text>
      <text className="ns" x={x - w / 2 + 16} y={y + 15}>{sub}</text>
    </g>
  );

  return (
    <div className="map-canvas">
      <svg viewBox={`0 0 ${W} ${height}`} role="group" aria-label="Схема сети">
        {wans.map((w, i) => (
          <g key={`e-${w.id}`}>
            <path className={`edge ${edgeState(w.up, w.primary)}`} d={curve(122, cy, 205, wanY[i])} />
            <path className={`edge ${edgeState(w.up, w.primary)}`} d={curve(375, wanY[i], router.x - router.w / 2, cy)} />
          </g>
        ))}
        {segments.map((s, i) => (
          <path key={`e-${s.id}`} className="edge live" d={curve(router.x + router.w / 2, cy, 755, segY[i])} />
        ))}
        {channels.map((c, i) => (
          <path key={`e-${c.id}`} className={`edge ${c.up ? "live" : "dead"}`} d={`M${chX[i]},78 C${chX[i]},${top - 10} ${router.x},${top - 10} ${router.x},${router.y - router.h / 2}`} />
        ))}

        <g>
          <circle cx={80} cy={cy} r={44} className="cloud" />
          <text className="nt" x={80} y={cy + 4} textAnchor="middle">Интернет</text>
        </g>

        {wans.map((w, i) => node(
          `wan:${w.id}`, 290, wanY[i], 170, 56, w.name,
          !w.up ? "нет связи" : w.primary ? (w.rate ? `↓ ${formatBitrate(w.rate.down)}` : w.iface) : `${w.iface} · резерв`,
          !w.up ? "danger" : w.primary ? "ok" : "idle",
        ))}
        {channels.map((c, i) => node(`channel:${c.id}`, chX[i], 52, 140, 52, c.type, c.up ? "на связи" : "нет связи", c.up ? "ok" : "danger"))}

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
      </svg>
    </div>
  );
}

function edgeState(up: boolean, primary: boolean) {
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

  return (
    <Card title="Узел">
      {body ? <><h3 className="details-title">{title}</h3>{body}</> : <Empty>Узел больше не существует</Empty>}
    </Card>
  );
}
