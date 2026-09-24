// Итог доступа «кто куда может ходить» для матрицы в «Защите сети».
//
// Считается в том же порядке, в каком backend/internal/subsys/firewall
// строит цепочки: правила без зоны, изоляция сегментов, правила зоны
// источника, проброшенные порты, запрет между сегментами по умолчанию,
// политика зоны. Для новых соединений: правила только для established,
// related или invalid на итог не влияют. Правило с портами, протоколом,
// расписанием или частью подсети решает не за весь трафик пары, поэтому даёт
// «частично». Модуль без зависимостей: его проверяют тесты в tests/.

export type Verdict = "y" | "n" | "p";

export type Access = {
  verdict: Verdict;
  // Что решает итог: правило, изоляция или политика зоны.
  reason: string;
  // Исключения — правила, решающие только часть трафика иначе, чем итог.
  exceptions: string[];
};

export type Entity = {
  id: string;
  title: string;
  kind: "segment" | "zone" | "router";
  zone: string;
  ifaces: string[];
  subnet?: Subnet;
  isolated?: boolean;
};

export type Matrix = {
  sources: Entity[];
  destinations: Entity[];
  // cells[i][j] — из sources[i] в destinations[j]; null — та же точка.
  cells: (Access | null)[][];
};

type Subnet = { net: number; bits: number };

export function accessMatrix(config: any, zoneIfaces: Record<string, string[]>): Matrix {
  const byID = new Map<string, string>((config.interfaces || []).map((i: any) => [i.id, i.name]));
  const zones: any[] = config.firewall?.zones || [];
  const segments: Entity[] = (config.networks || [])
    .filter((n: any) => n.enabled)
    .map((n: any) => ({
      id: `segment:${n.id}`,
      title: n.name || n.id,
      kind: "segment" as const,
      zone: n.zone || "lan",
      ifaces: [byID.get(n.interface) || n.interface],
      subnet: parseCIDR(n.router_address),
      isolated: !!n.isolated,
    }));
  const zoneEntity = (name: string): Entity[] => {
    const zone = zones.find((z) => z.name === name);
    if (!zone || !(zoneIfaces[name] || []).length) return [];
    return [{ id: `zone:${name}`, title: zone.title || name, kind: "zone", zone: name, ifaces: zoneIfaces[name] }];
  };
  const internet = zoneEntity("wan");
  const vpn = zoneEntity("vpn");
  const router: Entity = { id: "router", title: "Роутер", kind: "router", zone: "", ifaces: [] };

  const sources = [...segments, ...vpn, ...internet];
  const destinations = [...internet, ...segments, ...vpn, router];
  const cells = sources.map((src) =>
    destinations.map((dst) => (src.id === dst.id ? null : evaluate(config, src, dst, segments))),
  );
  return { sources, destinations, cells };
}

function evaluate(config: any, src: Entity, dst: Entity, segments: Entity[]): Access {
  const fw = config.firewall || {};
  if (!fw.enabled) return { verdict: "y", reason: "файрволл выключен", exceptions: [] };

  const flow = dst.kind === "router" ? "in" : "forward";
  const rules: any[] = (fw.rules || []).filter((r: any) => r.enabled && appliesToNew(r));
  const partial: { accept: boolean; text: string }[] = [];
  const finish = (accept: boolean, reason: string): Access => {
    const exceptions = partial.filter((p) => p.accept !== accept).map((p) => p.text);
    return { verdict: exceptions.length ? "p" : accept ? "y" : "n", reason, exceptions };
  };

  // Правило решает целиком, частично или не касается пары вовсе.
  const walk = (list: any[]): Access | null => {
    for (const r of list) {
      if (r.action === "continue") continue;
      const match = matchRule(r, src, dst, flow, segments);
      if (match === "none") continue;
      const accept = r.action === "accept";
      if (match === "part") partial.push({ accept, text: `«${r.name}»${conditions(r)}` });
      else return finish(accept, `правило «${r.name}»`);
    }
    return null;
  };

  const global = walk(rules.filter((r) => r.zone === "global" && (r.flow === flow || r.flow === "any")));
  if (global) return global;

  const zone = (fw.zones || []).find((z: any) => z.name === src.zone);
  if (!zone) return finish(false, `зона «${src.zone}» не описана — ядро отбрасывает`);

  if (flow === "forward" && src.kind === "segment" && dst.kind === "segment" && (src.isolated || dst.isolated)) {
    return finish(false, `изоляция сегмента «${src.isolated ? src.title : dst.title}»`);
  }

  const own = walk(rules.filter((r) => r.zone === src.zone && r.flow === flow));
  if (own) return own;

  if (flow === "forward" && src.zone === "wan" && dst.subnet) {
    for (const n of fw.nat || []) {
      const target = n.enabled && n.direction === "destination" ? parseCIDR(n.dest_ip) : undefined;
      if (target && within(target, dst.subnet)) {
        partial.push({ accept: true, text: `проброс «${n.name}»: ${String(n.protocol || "").toUpperCase()} ${n.ext_port} → ${n.dest_ip}` });
      }
    }
  }
  if (flow === "in" && src.zone === "wan") {
    for (const s of config.vpn_servers || []) {
      if (s.enabled) partial.push({ accept: true, text: `VPN-сервер «${s.name}»` });
    }
  }

  if (flow === "forward" && src.kind === "segment" && dst.kind === "segment") {
    return finish(false, "сегменты по умолчанию не видят друг друга");
  }
  return finish(zone.policy === "accept", `политика зоны «${zone.title || zone.name}»`);
}

// Правила для уже установленных соединений (ответы) и некорректных пакетов не
// решают, можно ли открыть новое соединение.
function appliesToNew(r: any): boolean {
  const states = String(r.conn_state || "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean);
  return states.length === 0 || states.includes("new");
}

function matchRule(r: any, src: Entity, dst: Entity, flow: string, segments: Entity[]): "full" | "part" | "none" {
  let part = false;

  if (flow === "forward" && r.dst_zone && r.dst_zone !== dst.zone) return "none";

  if (r.interface) {
    if (!src.ifaces.includes(r.interface)) return "none";
    if (src.ifaces.length > 1) part = true;
  }

  const from = side(r.src_ip, src);
  if (from === "none") return "none";
  const to = flow === "in" ? (r.dst_ip ? "part" : "full") : side(r.dst_ip, dst, segments);
  if (to === "none") return "none";
  if (from === "part" || to === "part") part = true;

  if ((r.protocol && r.protocol !== "any") || r.src_port || r.dst_port || r.src_mac || r.schedule) part = true;
  return part ? "part" : "full";
}

// side сравнивает адрес из правила с точкой матрицы. Про зоны без подсети
// (интернет, VPN) доказать ничего нельзя — такое условие сужает правило.
function side(spec: string, entity: Entity, segments: Entity[] = []): "full" | "part" | "none" {
  if (!spec) return "full";
  const nets = String(spec).split(",").map((s) => parseCIDR(s.trim()));
  if (nets.some((n) => !n)) return "part";
  if (entity.subnet) {
    if (nets.some((n) => within(entity.subnet!, n!))) return "full";
    if (nets.some((n) => overlaps(entity.subnet!, n!))) return "part";
    return "none";
  }
  // Адрес внутри одного из сегментов в интернет или VPN не ведёт.
  if (nets.every((n) => segments.some((s) => s.subnet && within(n!, s.subnet)))) return "none";
  return "part";
}

function conditions(r: any): string {
  const parts: string[] = [];
  if (r.protocol && r.protocol !== "any") parts.push(String(r.protocol).toUpperCase() + (r.dst_port ? ` ${r.dst_port}` : ""));
  else if (r.dst_port) parts.push(`порт ${r.dst_port}`);
  if (r.src_ip) parts.push(`из ${r.src_ip}`);
  if (r.dst_ip) parts.push(`в ${r.dst_ip}`);
  if (r.src_mac) parts.push(`MAC ${r.src_mac}`);
  if (r.schedule) parts.push("по расписанию");
  return parts.length ? `: ${parts.join(", ")}` : "";
}

// --- IPv4 ---

// parseCIDR разбирает «10.0.0.1/24» или «10.0.0.1» и приводит адрес к адресу
// сети: адрес интерфейса роутера «192.168.10.1/24» означает подсеть.
function parseCIDR(text: string): Subnet | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(text || "").trim());
  if (!m) return undefined;
  const octets = m.slice(1, 5).map(Number);
  const bits = m[5] === undefined ? 32 : Number(m[5]);
  if (octets.some((o) => o > 255) || bits > 32) return undefined;
  const ip = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  return { net: (ip & mask(bits)) >>> 0, bits };
}

function mask(bits: number): number {
  return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
}

// within: вся подсеть a лежит внутри b.
function within(a: Subnet, b: Subnet): boolean {
  return a.bits >= b.bits && ((a.net & mask(b.bits)) >>> 0) === b.net;
}

function overlaps(a: Subnet, b: Subnet): boolean {
  return within(a, b) || within(b, a);
}
