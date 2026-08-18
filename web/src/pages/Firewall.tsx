import { useState } from "react";
import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

// Направления названы так же, как цепочки ядра: администратор, глядящий в
// iptables-save, должен видеть те же слова, что и в панели.
const FLOWS = [
  { id: "in", title: "Вход", hint: "Пакет адресован самому роутеру", chain: "INPUT" },
  { id: "out", title: "Выход", hint: "Пакет отправлен самим роутером", chain: "OUTPUT" },
  { id: "forward", title: "Форвард", hint: "Пакет идёт сквозь роутер", chain: "FORWARD" },
  { id: "any", title: "Все", hint: "Во всех трёх направлениях", chain: "все" },
];

const ACTIONS = [
  { id: "accept", title: "Пропустить", tone: "ok" as const },
  { id: "drop", title: "Отбросить молча", tone: "danger" as const },
  { id: "reject", title: "Отклонить с ответом", tone: "danger" as const },
  { id: "continue", title: "Передать дальше по списку", tone: "neutral" as const },
];

export function FirewallPage({ config, patch }: { config: any; patch: Patch }) {
  const fw = config.firewall || {};
  const zones: any[] = fw.zones || [];
  const rules: any[] = fw.rules || [];
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  function move(index: number, delta: number) {
    patch((d) => {
      const list = d.firewall.rules;
      const to = index + delta;
      if (to < 0 || to >= list.length) return;
      const [item] = list.splice(index, 1);
      list.splice(to, 0, item);
    });
  }

  // Группируем правила по цепочке, в которую они попадут. Так список в панели
  // повторяет структуру вывода iptables-save.
  const groups = buildGroups(config, rules);

  return (
    <>
      <div className="page-head">
        <h1>Файрволл</h1>
        <p>Правила проверяются сверху вниз, срабатывает первое подходящее</p>
      </div>

      {!fw.enabled && (
        <Notice tone="danger" title="Файрволл выключен">
          Роутер пропускает весь трафик без фильтрации.
        </Notice>
      )}

      <Card title="Зоны и политики">
        <div className="row wrap" style={{ marginBottom: "1rem", gap: "1.5rem" }}>
          <Switch
            checked={fw.enabled}
            label="Файрволл включён"
            onChange={(v) => patch((d) => (d.firewall.enabled = v))}
          />
        </div>

        <div className="zone-grid">
          {zones.map((z: any, idx: number) => {
            const ifaces = interfacesOfZone(config, z.name);
            return (
              <div key={z.name} className="zone-card">
                <div className="row between">
                  <strong>{z.title || z.name}</strong>
                  <code className="faint">{z.name.toUpperCase()}-*</code>
                </div>
                <div className="faint" style={{ fontSize: 12.5, margin: "0.3rem 0 0.6rem" }}>
                  {z.description}
                </div>
                <Field label="Если ни одно правило не подошло">
                  <select
                    value={z.policy}
                    onChange={(e) => patch((d) => (d.firewall.zones[idx].policy = e.target.value))}
                  >
                    <option value="accept">пропустить</option>
                    <option value="reject">отклонить с ответом</option>
                    <option value="drop">отбросить молча</option>
                  </select>
                </Field>
                <Switch
                  checked={z.mss_clamp}
                  label="Подгонять размер пакетов"
                  onChange={(v) => patch((d) => (d.firewall.zones[idx].mss_clamp = v))}
                />
                <div className="faint" style={{ fontSize: 12, marginTop: "0.5rem" }}>
                  {ifaces.length > 0 ? (
                    <>Интерфейсы: {ifaces.join(", ")}</>
                  ) : (
                    <>Интерфейсов нет — цепочки для этой зоны не создаются</>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: "1rem", maxWidth: 340 }}>
          <Field
            label="Исходящий трафик самого роутера"
            hint="Относится к обновлениям, DNS-запросам роутера и его подключениям к VPN"
          >
            <select
              value={fw.output_policy || "accept"}
              onChange={(e) => patch((d) => (d.firewall.output_policy = e.target.value))}
            >
              <option value="accept">разрешён</option>
              <option value="drop">запрещён, кроме разрешённого правилами</option>
            </select>
          </Field>
        </div>
      </Card>

      <Card
        title="Правила"
        subtitle={`${rules.filter((r) => r.enabled).length} включено из ${rules.length}`}
        actions={
          <button className="btn sm primary" onClick={() => setAdding(true)}>
            Создать правило
          </button>
        }
        tight
      >
        {adding && (
          <div style={{ padding: "1.1rem", borderBottom: "1px solid var(--border)" }}>
            <RuleForm
              config={config}
              onCancel={() => setAdding(false)}
              onSubmit={(rule) => {
                patch((d) => d.firewall.rules.push(rule));
                setAdding(false);
              }}
            />
          </div>
        )}

        {groups.length === 0 ? (
          <Empty>Правил нет</Empty>
        ) : (
          groups.map((g) => (
            <div key={g.key}>
              <div className="chain-header">
                <code>{g.chain}</code>
                <span className="faint">{g.description}</span>
              </div>
              <TableWrap>
                <table className="rules">
                  <tbody>
                    {g.items.map(({ r, i }) => (
                      <RuleRow
                        key={r.id}
                        rule={r}
                        index={i}
                        config={config}
                        patch={patch}
                        onMove={move}
                        expanded={editing === r.id}
                        onToggleExpand={() => setEditing(editing === r.id ? null : r.id)}
                      />
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </div>
          ))
        )}
      </Card>

      <NATSection config={config} patch={patch} />
      <PortForwardSection config={config} patch={patch} />
    </>
  );
}

// ---------------------------------------------------------------------------
// Форма создания и правки
// ---------------------------------------------------------------------------

function RuleForm({
  config,
  initial,
  onSubmit,
  onCancel,
}: {
  config: any;
  initial?: any;
  onSubmit: (rule: any) => void;
  onCancel: () => void;
}) {
  const zones: any[] = config.firewall?.zones || [];
  const [r, setR] = useState<any>(
    initial || {
      id: "rule-" + Date.now(),
      name: "",
      enabled: true,
      system: false,
      zone: "global",
      flow: "in",
      action: "accept",
      protocol: "",
      src_ip: "",
      dst_ip: "",
      dst_port: "",
      src_mac: "",
      dst_zone: "",
      log: false,
    },
  );

  const set = (k: string, v: any) => setR({ ...r, [k]: v });
  const needsProtocol = (r.dst_port || r.src_port) && r.protocol !== "tcp" && r.protocol !== "udp";
  const zoneLabel = r.flow === "out" ? "В какую зону" : "Из какой зоны";

  return (
    <div className="rule-form">
      <div className="form-grid">
        <Field label="Название" hint="Попадёт в комментарий правила в ядре">
          <input
            type="text"
            autoFocus
            placeholder="Например: доступ к принтеру"
            value={r.name}
            onChange={(e) => set("name", e.target.value)}
          />
        </Field>

        <Field label="Направление">
          <select
            value={r.flow}
            onChange={(e) => {
              const flow = e.target.value;
              setR({ ...r, flow, dst_zone: flow === "forward" ? r.dst_zone : "" });
            }}
          >
            {FLOWS.map((f) => (
              <option key={f.id} value={f.id}>
                {f.title} — {f.hint}
              </option>
            ))}
          </select>
        </Field>

        <Field label={zoneLabel}>
          <select value={r.zone} onChange={(e) => set("zone", e.target.value)}>
            <option value="global">Любая зона</option>
            {zones.map((z: any) => (
              <option key={z.name} value={z.name}>
                {z.title || z.name}
              </option>
            ))}
          </select>
        </Field>

        {r.flow === "forward" && (
          <Field label="В какую зону">
            <select value={r.dst_zone || ""} onChange={(e) => set("dst_zone", e.target.value)}>
              <option value="">Любая</option>
              {zones.map((z: any) => (
                <option key={z.name} value={z.name}>
                  {z.title || z.name}
                </option>
              ))}
            </select>
          </Field>
        )}

        <Field label="Действие">
          <select value={r.action} onChange={(e) => set("action", e.target.value)}>
            {ACTIONS.map((a) => (
              <option key={a.id} value={a.id}>
                {a.title}
              </option>
            ))}
          </select>
        </Field>

        <Field label="Протокол">
          <select value={r.protocol || ""} onChange={(e) => set("protocol", e.target.value)}>
            <option value="">любой</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>
        </Field>

        <Field label="Адрес источника" hint="Адрес или подсеть, пусто — любой">
          <input
            type="text"
            className="mono"
            placeholder="192.168.10.0/24"
            value={r.src_ip || ""}
            onChange={(e) => set("src_ip", e.target.value)}
          />
        </Field>

        <Field label="Адрес назначения">
          <input
            type="text"
            className="mono"
            placeholder="любой"
            value={r.dst_ip || ""}
            onChange={(e) => set("dst_ip", e.target.value)}
          />
        </Field>

        <Field label="Порт назначения" hint="80, или 80,443, или 1000-2000">
          <input
            type="text"
            className="mono"
            placeholder="любой"
            value={r.dst_port || ""}
            onChange={(e) => set("dst_port", e.target.value)}
          />
        </Field>

        <Field label="MAC источника">
          <input
            type="text"
            className="mono"
            placeholder="любой"
            value={r.src_mac || ""}
            onChange={(e) => set("src_mac", e.target.value)}
          />
        </Field>
      </div>

      {needsProtocol && (
        <div style={{ marginTop: "0.8rem" }}>
          <Notice tone="warn" title="Для правила с портом нужен протокол">
            Выберите TCP или UDP — иначе ядро не примет правило.
          </Notice>
        </div>
      )}

      <div className="row between" style={{ marginTop: "1rem" }}>
        <Switch checked={r.log} label="Записывать срабатывания в журнал" onChange={(v) => set("log", v)} />
        <div className="row">
          <span className="faint mono" style={{ fontSize: 12 }}>
            попадёт в {targetChain(r)}
          </span>
          <button className="btn" onClick={onCancel}>
            Отмена
          </button>
          <button
            className="btn primary"
            disabled={!r.name || needsProtocol}
            onClick={() => onSubmit(r)}
          >
            {initial ? "Сохранить" : "Создать"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------

function RuleRow({
  rule,
  index,
  config,
  patch,
  onMove,
  expanded,
  onToggleExpand,
}: {
  rule: any;
  index: number;
  config: any;
  patch: Patch;
  onMove: (index: number, delta: number) => void;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const action = ACTIONS.find((a) => a.id === rule.action);

  return (
    <>
      <tr className={rule.enabled ? "" : "disabled-row"}>
        <td style={{ width: 46 }}>
          <Switch
            checked={rule.enabled}
            label=""
            onChange={(v) => patch((d) => (d.firewall.rules[index].enabled = v))}
          />
        </td>
        <td>
          <div>{rule.name}</div>
          <div className="row" style={{ gap: "0.35rem", marginTop: 2 }}>
            {rule.system && <Badge tone="neutral">создано netOS</Badge>}
            <span className="mono faint" style={{ fontSize: 12 }}>
              {describeConditions(rule) || "любой трафик"}
            </span>
          </div>
        </td>
        <td style={{ width: 170 }}>
          <Badge tone={action?.tone || "neutral"}>{action?.title || rule.action}</Badge>
        </td>
        <td style={{ width: 140, textAlign: "right", whiteSpace: "nowrap" }}>
          <button className="btn ghost sm" title="выше" onClick={() => onMove(index, -1)}>
            ↑
          </button>
          <button className="btn ghost sm" title="ниже" onClick={() => onMove(index, 1)}>
            ↓
          </button>
          <button className="btn ghost sm" onClick={onToggleExpand}>
            {expanded ? "Свернуть" : "Изменить"}
          </button>
          {!rule.system && (
            <button
              className="btn ghost sm"
              title="удалить"
              onClick={() =>
                patch(
                  (d) => (d.firewall.rules = d.firewall.rules.filter((x: any) => x.id !== rule.id)),
                )
              }
            >
              ✕
            </button>
          )}
        </td>
      </tr>

      {expanded && (
        <tr>
          <td colSpan={4} style={{ background: "var(--surface-2)" }}>
            {rule.comment && (
              <div className="dim" style={{ marginBottom: "0.8rem" }}>
                {rule.comment}
              </div>
            )}
            {rule.system ? (
              <Notice tone="info" title="Правило создано netOS">
                Его нельзя удалить, но можно выключить или изменить условия. Порт панели
                берётся из раздела «Система» и следует за ним автоматически.
              </Notice>
            ) : null}
            <RuleForm
              config={config}
              initial={rule}
              onCancel={onToggleExpand}
              onSubmit={(updated) => {
                patch((d) => (d.firewall.rules[index] = updated));
                onToggleExpand();
              }}
            />
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Трансляция адресов
// ---------------------------------------------------------------------------

function NATSection({ config, patch }: { config: any; patch: Patch }) {
  const nat: any[] = config.firewall?.nat || [];
  const zones: any[] = config.firewall?.zones || [];

  return (
    <Card
      title="Трансляция адресов"
      subtitle="Подмена адреса источника при выходе — это не разрешение, а именно подмена"
      actions={
        <button
          className="btn sm"
          onClick={() =>
            patch((d) => {
              d.firewall.nat.push({
                id: "nat-" + Date.now(),
                name: "Трансляция",
                enabled: true,
                system: false,
                type: "masquerade",
                out_zone: "wan",
                src_ip: "",
              });
            })
          }
        >
          Добавить
        </button>
      }
    >
      <Notice tone="info" title="Чем это отличается от правила файрволла">
        Правило файрволла решает, <b>пропустить ли</b> пакет. Трансляция решает,{" "}
        <b>с каким адресом</b> он уйдёт наружу. Для выхода клиентов в интернет нужны обе
        вещи: разрешение на транзит из локальной сети и подмена адреса на адрес роутера.
        Без разрешения пакет не пройдёт, без подмены ответ не вернётся.
      </Notice>

      {nat.length === 0 ? (
        <Empty>Правил трансляции нет</Empty>
      ) : (
        <div className="stack">
          {nat.map((n: any, idx: number) => (
            <div key={n.id} className="nat-row">
              <div className="row between wrap" style={{ marginBottom: "0.6rem" }}>
                <div className="row">
                  <Switch
                    checked={n.enabled}
                    label={<strong>{n.name}</strong>}
                    onChange={(v) => patch((d) => (d.firewall.nat[idx].enabled = v))}
                  />
                  {n.system && <Badge tone="neutral">создано netOS</Badge>}
                </div>
                {!n.system && (
                  <button
                    className="btn ghost sm"
                    onClick={() =>
                      patch(
                        (d) => (d.firewall.nat = d.firewall.nat.filter((x: any) => x.id !== n.id)),
                      )
                    }
                  >
                    Удалить
                  </button>
                )}
              </div>

              {/* Правило читается одной фразой слева направо. */}
              <div className="sentence">
                <span>Пакетам от</span>
                <input
                  type="text"
                  className="mono"
                  style={{ width: 150 }}
                  placeholder="кого угодно"
                  value={n.src_ip || ""}
                  onChange={(e) => patch((d) => (d.firewall.nat[idx].src_ip = e.target.value))}
                />
                <span>при выходе в</span>
                <select
                  value={n.out_zone || ""}
                  onChange={(e) => patch((d) => (d.firewall.nat[idx].out_zone = e.target.value))}
                >
                  {zones.map((z: any) => (
                    <option key={z.name} value={z.name}>
                      {z.title || z.name}
                    </option>
                  ))}
                </select>
                <span>подменять адрес источника на</span>
                <select
                  value={n.type}
                  onChange={(e) => patch((d) => (d.firewall.nat[idx].type = e.target.value))}
                >
                  <option value="masquerade">адрес роутера на этом интерфейсе</option>
                  <option value="snat">указанный адрес</option>
                </select>
                {n.type === "snat" && (
                  <input
                    type="text"
                    className="mono"
                    style={{ width: 150 }}
                    placeholder="203.0.113.5"
                    value={n.to_source || ""}
                    onChange={(e) => patch((d) => (d.firewall.nat[idx].to_source = e.target.value))}
                  />
                )}
              </div>

              <div className="faint" style={{ fontSize: 12, marginTop: "0.5rem" }}>
                Интерфейсы зоны: {interfacesOfZone(config, n.out_zone).join(", ") || "нет"}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function PortForwardSection({ config, patch }: { config: any; patch: Patch }) {
  const list: any[] = config.firewall?.port_forwards || [];
  const [draft, setDraft] = useState({ name: "", protocol: "tcp", ext: "", ip: "", port: "" });

  return (
    <Card
      title="Проброс портов"
      subtitle="Обращение снаружи на порт роутера перенаправляется на устройство внутри сети"
      tight
    >
      {list.length === 0 ? (
        <Empty>Проброшенных портов нет</Empty>
      ) : (
        <TableWrap>
          <table>
            <thead>
              <tr>
                <th>Название</th>
                <th>Протокол</th>
                <th>Внешний порт</th>
                <th>Куда перенаправить</th>
                <th>Вкл.</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((pf: any, idx: number) => (
                <tr key={pf.id}>
                  <td>{pf.name}</td>
                  <td>
                    <Badge tone="neutral">{pf.protocol}</Badge>
                  </td>
                  <td className="mono">{pf.ext_port}</td>
                  <td className="mono">
                    {pf.dest_ip}:{pf.dest_port}
                  </td>
                  <td>
                    <Switch
                      checked={pf.enabled}
                      label=""
                      onChange={(v) => patch((d) => (d.firewall.port_forwards[idx].enabled = v))}
                    />
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      className="btn ghost sm"
                      onClick={() =>
                        patch(
                          (d) =>
                            (d.firewall.port_forwards = d.firewall.port_forwards.filter(
                              (x: any) => x.id !== pf.id,
                            )),
                        )
                      }
                    >
                      Удалить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}

      <div style={{ padding: "1.1rem", borderTop: "1px solid var(--border)" }}>
        <div className="row wrap" style={{ alignItems: "flex-end", gap: "0.7rem" }}>
          <div className="field" style={{ margin: 0, width: 150 }}>
            <label>Название</label>
            <input
              type="text"
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
          </div>
          <div className="field" style={{ margin: 0, width: 110 }}>
            <label>Протокол</label>
            <select
              value={draft.protocol}
              onChange={(e) => setDraft({ ...draft, protocol: e.target.value })}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="tcpudp">оба</option>
            </select>
          </div>
          <div className="field" style={{ margin: 0, width: 120 }}>
            <label>Внешний порт</label>
            <input
              type="text"
              className="mono"
              value={draft.ext}
              onChange={(e) => setDraft({ ...draft, ext: e.target.value })}
            />
          </div>
          <div className="field" style={{ margin: 0, width: 150 }}>
            <label>Адрес внутри</label>
            <input
              type="text"
              className="mono"
              value={draft.ip}
              onChange={(e) => setDraft({ ...draft, ip: e.target.value })}
            />
          </div>
          <div className="field" style={{ margin: 0, width: 120 }}>
            <label>Порт внутри</label>
            <input
              type="text"
              className="mono"
              value={draft.port}
              onChange={(e) => setDraft({ ...draft, port: e.target.value })}
            />
          </div>
          <button
            className="btn primary"
            disabled={!draft.ext || !draft.ip}
            onClick={() => {
              patch((d) => {
                d.firewall.port_forwards.push({
                  id: "pf-" + Date.now(),
                  name: draft.name || "порт " + draft.ext,
                  enabled: true,
                  protocol: draft.protocol,
                  ext_port: draft.ext,
                  dest_ip: draft.ip,
                  dest_port: draft.port || draft.ext,
                });
              });
              setDraft({ name: "", protocol: "tcp", ext: "", ip: "", port: "" });
            }}
          >
            Добавить
          </button>
        </div>
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------

// buildGroups раскладывает правила по цепочкам ровно так же, как это делает
// генератор: панель должна показывать ту же структуру, что окажется в ядре.
function buildGroups(config: any, rules: any[]) {
  const zones: any[] = config.firewall?.zones || [];
  const groups: {
    key: string;
    chain: string;
    description: string;
    items: { r: any; i: number }[];
  }[] = [];

  const add = (key: string, chain: string, description: string, r: any, i: number) => {
    let g = groups.find((x) => x.key === key);
    if (!g) {
      g = { key, chain, description, items: [] };
      groups.push(g);
    }
    g.items.push({ r, i });
  };

  rules.forEach((r, i) => {
    const flows = r.flow === "any" ? ["in", "out", "forward"] : [r.flow];
    for (const flow of flows) {
      const f = FLOWS.find((x) => x.id === flow);
      if (r.zone === "global") {
        add(`builtin-${flow}`, f?.chain || flow, `без привязки к зоне — ${f?.hint}`, r, i);
      } else {
        const z = zones.find((x: any) => x.name === r.zone);
        const suffix = flow === "in" ? "IN" : flow === "out" ? "OUT" : "FWD";
        const chain = `${String(r.zone).toUpperCase()}-${suffix}`;
        const live = interfacesOfZone(config, r.zone).length > 0;
        add(
          `${r.zone}-${flow}`,
          chain,
          live
            ? `${f?.hint}, зона «${z?.title || r.zone}»`
            : `зона «${z?.title || r.zone}» без интерфейсов — цепочка не создаётся`,
          r,
          i,
        );
      }
    }
  });

  return groups;
}

function targetChain(r: any): string {
  if (r.flow === "any") return "INPUT, OUTPUT и FORWARD";
  const f = FLOWS.find((x) => x.id === r.flow);
  if (r.zone === "global") return f?.chain || "?";
  const suffix = r.flow === "in" ? "IN" : r.flow === "out" ? "OUT" : "FWD";
  return `${String(r.zone).toUpperCase()}-${suffix}`;
}

function interfacesOfZone(config: any, zone: string): string[] {
  if (!zone) return [];
  const names: string[] = [];
  const byID = new Map((config.interfaces || []).map((i: any) => [i.id, i.name]));

  for (const n of config.networks || []) {
    if (n.enabled && n.zone === zone) names.push(String(byID.get(n.interface) || ""));
  }
  if (zone === "wan") {
    for (const w of config.wans || []) {
      if (w.enabled) names.push(String(byID.get(w.interface) || ""));
    }
  }
  return names.filter(Boolean);
}

function describeConditions(r: any): string {
  const parts: string[] = [];
  if (r.interface) parts.push(`на ${r.interface}`);
  if (r.protocol) parts.push(r.protocol.toUpperCase());
  if (r.src_ip) parts.push(`от ${r.src_ip}`);
  if (r.src_mac) parts.push(`от ${r.src_mac}`);
  if (r.dst_ip) parts.push(`к ${r.dst_ip}`);
  if (r.dst_port) parts.push(`порт ${r.dst_port}`);
  if (r.conn_state) parts.push(r.conn_state);
  return parts.join(", ");
}
