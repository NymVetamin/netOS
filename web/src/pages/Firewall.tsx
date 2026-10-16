import { interfaceDisplay } from "../interfaceDisplay";
import { managedWanNAT } from "../wanNAT";
import { FirewallLive } from "./FirewallLive";
import { Ref, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Access, accessMatrix, Entity } from "../access";
import { newID } from "../id";
import { Badge, Cap, Card, Empty, Field, Notice, openOnCreate, Row, Rows, Switch, TableWrap } from "../ui";
import { Problem } from "../api";
import { ProblemsFor } from "./Network";

type Patch = (mutate: (draft: any) => void) => void;

function AddressSets({ config, patch }: { config: any; patch: Patch }) {
  const sets: any[] = config.firewall?.ipsets || [];
  const [editing, setEditing] = useState<{ id: string; name: string; text: string } | null>(null);
  const installed = (config.components || []).some((c: any) => c.id === "ipset" && c.installed);
  return <Card tight title="Наборы адресов" subtitle="IPv4-адреса и подсети для правил доступа">
    {!installed && <div className="rows-notes"><Notice tone="warn" title="Нужен компонент «Наборы адресов»">Включите его на странице компонентов перед применением настройки.</Notice></div>}
    {sets.length === 0 && !editing && <Empty>Наборов нет</Empty>}
    {sets.length > 0 && <Rows cols={["Набор", "Состав", "", "", ""]}>{sets.map((item: any) => {
      const used = (config.firewall?.rules || []).some((r: any) => r.src_ipset === item.id || r.dst_ipset === item.id);
      return <Row key={item.id} cells={[<strong>{item.name}</strong>, <span>{(item.entries || []).length} адресов и подсетей</span>, used ? <span className="dim">используется в правилах</span> : ""]}>
        <div className="row-actions">
          <button className="btn sm" onClick={() => setEditing({ id: item.id, name: item.name, text: (item.entries || []).join("\n") })}>Изменить набор</button>
          <button className="btn ghost sm" disabled={used} title={used ? "Сначала уберите набор из правил" : "Удалить набор"} onClick={() => patch((d) => { d.firewall.ipsets = d.firewall.ipsets.filter((s: any) => s.id !== item.id); })}>Удалить</button>
        </div>
      </Row>;
    })}</Rows>}
    <div className="rows-foot">
    {!editing && <button className="btn" onClick={() => setEditing({ id: newID("set"), name: "", text: "" })}>Добавить набор адресов</button>}
    {editing && <div>
      <Field label="Название набора"><input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} /></Field>
      <Field label="IPv4-адреса и подсети" hint="По одному на строку, например 192.0.2.10 или 198.51.100.0/24. Пустой набор не совпадает ни с одним адресом.">
        <textarea rows={6} className="mono" value={editing.text} onChange={(e) => setEditing({ ...editing, text: e.target.value })} />
      </Field>
      <div className="row" style={{ gap: "0.5rem" }}>
        <button className="btn primary" disabled={!editing.name.trim()} onClick={() => {
          const item = { id: editing.id, name: editing.name.trim(), entries: editing.text.split(/\r?\n/).map((v) => v.trim()).filter(Boolean) };
          patch((d) => { d.firewall.ipsets ||= []; const index = d.firewall.ipsets.findIndex((s: any) => s.id === item.id); if (index < 0) d.firewall.ipsets.push(item); else d.firewall.ipsets[index] = item; });
          setEditing(null);
        }}>Сохранить набор в черновик</button>
        <button className="btn" onClick={() => setEditing(null)}>Отмена</button>
      </div>
    </div>}
    </div>
  </Card>;
}

// Направления названы так же, как цепочки ядра: администратор, глядящий в
// iptables-save, должен видеть те же слова, что и в панели. Направления «во все
// сразу» нет намеренно — одно правило попадает ровно в одну цепочку.
const FLOWS = [
  { id: "in", title: "Input", hint: "Пакет адресован самому роутеру", chain: "INPUT" },
  { id: "out", title: "Output", hint: "Пакет отправлен самим роутером", chain: "OUTPUT" },
  { id: "forward", title: "Forward", hint: "Пакет идёт сквозь роутер", chain: "FORWARD" },
];

const ACTIONS = [
  { id: "accept", title: "Пропустить", tone: "ok" as const },
  { id: "drop", title: "Отбросить молча", tone: "danger" as const },
  { id: "reject", title: "Отклонить с ответом", tone: "danger" as const },
  { id: "continue", title: "Передать дальше по списку", tone: "neutral" as const },
];

const ZONE_POLICY: Record<string, string> = { accept: "пропустить", reject: "отклонить с ответом", drop: "отбросить молча" };

const SCHEDULE_DAYS = [
  { id: "Mon", title: "Пн" },
  { id: "Tue", title: "Вт" },
  { id: "Wed", title: "Ср" },
  { id: "Thu", title: "Чт" },
  { id: "Fri", title: "Пт" },
  { id: "Sat", title: "Сб" },
  { id: "Sun", title: "Вс" },
];

export function FirewallPage({ config, patch, problems }: { config: any; patch: Patch; problems: Problem[] }) {
  const fw = config.firewall || {};
  const zones: any[] = fw.zones || [];
  const rules: any[] = fw.rules || [];
  const [showAutomatic, setShowAutomatic] = useState(false);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  function moveTo(index: number, to: number) {
    patch((d) => {
      const list = d.firewall.rules;
      if (to < 0 || to >= list.length || to === index) return;
      const [item] = list.splice(index, 1);
      list.splice(to, 0, item);
    });
  }
  const move = (index: number, delta: number) => moveTo(index, index + delta);

  // Перетаскивание строки: правило встаёт на место той, на которую его
  // бросили. Порядок внутри цепочки и есть порядок проверки.
  const [dragging, setDragging] = useState<number | null>(null);
  const dragSource = useRef<number | null>(null);
  const [over, setOver] = useState<number | null>(null);
  const drag: Drag = {
    dragging,
    over,
    start: (index) => { dragSource.current = index; setDragging(index); },
    enter: (index) => setOver(index),
    drop: (index) => {
      if (dragSource.current !== null && dragSource.current !== index) moveTo(dragSource.current, index);
      dragSource.current = null;
      setDragging(null);
      setOver(null);
    },
    end: () => { dragSource.current = null; setDragging(null); setOver(null); },
  };

  const groups = buildGroups(config, rules);

  return (
    <>
      <div className="page-head">
        <h1>Защита сети</h1>
        <p>Правила доступа и перенаправления портов; проверяются сверху вниз</p>
      </div>

      <ProblemsFor problems={problems} prefixes={["firewall", "clients"]} />
      {config.samba?.enabled && <Notice tone="info" title="Доступ к дискам Samba">
        {!fw.enabled && <p>Файрволл выключен: описанные ниже сетевые правила не действуют. Ограничения самого Samba по адресам и пользователям сохраняются.</p>}
        TCP 445 разрешён для сетей {(config.networks || []).filter((n: any) => (config.samba.networks || []).includes(n.id)).map((n: any) => n.name).join(", ") || "—"} и VPN-серверов {(config.vpn_servers || []).filter((v: any) => (config.samba.vpns || []).includes(v.id)).map((v: any) => v.name).join(", ") || "—"}. Для остальных источников SMB закрыт, включая ранее установленные соединения. {config.samba.discovery && "Обнаружение Windows использует UDP/TCP 3702 и IGMP только в выбранных LAN."} Эти правила применяются до общих правил доступа; настройки находятся в разделе «Диски и файлы».
      </Notice>}

      {!fw.enabled && (
        <Notice tone="danger" title="Файрволл выключен">
          Роутер пропускает весь трафик без фильтрации.
        </Notice>
      )}

      <AccessCard config={config} />

      <AddressSets config={config} patch={patch} />

      <Card tight title="Зоны и политики">
        <div className="rows-foot top">
          <div className="form-grid">
            <Switch
              checked={fw.enabled}
              label="Файрволл включён"
              onChange={(v) => patch((d) => (d.firewall.enabled = v))}
            />
            <Field
              wide
              label="Исходящий трафик самого роутера"
              hint="Обновления, запросы DNS от роутера, его подключения к VPN"
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
        </div>

        <Rows cols={["Зона", "Цепочки", "Интерфейсы", "Без правила", "Размер пакетов"]}>
          {zones.map((z: any, idx: number) => {
            const ifaces = interfacesOfZone(config, z.name);
            return (
              <Row
                key={z.name}
                className="zone-card"
                cells={[
                  <strong>{z.title || z.name}</strong>,
                  <code className="faint">{z.name.toUpperCase()}-*</code>,
                  ifaces.length > 0 ? <span className="mono">{ifaces.map(name => interfaceDisplay(config, name)).join(", ")}</span> : <Badge tone="warn">нет интерфейсов</Badge>,
                  ZONE_POLICY[z.policy] || z.policy,
                  <span className="dim">{z.mss_clamp ? "подгоняется" : "не меняется"}</span>,
                ]}
              >
                <div className="dim">{z.description}</div>
                {ifaces.length === 0 && <div className="faint">Ни одного интерфейса — правила этой зоны сейчас не работают</div>}
                <div className="form-grid" style={{ marginTop: "0.8rem" }}>
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
                  <div className="field"><div className="field-label">&nbsp;</div>
                    <Switch
                      checked={z.mss_clamp}
                      label="Подгонять размер пакетов"
                      onChange={(v) => patch((d) => (d.firewall.zones[idx].mss_clamp = v))}
                    />
                  </div>
                </div>
              </Row>
            );
          })}
        </Rows>
      </Card>


      <Card
        title="Правила"
        subtitle={showAutomatic ? "Действующие правила, включая автоматические" : `${rules.filter((r) => r.enabled).length} включено из ${rules.length}`}
        actions={
          <div className="firewall-rule-actions">
            <label className="row"><input type="checkbox" checked={showAutomatic} disabled={adding || editing !== null} title={adding || editing !== null ? "Завершите редактирование правила" : undefined} onChange={e => { setShowAutomatic(e.target.checked); drag.end(); }} />Показать автоматические правила</label>
            {!showAutomatic && <button className="btn sm primary" onClick={() => setAdding(true)}>Создать правило</button>}
          </div>
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

        {showAutomatic ? <FirewallLive config={config} onEdit={() => setShowAutomatic(false)} /> : groups.length === 0 ? (
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
                        drag={drag}
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
    </>
  );
}

// ---------------------------------------------------------------------------
// Форма правила
// ---------------------------------------------------------------------------

function RuleForm({ config, initial, onSubmit, onCancel }: {
  config: any; initial?: any; onSubmit: (rule: any) => void; onCancel: () => void;
}) {
  const zones: any[] = config.firewall?.zones || [];
  const [r, setR] = useState<any>(() => ({ id: newID("rule"), name: "", enabled: true, system: false,
    zone: "global", flow: "in", action: "accept", protocol: "", interface: "", out_interface: "",
    src_ip: "", dst_ip: "", src_port: "", dst_port: "", src_mac: "", conn_state: "",
    schedule: null, dst_zone: "", log: false, comment: "", ...initial }));
  const set = (k: string, v: any) => setR((previous: any) => ({ ...previous, [k]: v }));
  const needsProtocol = !!(r.src_port || r.dst_port) && !["tcp", "udp"].includes(r.protocol);
  const options = (zone: string): string[] => zone && zone !== "global" ? interfacesOfZone(config, zone) :
    [...new Set<string>(["lo", ...(config.interfaces || []).map((i: any) => i.name), ...zones.flatMap(z => interfacesOfZone(config, z.name))])];
  const inputOptions = options(r.zone), outputOptions = options(r.flow === "out" ? r.zone : r.dst_zone);
  const badInput = r.flow !== "out" && r.interface && !inputOptions.includes(r.interface);
  const output = r.flow === "out" ? r.interface : r.out_interface;
  const badOutput = r.flow !== "in" && output && !outputOptions.includes(output);
  const states = String(r.conn_state || "").toLowerCase().split(",").map((v: string) => v.trim()).filter(Boolean);
  const zoneSelect = (field: string, label: string) => <Field label={label}>
    <select aria-label={label} value={r[field] || (field === "zone" ? "global" : "")} onChange={e => set(field, e.target.value)}>
      <option value={field === "zone" ? "global" : ""}>Любая зона</option>
      {zones.map(z => <option key={z.name} value={z.name}>{z.title || z.name}</option>)}
    </select>
  </Field>;
  const interfaceSelect = (field: string, label: string, values: string[]) => <Field label={label}>
    <select aria-label={label} value={r[field] || ""} onChange={e => set(field, e.target.value)}>
      <option value="">Любой в выбранной зоне</option>
      {r[field] && !values.includes(r[field]) && <option value={r[field]} disabled>{interfaceDisplay(config, r[field])} — не относится к выбранной зоне</option>}
      {values.map(name => <option key={name} value={name}>{interfaceDisplay(config, name)}</option>)}
    </select>
  </Field>;
  const textField = (field: string, label: string, hint?: string) => <Field label={label} hint={hint}>
    <input aria-label={label} className="mono" value={r[field] || ""} placeholder="любой" onChange={e => set(field, e.target.value)} />
  </Field>;
  const zoneName = (value: string) => zones.find(z => z.name === value)?.title || (value && value !== "global" ? value : "любая зона");
  const from = r.flow === "out" ? "сам роутер" : `${zoneName(r.zone)} / ${r.interface ? interfaceDisplay(config, r.interface) : "любой интерфейс"}`;
  const to = r.flow === "in" ? "сам роутер" : `${zoneName(r.flow === "out" ? r.zone : r.dst_zone)} / ${output ? interfaceDisplay(config, output) : "любой интерфейс"}`;
  return <div className="rule-form">
    <div className="form-grid">
      <Field label="Название" hint={r.system ? "Название системного правила задаёт netOS" : "Попадёт в комментарий правила в ядре"}>
        <input aria-label="Название" autoFocus readOnly={!!r.system} value={r.name} onChange={e => set("name", e.target.value)} />
      </Field>
      <Field label="Направление" hint={FLOWS.find(f => f.id === r.flow)?.hint}>
        <select aria-label="Направление" value={r.flow} onChange={e => {
          const flow = e.target.value;
          // Preserve the side of a selected interface when changing direction.
          const incoming = r.flow === "out" ? "" : r.interface;
          const outgoing = r.flow === "out" ? r.interface : r.out_interface;
          setR({ ...r, flow, interface: flow === "out" ? outgoing : incoming,
            out_interface: flow === "forward" ? outgoing : "",
            zone: flow === "out" ? (r.dst_zone || (r.flow === "out" ? r.zone : "global")) : r.flow === "out" ? "global" : r.zone,
            dst_zone: flow === "forward" ? (r.flow === "out" && r.zone !== "global" ? r.zone : r.dst_zone) : "" });
        }}>{FLOWS.map(f => <option key={f.id} value={f.id}>{f.title}</option>)}</select>
      </Field>
      <Field label="Действие"><select aria-label="Действие" value={r.action} onChange={e => set("action", e.target.value)}>{ACTIONS.map(a => <option key={a.id} value={a.id}>{a.title}</option>)}</select></Field>
      <Field label="Протокол"><select aria-label="Протокол" value={r.protocol || ""} onChange={e => set("protocol", e.target.value)}><option value="">Любой</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Field>
    </div>
    <div className="rule-endpoints">
      <fieldset><legend>Откуда</legend><div className="form-grid">
        {r.flow === "out" ? <p className="hint">Сам роутер</p> : <>{zoneSelect("zone", "Из какой зоны")}{interfaceSelect("interface", "Входящий интерфейс", inputOptions)}</>}
        {textField("src_ip", "Адрес источника", "IP-адрес или подсеть; пусто — любой")}
        {textField("src_port", "Порт источника", "80, 80,443 или 1000-2000")}
      </div></fieldset>
      <fieldset><legend>Куда</legend><div className="form-grid">
        {r.flow === "in" ? <p className="hint">Сам роутер</p> : <>{zoneSelect(r.flow === "out" ? "zone" : "dst_zone", "В какую зону")}{interfaceSelect(r.flow === "out" ? "interface" : "out_interface", "Исходящий интерфейс", outputOptions)}</>}
        {textField("dst_ip", "Адрес назначения", "IP-адрес или подсеть; пусто — любой")}
        {textField("dst_port", "Порт назначения", "80, 80,443 или 1000-2000")}
      </div></fieldset>
    </div>
    <details className="rule-advanced"><summary>Дополнительно</summary>
      <div className="form-grid">
        {(["src_ipset", "dst_ipset"] as const).map(field => <Field key={field} label={field === "src_ipset" ? "Набор адресов источника" : "Набор адресов назначения"} hint="Дополнительное условие: адрес входит в набор">
          <select aria-label={field === "src_ipset" ? "Набор адресов источника" : "Набор адресов назначения"} value={r[field] || ""} onChange={e => set(field, e.target.value)}><option value="">Любой адрес</option>{(config.firewall?.ipsets || []).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        </Field>)}
        {r.flow !== "out" && textField("src_mac", "MAC источника")}
        <Field label="Состояние соединения" hint="Ничего не выбрано — любое состояние">
          <div className="rule-states">{["new", "established", "related", "invalid"].map(state => <label key={state}>
            <input type="checkbox" aria-label={state.toUpperCase()} checked={states.includes(state)} onChange={e => set("conn_state", (e.target.checked ? [...states, state] : states.filter((v: string) => v !== state)).join(","))} />{state.toUpperCase()}
          </label>)}</div>
        </Field>
        <Field label="Комментарий" hint={r.system ? "Комментарий системного правила задаёт netOS" : "Заметка администратора"}><input aria-label="Комментарий" readOnly={!!r.system} value={r.comment || ""} onChange={e => set("comment", e.target.value)} /></Field>
      </div>
      <div style={{ marginTop: "0.9rem" }}>
        <Switch
          checked={!!r.schedule}
          label="Ограничить правило расписанием"
          onChange={(v) =>
            set("schedule", v ? { days: [], time_start: "", time_stop: "" } : null)
          }
        />
        {r.schedule && (
          <div className="form-grid" style={{ marginTop: "0.7rem" }}>
            <Field label="Дни недели" hint="Пусто — каждый день">
              <div className="row wrap" style={{ gap: "0.6rem" }}>
                {SCHEDULE_DAYS.map((day) => (
                  <label key={day.id} className="row" style={{ gap: "0.25rem" }}>
                    <input
                      type="checkbox"
                      aria-label={day.title}
                      checked={(r.schedule.days || []).includes(day.id)}
                      onChange={(e) => {
                        const days = r.schedule.days || [];
                        set("schedule", {
                          ...r.schedule,
                          days: e.target.checked
                            ? [...days, day.id]
                            : days.filter((x: string) => x !== day.id),
                        });
                      }}
                    />
                    {day.title}
                  </label>
                ))}
              </div>
            </Field>
            <Field label="Начало (UTC)" hint="Пусто — без нижней границы">
              <input
                type="time"
                value={r.schedule.time_start || ""}
                onChange={(e) =>
                  set("schedule", { ...r.schedule, time_start: e.target.value })
                }
              />
            </Field>
            <Field label="Окончание (UTC)" hint="Пусто — без верхней границы">
              <input
                type="time"
                value={r.schedule.time_stop || ""}
                onChange={(e) =>
                  set("schedule", { ...r.schedule, time_stop: e.target.value })
                }
              />
            </Field>
          </div>
        )}
      </div>


      <Switch checked={!!r.log} label="Записывать срабатывания в журнал" onChange={v => set("log", v)} />
      <a className="hint" href="#diagnostics?log=firewall">Открыть журнал firewall</a>
    </details>
    {(badInput || badOutput) && <Notice tone="warn" title="Выберите интерфейс заново">Сохранённый интерфейс не относится к выбранной зоне. Выберите подходящий интерфейс или явно укажите «Любой».</Notice>}
    {needsProtocol && <Notice tone="warn" title="Для правила с портом нужен протокол">Выберите TCP или UDP.</Notice>}
    <div className="rule-preview" aria-label="Описание правила">
      <strong>{FLOWS.find(f => f.id === r.flow)?.title} · {ACTIONS.find(a => a.id === r.action)?.title}</strong>
      <div>Откуда: {from} / {r.src_ip || "любой адрес"}{r.src_port ? ` · порт ${r.src_port}` : ""}</div>
      <div>Куда: {to} / {r.dst_ip || "любой адрес"}{r.dst_port ? ` · порт ${r.dst_port}` : ""}</div>
      <div className="hint">Протокол: {r.protocol || "любой"} · Состояние: {states.join(", ") || "любое"} · Цепочка: {targetChain(r)}</div>
    </div>
    <div className="row" style={{ justifyContent: "flex-end", gap: "0.5rem", marginTop: "1rem" }}>
      <button className="btn" onClick={onCancel}>Отмена</button>
      <button className="btn primary" disabled={!r.name.trim() || needsProtocol || !!badInput || !!badOutput} onClick={() => onSubmit(r)}>{initial ? "Сохранить" : "Создать"}</button>
    </div>
  </div>;
}

// ---------------------------------------------------------------------------

function RuleRow({
  rule,
  index,
  config,
  patch,
  onMove,
  drag,
  expanded,
  onToggleExpand,
}: {
  rule: any;
  index: number;
  config: any;
  patch: Patch;
  onMove: (index: number, delta: number) => void;
  drag: Drag;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const gesture = useRef<{ x: number; y: number; active: boolean } | null>(null);
  const latestDrag = useRef(drag);
  latestDrag.current = drag;
  useEffect(() => {
    const cancel = () => { if (gesture.current) { gesture.current = null; latestDrag.current.end(); } };
    const key = (event: KeyboardEvent) => { if (event.key === "Escape") cancel(); };
    window.addEventListener("keydown", key);
    window.addEventListener("blur", cancel);
    return () => { window.removeEventListener("keydown", key); window.removeEventListener("blur", cancel); };
  }, []);
  const targetAt = (x: number, y: number) => {
    const row = document.elementFromPoint(x, y)?.closest<HTMLElement>("[data-rule-index]");
    return row ? Number(row.dataset.ruleIndex) : null;
  };
  const action = ACTIONS.find((a) => a.id === rule.action);
  const target = drag.over === index && drag.dragging !== null && drag.dragging !== index;
  const rowClass = [
    rule.enabled ? "" : "disabled-row",
    drag.dragging === index ? "dragging" : "",
    target ? (drag.dragging! > index ? "drop-above" : "drop-below") : "",
  ].filter(Boolean).join(" ");

  return (
    <>
      <tr
        className={rowClass}
        data-rule-index={index}
      >
        <td style={{ width: 24, paddingRight: 0 }}>
          <button
            type="button"
            className="grip"
            aria-label={`Переместить правило ${rule.name}`}
            title="Перетащите, чтобы поменять порядок"
            onDragStart={e => e.preventDefault()}
            onPointerDown={e => {
              if (e.button !== 0 || !e.isPrimary) return;
              e.preventDefault();
              e.currentTarget.focus();
              e.currentTarget.setPointerCapture(e.pointerId);
              gesture.current = { x: e.clientX, y: e.clientY, active: false };
            }}
            onPointerMove={e => {
              const current = gesture.current;
              if (!current) return;
              if (!current.active) {
                if (Math.hypot(e.clientX - current.x, e.clientY - current.y) < 5) return;
                current.active = true;
                drag.start(index);
              }
              const target = targetAt(e.clientX, e.clientY);
              if (target !== null) drag.enter(target);
            }}
            onPointerUp={e => {
              const current = gesture.current;
              gesture.current = null;
              const target = targetAt(e.clientX, e.clientY);
              if (current?.active && target !== null) drag.drop(target);
              else drag.end();
              if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
            }}
            onPointerCancel={() => { gesture.current = null; drag.end(); }}
            onLostPointerCapture={() => { if (gesture.current) { gesture.current = null; drag.end(); } }}
            onKeyDown={e => {
              if (e.key === "ArrowUp" || e.key === "ArrowDown") {
                e.preventDefault();
                if (!gesture.current) onMove(index, e.key === "ArrowUp" ? -1 : 1);
              }
            }}
          >
            <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><circle cx="9" cy="6" r="1.4" /><circle cx="15" cy="6" r="1.4" /><circle cx="9" cy="12" r="1.4" /><circle cx="15" cy="12" r="1.4" /><circle cx="9" cy="18" r="1.4" /><circle cx="15" cy="18" r="1.4" /></svg>
          </button>
        </td>
        <td style={{ width: 46 }}>
          <Switch
            checked={rule.enabled}
            label=""
            ariaLabel={`Правило ${rule.name || index + 1} включено`}
            onChange={(v) => patch((d) => (d.firewall.rules[index].enabled = v))}
          />
        </td>
        <td>
          <div>{rule.name}</div>
          <div className="row" style={{ gap: "0.35rem", marginTop: 2 }}>
            {rule.system && <Badge tone="neutral">создано netOS</Badge>}
            <span className="mono faint" style={{ fontSize: 12 }}>
              {describeConditions(rule, config) || "любой трафик"}
            </span>
          </div>
        </td>
        <td style={{ width: 170 }}>
          <Badge tone={action?.tone || "neutral"}>{action?.title || rule.action}</Badge>
        </td>
        <td style={{ width: 210, textAlign: "right", whiteSpace: "nowrap" }}>
          <button className="btn ghost sm" title="выше" onClick={() => onMove(index, -1)}>
            ↑
          </button>
          <button className="btn ghost sm" title="ниже" onClick={() => onMove(index, 1)}>
            ↓
          </button>
          <button className="btn ghost sm" onClick={onToggleExpand}>
            {expanded ? "Свернуть" : "Изменить"}
          </button>
          {rule.id !== "sys-acme" && (
            <button
              className="btn ghost sm"
              title="удалить"
              onClick={() =>
                patch(
                  (d) => {
                    d.firewall.rules = d.firewall.rules.filter((x: any) => x.id !== rule.id);
                  },
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
          <td colSpan={5} style={{ background: "var(--surface-2)" }}>
            {rule.comment && (
              <div className="dim" style={{ marginBottom: "0.8rem" }}>
                {rule.comment}
              </div>
            )}
            {rule.system && (
              <Notice tone="info" title="Правило создано netOS">
                {rule.id === "sys-acme" ? "Правило управляется настройками сертификата в разделе «Система»." : "Это стартовое правило. Его можно изменить, выключить или удалить; удалённое правило не восстановится автоматически."}
                {rule.id === "sys-panel" && " Порт панели берётся из раздела «Система»."}
              </Notice>
            )}
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

type Drag = {
  dragging: number | null;
  over: number | null;
  start: (index: number) => void;
  enter: (index: number) => void;
  drop: (index: number) => void;
  end: () => void;
};

// ---------------------------------------------------------------------------
// Итог доступа
// ---------------------------------------------------------------------------

const VERDICT_TEXT = { y: "можно", n: "нельзя", p: "частично" } as const;

// AccessArrow рисует направление: сплошная стрелка — можно, пунктир —
// частично, стрелка в стену — нельзя.
function AccessArrow({ verdict, width = 20 }: { verdict: "y" | "n" | "p"; width?: number }) {
  const m = 7;
  const e = width - 2;
  return (
    <svg className="access-arrow" width={width} height={14} viewBox={`0 0 ${width} 14`} fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {verdict === "n" ? (
        <>
          <line x1={1} y1={m} x2={width / 2 - 3} y2={m} />
          <line x1={width / 2} y1={1} x2={width / 2} y2={13} strokeWidth={3} />
        </>
      ) : (
        <>
          <line x1={1} y1={m} x2={e - 2} y2={m} strokeDasharray={verdict === "p" ? "5 4" : undefined} />
          <path d={`M${e - 7} 2 L${e} ${m} L${e - 7} 12`} />
        </>
      )}
    </svg>
  );
}

// AccessCard — матрица «кто куда может ходить». Только показывает: итог
// считается из зон и правил, менять его — правилами ниже. Подробности —
// по нажатию на плашку.
function AccessCard({ config }: { config: any }) {
  const zoneIfaces = { wan: interfacesOfZone(config, "wan"), vpn: interfacesOfZone(config, "vpn") };
  const matrix = accessMatrix(config, zoneIfaces);
  const [open, setOpen] = useState<{ i: number; j: number } | null>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const anchorRef = useRef<HTMLButtonElement | null>(null);

  // Подсказка стоит у плашки. Координаты из getBoundingClientRect уже
  // умножены на масштаб интерфейса, а style.left в него пересчитывается,
  // поэтому делим на коэффициент.
  useLayoutEffect(() => {
    const tip = tipRef.current;
    const anchor = anchorRef.current;
    if (!tip || !anchor) return;
    const r = anchor.getBoundingClientRect();
    const k = r.width / anchor.offsetWidth || 1;
    const w = tip.offsetWidth * k;
    const h = tip.offsetHeight * k;
    tip.style.left = `${Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8)) / k}px`;
    tip.style.top = `${(window.innerHeight - r.bottom < h + 10 && r.top > h + 10 ? r.top - h - 6 : r.bottom + 6) / k}px`;
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => {
      if (e.type === "keydown" && (e as KeyboardEvent).key !== "Escape") return;
      if (e.type === "mousedown" && (tipRef.current?.contains(e.target as Node) || anchorRef.current?.contains(e.target as Node))) return;
      setOpen(null);
      if (e.type === "keydown") anchorRef.current?.focus();
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  if (matrix.sources.length === 0) return null;
  const cell = open ? matrix.cells[open.i][open.j] : null;

  return (
    <Card title="Кто куда может ходить" subtitle="итог зон и правил для новых соединений · нажмите на плашку, чтобы узнать, что её решает" tight>
      <TableWrap>
        <table className="access">
          <thead>
            <tr>
              <th className="corner" scope="col"><span className="c-to">куда</span><span className="c-from">откуда</span></th>
              {matrix.destinations.map((d) => <th key={d.id} scope="col"><EntityName entity={d} /></th>)}
            </tr>
          </thead>
          <tbody>
            {matrix.sources.map((src, i) => (
              <tr key={src.id}>
                <th scope="row"><EntityName entity={src} /></th>
                {matrix.destinations.map((dst, j) => {
                  const c = matrix.cells[i][j];
                  if (!c) return <td key={dst.id}><div className="access-tile same">—</div></td>;
                  const active = open?.i === i && open?.j === j;
                  return (
                    <td key={dst.id}>
                      <button
                        type="button"
                        className={`access-tile ${c.verdict} ${active ? "open" : ""}`}
                        aria-expanded={active}
                        aria-label={`${src.title} → ${dst.title}: ${VERDICT_TEXT[c.verdict]}. Подробнее`}
                        onClick={(e) => {
                          anchorRef.current = e.currentTarget;
                          setOpen(active ? null : { i, j });
                        }}
                      >
                        <AccessArrow verdict={c.verdict} />
                        <b>{VERDICT_TEXT[c.verdict]}</b>
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      {open && cell && <AccessTip tipRef={tipRef} from={matrix.sources[open.i]} to={matrix.destinations[open.j]} access={cell} />}
    </Card>
  );
}

function EntityName({ entity }: { entity: Entity }) {
  return (
    <span className="access-entity">
      {entity.title}
      {entity.kind === "segment" && <span className="faint mono">{entity.ifaces[0]}</span>}
    </span>
  );
}

function AccessTip({ tipRef, from, to, access }: { tipRef: Ref<HTMLDivElement>; from: Entity; to: Entity; access: Access }) {
  return (
    <div className="access-tip" role="dialog" aria-label={`${from.title} → ${to.title}`} ref={tipRef}>
      <div className="access-tip-head">
        <span className={`access-path ${access.verdict}`}>{from.title} <AccessArrow verdict={access.verdict} width={28} /> {to.title}</span>
        <b className={`access-verdict ${access.verdict}`}>{VERDICT_TEXT[access.verdict]}</b>
      </div>
      <div className="dim">Решает: {access.reason}</div>
      {access.exceptions.length > 0 && (
        <div>
          <div className="faint">{access.verdict === "p" ? "Кроме:" : "Исключения:"}</div>
          <ul>{access.exceptions.map((text) => <li key={text}>{text}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Трансляция адресов
// ---------------------------------------------------------------------------

// Интерфейсы, между которыми можно выбирать в правилах трансляции. Помимо
// объявленных портов, мостов и VLAN сюда входят сессии PPPoE и L2TP: пакеты
// клиентов уходят через ppp-<id>, а не через физический порт провайдера, и
// правило, оставленное на порту, оставляло локальную сеть без выхода наружу.
const NAT_PROTO: Record<string, string> = { tcp: "TCP", udp: "UDP", tcpudp: "TCP+UDP" };

function natInterfaceOptions(config: any): { key: string; name: string; hint?: string }[] {
  const options = (config.interfaces || []).map((x: any) => ({ key: String(x.id), name: String(x.name) }));
  for (const wan of config.wans || []) {
    if (wan.proto !== "pppoe" && wan.proto !== "l2tp") continue;
    options.push({
      key: `wan:${wan.id}`,
      name: `ppp-${wan.id}`,
      hint: `сессия аплинка «${wan.name || wan.id}»`,
    });
  }
  return options;
}

function NATSection({ config, patch }: { config: any; patch: Patch }) {
  const nat: any[] = config.firewall?.nat || [];
  const interfaces = natInterfaceOptions(config);
  const source = nat.map((n, i) => ({ n, i })).filter((x) => x.n.direction !== "destination" && !managedWanNAT(config, x.n));
  const dest = nat.map((n, i) => ({ n, i })).filter((x) => x.n.direction === "destination");

  const addRule = (direction: string) => {
    const id = newID("nat");
    openOnCreate(id);
    patch((d) => {
      d.firewall.nat = d.firewall.nat || [];
      const base = {
        id,
        enabled: true,
        system: false,
        interface: d.interfaces?.[0]?.name || "",
        comment: "",
      };
      d.firewall.nat.push(
        direction === "source"
          ? { ...base, name: "Подмена адреса", direction: "source", source: "", to_source: "" }
          : {
              ...base,
              name: "Проброс",
              direction: "destination",
              protocol: "tcp",
              ext_port: "",
              dest_ip: "",
              dest_port: "",
              allow_from: "",
            },
      );
    });
  };

  const remove = (id: string) =>
    patch((d) => (d.firewall.nat = d.firewall.nat.filter((x: any) => x.id !== id)));

  return (
    <Card split title="Трансляция адресов" subtitle="NAT: подмена адресов на выходе и на входе">
      <Notice tone="info" title="Чем это отличается от правил файрволла">
        Правило файрволла решает, <b>пропустить ли</b> пакет. Трансляция решает,{" "}
        <b>какой адрес</b> в нём подменить. Чтобы клиенты вышли в интернет, нужны обе
        вещи: разрешение на транзит и подмена адреса отправителя.
      </Notice>

      <h3 className="card-sub">
        Подмена адреса отправителя
        <span className="sub">Трафик уходит наружу с адресом роутера, а не с адресом клиента</span>
        <button className="btn sm" onClick={() => addRule("source")}>
          Добавить
        </button>
      </h3>
      <div className="card-part">
      <p className="hint">Ручные правила NAT. Маскарад аплинка настраивается в разделе «Сеть». Изменения попадут в firewall после применения.</p>
      {source.length === 0 ? (
        <Empty>Правил подмены адреса отправителя в настройках нет</Empty>
      ) : (
        <Rows cols={["Название", "Уходит через", "От кого", "Подменять на", ""]} toggle="Вкл.">
          {source.map(({ n, i }) => (
            <Row
              key={n.id}
              id={n.id}
              cells={[
                <strong>{n.name}</strong>,
                <span className="mono">{interfaceDisplay(config, n.interface) || "—"}</span>,
                n.source ? <span className="mono">{n.source}</span> : <span className="dim">кто угодно</span>,
                n.to_source ? <span className="mono">{n.to_source}</span> : <span className="dim">адрес интерфейса</span>,
                n.system ? <Badge tone="neutral">создано netOS</Badge> : <span className="dim">{n.comment}</span>,
              ]}
              toggle={<Switch
                checked={n.enabled}
                label=""
                ariaLabel={`Правило NAT ${n.name || i + 1} включено`}
                onChange={(v) => patch((d) => (d.firewall.nat[i].enabled = v))}
              />}
            >
              <div className="form-grid">
                <Cap label="Название">
                  <input
                      type="text"
                      aria-label="Название правила NAT"
                      value={n.name}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].name = e.target.value))}
                    />
                </Cap>
                <Cap label="Комментарий">
                  <input
                      type="text"
                      aria-label="Комментарий правила NAT"
                      placeholder="комментарий"
                      value={n.comment || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].comment = e.target.value))}
                    />
                </Cap>
                <Cap label="Уходит через">
                  <select
                      aria-label="Исходящий интерфейс правила NAT"
                      value={n.interface || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].interface = e.target.value))}
                    >
                      <option value="">— выберите —</option>
                      {interfaces.map((x) => (
                        <option key={x.key} value={x.name}>
                          {x.hint ? `${interfaceDisplay(config, x.name)} — ${x.hint}` : interfaceDisplay(config, x.name)}
                        </option>
                      ))}
                    </select>
                </Cap>
                <Cap label="От кого">
                  <input
                      type="text"
                      aria-label="Источник правила NAT"
                      className="mono"
                      placeholder="от кого угодно"
                      value={n.source || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].source = e.target.value))}
                    />
                </Cap>
                <Cap label="Подменять на">
                  <input
                      type="text"
                      aria-label="Адрес подмены правила NAT"
                      className="mono"
                      placeholder="адрес интерфейса"
                      value={n.to_source || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].to_source = e.target.value))}
                    />
                </Cap>
              </div>
              <div className="hint">Пустое поле подмены означает маскарад: подставится текущий адрес интерфейса. Именно это нужно, когда провайдер выдаёт адрес динамически.</div>
              {!n.system && (
                <div className="row-actions">
                  <button className="btn ghost sm to-right" onClick={() => remove(n.id)}>
                    Удалить
                  </button>
                </div>
              )}
            </Row>
          ))}

        </Rows>
      )}
      </div>

      <h3 className="card-sub">
        Проброс портов внутрь
        <span className="sub">Обращение снаружи на порт роутера уезжает на устройство в локальной сети</span>
        <button className="btn sm" onClick={() => addRule("destination")}>
          Добавить
        </button>
      </h3>
      <div className="card-part">
      {dest.length === 0 ? (
        <Empty>Проброшенных портов нет</Empty>
      ) : (
        <Rows cols={["Название", "Приходит на", "Внешний порт", "Куда", "Только с адресов"]} toggle="Вкл.">
          {dest.map(({ n, i }) => (
            <Row
              key={n.id}
              id={n.id}
              cells={[
                <strong>{n.name}</strong>,
                n.interface ? <span className="mono">{interfaceDisplay(config, n.interface)}</span> : <span className="dim">любой</span>,
                <span className="mono">{NAT_PROTO[n.protocol || "tcp"]} {n.ext_port || "—"}</span>,
                <span className="mono">{n.dest_ip || "—"}:{n.dest_port || n.ext_port || "—"}</span>,
                n.allow_from ? <span className="mono">{n.allow_from}</span> : <span className="dim">с любых</span>,
              ]}
              toggle={<Switch
                checked={n.enabled}
                label=""
                ariaLabel={`Проброс порта ${n.name || i + 1} включён`}
                onChange={(v) => patch((d) => (d.firewall.nat[i].enabled = v))}
              />}
            >
              <div className="form-grid">
                <Cap label="Название">
                  <input
                      type="text"
                      aria-label={`Название проброса порта ${i + 1}`}
                      value={n.name}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].name = e.target.value))}
                    />
                </Cap>
                <Cap label="Комментарий">
                  <input
                      type="text"
                      aria-label={`Комментарий проброса порта ${i + 1}`}
                      placeholder="комментарий"
                      value={n.comment || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].comment = e.target.value))}
                    />
                </Cap>
                <Cap label="Приходит на">
                  <select
                      aria-label={`Входящий интерфейс проброса порта ${n.name || i + 1}`}
                      value={n.interface || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].interface = e.target.value))}
                    >
                      <option value="">любой</option>
                      {interfaces.map((x) => (
                        <option key={x.key} value={x.name}>
                          {x.hint ? `${interfaceDisplay(config, x.name)} — ${x.hint}` : interfaceDisplay(config, x.name)}
                        </option>
                      ))}
                    </select>
                </Cap>
                <Cap label="Протокол">
                  <select
                      aria-label={`Протокол проброса порта ${n.name || i + 1}`}
                      value={n.protocol || "tcp"}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].protocol = e.target.value))}
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="tcpudp">оба</option>
                    </select>
                </Cap>
                <Cap label="Внешний порт">
                  <input
                      type="text"
                      aria-label={`Внешний порт проброса ${n.name || i + 1}`}
                      className="mono"
                      value={n.ext_port || ""}
                      onChange={(e) => patch((d) => (d.firewall.nat[i].ext_port = e.target.value))}
                    />
                </Cap>
                <Cap label="Адрес назначения">
                  <input
                        type="text"
                        aria-label={`Адрес назначения проброса ${n.name || i + 1}`}
                        className="mono"
                        placeholder="192.168.10.5"
                        value={n.dest_ip || ""}
                        onChange={(e) => patch((d) => (d.firewall.nat[i].dest_ip = e.target.value))}
                      />
                </Cap>
                <Cap label="Порт назначения">
                  <input
                        type="text"
                        aria-label={`Порт назначения проброса ${n.name || i + 1}`}
                        className="mono"
                        placeholder="тот же"
                        value={n.dest_port || ""}
                        onChange={(e) =>
                          patch((d) => (d.firewall.nat[i].dest_port = e.target.value))
                        }
                      />
                </Cap>
                <Cap label="Только с адресов">
                  <input
                      type="text"
                      aria-label={`Разрешённые источники проброса ${n.name || i + 1}`}
                      className="mono"
                      placeholder="с любых"
                      value={n.allow_from || ""}
                      onChange={(e) =>
                        patch((d) => (d.firewall.nat[i].allow_from = e.target.value))
                      }
                    />
                </Cap>
              </div>
              <div className="hint">Разрешение на транзит проброшенных пакетов netOS добавляет само — отдельное правило файрволла заводить не нужно. Внешний и внутренний порт задаются одним портом или одним диапазоном, например 443 или 8000-8010; списки здесь не поддерживаются.</div>
              {!n.system && (
                <div className="row-actions">
                  <button className="btn ghost sm to-right" onClick={() => remove(n.id)}>
                    Удалить
                  </button>
                </div>
              )}
            </Row>
          ))}
        </Rows>
      )}
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
    const f = FLOWS.find((x) => x.id === r.flow);
    if (r.zone === "global") {
      add(`builtin-${r.flow}`, f?.chain || r.flow, `без привязки к зоне — ${f?.hint}`, r, i);
      return;
    }
    const z = zones.find((x: any) => x.name === r.zone);
    const suffix = r.flow === "in" ? "IN" : r.flow === "out" ? "OUT" : "FWD";
    const chain = `${String(r.zone).toUpperCase()}-${suffix}`;
    const live = interfacesOfZone(config, r.zone).length > 0;
    add(
      `${r.zone}-${r.flow}`,
      chain,
      live
        ? `${f?.hint}, зона «${z?.title || r.zone}»`
        : `в зоне «${z?.title || r.zone}» пока нет интерфейсов, поэтому эти правила не действуют`,
      r,
      i,
    );
  });

  return groups;
}

function targetChain(r: any): string {
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
      if (w.enabled) names.push(w.proto === "pppoe" || w.proto === "l2tp" ? `ppp-${w.id}` : String(byID.get(w.interface) || ""));
    }
  }
	if (zone === "vpn") {
		for (const channel of config.channels || []) {
			if (!channel.enabled || channel.type === "direct") continue;
			const prefix = channel.type === "wireguard" ? "wg-ch" :
				channel.type === "l2tp" ? "ppp-ch" :
				channel.type === "ikev2" ? "xfrm-ch" : "tun-ch";
			names.push(`${prefix}${channel.index}`);
		}
		for (const server of config.vpn_servers || []) {
			if (!server.enabled) continue;
			const prefix = server.type === "wireguard" ? "wg-srv" :
				server.type === "ocserv" ? "vpns" :
				server.type === "ikev2" ? "xfrm-srv" : server.type === "l2tp" ? "ppp-srv" : "";
			if (prefix) names.push(`${prefix}${server.index}${server.type === "ocserv" ? "+" : ""}`);
		}
	}
  return [...new Set(names.filter(Boolean))];
}

function describeConditions(r: any, config: any): string {
  const sets: any[] = config.firewall?.ipsets || [];
  const parts: string[] = [];
  const setName = (id: string) => sets.find((s) => s.id === id)?.name || id || "интерфейс не задан";
  if (r.interface) parts.push(`${r.flow === "out" ? "выход" : "вход"}: ${interfaceDisplay(config, r.interface)}`);
  if (r.out_interface) parts.push(`выход: ${interfaceDisplay(config, r.out_interface)}`);
  if (r.protocol) parts.push(r.protocol.toUpperCase());
  if (r.src_ip) parts.push(`от ${r.src_ip}`);
  if (r.src_ipset) parts.push(`из набора «${setName(r.src_ipset)}»`);
  if (r.src_mac) parts.push(`от ${r.src_mac}`);
  if (r.dst_ip) parts.push(`к ${r.dst_ip}`);
  if (r.dst_ipset) parts.push(`в набор «${setName(r.dst_ipset)}»`);
  if (r.src_port) parts.push(`из порта ${r.src_port}`);
  if (r.dst_port) parts.push(`порт ${r.dst_port}`);
  if (r.conn_state) parts.push(r.conn_state);
  if (r.schedule) {
    const days = (r.schedule.days || []).join(",") || "ежедневно";
    const time = [r.schedule.time_start, r.schedule.time_stop].filter(Boolean).join("–");
    parts.push(`${days}${time ? ` ${time} UTC` : ""}`);
  }
  return parts.join(", ");
}
