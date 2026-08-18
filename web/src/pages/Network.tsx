import { Problem } from "../api";
import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

// Типы подключения к провайдеру. Названия — те, которыми провайдер объясняет
// настройку по телефону, а не термины из документации.
const WAN_TYPES = [
  {
    id: "dhcp",
    title: "Автоматически",
    hint: "Провайдер сам выдаёт адрес. Самый частый случай.",
  },
  {
    id: "static",
    title: "Фиксированный адрес",
    hint: "Провайдер выдал адрес, маску и шлюз на бумаге или в личном кабинете.",
  },
  {
    id: "pppoe",
    title: "PPPoE",
    hint: "Подключение по логину и паролю. Обычно у домашних провайдеров.",
    component: "pppoe",
  },
  {
    id: "l2tp",
    title: "L2TP",
    hint: "Логин, пароль и адрес сервера провайдера.",
    component: "l2tp",
  },
];

export function NetworkPage({
  config,
  patch,
  problems,
}: {
  config: any;
  patch: Patch;
  problems: Problem[];
}) {
  return (
    <>
      <div className="page-head">
        <h1>Интерфейсы и сегменты</h1>
        <p>Подключение к провайдеру, локальные сети и физические порты</p>
      </div>

      <ProblemsFor problems={problems} prefixes={["wans", "networks", "interfaces"]} />

      <UplinkSection config={config} patch={patch} />
      <SegmentSection config={config} patch={patch} />
      <InterfaceSection config={config} patch={patch} />
    </>
  );
}

// ---------------------------------------------------------------------------

function UplinkSection({ config, patch }: { config: any; patch: Patch }) {
  const wans: any[] = config.wans || [];

  return (
    <Card
      title="Подключение к интернету"
      subtitle="Как роутер выходит наружу"
      actions={
        <button
          className="btn sm"
          onClick={() =>
            patch((d) => {
              d.wans = d.wans || [];
              d.wans.push({
                id: "wan-" + Date.now(),
                name: "Аплинк " + (d.wans.length + 1),
                interface: d.interfaces?.[0]?.id || "",
                enabled: false,
                proto: "dhcp",
                metric: 100 + d.wans.length,
                weight: 1,
              });
            })
          }
        >
          Добавить
        </button>
      }
    >
      {wans.length === 0 ? (
        <Empty>Подключение не настроено</Empty>
      ) : (
        <div className="stack">
          {wans.map((w, idx) => (
            <div key={w.id} className="subcard">
              <div className="subcard-head">
                <Switch
                  checked={w.enabled}
                  label={<strong>{w.name}</strong>}
                  onChange={(v) => patch((d) => (d.wans[idx].enabled = v))}
                />
                <div className="row">
                  <Badge tone="neutral">{ifaceName(config, w.interface)}</Badge>
                  {wans.length > 1 && (
                    <button
                      className="btn ghost sm"
                      onClick={() =>
                        patch((d) => (d.wans = d.wans.filter((x: any) => x.id !== w.id)))
                      }
                    >
                      Удалить
                    </button>
                  )}
                </div>
              </div>

              <div className="subcard-body">
                <div className="form-grid">
                  <Field label="Название">
                    <input
                      type="text"
                      value={w.name}
                      onChange={(e) => patch((d) => (d.wans[idx].name = e.target.value))}
                    />
                  </Field>
                  <Field label="Порт" hint="Через какой физический порт идёт провайдер">
                    <select
                      value={w.interface}
                      onChange={(e) => patch((d) => (d.wans[idx].interface = e.target.value))}
                    >
                      {(config.interfaces || []).map((i: any) => (
                        <option key={i.id} value={i.id}>
                          {i.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>

                <div className="field">
                  <label>Тип подключения</label>
                  <div className="choice-grid">
                    {WAN_TYPES.map((t) => {
                      const missing = t.component && !hasComponent(config, t.component);
                      return (
                        <label
                          key={t.id}
                          className={`choice ${w.proto === t.id ? "selected" : ""}`}
                        >
                          <input
                            type="radio"
                            name={`proto-${w.id}`}
                            checked={w.proto === t.id}
                            onChange={() => patch((d) => (d.wans[idx].proto = t.id))}
                          />
                          <div>
                            <div className="row" style={{ gap: "0.4rem" }}>
                              <strong>{t.title}</strong>
                              {missing && <Badge tone="warn">нужен компонент</Badge>}
                            </div>
                            <div className="faint" style={{ fontSize: 12.5 }}>
                              {t.hint}
                            </div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>

                {w.proto === "static" && (
                  <div className="form-grid">
                    <Field label="Адрес с маской" hint="Например 203.0.113.5/24">
                      <input
                        type="text"
                        className="mono"
                        value={w.address || ""}
                        onChange={(e) => patch((d) => (d.wans[idx].address = e.target.value))}
                      />
                    </Field>
                    <Field label="Шлюз провайдера">
                      <input
                        type="text"
                        className="mono"
                        value={w.gateway || ""}
                        onChange={(e) => patch((d) => (d.wans[idx].gateway = e.target.value))}
                      />
                    </Field>
                  </div>
                )}

                {w.proto === "l2tp" && (
                  <div className="form-grid">
                    <Field
                      label="Адрес в сети провайдера"
                      hint="Туннель поднимается поверх него. Обычно провайдер выдаёт его по DHCP."
                    >
                      <select
                        value={w.underlay || "dhcp"}
                        onChange={(e) => patch((d) => (d.wans[idx].underlay = e.target.value))}
                      >
                        <option value="dhcp">Получать по DHCP</option>
                        <option value="static">Задать вручную</option>
                      </select>
                    </Field>
                    {w.underlay === "static" && (
                      <>
                        <Field label="Адрес с маской">
                          <input
                            type="text"
                            className="mono"
                            placeholder="10.0.0.5/24"
                            value={w.address || ""}
                            onChange={(e) => patch((d) => (d.wans[idx].address = e.target.value))}
                          />
                        </Field>
                        <Field label="Шлюз сети провайдера">
                          <input
                            type="text"
                            className="mono"
                            placeholder="10.0.0.1"
                            value={w.gateway || ""}
                            onChange={(e) => patch((d) => (d.wans[idx].gateway = e.target.value))}
                          />
                        </Field>
                      </>
                    )}
                  </div>
                )}

                {(w.proto === "pppoe" || w.proto === "l2tp") && (
                  <div className="form-grid">
                    {w.proto === "l2tp" && (
                      <Field label="Адрес концентратора">
                        <input
                          type="text"
                          className="mono"
                          value={w.server || ""}
                          onChange={(e) => patch((d) => (d.wans[idx].server = e.target.value))}
                        />
                      </Field>
                    )}
                    <Field label="Логин">
                      <input
                        type="text"
                        value={w.username || ""}
                        onChange={(e) => patch((d) => (d.wans[idx].username = e.target.value))}
                      />
                    </Field>
                    <Field label="Пароль">
                      <input
                        type="password"
                        value={w.password || ""}
                        onChange={(e) => patch((d) => (d.wans[idx].password = e.target.value))}
                      />
                    </Field>
                    {w.proto === "pppoe" && (
                      <Field label="Имя услуги" hint="Обычно оставляют пустым">
                        <input
                          type="text"
                          value={w.service || ""}
                          onChange={(e) => patch((d) => (d.wans[idx].service = e.target.value))}
                        />
                      </Field>
                    )}
                  </div>
                )}

                <div className="form-grid">
                  <Field
                    label="Приоритет"
                    hint="Меньше — предпочтительнее. Важно при нескольких подключениях."
                  >
                    <input
                      type="number"
                      value={w.metric ?? 100}
                      onChange={(e) => patch((d) => (d.wans[idx].metric = Number(e.target.value)))}
                    />
                  </Field>
                  <Field label="MTU" hint="0 — не менять">
                    <input
                      type="number"
                      value={w.mtu || 0}
                      onChange={(e) => patch((d) => (d.wans[idx].mtu = Number(e.target.value)))}
                    />
                  </Field>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------

function SegmentSection({ config, patch }: { config: any; patch: Patch }) {
  const networks: any[] = config.networks || [];

  return (
    <Card
      title="Локальные сегменты"
      subtitle="Подсети, которые обслуживает роутер"
      actions={
        <button
          className="btn sm"
          disabled={(config.interfaces || []).length === 0}
          onClick={() =>
            patch((d) => {
              d.networks = d.networks || [];
              const n = d.networks.length + 1;
              d.networks.push({
                id: "net-" + Date.now(),
                name: "Сегмент " + n,
                interface: d.interfaces?.[0]?.id || "",
                router_address: `192.168.${10 * n}.1/24`,
                enabled: true,
                zone: "lan",
                isolated: false,
                dhcp_pool: {
                  enabled: false,
                  start: `192.168.${10 * n}.100`,
                  end: `192.168.${10 * n}.200`,
                  lease_time: 43200,
                },
              });
            })
          }
        >
          Добавить
        </button>
      }
    >
      {networks.length === 0 ? (
        <Empty>
          Локальных сегментов нет. Роутер сейчас доступен только по адресу, который у
          него уже был.
        </Empty>
      ) : (
        <div className="stack">
          {networks.map((n, idx) => (
            <div key={n.id} className="subcard">
              <div className="subcard-head">
                <Switch
                  checked={n.enabled}
                  label={
                    <span>
                      <strong>{n.name}</strong>{" "}
                      <span className="faint" style={{ fontWeight: 400 }}>
                        {n.enabled ? "обслуживается" : "не обслуживается"}
                      </span>
                    </span>
                  }
                  onChange={(v) => patch((d) => (d.networks[idx].enabled = v))}
                />
                <div className="row">
                  <Badge tone="neutral">{ifaceName(config, n.interface)}</Badge>
                  <button
                    className="btn ghost sm"
                    onClick={() =>
                      patch((d) => (d.networks = d.networks.filter((x: any) => x.id !== n.id)))
                    }
                  >
                    Удалить
                  </button>
                </div>
              </div>

              {!n.enabled && (
                <div style={{ padding: "0 1rem" }}>
                  <Notice tone="info" title="Сегмент выключен">
                    Адрес с интерфейса снимется, DHCP в этом сегменте работать не будет.
                    Сам интерфейс останется — его состояние настраивается ниже, в списке
                    портов.
                  </Notice>
                </div>
              )}

              <div className="subcard-body">
                <div className="form-grid">
                  <Field label="Название">
                    <input
                      type="text"
                      value={n.name}
                      onChange={(e) => patch((d) => (d.networks[idx].name = e.target.value))}
                    />
                  </Field>
                  <Field
                    label="Адрес шлюза и размер сети"
                    hint="Адрес, по которому роутер виден клиентам этого сегмента. После косой черты — размер сети: /24 это 254 адреса."
                  >
                    <input
                      type="text"
                      className="mono"
                      placeholder="192.168.10.1/24"
                      value={n.router_address || ""}
                      onChange={(e) =>
                        patch((d) => (d.networks[idx].router_address = e.target.value))
                      }
                    />
                  </Field>
                  <Field label="Порт или мост">
                    <select
                      value={n.interface}
                      onChange={(e) => patch((d) => (d.networks[idx].interface = e.target.value))}
                    >
                      {(config.interfaces || []).map((i: any) => (
                        <option key={i.id} value={i.id}>
                          {i.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Зона файрволла">
                    <select
                      value={n.zone}
                      onChange={(e) => patch((d) => (d.networks[idx].zone = e.target.value))}
                    >
                      {(config.firewall?.zones || []).map((z: any) => (
                        <option key={z.name} value={z.name}>
                          {z.title || z.name}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>

                <div className="row wrap" style={{ gap: "1.5rem", marginTop: "0.5rem" }}>
                  <Switch
                    checked={n.isolated}
                    label="Запретить доступ в другие сегменты"
                    onChange={(v) => patch((d) => (d.networks[idx].isolated = v))}
                  />
                  <Switch
                    checked={n.dhcp_pool?.enabled}
                    label="Выдавать адреса по DHCP"
                    onChange={(v) => patch((d) => (d.networks[idx].dhcp_pool.enabled = v))}
                  />
                </div>

                {n.dhcp_pool?.enabled && (
                  <>
                    {!config.dhcp?.enabled && (
                      <div style={{ marginTop: "0.8rem" }}>
                        <Notice tone="warn" title="Сервер DHCP выключен">
                          Пул задан, но адреса выдаваться не будут. Включите DHCP в
                          разделе «DHCP и DNS».
                        </Notice>
                      </div>
                    )}
                    <div className="form-grid" style={{ marginTop: "0.9rem" }}>
                      <Field label="Первый адрес пула">
                        <input
                          type="text"
                          className="mono"
                          value={n.dhcp_pool.start}
                          onChange={(e) =>
                            patch((d) => (d.networks[idx].dhcp_pool.start = e.target.value))
                          }
                        />
                      </Field>
                      <Field label="Последний адрес пула">
                        <input
                          type="text"
                          className="mono"
                          value={n.dhcp_pool.end}
                          onChange={(e) =>
                            patch((d) => (d.networks[idx].dhcp_pool.end = e.target.value))
                          }
                        />
                      </Field>
                      <Field label="Срок аренды, секунд">
                        <input
                          type="number"
                          value={n.dhcp_pool.lease_time}
                          onChange={(e) =>
                            patch(
                              (d) =>
                                (d.networks[idx].dhcp_pool.lease_time = Number(e.target.value)),
                            )
                          }
                        />
                      </Field>
                    </div>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------

function InterfaceSection({ config, patch }: { config: any; patch: Patch }) {
  return (
    <Card
      title="Порты, мосты и VLAN"
      subtitle="Физические сетевые карты и построенные поверх них интерфейсы"
      tight
      actions={
        <div className="row" style={{ gap: "0.4rem" }}>
          <button
            className="btn sm"
            onClick={() =>
              patch((d) => {
                d.interfaces = d.interfaces || [];
                const n = d.interfaces.filter((i: any) => i.type === "bridge").length + 1;
                d.interfaces.push({
                  id: "br-" + Date.now(),
                  name: "br" + n,
                  type: "bridge",
                  members: [],
                  enabled: true,
                });
              })
            }
          >
            Добавить мост
          </button>
          <button
            className="btn sm"
            onClick={() =>
              patch((d) => {
                d.interfaces = d.interfaces || [];
                const parent = d.interfaces[0]?.name || "eth0";
                d.interfaces.push({
                  id: "vl-" + Date.now(),
                  name: parent + ".100",
                  type: "vlan",
                  parent,
                  vlan_id: 100,
                  enabled: true,
                });
              })
            }
          >
            Добавить VLAN
          </button>
        </div>
      }
    >
      <TableWrap>
        <table>
          <thead>
            <tr>
              <th>Имя</th>
              <th>Тип</th>
              <th>Состав</th>
              <th>MTU</th>
              <th>Включён</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(config.interfaces || []).map((i: any, idx: number) => (
              <tr key={i.id}>
                <td>
                  {i.type === "physical" ? (
                    <span className="mono">{i.name}</span>
                  ) : (
                    <input
                      type="text"
                      className="mono"
                      style={{ width: 130 }}
                      value={i.name}
                      onChange={(e) => patch((d) => (d.interfaces[idx].name = e.target.value))}
                    />
                  )}
                </td>
                <td>
                  <Badge tone="neutral">{typeLabel(i.type)}</Badge>
                </td>
                <td className="faint mono">
                  {i.type === "vlan" ? (
                    <span className="row" style={{ gap: "0.3rem" }}>
                      <select
                        value={i.parent || ""}
                        onChange={(e) => patch((d) => (d.interfaces[idx].parent = e.target.value))}
                      >
                        {(config.interfaces || [])
                          .filter((x: any) => x.type !== "vlan")
                          .map((x: any) => (
                            <option key={x.id} value={x.name}>
                              {x.name}
                            </option>
                          ))}
                      </select>
                      <input
                        type="number"
                        style={{ width: 80 }}
                        value={i.vlan_id || 0}
                        onChange={(e) =>
                          patch((d) => (d.interfaces[idx].vlan_id = Number(e.target.value)))
                        }
                      />
                    </span>
                  ) : i.type === "bridge" ? (
                    <MemberPicker config={config} patch={patch} index={idx} iface={i} />
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  <input
                    type="number"
                    style={{ width: 90 }}
                    value={i.mtu || 0}
                    onChange={(e) => patch((d) => (d.interfaces[idx].mtu = Number(e.target.value)))}
                  />
                </td>
                <td>
                  <Switch
                    checked={i.enabled}
                    label=""
                    onChange={(v) => patch((d) => (d.interfaces[idx].enabled = v))}
                  />
                </td>
                <td style={{ textAlign: "right" }}>
                  {i.type !== "physical" && (
                    <button
                      className="btn ghost sm"
                      onClick={() =>
                        patch(
                          (d) => (d.interfaces = d.interfaces.filter((x: any) => x.id !== i.id)),
                        )
                      }
                    >
                      Удалить
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

// MemberPicker показывает, какие порты входят в мост, и позволяет их менять.
function MemberPicker({
  config,
  patch,
  index,
  iface,
}: {
  config: any;
  patch: Patch;
  index: number;
  iface: any;
}) {
  const candidates = (config.interfaces || []).filter(
    (x: any) => x.type === "physical" || x.type === "vlan",
  );
  const members: string[] = iface.members || [];

  return (
    <div className="row wrap" style={{ gap: "0.5rem" }}>
      {candidates.length === 0 && <span className="faint">нет свободных портов</span>}
      {candidates.map((c: any) => (
        <label key={c.id} className="row" style={{ gap: "0.25rem", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={members.includes(c.name)}
            onChange={(e) =>
              patch((d) => {
                const list: string[] = d.interfaces[index].members || [];
                d.interfaces[index].members = e.target.checked
                  ? [...list, c.name]
                  : list.filter((m) => m !== c.name);
              })
            }
          />
          <span className="mono">{c.name}</span>
        </label>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------

export function ProblemsFor({
  problems,
  prefixes,
}: {
  problems: Problem[];
  prefixes: string[];
}) {
  const mine = problems.filter((p) => prefixes.some((pref) => p.path.startsWith(pref)));
  if (mine.length === 0) return null;
  return (
    <div className="stack" style={{ marginBottom: "1rem" }}>
      {mine.map((p, i) => (
        <div
          key={i}
          className={`notice ${p.severity === "error" ? "danger" : "warn"}`}
          style={{ marginBottom: 0 }}
        >
          <strong aria-hidden="true">!</strong>
          <div className="body">
            <div className="text">{p.message}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function ifaceName(config: any, id: string): string {
  return (config.interfaces || []).find((i: any) => i.id === id)?.name || "не выбран";
}

function hasComponent(config: any, id: string): boolean {
  return (config.components || []).some((c: any) => c.id === id && c.installed);
}

function typeLabel(t: string): string {
  switch (t) {
    case "physical":
      return "порт";
    case "bridge":
      return "мост";
    case "vlan":
      return "VLAN";
    case "bond":
      return "агрегация";
    default:
      return t;
  }
}
