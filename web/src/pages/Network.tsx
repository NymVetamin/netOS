import { SectionLink } from "../permissions";
import { interfaceDisplay } from "../interfaceDisplay";
import { linkSpeed, PortLinkSettings } from "./PortLinkSettings";
import { wanNAT, setWanNAT } from "../wanNAT";
import { confirmAction } from "../confirm";
import { secretInput } from "../secrets";
import { useEffect, useState } from "react";
import { api, Problem } from "../api";
import { newID } from "../id";
import { AddMenu, Badge, Cap, Card, Empty, Field, Notice, openOnCreate, Row, Rows, Switch } from "../ui";
import { Icon, INTERFACE_ICONS } from "../icons";

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
        <h1><Icon name="network" />Сеть</h1>
        <p>Подключение к интернету, локальные сети и физические порты</p>
      </div>

      <ProblemsFor problems={problems} prefixes={["wans", "multiwan", "networks", "interfaces"]} />

      <UplinkSection config={config} patch={patch} />
      <SegmentSection config={config} patch={patch} />
      <InterfaceSection config={config} patch={patch} />
    </>
  );
}

// ---------------------------------------------------------------------------

function UplinkSection({ config, patch }: { config: any; patch: Patch }) {
  const wans: any[] = config.wans || [];
  const [liveWANs, setLiveWANs] = useState<Record<string, any>>({});
  const [networkConflicts, setNetworkConflicts] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    const load = () => api.status().then((status) => {
      if (active) {
        setLiveWANs(Object.fromEntries((status.wans || []).map((wan: any) => [wan.id, wan])));
        setNetworkConflicts(status.network_conflicts || []);
      }
    }).catch(() => {});
    load();
    const timer = window.setInterval(load, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  return (
    <>
    {networkConflicts.map((conflict) => <Notice key={conflict} tone="warn" title="Конфликт сетевой конфигурации">{conflict}: networking.service настраивает интерфейс, которым управляет netOS. Уберите чужое объявление или отключите networking.service.</Notice>)}
    <Card title="Multi-WAN" subtitle="Автоматическое переключение на резервный аплинк">
      <div className="multiwan-enable">
          <Switch
            checked={!!config.multiwan?.enabled}
            disabled={wans.filter((wan) => wan.enabled).length < 2}
            onChange={(enabled) => patch((draft) => {
              draft.multiwan = draft.multiwan || { mode: "failover", sticky_connections: true };
              if (enabled) assignMissingWANIndexes(draft.wans || []);
              draft.multiwan.enabled = enabled;
            })}
            label="Включить Multi-WAN"
          />
        {wans.filter((wan) => wan.enabled).length < 2 && <div className="hint">Включите минимум два подключения.</div>}
      </div>
      <div className="multiwan-grid">
        <Field label="Распределение">
          <select aria-label="Распределение Multi-WAN" disabled={!config.multiwan?.enabled} value={config.multiwan?.mode || "failover"} onChange={(e) => patch((draft) => (draft.multiwan.mode = e.target.value))}>
            <option value="failover">Резервирование</option>
            <option value="balance">Балансировка по весам</option>
          </select>
        </Field>
        <Field label="Соединения" hint="TCP и соединения с подменой адреса (NAT) всегда сохраняют аплинк, чтобы не терять пакеты">
          <Switch
            checked={config.multiwan?.sticky_connections !== false}
            label="Закреплять до завершения"
            onChange={(sticky) => patch((draft) => {
              draft.multiwan = draft.multiwan || { enabled: false, mode: "failover", sticky_connections: true };
              draft.multiwan.sticky_connections = sticky;
            })}
          />
        </Field>
      </div>
    </Card>
    <Card
      tight
      title="Подключение к интернету"
      subtitle="Как роутер выходит наружу"
      actions={
        <button
          className="btn sm"
          onClick={() => {
            const id = newID("wan");
            openOnCreate(id);
            patch((d) => {
              d.wans = d.wans || [];
              d.wans.push({
                id,
                index: Math.max(0, ...d.wans.map((wan: any) => wan.index || 0)) + 1,
                name: "Аплинк " + (d.wans.length + 1),
                interface: d.interfaces?.[0]?.id || "",
                enabled: false,
                proto: "dhcp",
                metric: 100 + d.wans.length,
                weight: 1,
                probe: { enabled: true, type: "icmp", targets: ["1.1.1.1", "8.8.8.8"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
              });
            });
          }}
        >
          Добавить
        </button>
      }
    >
      {wans.length === 0 ? (
        <Empty>Подключение не настроено</Empty>
      ) : (
        <Rows cols={["Подключение", "Порт", "Адрес", "Тип", "Состояние"]} toggle="Включено">
          {wans.map((w, idx) => (
            <Row
              key={w.id}
              id={w.id}
              icon="globe"
              className="subcard"
              cells={[
                <strong>{w.name}</strong>,
                <span className="mono">{ifaceName(config, w.interface)}</span>,
                <span className="mono">{liveWANs[w.id]?.address || w.address || "—"}</span>,
                WAN_PROTO[w.proto] || w.proto,
                w.enabled && liveWANs[w.id]
                  ? <Badge tone={liveWANs[w.id].up ? "ok" : "warn"}>{liveWANs[w.id].probe_down ? "проба не прошла" : liveWANs[w.id].up ? "на связи" : "нет связи"}</Badge>
                  : <Badge tone="neutral">{w.enabled ? "включено" : "выключено"}</Badge>,
              ]}
              toggle={<Switch checked={w.enabled} label="" ariaLabel={w.name} onChange={(v) => patch((d) => (d.wans[idx].enabled = v))} />}
            >
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
                      {!w.interface && <option value="">не выбран</option>}
                      {ifaceOptions(config, w.interface).map((i: any) => (
                        <option key={i.id} value={i.id}>
                          {i.label ? `${i.label} (${i.name})` : i.name}
                          {usageOf(config, i) ? " — " + usageOf(config, i) : ""}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>
                <Field label="NAT аплинка" hint="Нужен, если вышестоящая сеть не знает маршруты к вашим клиентам.">
                  <Switch label="Подменять адреса клиентов (NAT)" checked={wanNAT(config,w).enabled}
                    disabled={!wanNAT(config,w).iface || wanNAT(config,w).manual}
                    onChange={enabled => patch(d => setWanNAT(d,d.wans[idx],enabled))} />
                  {wanNAT(config,w).manual && <SectionLink className="hint" section="firewall">Маскарад задан ручным правилом — изменить в защите сети</SectionLink>}
                </Field>
                {config.multiwan?.enabled && (
                  <div className="form-grid">
                    <Field label="Проверка доступности">
                      <select value={w.probe?.type || "icmp"} onChange={(e) => patch((d) => {
                        d.wans[idx].probe = d.wans[idx].probe || {};
                        d.wans[idx].probe.type = e.target.value;
                        d.wans[idx].probe.enabled = true;
                      })}>
                        <option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option>
                      </select>
                    </Field>
                    <Field label="Цели" hint="Через запятую: IP, host:port или URL">
                      <input className="mono" value={(w.probe?.targets || []).join(", ")} onChange={(e) => patch((d) => {
                        d.wans[idx].probe = d.wans[idx].probe || {};
                        d.wans[idx].probe.targets = e.target.value.split(",").map((v) => v.trim()).filter(Boolean);
                      })} />
                    </Field>
                    {w.probe?.type === "tcp" && <>
                      <Field label="Запрос TCP" hint="Текст, отправляемый удалённой службе"><textarea className="mono" value={w.probe?.tcp_request || ""} onChange={(e) => patch((d) => (d.wans[idx].probe.tcp_request = e.target.value))} /></Field>
                      <Field label="Начало ответа TCP" hint="Точное начало ожидаемого ответа"><textarea className="mono" value={w.probe?.tcp_response || ""} onChange={(e) => patch((d) => (d.wans[idx].probe.tcp_response = e.target.value))} /></Field>
                    </>}
                    <Field label="Интервал, сек"><input type="number" min={1} max={3600} value={w.probe?.interval || 10} onChange={(e) => patch((d) => (d.wans[idx].probe.interval = Number(e.target.value)))} /></Field>
                    <Field label="Таймаут, сек"><input type="number" min={1} max={60} value={w.probe?.timeout || 3} onChange={(e) => patch((d) => (d.wans[idx].probe.timeout = Number(e.target.value)))} /></Field>
                    <Field label="Ошибок до переключения"><input type="number" min={1} max={100} value={w.probe?.fail_threshold || 3} onChange={(e) => patch((d) => (d.wans[idx].probe.fail_threshold = Number(e.target.value)))} /></Field>
                    <Field label="Успехов до возврата"><input type="number" min={1} max={100} value={w.probe?.rise_threshold || 2} onChange={(e) => patch((d) => (d.wans[idx].probe.rise_threshold = Number(e.target.value)))} /></Field>
                  </div>
                )}

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
                        {...secretInput(w, "password")} value={w.password || ""}
                        onChange={(e) => patch((d) => (d.wans[idx].password = e.target.value))}
                      />
                    </Field>
                    {w.proto === "pppoe" && (
                      <>
                        <Field label="Имя услуги" hint="PPPoE Service-Name; обычно оставляют пустым">
                          <input
                            type="text"
                            value={w.service || ""}
                            onChange={(e) => patch((d) => (d.wans[idx].service = e.target.value))}
                          />
                        </Field>
                        <Field
                          label="Имя концентратора"
                          hint="PPPoE Access Concentrator (AC); заполняйте только если это требует провайдер"
                        >
                          <input
                            type="text"
                            value={w.ac || ""}
                            onChange={(e) => patch((d) => (d.wans[idx].ac = e.target.value))}
                          />
                        </Field>
                      </>
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
                  {config.multiwan?.mode === "balance" && (
                    <Field label="Вес" hint="Доля новых соединений">
                      <input type="number" min={1} max={1000} value={w.weight || 1} onChange={(e) => patch((d) => (d.wans[idx].weight = Number(e.target.value)))} />
                    </Field>
                  )}
                </div>
                {wans.length > 1 && (
                  <div className="row-actions">
                    <button className="btn ghost sm to-right" onClick={() => patch((d) => (d.wans = d.wans.filter((x: any) => x.id !== w.id)))}>
                      Удалить
                    </button>
                  </div>
                )}
            </Row>
          ))}
        </Rows>
      )}
    </Card>
    </>
  );
}

// ---------------------------------------------------------------------------

function SegmentSection({ config, patch }: { config: any; patch: Patch }) {
  const networks: any[] = config.networks || [];
  const channels: any[] = config.channels || [];

  return (
    <Card
      tight
      title="Локальные сегменты"
      subtitle="Подсети, которые обслуживает роутер"
      actions={
        <button
          className="btn sm"
          disabled={(config.interfaces || []).length === 0}
          onClick={() => {
            const id = newID("net");
            openOnCreate(id);
            patch((d) => {
              d.networks = d.networks || [];
              const n = d.networks.length + 1;
              d.networks.push({
                id,
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
            });
          }}
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
        <Rows cols={["Сегмент", "Интерфейс", "Адрес и сеть", "DHCP", "Состояние"]} toggle="Включён">
          {networks.map((n, idx) => (
            <Row
              key={n.id}
              id={n.id}
              icon="network"
              className="subcard"
              cells={[
                <strong>{n.name}</strong>,
                <span className="mono">{ifaceName(config, n.interface)}</span>,
                <span className="mono">{n.router_address || "—"}</span>,
                <span className="dim">{n.dhcp_pool?.enabled ? "выдаёт адреса" : "выключен"}</span>,
                <Badge tone={n.enabled ? "ok" : "neutral"}>{n.enabled ? "обслуживается" : "не обслуживается"}</Badge>,
              ]}
              toggle={<Switch checked={n.enabled} label="" ariaLabel={`${n.name} ${n.enabled ? "обслуживается" : "не обслуживается"}`} onChange={(v) => patch((d) => (d.networks[idx].enabled = v))} />}
            >
              {!n.enabled && (
                  <Notice tone="info" title="Сегмент выключен">
                    Адрес с интерфейса снимется, DHCP в этом сегменте работать не будет.
                    Сам интерфейс останется — его состояние настраивается ниже, в списке
                    портов.
                  </Notice>
              )}

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
                  <Field
                    label="Порт или мост"
                    hint="Порт, отданный мосту, здесь не появится: адрес принадлежит самому мосту"
                  >
                    <select
                      value={n.interface}
                      onChange={(e) => patch((d) => (d.networks[idx].interface = e.target.value))}
                    >
                      {!n.interface && <option value="">не выбран</option>}
                      {ifaceOptions(config, n.interface).map((i: any) => (
                        <option key={i.id} value={i.id}>
                          {i.label ? `${i.label} (${i.name})` : i.name}
                          {usageOf(config, i) ? " — " + usageOf(config, i) : ""}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field
                    label="Канал выхода"
                    hint="Выход в интернет по умолчанию для этого сегмента. Политики и отдельные настройки клиентов имеют приоритет."
                  >
                    <select
                      value={n.default_channel || "direct"}
                      onChange={(e) => patch((d) => (d.networks[idx].default_channel = e.target.value))}
                    >
                      <option value="direct">Напрямую</option>
                      {channels.filter((c) => c.id !== "direct" && (c.enabled || c.id === n.default_channel)).map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.name || c.id}{!c.enabled ? " — выключен" : ""}
                        </option>
                      ))}
                      {n.default_channel && n.default_channel !== "direct" && !channels.some((c) => c.id === n.default_channel) && (
                        <option value={n.default_channel}>{n.default_channel} — недоступен</option>
                      )}
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
                    label="Изолировать от других локальных и VPN-сетей"
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
                          min={1}
                          max={31536000}
                          value={n.dhcp_pool.lease_time}
                          onChange={(e) =>
                            patch(
                              (d) =>
                                (d.networks[idx].dhcp_pool.lease_time = Number(e.target.value)),
                            )
                          }
                        />
                      </Field>
                      <Field label="Шлюз для клиентов" hint="Пусто — адрес роутера в сегменте">
                        <input
                          type="text"
                          className="mono"
                          value={n.dhcp_pool.gateway || ""}
                          onChange={(e) => patch((d) => (d.networks[idx].dhcp_pool.gateway = e.target.value))}
                        />
                      </Field>
                      <Field label="DHCP-домен">
                        <input
                          type="text"
                          value={n.dhcp_pool.domain || ""}
                          onChange={(e) => patch((d) => (d.networks[idx].dhcp_pool.domain = e.target.value))}
                        />
                      </Field>
                      <Field label="DNS для клиентов" hint="По одному IPv4-адресу в строке; пусто — роутер">
                        <textarea
                          className="mono"
                          value={(n.dhcp_pool.dns_servers || []).join("\n")}
                          onChange={(e) => patch((d) => (d.networks[idx].dhcp_pool.dns_servers = e.target.value.split(/\s+/).filter(Boolean)))}
                        />
                      </Field>
                    </div>
                    <Field label="Дополнительные DHCP-опции" hint="По одной в строке: номер=значение (например, 66=pxe.lan)">
                      <textarea
                        className="mono"
                        value={Object.entries(n.dhcp_pool.options || {}).map(([key, value]) => `${key}=${value}`).join("\n")}
                        onChange={(e) => patch((d) => {
                          const options: Record<string, string> = {};
                          for (const line of e.target.value.split("\n")) {
                            const pos = line.indexOf("=");
                            if (pos > 0) options[line.slice(0, pos).trim()] = line.slice(pos + 1).trim();
                          }
                          d.networks[idx].dhcp_pool.options = options;
                        })}
                      />
                    </Field>
                  </>
                )}
              
                <div className="row-actions">
                  <button className="btn ghost sm to-right" onClick={() => patch((d) => (d.networks = d.networks.filter((x: any) => x.id !== n.id)))}>
                    Удалить
                  </button>
                </div>
            </Row>
          ))}
        </Rows>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------

function InterfaceSection({ config, patch }: { config: any; patch: Patch }) {
  const interfaces: any[] = config.interfaces || [];
  const [liveInterfaces, setLiveInterfaces] = useState<any[]>([]);
  const [scanError, setScanError] = useState("");

  const refreshPorts = () => {
    setScanError("");
    api.interfaces()
      .then((result) => setLiveInterfaces(result.interfaces || []))
      .catch(() => setScanError("Не удалось прочитать сетевые порты машины"));
  };

  useEffect(() => {
    refreshPorts();
  }, []);

  const configuredNames = new Set(interfaces.map((i: any) => i.name));
  const discovered = liveInterfaces.filter(
    (i: any) => i.physical && !configuredNames.has(i.name),
  );

  return (
    <Card
      title="Порты, агрегации, мосты и VLAN"
      subtitle="Физические сетевые карты и построенные поверх них интерфейсы"
      tight
      actions={
        <div className="row" style={{ gap: "0.4rem" }}>
          <button className="btn ghost sm" onClick={refreshPorts}>
            Обновить порты
          </button>
          <AddMenu
            label="Добавить"
            items={[
              { label: "Мост", ariaLabel: "Добавить мост", icon: "merge", onSelect: () => patch((d) => {
                d.interfaces = d.interfaces || [];
                d.interfaces.push({
                  id: openOnCreate(newID("br")),
                  name: freeName(d.interfaces, "br"),
                  type: "bridge",
                  members: [],
                  enabled: true,
                });
              }) },
              { label: "Агрегация", ariaLabel: "Добавить агрегацию", icon: "combine", onSelect: () => patch((d) => {
                d.interfaces = d.interfaces || [];
                d.interfaces.push({
                  id: openOnCreate(newID("bond")),
                  name: freeName(d.interfaces, "bond"),
                  type: "bond",
                  members: [],
                  enabled: true,
                });
              }) },
              {
                label: "VLAN",
                ariaLabel: "Добавить VLAN",
                icon: "layers",
                // Нет интерфейса, над которым можно поднять VLAN: все порты отданы мостам или агрегациям.
                disabled: vlanParents(config).length === 0,
                note: vlanParents(config).length === 0 ? "все порты заняты мостами" : undefined,
                onSelect: () => patch((d) => {
                d.interfaces = d.interfaces || [];
                const parent = vlanParents(d)[0];
                if (!parent) return;
                const vid = freeVlanID(d, parent.id);
                d.interfaces.push({
                  id: openOnCreate(newID("vl")),
                  name: vlanName(parent.name, vid),
                  type: "vlan",
                  parent: parent.id,
                  vlan_id: vid,
                  enabled: true,
                });
              }),
              },
            ]}
          />
        </div>
      }
    >
      <Rows cols={["Имя", "Тип", "Используется", "MAC", "Состояние"]} toggle="Включён">
          {discovered.map((i: any) => (
            <Row
              key={`discovered-${i.name}`}
              icon="ethernet-port"
              cells={[
                <span><strong>{i.label || i.name}</strong>{i.label && <div className="mono faint">{i.name}</div>}</span>,
                <Badge tone="accent">новый порт</Badge>,
                <span className="dim">не настроен</span>,
                <span className="mono dim">{i.mac || "—"}</span>,
                <Badge tone={i.up ? "ok" : "neutral"}>{<span title={linkSpeed(i)}>{linkSpeed(i,true) || (i.up ? "Линк есть" : "Нет линка")}</span>}</Badge>,
              ]}
              toggle={<button
                    className="btn sm"
                    onClick={() => patch((d) => {
                      d.interfaces = d.interfaces || [];
                      if (d.interfaces.some((item: any) => item.name === i.name)) return;
                      d.interfaces.push({
                        id: openOnCreate(newID("if")),
                        name: i.name,
                        type: "physical",
                        enabled: true,
                      });
                    })}
                  >
                    Настроить
                  </button>}
            />
          ))}
          {interfaces.map((i: any, idx: number) => (
            <Row
              key={i.id}
              id={i.id}
              icon={INTERFACE_ICONS[i.type] || "ethernet-port"}
              cells={[
                <span><strong>{i.label || i.name}</strong>{i.label && <div className="mono faint">{i.name}</div>}</span>,
                <Badge tone="neutral">{typeLabel(i.type)}</Badge>,
                <span className="dim">{usageOf(config, i) || "свободен"}</span>,
                <span className="mono">{i.mac || liveInterfaces.find((live: any) => live.name === i.name)?.mac || "—"}</span>,
                (() => { const live = liveInterfaces.find((l:any)=>l.name===i.name); return live ? <Badge tone={live.up?"ok":"neutral"}>{live.admin_up===false?"Отключён":live.up?(<span title={linkSpeed(live)}>{linkSpeed(live,true) || "Линк есть"}</span>):"Включён, нет линка"}</Badge> : <Badge tone="neutral">Нет в ОС</Badge>; })(),
              ]}
              toggle={<Switch
                    checked={i.enabled}
                    label=""
                    ariaLabel={`Интерфейс ${i.name || idx + 1} включён`}
                    onChange={async (v) => {
                      if (!v) {
                        const usage = usageOf(config, i);
                        const children = interfaces.filter((child:any)=>child.parent===i.id).map((child:any)=>child.name);
                        const detail = [usage, children.length?`VLAN: ${children.join(", ")}`:""].filter(Boolean).join("; ");
                        if (!(await confirmAction(`Отключить интерфейс ${i.name}? ${detail?`Используется: ${detail}. `:""}Передача через него и зависимые подключения прекратится. Настройки сохранятся. Если доступ к панели пропадёт, не подтверждайте применение — прежняя конфигурация восстановится автоматически.`, "Отключить интерфейс"))) return;
                      }
                      patch((d) => (d.interfaces[idx].enabled = v));
                    }}
                  />}
            >
              <div className="form-grid">
                {i.type !== "physical" && <Cap label="Имя"><input
                      type="text"
                      className="mono"
                      value={i.name}
                      onChange={(e) =>
                        patch((d) => {
                          // Связи идут по идентификатору, поэтому переименование
                          // ничего не рвёт. Имена дочерних VLAN, которые их ещё
                          // не переопределяли, идут следом за родителем.
                          d.interfaces[idx].name = e.target.value;
                          renameVLANChildren(d, i.id, i.name, e.target.value);
                        })
                      }
                    /></Cap>}
                {i.type !== "physical" && <Cap label={i.type === "vlan" ? "Номер и родитель" : "Состав"} wide><div className="mono">{i.type === "vlan" ? (
                    <VLANPicker config={config} patch={patch} index={idx} iface={i} />
                  ) : i.type === "bridge" || i.type === "bond" ? (
                    <MemberPicker config={config} patch={patch} index={idx} iface={i} />
                  ) : (
                    "—"
                  )}</div></Cap>}
                <Cap label="Имя для отображения"><input value={i.label || ""} maxLength={64} aria-label={`Имя порта ${i.name}`} placeholder="Например, Кабинет" onChange={e=>patch(d=>{d.interfaces[idx].label=e.target.value})}/></Cap>
                <Cap label="MAC-адрес"><input
                    type="text"
                    className="mono"
                    aria-label={`MAC интерфейса ${i.name}`}
                    placeholder={liveInterfaces.find((live: any) => live.name === i.name)?.mac || "не менять"}
                    title="Пусто — оставить заводской адрес"
                    value={i.mac || ""}
                    onChange={(e) => patch((d) => (d.interfaces[idx].mac = e.target.value.trim()))}
                  /></Cap>
                <Cap label="MTU"><input
                    type="number"
                    aria-label={`MTU интерфейса ${i.name}`}
                    placeholder={String(liveInterfaces.find((live: any) => live.name === i.name)?.mtu || "")}
                    title="Пусто — не менять"
                    value={i.mtu || ""}
                    onChange={(e) => patch((d) => (d.interfaces[idx].mtu = Number(e.target.value)))}
                  /></Cap>
              </div>
              {i.type==="physical" && <PortLinkSettings iface={i} onChange={v=>patch(d=>{d.interfaces[idx].link_mode=v})}/>}
              <div className="row-actions end">{i.type !== "physical" && (
                    <button
                      className="btn ghost sm"
                      disabled={isInterfaceReferenced(config, i.id)}
                      title={isInterfaceReferenced(config, i.id) ? "Интерфейс или его VLAN используется в маршрутизации, правилах защиты или NAT" : undefined}
                      onClick={() => patch((d) => removeInterface(d, i.id))}
                    >
                      Удалить
                    </button>
                  )}</div>
            </Row>
          ))}
        </Rows>
      {scanError && <div className="rows-notes"><Notice tone="warn" title="Список портов недоступен">{scanError}</Notice></div>}
      <div className="rows-foot faint" style={{ fontSize: 12.5 }}>
        Порт входит только в один мост. У подчинённого порта нет своего адреса:
        сегмент и подключение к провайдеру назначаются самому мосту.
      </div>
    </Card>
  );
}

// VLANPicker выбирает родителя и номер. Родителем может быть только тот
// интерфейс, чей трафик действительно дойдёт до VLAN: свободный порт, мост или
// агрегация. Порт, отданный мосту, отдаёт туда всё, включая тегированное.
function VLANPicker({
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
  const parents = vlanParents(config, iface.id);
  const current = byID(config, iface.parent);
  const orphan = iface.parent && !current;

  return (
    <span className="row wrap" style={{ gap: "0.3rem" }}>
      <select
        value={iface.parent || ""}
        onChange={(e) => patch((d) => setVLANParent(d, index, e.target.value))}
      >
        {!iface.parent && <option value="">не выбран</option>}
        {orphan && <option value={iface.parent}>интерфейс удалён</option>}
        {current && !parents.some((p: any) => p.id === current.id) && (
          <option value={current.id}>{interfaceDisplay(config, current.name)} (занят)</option>
        )}
        {parents.map((x: any) => (
          <option key={x.id} value={x.id}>
            {interfaceDisplay(config, x.name)}
          </option>
        ))}
      </select>
      <input
        type="number"
        style={{ width: 80 }}
        min={1}
        max={4094}
        value={iface.vlan_id || 0}
        onChange={(e) => patch((d) => setVLANID(d, index, Number(e.target.value)))}
      />
    </span>
  );
}

// MemberPicker показывает, какие порты входят в мост, и позволяет их менять.
// Занятые в другом мосту и отданные под аплинк показаны, но выбрать их нельзя:
// объяснение рядом честнее исчезнувшей строки.
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
  const members: string[] = iface.members || [];
  const candidates = (config.interfaces || []).filter(
    (x: any) =>
      x.id !== iface.id &&
      (x.type === "physical" ||
        x.type === "vlan" ||
        (iface.type === "bridge" && x.type === "bond")) &&
      // VLAN, поднятый над этим же мостом, включать в него нельзя: вышло бы
      // кольцо из интерфейса в самого себя.
      x.parent !== iface.id,
  );

  return (
    <div className="row wrap" style={{ gap: "0.5rem" }}>
      {candidates.length === 0 && <span className="faint">нет портов</span>}
      {candidates.map((c: any) => {
        const mine = members.includes(c.id);
        const blocker = mine ? "" : whyUnavailable(config, c, iface);
        return (
          <label
            key={c.id}
            className="row"
            style={{ gap: "0.25rem", cursor: blocker ? "not-allowed" : "pointer" }}
            title={blocker || undefined}
          >
            <input
              type="checkbox"
              checked={mine}
              disabled={!!blocker}
              onChange={(e) =>
                patch((d) => {
                  const list: string[] = d.interfaces[index].members || [];
                  d.interfaces[index].members = e.target.checked
                    ? [...list, c.id]
                    : list.filter((m) => m !== c.id);
                })
              }
            />
            <span className="mono" style={blocker ? { opacity: 0.45 } : undefined}>
              {interfaceDisplay(config, c.name)}
            </span>
            {blocker && (
              <span className="faint" style={{ fontSize: 11.5 }}>
                ({blocker})
              </span>
            )}
          </label>
        );
      })}
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
  const iface=(config.interfaces || []).find((i: any) => i.id === id);
  return iface ? iface.label ? `${iface.label} (${iface.name})` : iface.name : "не выбран";
}

function hasComponent(config: any, id: string): boolean {
  return (config.components || []).some((c: any) => c.id === id && c.installed);
}

const WAN_PROTO: Record<string, string> = { dhcp: "Автоматически", static: "Фиксированный адрес", pppoe: "PPPoE", l2tp: "L2TP" };

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

// ---------------------------------------------------------------------------
// Связи между интерфейсами
//
// Ссылки хранятся идентификаторами, а не именами: имя администратор меняет, и
// связь по имени пережила бы переименование только на бумаге. Правила ниже —
// те же, что проверяет сервер: порт входит ровно в один мост, у подчинённого
// порта нет своего адреса, VLAN поднимается только над тем, чей трафик до него
// дойдёт. Панель не даёт натыкать невозможное, а не молчит и не чинит потом.
// ---------------------------------------------------------------------------

const MAX_IFACE_NAME = 15;

function byID(config: any, id: string): any {
  if (!id) return undefined;
  return (config.interfaces || []).find((i: any) => i.id === id);
}

// masterOf — мост или агрегация, которой отдан порт.
function masterOf(config: any, id: string): any {
  return (config.interfaces || []).find(
    (i: any) =>
      (i.type === "bridge" || i.type === "bond") && (i.members || []).includes(id),
  );
}

// usageOf объясняет одной строкой, кем интерфейс занят. Без этого непонятно,
// почему порт нельзя выбрать, и почему настройка не даёт ожидаемого результата.
function usageOf(config: any, iface: any): string {
  const parts: string[] = [];
  const master = masterOf(config, iface.id);
  if (master) parts.push((master.type === "bond" ? "в агрегации " : "в мосту ") + master.name);
  const wan = (config.wans || []).find((w: any) => w.interface === iface.id);
  if (wan) parts.push("аплинк «" + wan.name + "»");
  const net = (config.networks || []).find((n: any) => n.interface === iface.id);
  if (net) parts.push("сегмент «" + net.name + "»");
  const vlans = (config.interfaces || []).filter(
    (i: any) => i.type === "vlan" && i.parent === iface.id,
  );
  if (vlans.length > 0) parts.push("VLAN " + vlans.map((v: any) => v.name).join(", "));
  return parts.join(", ");
}

// whyUnavailable объясняет, почему порт нельзя включить в этот мост.
function whyUnavailable(config: any, candidate: any, target: any): string {
  const master = masterOf(config, candidate.id);
  if (master && master.id !== target.id) return "уже в " + master.name;
  const wan = (config.wans || []).find((w: any) => w.interface === candidate.id);
  if (wan) return "занят аплинком";
  const net = (config.networks || []).find((n: any) => n.interface === candidate.id);
  if (net) return "занят сегментом «" + net.name + "»";
  return "";
}

// vlanParents — интерфейсы, над которыми VLAN действительно заработает.
// Подчинённый мосту порт отдаёт туда весь трафик, включая тегированный, и
// VLAN над ним остался бы пустым. VLAN поверх VLAN netOS не настраивает.
function vlanParents(config: any, exceptID?: string): any[] {
  return (config.interfaces || []).filter(
    (i: any) =>
      i.id !== exceptID && i.type !== "vlan" && !masterOf(config, i.id),
  );
}

// vlanName строит имя так, как его принято записывать в Linux: имя родителя,
// точка, номер. Длину режем сами: ядро обрежет молча, а на имя ссылаются зоны
// файрволла.
function vlanName(parentName: string, vlanID: number): string {
  const suffix = "." + vlanID;
  const keep = Math.max(1, MAX_IFACE_NAME - suffix.length);
  return parentName.slice(0, keep) + suffix;
}

// freeVlanID подбирает номер, не занятый на этом же родителе: два интерфейса с
// одним номером на одном родителе ядро не создаст.
function freeVlanID(config: any, parentID: string): number {
  const taken = new Set(
    (config.interfaces || [])
      .filter((i: any) => i.type === "vlan" && i.parent === parentID)
      .map((i: any) => i.vlan_id),
  );
  let id = 100;
  while (taken.has(id) && id < 4095) id++;
  return id;
}

function freeName(interfaces: any[], prefix: string): string {
  const taken = new Set(interfaces.map((i: any) => i.name));
  let n = 1;
  while (taken.has(prefix + n)) n++;
  return prefix + n;
}

function assignMissingWANIndexes(wans: any[]) {
  const used = new Set<number>(wans.map((wan: any) => Number(wan.index)).filter((index: number) => index > 0));
  let candidate = 1;
  for (const wan of wans) {
    if (Number(wan.index) > 0) continue;
    while (used.has(candidate)) candidate++;
    wan.index = candidate;
    used.add(candidate);
  }
}

// setVLANParent и setVLANID меняют связь и подтягивают имя, если его не
// переопределяли вручную: иначе в таблице остаётся eth0.100 на другом порту и
// с другим номером.
function setVLANParent(draft: any, index: number, parentID: string) {
  const iface = draft.interfaces[index];
  const before = byID(draft, iface.parent);
  const after = byID(draft, parentID);
  const wasDefault = !before || iface.name === vlanName(before.name, iface.vlan_id);
  iface.parent = parentID;
  if (wasDefault && after) iface.name = vlanName(after.name, iface.vlan_id);
}

function setVLANID(draft: any, index: number, vlanID: number) {
  const iface = draft.interfaces[index];
  const parent = byID(draft, iface.parent);
  const wasDefault = parent && iface.name === vlanName(parent.name, iface.vlan_id);
  iface.vlan_id = vlanID;
  if (wasDefault) iface.name = vlanName(parent.name, vlanID);
}

// renameVLANChildren тянет за родителем имена дочерних VLAN, пока они
// стандартные: администратор переименовал порт, а eth0.100 на нём остался бы.
function renameVLANChildren(draft: any, parentID: string, oldName: string, newName: string) {
  for (const child of draft.interfaces || []) {
    if (child.type === "vlan" && child.parent === parentID) {
      if (child.name === vlanName(oldName, child.vlan_id)) {
        child.name = vlanName(newName, child.vlan_id);
      }
    }
  }
}

function isInterfaceReferenced(config: any, id: string): boolean {
  // Removing a parent also removes its VLANs. Include references to those
  // names, even in disabled rules, so saved settings remain usable.
  const removed = new Set([id]);
  const interfaces: any[] = config.interfaces || [];
  let previousSize = 0;
  while (previousSize !== removed.size) {
    previousSize = removed.size;
    for (const iface of interfaces) {
      if (iface.type === "vlan" && removed.has(iface.parent)) removed.add(iface.id);
    }
  }
  const names = new Set(interfaces.filter((iface) => removed.has(iface.id)).map((iface) => iface.name));
  return [
    ...(config.routing?.static || []),
    ...(config.routing?.rules || []),
    ...(config.firewall?.rules || []),
    ...(config.firewall?.nat || []),
  ].some((rule: any) => rule.interface && names.has(rule.interface));
}

// Remove dependent topology only when no route or firewall rule needs it.
function removeInterface(draft: any, id: string) {
  if (isInterfaceReferenced(draft, id)) return;
  draft.interfaces = (draft.interfaces || []).filter((i: any) => i.id !== id);
  // VLAN живёт только вместе с родителем: без него настраивать нечего.
  const orphans = (draft.interfaces || []).filter(
    (i: any) => i.type === "vlan" && i.parent === id,
  );
  for (const o of orphans) removeInterface(draft, o.id);

  for (const i of draft.interfaces || []) {
    if (i.members) i.members = i.members.filter((m: string) => m !== id);
  }
  draft.networks = (draft.networks || []).filter((n: any) => n.interface !== id);
  draft.wans = (draft.wans || []).filter((w: any) => w.interface !== id);
}

// ifaceOptions — интерфейсы, которым можно назначить адрес: сегмент или
// аплинк. Подчинённый порт своего адреса не имеет, поэтому в список не идёт,
// но уже выбранный показывается, чтобы настройка не подменилась молча.
function ifaceOptions(config: any, selected: string): any[] {
  return (config.interfaces || []).filter(
    (i: any) => i.id === selected || !masterOf(config, i.id),
  );
}
