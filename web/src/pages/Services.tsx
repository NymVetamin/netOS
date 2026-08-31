import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";
import { newID } from "../id";

type Patch = (mutate: (draft: any) => void) => void;

// Возможности резолверов. Панель обязана честно показывать, что умеет
// выбранный демон: узнать, что dnsmasq не поддерживает шифрованный DNS, лучше
// здесь, а не после неудачного применения.
const DNS_CAPS: Record<
  string,
  { dot: boolean; doh: boolean; doq: boolean; filterAAAA: boolean }
> = {
  dnsmasq: { dot: false, doh: false, doq: false, filterAAAA: true },
  // netOS фильтрует AAAA в unbound через respip-теги для loopback и локальных сегментов.
  unbound: { dot: true, doh: false, doq: false, filterAAAA: true },
  dnsproxy: { dot: true, doh: true, doq: true, filterAAAA: true },
};

// Порт, на который уходит dnsmasq, когда 53 занимает другой резолвер.
// Должен совпадать с dnsmasqLocalPort в backend/internal/subsys/services.
const DNSMASQ_LOCAL_PORT = 5354;

export function ServicesPage({ config, patch }: { config: any; patch: Patch }) {
  const dnsProviders = installedProviders(config, ["dnsmasq", "unbound", "dnsproxy"]);
  const dhcpProviders = installedProviders(config, ["dnsmasq", "isc-dhcp-server", "kea"]);

  return (
    <>
      <div className="page-head">
        <h1>Адреса и DNS</h1>
        <p>Автоматическая настройка устройств и разрешение доменных имён</p>
      </div>

      <DHCPSection config={config} patch={patch} providers={dhcpProviders} />
      <DNSSection config={config} patch={patch} providers={dnsProviders} />
    </>
  );
}

// ---------------------------------------------------------------------------

function DHCPSection({
  config,
  patch,
  providers,
}: {
  config: any;
  patch: Patch;
  providers: string[];
}) {
  const pools = (config.networks || []).filter((n: any) => n.dhcp_pool?.enabled);

  return (
    <Card title="Выдача адресов" subtitle="DHCP-сервер для локальных сегментов">
      {providers.length === 0 ? (
        <Notice tone="warn" title="Сервер DHCP не установлен">
          Установите dnsmasq, ISC DHCP или Kea в разделе «Компоненты» — после этого его
          можно будет включить здесь.
        </Notice>
      ) : (
        <>
          <div className="row wrap" style={{ gap: "1.5rem", marginBottom: "1rem" }}>
            <Switch
              checked={config.dhcp?.enabled}
              label="DHCP сервер"
              onChange={(v) =>
                patch((d) => {
                  d.dhcp.enabled = v;
                  if (v && !d.dhcp.provider) d.dhcp.provider = providers[0];
                })
              }
            />
          </div>

          {providers.length > 1 && (
            <Field label="Чем раздавать" hint="Выбор из установленных компонентов">
              <select
                value={config.dhcp?.provider || ""}
                onChange={(e) => patch((d) => (d.dhcp.provider = e.target.value))}
              >
                {providers.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </Field>
          )}

          {config.dhcp?.enabled && (
            <div style={{ marginTop: "1rem" }}>
              {pools.length === 0 ? (
                <Notice tone="warn" title="Ни в одном сегменте не включён пул адресов">
                  Пул задаётся для каждого сегмента отдельно в разделе «Интерфейсы и
                  сегменты».
                </Notice>
              ) : (
                <TableWrap>
                  <table>
                    <thead>
                      <tr>
                        <th>Сегмент</th>
                        <th>Пул</th>
                        <th>Аренда</th>
                        <th>Шлюз для клиентов</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pools.map((n: any) => (
                        <tr key={n.id}>
                          <td>{n.name}</td>
                          <td className="mono">
                            {n.dhcp_pool.start} – {n.dhcp_pool.end}
                          </td>
                          <td className="faint">{Math.round(n.dhcp_pool.lease_time / 3600)} ч</td>
                          <td className="mono faint">
                            {n.dhcp_pool.gateway || n.router_address?.split("/")[0]}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </div>
          )}
        </>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------

function DNSSection({
  config,
  patch,
  providers,
}: {
  config: any;
  patch: Patch;
  providers: string[];
}) {
  const provider = config.dns?.provider || "";
  const caps = DNS_CAPS[provider];
  const encrypted = (config.dns?.upstreams || []).filter(
    (u: any) => u.enabled && u.type !== "plain",
  );
  const cantEncrypt = encrypted.length > 0 && caps && !caps.dot;
  const cantFilterAAAA = config.dns?.enabled && caps && !caps.filterAAAA && config.ipv6?.filter_aaaa;

  if (providers.length === 0) {
    return (
      <Card title="Разрешение имён" subtitle="DNS-резолвер">
        <Notice tone="warn" title="Резолвер не установлен">
          Установите dnsmasq, Unbound или dnsproxy в разделе «Компоненты».
          Для шифрованного DNS (DoT, DoH) подойдут последние два.
        </Notice>
      </Card>
    );
  }

  return (
    <>
      <Card title="Разрешение имён" subtitle="DNS-резолвер для клиентов сети">
        <div className="row wrap" style={{ gap: "1.5rem", marginBottom: "1rem" }}>
          <Switch
            checked={config.dns?.enabled}
            label="Резолвер включён"
            onChange={(v) =>
              patch((d) => {
                d.dns.enabled = v;
                if (v && !d.dns.provider) d.dns.provider = providers[0];
              })
            }
          />
          <Switch
            checked={config.dns?.force_local}
            label="Заворачивать запросы клиентов на роутер"
            onChange={(v) => patch((d) => (d.dns.force_local = v))}
          />
        </div>

        {providers.length > 1 && (
          <Field label="Чем резолвить" hint="Выбор из установленных компонентов">
            <select
              value={provider}
              onChange={(e) => patch((d) => (d.dns.provider = e.target.value))}
            >
              {providers.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </Field>
        )}

        {caps && (
          <div className="row wrap" style={{ gap: "0.5rem", marginTop: "0.5rem" }}>
            <Badge tone={caps.dot ? "ok" : "neutral"}>
              DoT {caps.dot ? "поддерживается" : "не поддерживается"}
            </Badge>
            <Badge tone={caps.doh ? "ok" : "neutral"}>
              DoH {caps.doh ? "поддерживается" : "не поддерживается"}
            </Badge>
            <Badge tone={caps.doq ? "ok" : "neutral"}>
              DoQ {caps.doq ? "поддерживается" : "не поддерживается"}
            </Badge>
            <Badge tone={caps.filterAAAA ? "ok" : "neutral"}>
              Фильтр AAAA {caps.filterAAAA ? "поддерживается" : "не поддерживается"}
            </Badge>
          </div>
        )}

        {cantEncrypt && (
          <div style={{ marginTop: "1rem" }}>
            <Notice tone="warn" title="Выбранный резолвер не умеет шифровать запросы">
              Настроено шифрованных апстримов: {encrypted.length}. Установите dnsproxy
              либо оставьте только обычные.
            </Notice>
          </div>
        )}

        {cantFilterAAAA && (
          <div style={{ marginTop: "1rem" }}>
            <Notice tone="warn" title="Выбранный резолвер не фильтрует AAAA">
              В настройках IPv6 фильтр AAAA включён, но unbound вырезать эти записи не
              умеет — клиенты будут их получать. Вырезать AAAA умеют dnsmasq и dnsproxy.
            </Notice>
          </div>
        )}

        <div className="form-grid" style={{ marginTop: "1rem" }}>
          <Field label="Порт">
            <input
              type="number"
              value={config.dns?.port}
              onChange={(e) => patch((d) => (d.dns.port = Number(e.target.value)))}
            />
          </Field>
          <Field label="Размер кэша, записей">
            <input
              type="number"
              value={config.dns?.cache_size}
              onChange={(e) => patch((d) => (d.dns.cache_size = Number(e.target.value)))}
            />
          </Field>
          <Field label="Локальный домен" hint="Суффикс для имён устройств в сети">
            <input
              type="text"
              value={config.dns?.local_domain || ""}
              onChange={(e) => patch((d) => (d.dns.local_domain = e.target.value))}
            />
          </Field>
        </div>

        <div className="row wrap" style={{ marginTop: "0.6rem", gap: "1.5rem" }}>
          <Switch
            checked={config.dns?.rebind_protection}
            label="Защита от DNS rebinding"
            onChange={(v) => patch((d) => (d.dns.rebind_protection = v))}
          />
          <Switch
            checked={config.dns?.query_log}
            label="Журнал запросов"
            onChange={(v) => patch((d) => (d.dns.query_log = v))}
          />
        </div>

        <ResolutionChain config={config} />
      </Card>

      <Card
        title="Вышестоящие резолверы"
        subtitle="Куда роутер обращается за ответами, которых нет в кэше"
        tight
      >
        {(config.dns?.upstreams || []).length === 0 ? (
          <Empty>Апстримы не заданы</Empty>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Адрес</th>
                  <th>Тип</th>
                  <th>Канал</th>
                  <th>Комментарий</th>
                  <th>Вкл.</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {config.dns.upstreams.map((u: any, idx: number) => (
                  <tr key={u.id}>
                    <td>
                      <input
                        type="text"
                        aria-label={`Адрес DNS-сервера ${idx + 1}`}
                        className="mono"
                        style={{ width: 240 }}
                        value={u.address}
                        onChange={(e) =>
                          patch((d) => (d.dns.upstreams[idx].address = e.target.value))
                        }
                      />
                    </td>
                    <td>
                      <select
                        aria-label={`Тип DNS-сервера ${idx + 1}`}
                        value={u.type}
                        onChange={(e) => patch((d) => (d.dns.upstreams[idx].type = e.target.value))}
                      >
                        <option value="plain">открытый</option>
                        <option value="dot">DoT</option>
                        <option value="doh">DoH</option>
                        <option value="doq">DoQ</option>
                      </select>
                    </td>
                    <td>
                      <select aria-label={`Канал DNS-сервера ${idx + 1}`} value={u.channel || "direct"} onChange={(e) => patch((d) => (d.dns.upstreams[idx].channel = e.target.value))}>
                        {(config.channels || []).filter((channel: any) => channel.enabled).map((channel: any) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
                      </select>
                    </td>
                    <td>
                      <input
                        type="text"
                        aria-label={`Комментарий DNS-сервера ${idx + 1}`}
                        value={u.comment || ""}
                        onChange={(e) =>
                          patch((d) => (d.dns.upstreams[idx].comment = e.target.value))
                        }
                      />
                    </td>
                    <td>
                      <Switch
                        checked={u.enabled}
                        label=""
                        ariaLabel={`DNS-сервер ${u.address || idx + 1} включён`}
                        onChange={(v) => patch((d) => (d.dns.upstreams[idx].enabled = v))}
                      />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost sm"
                        disabled={(config.dns?.split_rules || []).some((rule: any) => rule.upstream === u.id)}
                        onClick={() =>
                          patch((d) => {
                            d.dns.upstreams = d.dns.upstreams.filter((x: any) => x.id !== u.id);
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
        <div style={{ padding: "1.1rem", borderTop: "1px solid var(--border)" }}>
          <button
            className="btn"
            onClick={() =>
              patch((d) => {
                d.dns.upstreams = d.dns.upstreams || [];
                d.dns.upstreams.push({
                  id: newID("up"),
                  type: "plain",
                  address: "",
                  channel: "direct",
                  enabled: true,
                });
              })
            }
          >
            Добавить апстрим
          </button>
        </div>
      </Card>

      <Card title="Split-DNS" subtitle="Отдельные домены — через отдельный DNS-сервер и, при необходимости, VPN-канал" tight>
        {(config.dns?.split_rules || []).length === 0 ? <Empty>Раздельных правил DNS нет</Empty> : (
          <TableWrap>
            <table>
              <thead><tr><th>Домены</th><th>Апстрим</th><th>Канал</th><th>Вкл.</th><th /></tr></thead>
              <tbody>
                {config.dns.split_rules.map((rule: any, idx: number) => (
                  <tr key={rule.id}>
                    <td><textarea aria-label={`Домены правила Split-DNS ${idx + 1}`} className="mono" value={(rule.domains || []).join("\n")} onChange={(e) => patch((d) => (d.dns.split_rules[idx].domains = e.target.value.split(/\s+/).filter(Boolean)))} /></td>
                    <td><select aria-label={`DNS-сервер правила Split-DNS ${idx + 1}`} value={rule.upstream || ""} onChange={(e) => patch((d) => (d.dns.split_rules[idx].upstream = e.target.value))}>
                      <option value="">Выберите сервер</option>
                      {(config.dns?.upstreams || []).filter((up: any) => up.enabled).map((up: any) => <option key={up.id} value={up.id}>{up.comment || up.address}</option>)}
                    </select></td>
                    <td><select aria-label={`Канал правила Split-DNS ${idx + 1}`} value={rule.channel || "direct"} onChange={(e) => patch((d) => (d.dns.split_rules[idx].channel = e.target.value))}>
                      {(config.channels || []).filter((channel: any) => channel.enabled).map((channel: any) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
                    </select></td>
                    <td><Switch checked={!!rule.enabled} label="" ariaLabel={`Правило Split-DNS ${idx + 1} включено`} onChange={(enabled) => patch((d) => (d.dns.split_rules[idx].enabled = enabled))} /></td>
                    <td><button className="btn ghost sm" onClick={() => patch((d) => { d.dns.split_rules = d.dns.split_rules.filter((item: any) => item.id !== rule.id); })}>Убрать</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div style={{ padding: "1.1rem", borderTop: "1px solid var(--border)" }}>
          <button className="btn" onClick={() => patch((d) => {
            d.dns.split_rules = d.dns.split_rules || [];
            d.dns.split_rules.push({ id: newID("split"), domains: [], upstream: "", channel: "direct", enabled: false });
          })}>Добавить правило</button>
        </div>
      </Card>
    </>
  );
}

function installedProviders(config: any, candidates: string[]): string[] {
  const installed = new Set(
    (config.components || []).filter((c: any) => c.installed).map((c: any) => c.id),
  );
  return candidates.filter((c) => installed.has(c));
}

// ResolutionChain показывает получившийся путь запроса явной схемой.
//
// Схема собирается из той же конфигурации, что и конфиги демонов, поэтому она
// не «картинка про то, как обычно бывает», а описание того, что реально
// применится. Главное, что она объясняет: почему при выборе unbound или
// dnsproxy рядом остаётся dnsmasq — имена клиентов знает только тот, кто
// раздал им адреса.
function ResolutionChain({ config }: { config: any }) {
  const provider = config.dns?.provider || "";
  if (!config.dns?.enabled || !provider) return null;

  const localDNS =
    config.dhcp?.enabled && config.dhcp?.provider === "dnsmasq" && provider !== "dnsmasq";
  const upstreams = (config.dns?.upstreams || []).filter((u: any) => u.enabled);
  const localDomain = config.dns?.local_domain || "";

  const step = (title: string, detail: string) => (
    <div key={title} className="chain-step">
      <strong>{title}</strong>
      <span className="faint">{detail}</span>
    </div>
  );

  // Резолвером пользуется и сам роутер: netOS забирает себе /etc/resolv.conf,
  // чтобы у машины не было второго пути к именам мимо шифрования и фильтров.
  // Указать порт в этом файле нечем, поэтому на нестандартном порту роутер
  // остаётся с системным резолвером — и об этом надо сказать, а не умолчать.
  const routerUsesOwn = config.dns?.port === 53;
  const steps = [
    step(
      "Клиенты сети и сам роутер",
      routerUsesOwn
        ? `запрос на ${provider}, порт 53`
        : `клиенты — на ${provider}, порт ${config.dns?.port}; роутер порт указать не может и идёт мимо`,
    ),
  ];
  if (localDNS) {
    steps.push(
      step(
        "dnsmasq",
        `локальные имена${localDomain ? ` в зоне .${localDomain}` : ""} и обратные зоны, 127.0.0.1:${DNSMASQ_LOCAL_PORT}`,
      ),
    );
  }
  steps.push(
    step(
      "Вышестоящие резолверы",
      upstreams.length === 0
        ? provider === "unbound"
          ? "не заданы — unbound рекурсивно опрашивает корневые серверы"
          : "не заданы"
        : upstreams.map((u: any) => `${u.address} (${u.type})`).join(", "),
    ),
  );

  return (
    <div style={{ marginTop: "1.25rem" }}>
      <div className="faint" style={{ marginBottom: "0.5rem" }}>
        Путь запроса
      </div>
      <div className="chain">{steps}</div>
      {localDNS && (
        <div className="faint" style={{ marginTop: "0.5rem", fontSize: "0.85em" }}>
          dnsmasq остаётся поднятым ради DHCP и локальной зоны: имена устройств знает
          только тот, кто раздал им адреса. Наружу он не ходит.
        </div>
      )}
    </div>
  );
}
