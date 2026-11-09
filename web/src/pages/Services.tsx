import { SocksSection } from "./Socks";
import { IPTVSection } from "./IPTV";
import { DDNSSection } from "./DDNS";
import { useContext, useEffect, useState } from "react";
import { HintContext } from "../HintContext";
import { PermissionContext } from "../permissions";
import { Badge, Cap, Card, Empty, Field, NeedComponent, Notice, openOnCreate, Row, Rows, Switch, TableWrap } from "../ui";
import { Icon } from "../icons";
import { newID } from "../id";
import { api, Problem } from "../api";
import { ProblemsFor } from "./Network";
import { DNSUpstreamEditor } from "./DNSUpstreamEditor";
import { matchDNSPreset, presetAddress, presetLabel } from "../dnsPresets";

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

// Службы независимы друг от друга, поэтому показываются по одной: вкладкой.
// Вкладка записывается в адрес (#services?tab=dns), чтобы на службу можно было
// дать ссылку. Все вкладки остаются в документе (hidden), как раньше все
// разделы: их состояние и запросы не перезапускаются при переключении.
const SERVICE_TABS = [
  { id: "dhcp", label: "DHCP", problems: "dhcp" },
  { id: "dns", label: "DNS", problems: "dns" },
  { id: "ddns", label: "DDNS", problems: "ddns" },
  { id: "socks", label: "SOCKS5", problems: "socks" },
  { id: "iptv", label: "IPTV", problems: "iptv" },
] as const;
type ServiceTab = (typeof SERVICE_TABS)[number]["id"];

// Переход из меню ведёт на #services без вкладки — тогда открывается та,
// с которой администратор ушёл, а не каждый раз первая.
let lastTab: ServiceTab = "dhcp";

function tabFromHash(): ServiceTab {
  const tab = new URLSearchParams(window.location.hash.split("?")[1] || "").get("tab");
  lastTab = SERVICE_TABS.find((item) => item.id === tab)?.id || lastTab;
  return lastTab;
}

export function ServicesPage({ config, patch, problems }: { config: any; patch: Patch; problems: Problem[] }) {
  const dnsProviders = installedProviders(config, ["dnsmasq", "unbound", "dnsproxy"]);
  const dhcpProviders = installedProviders(config, ["dnsmasq", "isc-dhcp-server", "kea"]);
  const showHints = useContext(HintContext);
  const [tab, setTab] = useState<ServiceTab>(tabFromHash);
  useEffect(() => {
    const follow = () => setTab(tabFromHash());
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, []);
  const panels: Record<ServiceTab, JSX.Element> = {
    dhcp: <DHCPSection config={config} patch={patch} providers={dhcpProviders} />,
    dns: <DNSSection config={config} patch={patch} providers={dnsProviders} />,
    ddns: <DDNSSection config={config} patch={patch} />,
    socks: <SocksSection config={config} patch={patch} />,
    iptv: <IPTVSection config={config} patch={patch} />,
  };

  return (
    <>
      <div className="page-head">
        <h1><Icon name="server-cog" />Сетевые службы</h1>
        <p>DHCP, DNS, динамические адреса и прокси для клиентов</p>
      </div>

      <div role="tablist" aria-label="Службы" className="row wrap service-tabs">
        {SERVICE_TABS.map((item) => {
          const warned = problems.some((p) => (showHints || p.severity === "error") && p.path.startsWith(item.problems));
          return (
            <a
              key={item.id}
              href={`#services?tab=${item.id}`}
              role="tab"
              id={`service-tab-${item.id}`}
              aria-controls={`service-${item.id}`}
              aria-selected={tab === item.id}
              className={`btn sm ${tab === item.id ? "primary" : ""}`}
            >
              {item.label}
              {warned && <span className="tab-dot" title="Есть предупреждение" />}
            </a>
          );
        })}
      </div>

      {SERVICE_TABS.map((item) => (
        <div key={item.id} role="tabpanel" id={`service-${item.id}`} aria-labelledby={`service-tab-${item.id}`} hidden={tab !== item.id}>
          <ProblemsFor problems={problems} prefixes={[item.problems]} />
          {panels[item.id]}
        </div>
      ))}
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
  // Директивы попадают в конфиг демона, работающего от root: ограниченной
  // учётной записи сервер их не отдаёт и изменить их не даёт.
  const session = useContext(PermissionContext);
  const showDirectives = session?.role !== "limited";

  return (
    <Card title="Выдача адресов" subtitle="DHCP-сервер для локальных сегментов">
      {providers.length === 0 ? (
        <NeedComponent name="dnsmasq, ISC DHCP или Kea" effect="без сервера DHCP устройства не получат адреса автоматически" />
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
                onChange={(e) => patch((d) => {
                  d.dhcp.provider = e.target.value;
                  if (e.target.value === "kea") d.dhcp.advanced_options = "";
                })}
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
              {showDirectives && config.dhcp?.provider !== "kea" && (
                <Field label="Дополнительные директивы DHCP" hint="Вставляются в конфиг выбранного DHCP-сервера; по одной директиве в строке">
                  <textarea
                    className="mono"
                    value={config.dhcp?.advanced_options || ""}
                    onChange={(e) => patch((d) => (d.dhcp.advanced_options = e.target.value))}
                  />
                </Field>
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
  const [blocklistStatus, setBlocklistStatus] = useState<Record<string, { source: string; error?: string }>>({});
  const session = useContext(PermissionContext);
  const showDirectives = session?.role !== "limited";
  const [statusError, setStatusError] = useState("");
  async function refreshBlocklistStatus() {
    try {
      const result = await api.blocklistStatus();
      setBlocklistStatus(result.sources || {});
      setStatusError("");
    } catch (error) {
      setStatusError(error instanceof Error ? error.message : "Не удалось получить статус");
    }
  }
  useEffect(() => { void refreshBlocklistStatus(); }, []);
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
        <NeedComponent name="dnsmasq, Unbound или dnsproxy" effect="без резолвера клиенты не получат имена; для DoT и DoH подходят два последних" />
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
                if (v && !d.dns.provider) {
                  d.dns.provider = providers[0];
                  if (providers[0] === "dnsmasq") d.dns.dnssec = false;
                }
              })
            }
          />
          <Switch
            checked={config.dns?.force_local}
            label="Заворачивать запросы клиентов на роутер"
            onChange={(v) => patch((d) => (d.dns.force_local = v))}
          />
        </div>

        {(providers.length > 1 || (!!provider && !providers.includes(provider))) && (
          <Field label="Чем резолвить" hint="Выбор из установленных компонентов">
            <select
              value={provider}
              onChange={(e) => patch((d) => {
                for (const upstream of d.dns.upstreams || []) {
                  const preset = matchDNSPreset(upstream);
                  if (preset && upstream.type === "dot") upstream.address = presetAddress(preset, upstream.type, e.target.value);
                }
                d.dns.provider = e.target.value;
                if (e.target.value === "dnsmasq") d.dns.dnssec = false;
                if (e.target.value !== "unbound") d.dns.advanced_options = "";
              })}
            >
              <option value="" disabled>
                — выберите резолвер —
              </option>
              {provider && !providers.includes(provider) && (
                <option value={provider} disabled>{provider} — компонент не установлен</option>
              )}
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
            <Notice hint tone="warn" title="Выбранный резолвер не умеет шифровать запросы">
              Настроено шифрованных апстримов: {encrypted.length}. Установите dnsproxy
              либо оставьте только обычные.
            </Notice>
          </div>
        )}

        {cantFilterAAAA && (
          <div style={{ marginTop: "1rem" }}>
            <Notice hint tone="warn" title="Выбранный резолвер не фильтрует AAAA">
              В настройках IPv6 фильтр AAAA включён, но unbound вырезать эти записи не
              умеет — клиенты будут их получать. Вырезать AAAA умеют dnsmasq и dnsproxy.
            </Notice>
          </div>
        )}

        <div className="form-grid" style={{ marginTop: "1rem" }}>
          <Field label="Порт">
            <input
              type="number"
              min={1}
              max={65535}
              value={config.dns?.port}
              onChange={(e) => patch((d) => (d.dns.port = Number(e.target.value)))}
            />
          </Field>
          <Field label="Размер кэша, записей">
            <input
              type="number"
              min={0}
              max={1000000}
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
          {provider !== "dnsmasq" && (
            <Switch
              checked={config.dns?.dnssec}
              label={provider === "dnsproxy" ? "Запрашивать данные DNSSEC" : "Проверять DNSSEC"}
              onChange={(v) => patch((d) => (d.dns.dnssec = v))}
            />
          )}
        </div>

        {provider === "dnsproxy" && config.dns?.dnssec && (
          <Notice hint tone="info" title="Проверка подписей зависит от вышестоящего резолвера">
            dnsproxy запрашивает данные DNSSEC, но сам не проверяет подписи.
            Выберите вышестоящий резолвер с проверкой DNSSEC или Unbound для
            проверки подписей на роутере.
          </Notice>
        )}

        {provider === "dnsproxy" && (
          <Field label="Bootstrap DNS" hint="Для разрешения имён DoH/DoT/DoQ-серверов; по одному IP-адресу в строке">
            <textarea
              className="mono"
              value={(config.dns?.bootstrap || []).join("\n")}
              onChange={(e) => patch((d) => (d.dns.bootstrap = e.target.value.split(/\s+/).filter(Boolean)))}
            />
          </Field>
        )}

        {showDirectives && provider === "unbound" && (
          <details className="more" open={!!config.dns?.advanced_options}>
            <summary>Дополнительные директивы DNS</summary>
            <Field label="Дополнительные директивы DNS" hint="Вставляются в unbound.conf; по одной директиве в строке">
              <textarea
                className="mono"
                value={config.dns?.advanced_options || ""}
                onChange={(e) => patch((d) => (d.dns.advanced_options = e.target.value))}
              />
            </Field>
          </details>
        )}

        <ResolutionChain config={config} />
      </Card>

      <Card
        title="Вышестоящие резолверы"
        subtitle="Куда роутер обращается за ответами, которых нет в кэше"
        tight
        actions={<button
            className="btn sm"
            onClick={() =>
              patch((d) => {
                d.dns.upstreams = d.dns.upstreams || [];
                d.dns.upstreams.push({
                  id: openOnCreate(newID("up")),
                  type: "plain",
                  address: "",
                  channel: "direct",
                  enabled: true,
                });
              })
            }
          >
            Добавить
          </button>}
      >
        {(config.dns?.upstreams || []).length === 0 ? (
          <Empty>Вышестоящих резолверов нет.</Empty>
        ) : (
          <div className="dns-upstream-rows"><Rows cols={["Резолвер", "Тип", "Канал"]}>
          {config.dns.upstreams.map((u: any, idx: number) => (
            <Row
              key={u.id}
              id={u.id}
              cells={[
                <strong className="dns-upstream-name">{matchDNSPreset(u) ? presetLabel(matchDNSPreset(u)!, u.type) : u.address || "—"}</strong>,
                DNS_TYPE[u.type] || u.type,
                (config.channels || []).find((channel: any) => channel.id === (u.channel || "direct"))?.name || "—",
              ]}
              toggle={<Switch
                        checked={u.enabled}
                        label=""
                        ariaLabel={`DNS-сервер ${u.address || idx + 1} включён`}
                        onChange={(v) => patch((d) => (d.dns.upstreams[idx].enabled = v))}
                      />}
            >
              <DNSUpstreamEditor upstream={u} index={idx + 1} provider={provider}
                channels={config.channels || []}
                onChange={values => patch(d => Object.assign(d.dns.upstreams[idx], values))} />
              <div className="row-actions end"><button
                        className="btn ghost sm"
                        disabled={(config.dns?.split_rules || []).some((rule: any) => rule.upstream === u.id)}
                        onClick={() =>
                          patch((d) => {
                            d.dns.upstreams = d.dns.upstreams.filter((x: any) => x.id !== u.id);
                          })
                        }
                      >
                        Убрать
                      </button></div>
            </Row>
          ))}
        </Rows></div>
        )}
      </Card>

      <Card title="Локальные DNS-записи" subtitle="Имена, которые обслуживает роутер" tight
        actions={<button className="btn sm" onClick={() => patch((d) => {
          d.dns.static_records = d.dns.static_records || [];
          d.dns.static_records.push({ id: openOnCreate(newID("dns")), type: "A", name: "", value: "" });
        })}>Добавить</button>}>
        {(config.dns?.static_records || []).length === 0 ? (
          <Empty>Локальных записей нет.</Empty>
        ) : (
          <Rows cols={["Имя", "Тип", "Значение", "", ""]}>
          {config.dns.static_records.map((record: any, idx: number) => (
            <Row
              key={record.id}
              id={record.id}
              cells={[<strong className="mono">{record.name || "—"}</strong>, record.type || "A", <span className="mono">{record.value}</span>]}
            >
              <div className="form-grid">
                <Cap label="Тип"><select aria-label={`Тип DNS-записи ${idx + 1}`} value={record.type || "A"} onChange={(e) => patch((d) => (d.dns.static_records[idx].type = e.target.value))}>
                        {['A', 'CNAME', 'TXT', 'SRV', 'MX'].map((type) => <option key={type} value={type}>{type}</option>)}
                      </select></Cap>
                <Cap label="Имя"><input aria-label={`Имя DNS-записи ${idx + 1}`} className="mono" value={record.name || ""} onChange={(e) => patch((d) => (d.dns.static_records[idx].name = e.target.value))} /></Cap>
                <Cap label="Значение" wide><input aria-label={`Значение DNS-записи ${idx + 1}`} className="mono" value={record.value || ""} onChange={(e) => patch((d) => (d.dns.static_records[idx].value = e.target.value))} /></Cap>
              </div>
              <div className="row-actions end"><button className="btn ghost sm" onClick={() => patch((d) => { d.dns.static_records = d.dns.static_records.filter((item: any) => item.id !== record.id); })}>Убрать</button></div>
            </Row>
          ))}
        </Rows>
        )}
      </Card>

      <Card title="Split-DNS" subtitle="Отдельные домены — через отдельный DNS-сервер и, при необходимости, VPN-канал" tight
        actions={<button className="btn sm" onClick={() => patch((d) => {
          d.dns.split_rules = d.dns.split_rules || [];
          d.dns.split_rules.push({ id: openOnCreate(newID("split")), domains: [], upstream: "", channel: "direct", enabled: false });
        })}>Добавить</button>}>
        {(config.dns?.split_rules || []).length === 0 ? <Empty>Раздельных правил DNS нет.</Empty> : (
          <Rows cols={["Домены", "Резолвер", "Канал", "", "Состояние"]}>
          {config.dns.split_rules.map((rule: any, idx: number) => {
            const upstream = (config.dns?.upstreams || []).find((up: any) => up.id === rule.upstream);
            return (
            <Row
              key={rule.id}
              id={rule.id}
              cells={[
                <strong className="mono">{(rule.domains || [])[0] || "—"}{(rule.domains || []).length > 1 ? ` и ещё ${rule.domains.length - 1}` : ""}</strong>,
                upstream ? upstream.comment || upstream.address : <span className="dim">не выбран</span>,
                (config.channels || []).find((channel: any) => channel.id === (rule.channel || "direct"))?.name || "—",
                "",
                <Badge tone={rule.enabled ? "ok" : "neutral"}>{rule.enabled ? "включено" : "выключено"}</Badge>,
              ]}
              toggle={<Switch checked={!!rule.enabled} label="" ariaLabel={`Правило Split-DNS ${idx + 1} включено`} onChange={(enabled) => patch((d) => (d.dns.split_rules[idx].enabled = enabled))} />}
            >
              <div className="form-grid">
                <Cap label="Домены" wide><textarea aria-label={`Домены правила Split-DNS ${idx + 1}`} className="mono" value={(rule.domains || []).join("\n")} onChange={(e) => patch((d) => (d.dns.split_rules[idx].domains = e.target.value.split(/\s+/).filter(Boolean)))} /></Cap>
                <Cap label="Резолвер"><select aria-label={`DNS-сервер правила Split-DNS ${idx + 1}`} value={rule.upstream || ""} onChange={(e) => patch((d) => (d.dns.split_rules[idx].upstream = e.target.value))}>
                      <option value="">Выберите сервер</option>
                      {(config.dns?.upstreams || []).filter((up: any) => up.enabled).map((up: any) => <option key={up.id} value={up.id}>{up.comment || up.address}</option>)}
                    </select></Cap>
                <Cap label="Канал"><select aria-label={`Канал правила Split-DNS ${idx + 1}`} value={rule.channel || "direct"} onChange={(e) => patch((d) => (d.dns.split_rules[idx].channel = e.target.value))}>
                      {(config.channels || []).filter((channel: any) => channel.enabled).map((channel: any) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
                    </select></Cap>
              </div>
              <div className="row-actions end"><button className="btn ghost sm" onClick={() => patch((d) => { d.dns.split_rules = d.dns.split_rules.filter((item: any) => item.id !== rule.id); })}>Убрать</button></div>
            </Row>
            );
          })}
        </Rows>
        )}
      </Card>

	  <Card title="DNS blocklists" subtitle="Блокировка рекламы и трекеров по внешним спискам доменов" tight
		actions={<>
		  <button className="btn ghost sm" onClick={() => void refreshBlocklistStatus()}>Обновить статусы</button>
		  <button className="btn sm" onClick={() => patch((d) => {
			d.dns.blocklists = d.dns.blocklists || [];
			d.dns.blocklists.push({ id: openOnCreate(newID("blocklist")), name: "", url: "", ca_file: "", enabled: false });
		  })}>Добавить</button>
		</>}>
		{statusError && <div className="rows-notes"><Notice tone="warn" title="Не удалось получить статус списков">{statusError}</Notice></div>}
		{!config.dns?.enabled && (config.dns?.blocklists || []).length > 0 && (
		  <Notice tone="warn" title="DNS выключен">
			Списки можно сохранить, но включить их получится только вместе с DNS-резолвером.
		  </Notice>
		)}
		{(config.dns?.blocklists || []).length === 0 ? <Empty>Списков блокировки нет.</Empty> : (
		  <Rows cols={["Название", "HTTPS URL списка", "", "", "Состояние"]}>
          {config.dns.blocklists.map((list: any, idx: number) => (
            <Row
              key={list.id}
              id={list.id}
              cells={[
                <strong>{list.name || "—"}</strong>,
                <span className="mono wrap-cell" title={list.url}>{list.url || "—"}</span>,
                "",
                "",
                <span title={blocklistStatus[list.url]?.error || ""}><BlocklistState enabled={!!list.enabled} source={blocklistStatus[list.url]?.source} /></span>,
              ]}
              toggle={<Switch checked={!!list.enabled} disabled={!config.dns?.enabled} label="" ariaLabel={`DNS blocklist ${list.name || idx + 1} включён`} onChange={(enabled) => patch((d) => (d.dns.blocklists[idx].enabled = enabled))} />}
            >
              <div className="form-grid">
                <Cap label="Название"><input aria-label={`Название DNS blocklist ${idx + 1}`} value={list.name || ""} onChange={(e) => patch((d) => (d.dns.blocklists[idx].name = e.target.value))} /></Cap>
                <Cap label="HTTPS URL списка" wide><input type="url" aria-label={`URL DNS blocklist ${idx + 1}`} className="mono" placeholder="https://example.org/hosts.txt" value={list.url || ""} onChange={(e) => patch((d) => (d.dns.blocklists[idx].url = e.target.value))} /></Cap>
                <Cap label="CA-файл (необязательно)" wide><input aria-label={`CA-файл DNS blocklist ${idx + 1}`} className="mono" placeholder="/etc/netos/blocklist-ca.pem" value={list.ca_file || ""} onChange={(e) => patch((d) => (d.dns.blocklists[idx].ca_file = e.target.value))} /></Cap>
              </div>
              <div className="row-actions end"><button className="btn ghost sm" onClick={() => patch((d) => { d.dns.blocklists = d.dns.blocklists.filter((item: any) => item.id !== list.id); })}>Убрать</button></div>
            </Row>
          ))}
        </Rows>
		)}
	  </Card>
    </>
  );
}

// Состояние списка блокировки: выключен, загружен, работает из кэша или
// недоступен вовсе. Цвет по общему правилу: зелёный — проверено и работает.
function BlocklistState({ enabled, source }: { enabled: boolean; source?: string }) {
  if (!enabled) return <Badge>выключен</Badge>;
  if (source === "fetched") return <Badge tone="ok">загружен</Badge>;
  if (source === "cache") return <Badge tone="warn">из кэша: источник недоступен</Badge>;
  if (source === "unavailable") return <Badge tone="danger">недоступен, кэша нет</Badge>;
  return <Badge>нет данных</Badge>;
}

const DNS_TYPE: Record<string, string> = { plain: "открытый", dot: "DoT", doh: "DoH", doq: "DoQ" };

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

  const xrayServers = new Set((config.vpn_servers || []).filter((s: any) => s.type === "xray").map((s: any) => s.id));
  const dynamicFrontend = provider !== "dnsmasq" && (
    (config.vpn_servers || []).some((s: any) => s.enabled && s.type === "ocserv") ||
    (config.policies || []).some((p: any) => p.enabled && p.domains?.length && !xrayServers.has(p.vpn_server))
  );
  const localDNS = !dynamicFrontend &&
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
  const port = config.dns?.port;
  const routerUsesOwn = port === 53;
  const steps = [
    step(
      "Клиенты сети и сам роутер",
      routerUsesOwn
        ? `запрос на ${dynamicFrontend ? "dnsmasq" : provider}, порт 53`
        : `клиенты — на ${dynamicFrontend ? "dnsmasq" : provider}, ${port ? `порт ${port}` : "порт не задан"}; роутер порт указать не может и идёт мимо`,
    ),
  ];
  if (dynamicFrontend) {
    steps.push(step(provider, "внешние имена через выбранный резолвер; локальные имена обслуживает dnsmasq"));
  }
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
