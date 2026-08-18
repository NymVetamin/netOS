import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

// Возможности резолверов. Панель обязана честно показывать, что умеет
// выбранный демон: узнать, что dnsmasq не поддерживает шифрованный DNS, лучше
// здесь, а не после неудачного применения.
const DNS_CAPS: Record<string, { dot: boolean; doh: boolean }> = {
  dnsmasq: { dot: false, doh: false },
  unbound: { dot: true, doh: false },
  dnsproxy: { dot: true, doh: true },
  adguardhome: { dot: true, doh: true },
};

export function ServicesPage({ config, patch }: { config: any; patch: Patch }) {
  const dnsProviders = installedProviders(config, ["dnsmasq", "unbound", "dnsproxy", "adguardhome"]);
  const dhcpProviders = installedProviders(config, ["dnsmasq", "isc-dhcp-server", "kea"]);

  return (
    <>
      <div className="page-head">
        <h1>DHCP и DNS</h1>
        <p>Выдача адресов и разрешение имён</p>
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
              label="Раздавать адреса"
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

  if (providers.length === 0) {
    return (
      <Card title="Разрешение имён" subtitle="DNS-резолвер">
        <Notice tone="warn" title="Резолвер не установлен">
          Установите dnsmasq, Unbound, dnsproxy или AdGuard Home в разделе «Компоненты».
          Для шифрованного DNS (DoT, DoH) подойдут последние три.
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
          <div className="row" style={{ gap: "0.5rem", marginTop: "0.5rem" }}>
            <Badge tone={caps.dot ? "ok" : "neutral"}>
              DoT {caps.dot ? "поддерживается" : "не поддерживается"}
            </Badge>
            <Badge tone={caps.doh ? "ok" : "neutral"}>
              DoH {caps.doh ? "поддерживается" : "не поддерживается"}
            </Badge>
          </div>
        )}

        {cantEncrypt && (
          <div style={{ marginTop: "1rem" }}>
            <Notice tone="warn" title="Выбранный резолвер не умеет шифровать запросы">
              Настроено шифрованных апстримов: {encrypted.length}. Установите dnsproxy или
              AdGuard Home, либо оставьте только обычные.
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
                      <input
                        type="text"
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
                        onChange={(v) => patch((d) => (d.dns.upstreams[idx].enabled = v))}
                      />
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn ghost sm"
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
                  id: "up-" + Date.now(),
                  type: "plain",
                  address: "",
                  enabled: true,
                });
              })
            }
          >
            Добавить апстрим
          </button>
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
