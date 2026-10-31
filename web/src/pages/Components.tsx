import { useEffect, useState } from "react";
import { api, CatalogResponse } from "../api";
import { Badge, Card, Notice, Spinner, Switch } from "../ui";
import { COMPONENT_ICONS, Icon } from "../icons";
import { ComponentOperation, ComponentUpdates } from "../componentUpdates";

type Patch = (mutate: (draft: any) => void) => void;

// Компоненты — то, что вообще стоит на роутере.
//
// После установки netOS на машине нет ни DHCP-сервера, ни резолвера, ни VPN:
// только панель и доступ по SSH. Всё остальное появляется здесь и только по
// решению администратора.

// LIVE_POLL_MS — как часто перепрашивается живое состояние машины. Установка
// пакета занимает минуты, а служба поднимается и падает за секунды, поэтому
// «используется» должно обновляться само, без перезагрузки страницы.
const LIVE_POLL_MS = 5000;

function ComponentProgress({ operation }: { operation?: ComponentOperation }) {
  if (!operation) return null;
  const running = operation.active;
  const percentage = running && operation.total && operation.total > 0
    ? Math.min(100, Math.round(((operation.bytes || 0) * 100) / operation.total))
    : undefined;
  return (
    <div className={`component-progress ${operation.status || ""}`} role="status">
      <div className="component-progress-label">
        <span>{operation.error || operation.stage || "Подготовка…"}</span>
        {running && <span className="dim">
          {percentage !== undefined ? `${percentage}% · ` : ""}
          {operation.started_at && !operation.started_at.startsWith("0001")
            ? `${Math.max(0, Math.floor((Date.now() - Date.parse(operation.started_at)) / 1000))} с`
            : ""}
        </span>}
      </div>
      {running && <progress aria-label="Ход операции с компонентом" max={100} value={percentage} />}
    </div>
  );
}

export function ComponentsPage({
  config,
  patch,
  updates,
  canUpdate,
}: {
  config: any;
  patch: Patch;
  updates: {
    state: ComponentUpdates | null;
    error: string;
    reload: () => void;
  };
  canUpdate: boolean;
}) {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [catalogError, setCatalogError] = useState("");
  const [actionError, setActionError] = useState("");
  const [starting, setStarting] = useState(false);
  const operation = updates.state?.operation;
  const busy = starting || operation?.active === true;
  async function perform(id?: string, token?: string) {
    setStarting(true);
    setActionError("");
    try {
      if (id === "all") {
        await api.updateAllComponents(Object.entries(updates.state?.components || {})
          .filter(([, row]) => row.update_available && !row.error)
          .map(([id, row]) => ({ id, token: row.token })));
      } else if (id) await api.updateComponent(id, token!);
      else await api.checkComponentUpdates();
      updates.reload();
    } catch (e) {
      setActionError(
        e instanceof Error ? e.message : "Не удалось начать операцию",
      );
    } finally {
      setStarting(false);
    }
  }

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    let controller: AbortController | undefined;
    const load = () => {
      const requestController = new AbortController();
      controller = requestController;
      const timeout = window.setTimeout(
        () => requestController.abort(),
        15_000,
      );
      api
        .catalog(requestController.signal)
        .then((r) => {
          if (alive) {
            setCatalog(r);
            setCatalogError("");
          }
        })
        .catch(() => {
          if (alive) {
            setCatalogError(
              "Не удалось получить состояние компонентов. Повторная попытка выполняется автоматически.",
            );
            setCatalog((prev) => prev ?? { components: [] });
          }
        })
        .finally(() => {
          window.clearTimeout(timeout);
          if (alive) timer = window.setTimeout(load, LIVE_POLL_MS);
        });
    };
    load();
    return () => {
      alive = false;
      controller?.abort();
      window.clearTimeout(timer);
    };
  }, []);

  if (!catalog)
    return (
      <>
        <div className="page-head">
          <h1>
            <Icon name="package" />
            Компоненты
          </h1>
          <p>Установленные возможности и системные службы роутера</p>
        </div>

        <Card>
          <div className="loading-state">
            <Spinner /> Загружаем состояние компонентов…
          </div>
        </Card>
      </>
    );

  const wanted = new Map<string, boolean>(
    (config.components || []).map((c: any) => [c.id, c.installed]),
  );
  // Что полностью готово на машине и что на ней работает — разные вопросы, и оба
  // отвечаются живой системой, а не конфигурацией: пакет мог не установиться,
  // а установленный демон — быть никем не выбран.
  const ready = catalog.installed || {};
  const running = catalog.running || {};

  const groups = catalog.components.reduce<
    Record<string, CatalogResponse["components"]>
  >((acc, c) => {
    (acc[c.group] = acc[c.group] || []).push(c);
    return acc;
  }, {});

  const installedCount = Array.from(wanted.values()).filter(Boolean).length;
  const runningCount = Object.values(running).filter(Boolean).length;
  const updateEntries = Object.values(updates.state?.components || {});
  const updateCount = updateEntries.filter((entry) => entry.update_available).length;
  const actionableCount = updateEntries.filter((entry) => entry.update_available && !entry.error).length;
  const checkFailed = Boolean(updates.error || updates.state?.error) ||
    updateEntries.some((entry) => entry.error);
  const checked = Boolean(updates.state?.checked_at &&
    !updates.state.checked_at.startsWith("0001"));
  const checkResult = operation?.active && operation.kind === "check"
    ? "Проверяем обновления…"
    : checkFailed
      ? "Не удалось проверить все обновления"
      : !checked
        ? "Обновления ещё не проверялись"
        : updateCount > 0
          ? `Доступно обновлений: ${updateCount}`
          : "Обновлений нет";

  function toggle(id: string, on: boolean) {
    patch((d) => {
      d.components = d.components || [];
      const existing = d.components.find((c: any) => c.id === id);
      if (existing) existing.installed = on;
      else d.components.push({ id, installed: on });

      // Снятый компонент не должен оставаться выбранным поставщиком службы:
      // иначе конфигурация останется ссылаться на то, чего на машине уже нет.
      if (!on) {
        if (id === "qos" && d.qos) {
          d.qos.enabled = false;
        }
        if (d.dns?.provider === id) {
          // Keep provider-specific draft syntax while the service is disabled.
          // Reinstalling can then restore the existing upstreams and options.
          d.dns.enabled = false;
        }
        if (d.dhcp?.provider === id) {
          d.dhcp.provider = "";
          d.dhcp.enabled = false;
        }
      }
    });
  }

  return (
    <>
      <div className="page-head">
        <h1>
          <Icon name="package" />
          Компоненты
        </h1>
        <p>Установленные возможности и системные службы роутера</p>
      </div>

      {catalogError && (
        <Notice tone="warn" title="Состояние временно недоступно">
          {catalogError}
        </Notice>
      )}
      <div className="component-update-toolbar">
        <span className="dim">
          {checkResult}
          {checked && !operation?.active &&
            ` · Проверено: ${new Date(updates.state!.checked_at).toLocaleString()}`}
        </span>
        {canUpdate && (
          <div className="component-update-actions">
          <button
            className="btn"
            disabled={busy}
            onClick={() => void perform()}
          >
            Проверить обновления
          </button>
          <button className="btn primary" disabled={busy || actionableCount === 0}
            onClick={() => void perform("all")}>
            Обновить всё{actionableCount > 0 ? ` (${actionableCount})` : ""}
          </button>
          </div>
        )}
      </div>

      {(actionError ||
        updates.error ||
        updates.state?.error ||
        operation?.error) && (
        <Notice tone="warn" title="Операция с компонентами">
          {actionError ||
            updates.error ||
            updates.state?.error ||
            operation?.error}
        </Notice>
      )}

      <Notice hint tone="info" title="Базовая установка минимальна">
        Сразу после установки на машине работают только веб-панель и SSH. Роутер
        не поднимает служб, которых у него не просили: меньше открытых портов,
        меньше занятого места, меньше того, что может сломаться. Выбрано
        компонентов: {installedCount}, используется компонентов: {runningCount}.
      </Notice>

      {Object.entries(groups).map(([group, items]) => (
        <Card key={group} title={group}>
          <div className="stack">
            {items.map((c) => {
              const on = wanted.get(c.id) === true;
              const isReady = ready[c.id] === true;
              const atWork = running[c.id] === true;
              const update = updates.state?.components?.[c.id];
              const componentOperation = updates.state?.operations?.[c.id];
              return (
                <div key={c.id} className={`component ${on ? "on" : ""}`}>
                  <div className="component-main">
                    <div className="row" style={{ gap: "0.5rem" }}>
                      {COMPONENT_ICONS[c.id] && (
                        <Icon name={COMPONENT_ICONS[c.id]} />
                      )}
                      <strong>{c.title}</strong>
                      {update?.installed && <span className="component-version dim">
                        {update.installed}
                        {update.update_available && update.available !== update.installed &&
                          <span className="component-new-version"> → {update.available}</span>}
                      </span>}
                      {isReady && <Badge tone="ok">готов</Badge>}
                      {atWork && <Badge tone="ok">используется</Badge>}
                      {/* Желаемое состояние сравнивается с живой машиной. Essential
                          пакет остаётся частью базовой системы даже при выключенной
                          функции; обычный установленный компонент будет удалён. */}
                      {on && !isReady && (
                        <Badge tone="warn">
                          будет установлен или исправлен
                        </Badge>
                      )}
                      {!on && isReady && !c.essential && (
                        <Badge tone="warn">будет удалён</Badge>
                      )}
                      {!on && isReady && c.essential && (
                        <Badge tone="neutral">базовый пакет останется</Badge>
                      )}
                      {c.external && (
                        <Badge tone="warn">не из репозитория Debian</Badge>
                      )}
                    </div>
                    <div className="dim" style={{ marginTop: 2 }}>
                      {c.description}
                    </div>
                    <div
                      className="faint"
                      style={{ fontSize: 12, marginTop: 4 }}
                    >
                      {c.size_hint && <span>Размер: {c.size_hint}</span>}
                      {c.packages && c.packages.length > 0 && (
                        <span className="mono"> · {c.packages.join(", ")}</span>
                      )}
                    </div>
                  {update && (
                    <div className="component-update-details">
                      {update.error && (
                        <small className="dim">{update.error}</small>
                      )}
                      {update.packages &&
                        update.packages.some((p) => p.update_available) && (
                          <small className="dim">
                            {update.packages
                              .filter((p) => p.update_available)
                              .map(
                                (p) =>
                                  `${p.name}: ${p.installed} → ${p.available}`,
                              )
                              .join("; ")}
                          </small>
                        )}
                    </div>
                  )}
                  <ComponentProgress operation={componentOperation} />
                  </div>
                  <div className="component-controls">
                      {canUpdate && update?.update_available && (
                        <button
                          className="btn"
                          disabled={busy || !!update.error}
                          onClick={() => void perform(c.id, update.token)}
                        >
                          Обновить
                        </button>
                      )}
                  <Switch
                    checked={on}
                    label=""
                    ariaLabel={`Компонент ${c.title || c.id} включён`}
                    onChange={(v) => toggle(c.id, v)}
                  />
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      ))}

      <Card title="Как это применяется">
        <div className="dim">
          Установка и удаление происходят при нажатии «Применить». Пакеты
          ставятся из репозиториев Debian, поэтому роутеру нужен доступ в
          интернет. Компоненты, помеченные как не из репозитория, загружаются с
          сайта разработчика с проверкой контрольной суммы официального релиза.
          Новые версии проверяются ежедневно; установка обновления запускается
          кнопкой «Обновить».
        </div>
      </Card>
    </>
  );
}
