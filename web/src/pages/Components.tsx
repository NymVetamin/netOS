import { useEffect, useState } from "react";
import { api, CatalogResponse } from "../api";
import { Badge, Card, Notice, Spinner, Switch } from "../ui";

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

export function ComponentsPage({ config, patch }: { config: any; patch: Patch }) {
  const [catalog, setCatalog] = useState<CatalogResponse | null>(null);
  const [catalogError, setCatalogError] = useState("");

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    let controller: AbortController | undefined;
    const load = () => {
      const requestController = new AbortController();
      controller = requestController;
      const timeout = window.setTimeout(() => requestController.abort(), 15_000);
      api
        .catalog(requestController.signal)
        .then((r) => { if (alive) { setCatalog(r); setCatalogError(""); } })
        .catch(() => { if (alive) { setCatalogError("Не удалось получить состояние компонентов. Повторная попытка выполняется автоматически."); setCatalog((prev) => prev ?? { components: [] }); } })
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

  if (!catalog) return <><div className="page-head"><h1>Компоненты</h1><p>Установленные возможности и системные службы роутера</p></div><Card><div className="loading-state"><Spinner /> Загружаем состояние компонентов…</div></Card></>;

  const wanted = new Map<string, boolean>(
    (config.components || []).map((c: any) => [c.id, c.installed]),
  );
  // Что полностью готово на машине и что на ней работает — разные вопросы, и оба
  // отвечаются живой системой, а не конфигурацией: пакет мог не установиться,
  // а установленный демон — быть никем не выбран.
  const ready = catalog.installed || {};
  const running = catalog.running || {};

  const groups = catalog.components.reduce<Record<string, CatalogResponse["components"]>>(
    (acc, c) => {
      (acc[c.group] = acc[c.group] || []).push(c);
      return acc;
    },
    {},
  );

  const installedCount = Array.from(wanted.values()).filter(Boolean).length;
  const runningCount = Object.values(running).filter(Boolean).length;

  function toggle(id: string, on: boolean) {
    patch((d) => {
      d.components = d.components || [];
      const existing = d.components.find((c: any) => c.id === id);
      if (existing) existing.installed = on;
      else d.components.push({ id, installed: on });

      // Снятый компонент не должен оставаться выбранным поставщиком службы:
      // иначе конфигурация останется ссылаться на то, чего на машине уже нет.
      if (!on) {
        if (d.dns?.provider === id) {
          d.dns.provider = "";
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
        <h1>Компоненты</h1>
        <p>Установленные возможности и системные службы роутера</p>
      </div>

      {catalogError && <Notice tone="warn" title="Состояние временно недоступно">{catalogError}</Notice>}

      <Notice tone="info" title="Базовая установка минимальна">
        Сразу после установки на машине работают только веб-панель и SSH. Роутер не
        поднимает служб, которых у него не просили: меньше открытых портов, меньше
        занятого места, меньше того, что может сломаться. Выбрано компонентов:{" "}
        {installedCount}, работает служб: {runningCount}.
      </Notice>

      {Object.entries(groups).map(([group, items]) => (
        <Card key={group} title={group}>
          <div className="stack">
            {items.map((c) => {
              const on = wanted.get(c.id) === true;
              const isReady = ready[c.id] === true;
              const atWork = running[c.id] === true;
              return (
                <div key={c.id} className={`component ${on ? "on" : ""}`}>
                  <div className="component-main">
                    <div className="row" style={{ gap: "0.5rem" }}>
                      <strong>{c.title}</strong>
                      {isReady && <Badge tone="ok">готов</Badge>}
                      {atWork && <Badge tone="ok">используется</Badge>}
                      {/* Желаемое состояние сравнивается с живой машиной. Essential
                          пакет остаётся частью базовой системы даже при выключенной
                          функции; обычный установленный компонент будет удалён. */}
                      {on && !isReady && <Badge tone="warn">будет установлен или исправлен</Badge>}
                      {!on && isReady && !c.essential && <Badge tone="warn">будет удалён</Badge>}
                      {!on && isReady && c.essential && <Badge tone="neutral">базовый пакет останется</Badge>}
                      {c.external && <Badge tone="warn">не из репозитория Debian</Badge>}
                    </div>
                    <div className="dim" style={{ marginTop: 2 }}>
                      {c.description}
                    </div>
                    <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
                      {c.size_hint && <span>Размер: {c.size_hint}</span>}
                      {c.packages && c.packages.length > 0 && (
                        <span className="mono"> · {c.packages.join(", ")}</span>
                      )}
                    </div>
                  </div>
                  <Switch
                    checked={on}
                    label=""
                    ariaLabel={`Компонент ${c.title || c.id} включён`}
                    onChange={(v) => toggle(c.id, v)}
                  />
                </div>
              );
            })}
          </div>
        </Card>
      ))}

      <Card title="Как это применяется">
        <div className="dim">
          Установка и удаление происходят при нажатии «Применить». Пакеты ставятся из
          репозиториев Debian, поэтому роутеру нужен доступ в интернет. Компоненты,
          помеченные как не из репозитория, загружаются с сайта разработчика с
          проверкой закреплённой контрольной суммы.
        </div>
      </Card>
    </>
  );
}
