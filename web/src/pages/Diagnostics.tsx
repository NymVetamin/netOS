import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, TableWrap } from "../ui";

// Диагностика показывает, во что превратилась конфигурация: настоящие правила
// iptables, конфиги работающих демонов, таблицу маршрутов. Администратор
// должен иметь возможность проверить работу панели, а не верить ей на слово.
//
// Список конфигов приходит с сервера и зависит от выбранных демонов. Зашитый в
// панели перечень показывал конфигурацию dnsmasq всегда — в том числе когда
// dnsmasq выключен, а работают unbound и ISC DHCP, конфигов которых не было
// видно вовсе.
const ROUTES = "netos:routes";
const NEIGHBORS = "netos:neighbors";

export function DiagnosticsPage() {
  const [artifacts, setArtifacts] = useState<{ id: string; title: string }[]>([]);
  // Вкладка пуста, пока не пришёл список: открывать что-то до него значило бы
  // сходить на сервер дважды и показать не то, что откроется в итоге.
  const [tab, setTab] = useState<string>("");
  const [content, setContent] = useState("");
  const [arp, setArp] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadedTab, setLoadedTab] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await api.renderList();
        if (cancelled) return;
        setArtifacts(list);
        // Первым открывается первый же артефакт — им всегда оказывается то, что
        // определяет доступность машины: правила iptables.
        setLoading(true);
        setTab(list.length > 0 ? list[0].id : ROUTES);
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Не удалось загрузить список диагностики");
          setLoadedTab(ROUTES);
          setTab(ROUTES);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!tab) return;
    let cancelled = false;
    setLoading(true);
    setError("");
    (async () => {
      try {
        if (tab === ROUTES) {
          const r = await api.routes();
          if (!cancelled) {
            setContent(
              "# таблица маршрутов\n" + r.routes + "\n# правила выбора таблиц\n" + r.rules,
            );
            setLoadedTab(tab);
          }
        } else if (tab === NEIGHBORS) {
          const r = await api.arp();
          if (!cancelled) {
            setArp(r.arp || []);
            setLoadedTab(tab);
          }
        } else {
          const text = await api.render(tab);
          if (!cancelled) {
            setContent(text);
            setLoadedTab(tab);
          }
        }
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Не удалось загрузить диагностику");
          setLoadedTab(tab);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tab]);

  const tabs = [
    ...artifacts,
    { id: ROUTES, title: "Маршруты" },
    { id: NEIGHBORS, title: "Таблица соседей" },
  ];

  const selectTab = (id: string) => {
    if (id === tab) return;
    // React applies both changes in one update, so stale content cannot appear
    // under the next tab's title even when the request is slow.
    setLoading(true);
    setError("");
    setTab(id);
  };

  const pending = loading || loadedTab !== tab;

  return (
    <>
      <div className="page-head">
        <h1>Диагностика</h1>
        <p>Что получилось из настроек на самом деле</p>
      </div>

      <div className="row wrap" style={{ marginBottom: "1rem", gap: "0.4rem" }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`btn sm ${tab === t.id ? "primary" : ""}`}
            onClick={() => selectTab(t.id)}
          >
            {t.title}
          </button>
        ))}
      </div>

      {tab === NEIGHBORS ? (
        <Card title="Таблица соседей" tight>
          {pending ? (
            <Empty>Загрузка…</Empty>
          ) : error ? (
            <Empty>{error}</Empty>
          ) : arp.length === 0 ? (
            <Empty>Записей нет</Empty>
          ) : (
            <TableWrap>
              <table>
                <thead>
                  <tr>
                    <th>Адрес</th>
                    <th>MAC</th>
                    <th>Интерфейс</th>
                    <th>Состояние</th>
                  </tr>
                </thead>
                <tbody>
                  {arp.map((e, i) => (
                    <tr key={i}>
                      <td className="mono">{e.ip}</td>
                      <td className="mono faint">{e.mac}</td>
                      <td className="mono">{e.interface}</td>
                      <td className="faint">{e.state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>
      ) : (
        <div className="card">
          <div className="card-head">
            <div>
              <h2>{tabs.find((t) => t.id === tab)?.title}</h2>
              <div className="sub">
                {tab === ROUTES ? "Снято с живой системы" : "Сгенерировано из текущей конфигурации"}
              </div>
            </div>
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(content)}>
              Скопировать
            </button>
          </div>
          <pre className="output">{pending ? "Загрузка…" : error || content}</pre>
        </div>
      )}
    </>
  );
}
