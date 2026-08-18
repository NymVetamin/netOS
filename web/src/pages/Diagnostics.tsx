import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, TableWrap } from "../ui";

// Диагностика показывает, во что превратилась конфигурация: настоящие правила
// iptables, конфиг dnsmasq, таблицу маршрутов. Администратор должен иметь
// возможность проверить работу панели, а не верить ей на слово.
export function DiagnosticsPage() {
  const [tab, setTab] = useState<"iptables" | "dnsmasq" | "routes" | "arp">("iptables");
  const [content, setContent] = useState("");
  const [arp, setArp] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        if (tab === "iptables" || tab === "dnsmasq") {
          const text = await api.render(tab);
          if (!cancelled) setContent(text);
        } else if (tab === "routes") {
          const r = await api.routes();
          if (!cancelled) {
            setContent(
              "# таблица маршрутов\n" + r.routes + "\n# правила выбора таблиц\n" + r.rules,
            );
          }
        } else {
          const r = await api.arp();
          if (!cancelled) setArp(r.arp || []);
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
    { id: "iptables" as const, label: "Правила iptables" },
    { id: "dnsmasq" as const, label: "Конфигурация dnsmasq" },
    { id: "routes" as const, label: "Маршруты" },
    { id: "arp" as const, label: "Таблица соседей" },
  ];

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
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "arp" ? (
        <Card title="Таблица соседей" tight>
          {arp.length === 0 ? (
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
              <h2>{tabs.find((t) => t.id === tab)?.label}</h2>
              <div className="sub">Сгенерировано из текущей конфигурации</div>
            </div>
            <button className="btn sm" onClick={() => navigator.clipboard?.writeText(content)}>
              Скопировать
            </button>
          </div>
          <pre className="output">{loading ? "Загрузка…" : content}</pre>
        </div>
      )}
    </>
  );
}
