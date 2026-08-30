import { useEffect, useState } from "react";
import { api, formatBytes, formatTime, Session } from "../api";
import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

// Чем настраивать сетевые интерфейсы. На машине может быть принятый способ
// настройки сети, и навязывать свой netOS не должен.
const BACKENDS = [
  {
    id: "netos",
    title: "netOS напрямую",
    hint: "Интерфейсы поднимает сам netOS через iproute2, а systemd-networkd получает указание их не трогать. Изменения применяются мгновенно, но до старта netOS сеть не настроена.",
  },
  {
    id: "ifupdown",
    title: "networking (ifupdown)",
    hint: "Дополнительно к прямому управлению netOS пишет /etc/network/interfaces.d/netos.conf, и сегменты существуют уже с загрузки. Привычно для Debian.",
  },
  {
    id: "networkd",
    title: "systemd-networkd",
    hint: "То же самое файлами .network и .netdev в /etc/systemd/network.",
  },
];

export function SystemPage({
  config,
  patch,
  session,
}: {
  config: any;
  patch: Patch;
  session: Session;
}) {
  return (
    <>
      <div className="page-head">
        <h1>Система</h1>
        <p>Общие параметры роутера, панель управления и учётная запись</p>
      </div>

      <Card title="Основное">
        <div className="form-grid">
          <Field label="Имя хоста">
            <input
              type="text"
              value={config.system?.hostname || ""}
              onChange={(e) => patch((d) => (d.system.hostname = e.target.value))}
            />
          </Field>
          <Field label="Часовой пояс" hint="Влияет на расписания правил и время в журналах">
            <input
              type="text"
              value={config.system?.timezone || ""}
              onChange={(e) => patch((d) => (d.system.timezone = e.target.value))}
            />
          </Field>
        </div>
      </Card>

      <Card
        title="Настройка сетевых интерфейсов"
        subtitle="Кто именно поднимает интерфейсы и назначает адреса"
      >
        <div className="stack">
          {BACKENDS.map((b) => (
            <label
              key={b.id}
              className={`choice ${config.system?.network_backend === b.id ? "selected" : ""}`}
            >
              <input
                type="radio"
                name="backend"
                checked={config.system?.network_backend === b.id}
                onChange={() => patch((d) => (d.system.network_backend = b.id))}
              />
              <div>
                <strong>{b.title}</strong>
                <div className="faint" style={{ fontSize: 12.5 }}>
                  {b.hint}
                </div>
              </div>
            </label>
          ))}
        </div>
        <div style={{ marginTop: "0.9rem" }}>
          {config.system?.network_backend === "netos" ? (
            <Notice tone="info" title="Интерфейсы переходят под управление netOS">
              systemd-networkd оставляет перечисленные интерфейсы управляемыми, но
              пассивными: не выдаёт им адреса и не спорит за маршруты, а ожидание сети
              при загрузке не упирается в таймаут. Записи в /etc/network/interfaces
              перекрыть нельзя — если такие найдутся, netOS предупредит об этом в
              журнале.
            </Notice>
          ) : (
            <Notice tone="info" title="Что попадёт в сгенерированный файл">
              Бриджи, VLAN, агрегаты и адреса сегментов — они статичны и будут подняты
              системой ещё до старта netOS. Аплинки только поднимаются: их адресами,
              маршрутами и метриками управляет netOS, и второй клиент DHCP на том же
              интерфейсе сломал бы переключение между каналами. Изменения по-прежнему
              применяются сразу, а не после перезагрузки.
            </Notice>
          )}
        </div>
        <div style={{ marginTop: "0.6rem" }}>
          <Notice tone="warn" title="Смена способа настройки кратковременно рвёт связность">
            Тот, у кого забирают интерфейс, снимает выданные им адреса, и netOS
            назначает свои заново. Если панель открыта через настраиваемый
            интерфейс, подтвердить изменения нужно будет после короткого разрыва.
          </Notice>
        </div>
      </Card>

      <Card
        title="IPv6"
        subtitle="Подавление протокола, чтобы трафик не уходил мимо правил маршрутизации"
      >
        <Notice tone="info" title="Почему это важно">
          Правила выбора канала работают для IPv4. Если у клиента поднят IPv6, он пойдёт
          в интернет напрямую, минуя выбранный туннель.
        </Notice>
        <div className="form-grid">
          <Field label="Режим">
            <select
              value={config.ipv6?.mode}
              onChange={(e) => patch((d) => (d.ipv6.mode = e.target.value))}
            >
              <option value="off">Подавлять полностью</option>
              <option value="passthrough">Разрешить</option>
            </select>
          </Field>
        </div>
        <div style={{ marginTop: "0.6rem" }}>
          <Switch
            checked={config.ipv6?.filter_aaaa}
            label="Не отдавать клиентам AAAA-записи"
            onChange={(v) => patch((d) => (d.ipv6.filter_aaaa = v))}
          />
        </div>
      </Card>

      <Card title="Веб-панель">
        <div className="form-grid">
          <Field
            label="Порт"
            hint="Изменение порта работающей панели пока не поддерживается"
          >
            <input
              type="number"
              value={config.system?.panel?.port}
              disabled
            />
          </Field>
          <Field
            label="Время на подтверждение, секунд"
            hint="Столько роутер ждёт подтверждения, прежде чем откатить изменения"
          >
            <input
              type="number"
              value={config.system?.panel?.commit_timeout}
              onChange={(e) =>
                patch((d) => (d.system.panel.commit_timeout = Number(e.target.value)))
              }
            />
          </Field>
        </div>
        <div className="faint" style={{ fontSize: 12.5, marginTop: "0.6rem" }}>
          Кому доступна панель, задаётся правилом «Веб-панель netOS» в разделе «Файрволл».
        </div>
      </Card>

      {session.role === "admin" && <MaintenancePanel />}
      <ChangePassword />
    </>
  );
}

function MaintenancePanel() {
  const [backups, setBackups] = useState<any[]>([]);
  const [status, setStatus] = useState<any>({ state: "idle" });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [restoreName, setRestoreName] = useState("");
  const [restoreConfirm, setRestoreConfirm] = useState("");
  const [version, setVersion] = useState("latest");
  const [updateConfirm, setUpdateConfirm] = useState("");

  async function load() {
    const [list, live] = await Promise.all([api.backups(), api.maintenanceStatus()]);
    setBackups(list.backups || []);
    setStatus(live);
  }
  useEffect(() => {
    load().catch(() => {});
    const timer = window.setInterval(() => load().catch(() => {}), 5000);
    return () => window.clearInterval(timer);
  }, []);

  async function action(run: () => Promise<any>, success: string) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await run();
      setMessage(success);
      window.setTimeout(() => load().catch(() => {}), 4000);
    } catch (e: any) {
      setError(e.message || "Операция не выполнена");
    } finally {
      setBusy(false);
    }
  }

  const running = status.state === "active" || status.state === "activating";
  return (
    <Card
      title="Резервные копии и обновление"
      subtitle="Операции выполняются отдельно от панели и продолжаются после перезапуска службы"
      actions={<Badge tone={running ? "warn" : status.result === "failed" ? "danger" : "neutral"}>{running ? "выполняется" : status.result === "failed" ? "последняя операция завершилась ошибкой" : "готово"}</Badge>}
    >
      {message && <Notice tone="info" title={message} />}
      {error && <Notice tone="danger" title={error} />}
      <div className="row wrap" style={{ margin: ".8rem 0" }}>
        <button className="btn primary" disabled={busy || running} onClick={() => action(api.createBackup, "Создание резервной копии запланировано")}>Создать копию</button>
      </div>
      {backups.length === 0 ? <Empty>Резервных копий пока нет</Empty> : (
        <TableWrap>
          <table>
            <thead><tr><th>Файл</th><th>Создан</th><th>Размер</th><th /></tr></thead>
            <tbody>{backups.map((backup) => <tr key={backup.name}>
              <td className="mono">{backup.name}</td>
              <td>{formatTime(backup.modified)}</td>
              <td>{formatBytes(backup.size)}</td>
              <td><div className="row">
                <a className="btn ghost sm" href={`/api/backups/${encodeURIComponent(backup.name)}`}>Скачать</a>
                <button className="btn sm" disabled={busy || running} onClick={() => { setRestoreName(backup.name); setRestoreConfirm(""); }}>Восстановить</button>
                <button className="btn ghost sm" disabled={busy || running} onClick={() => {
                  if (window.confirm(`Удалить ${backup.name}?`)) action(() => api.deleteBackup(backup.name), "Резервная копия удалена");
                }}>Удалить</button>
              </div></td>
            </tr>)}</tbody>
          </table>
        </TableWrap>
      )}

      {restoreName && <div style={{ marginTop: "1rem" }}>
        <Notice tone="warn" title={`Восстановить ${restoreName}?`}>
          Текущие настройки, история и учётные записи будут заменены. Перед восстановлением автоматически создастся страховочная копия.
        </Notice>
        <div className="row wrap" style={{ marginTop: ".7rem" }}>
          <input style={{ maxWidth: 220 }} placeholder="Введите RESTORE" value={restoreConfirm} onChange={(e) => setRestoreConfirm(e.target.value)} />
          <button className="btn danger" disabled={busy || restoreConfirm !== "RESTORE"} onClick={() => action(() => api.restoreBackup(restoreName, restoreConfirm), "Восстановление запланировано")}>Восстановить</button>
          <button className="btn ghost" onClick={() => setRestoreName("")}>Отмена</button>
        </div>
      </div>}

      <div style={{ marginTop: "1.2rem", paddingTop: "1rem", borderTop: "1px solid var(--border)" }}>
        <strong>Обновление netOS</strong>
        <div className="faint" style={{ fontSize: 12.5, margin: ".25rem 0 .7rem" }}>Перед обновлением установщик сохраняет данные; укажите latest или тег релиза, например v0.06.</div>
        <div className="row wrap">
          <input style={{ maxWidth: 160 }} value={version} onChange={(e) => setVersion(e.target.value.trim())} />
          <input style={{ maxWidth: 220 }} placeholder="Введите UPDATE" value={updateConfirm} onChange={(e) => setUpdateConfirm(e.target.value)} />
          <button className="btn" disabled={busy || running || updateConfirm !== "UPDATE" || !version} onClick={() => action(() => api.updateSystem(version, updateConfirm), "Обновление запланировано")}>Обновить</button>
        </div>
      </div>
    </Card>
  );
}

function ChangePassword() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const mismatch = repeat.length > 0 && next !== repeat;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy || !current || next.length < 10 || !repeat || next !== repeat) return;
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await api.changePassword(current, next);
      setMsg("Пароль изменён");
      setCurrent("");
      setNext("");
      setRepeat("");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Пароль администратора">
      <form onSubmit={submit}>
        <div className="form-grid">
          <Field label="Текущий пароль">
            <input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </Field>
          <Field label="Новый пароль" hint="Не короче 10 символов">
            <input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </Field>
          <Field label="Повторите новый пароль">
            <input
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => setRepeat(e.target.value)}
            />
          </Field>
        </div>

        {mismatch && <div style={{ color: "var(--danger)" }}>Пароли не совпадают</div>}
        {err && <div style={{ color: "var(--danger)" }}>{err}</div>}
        {msg && <div style={{ color: "var(--ok)" }}>{msg}</div>}

        <div style={{ marginTop: "0.9rem" }}>
          <button
            type="submit"
            className="btn primary"
            disabled={busy || !current || next.length < 10 || !repeat || mismatch}
          >
            Сменить пароль
          </button>
        </div>
      </form>
    </Card>
  );
}
