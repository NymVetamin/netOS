import { useEffect, useState } from "react";
import { api } from "./api";
import { PANEL_SECTIONS } from "./permissions";
import { Badge, Card, Field, Notice } from "./ui";
import { confirmAction } from "./confirm";

type User = { username: string; role: string; enabled: boolean; permissions: Record<string, string> };
const emptyUser = (): User & { password: string } => ({ username: "", role: "limited", enabled: true, permissions: {}, password: "" });

export function PanelUsers() {
  const [users, setUsers] = useState<User[]>([]);
  const [form, setForm] = useState<ReturnType<typeof emptyUser> | null>(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  function edit(user: User) {
    setCreating(false);
    setForm(user.role === "viewer"
      ? { ...user, role: "limited", permissions: Object.fromEntries(Object.keys(PANEL_SECTIONS).filter(key => key !== "diagnostics").map(key => [key, "view"])), password: "" }
      : { ...user, password: "" });
  }
  const reload = () => api.panelUsers().then(setUsers).catch(e => setError(e.message));
  useEffect(() => { void reload(); }, []);
  async function save() {
    if (!form) return;
    setBusy(true); setError("");
    try { await api.savePanelUser(form, creating); setForm(null); await reload(); }
    catch (e) { setError(e instanceof Error ? e.message : "Не удалось сохранить пользователя"); }
    finally { setBusy(false); }
  }
  async function remove(user: User) {
    if (!await confirmAction(`Удалить пользователя панели «${user.username}»? Его сессии будут завершены.`, "Удалить пользователя")) return;
    setBusy(true); setError("");
    try { await api.deletePanelUser(user.username); await reload(); }
    catch (e) { setError(e instanceof Error ? e.message : "Не удалось удалить пользователя"); }
    finally { setBusy(false); }
  }
  return <Card tight title="Пользователи панели" subtitle="Доступ к управлению netOS; учётные записи файлового сервера настраиваются отдельно"
    actions={<button className="btn sm primary" disabled={busy || !!form} onClick={() => { setCreating(true); setForm(emptyUser()); }}>Добавить пользователя панели</button>}>
    {error && <Notice tone="danger" title={error} />}
    <table className="panel-users-table" aria-label="Пользователи панели">
      <thead><tr><th scope="col">Логин</th><th scope="col">Права</th><th scope="col">Состояние</th><th scope="col" className="user-actions-heading">Действия</th></tr></thead>
      <tbody>{users.map(user => <tr key={user.username}>
        <td className="user-login"><strong>{user.username}</strong></td>
        <td className="user-role"><span className="dim">{user.role === "admin" ? "Администратор" : "Ограниченный доступ"}</span></td>
        <td className="user-state"><Badge tone={user.enabled ? "ok" : "neutral"}>{user.enabled ? "Включён" : "Отключён"}</Badge></td>
        <td className="user-actions"><div>
          <button className="btn sm" disabled={busy} onClick={() => edit(user)}>Изменить</button>
          <button className="btn sm danger" disabled={busy} onClick={() => void remove(user)}>Удалить</button>
        </div></td>
      </tr>)}</tbody>
    </table>
    {form && <fieldset disabled={busy} className="panel-user-form">
      <div className="form-grid">
        <Field label="Логин"><input aria-label="Логин пользователя панели" autoComplete="off" disabled={!creating} value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></Field>
        <Field label={creating ? "Пароль" : "Новый пароль"} hint={creating ? "Не менее 12 символов" : "Оставьте пустым, чтобы сохранить текущий пароль"}><input aria-label="Пароль пользователя панели" type="password" autoComplete="new-password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></Field>
        <Field label="Права"><select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="limited">По разделам</option><option value="admin">Администратор</option></select></Field>
        <label><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> Пользователь включён</label>
      </div>
      {form.role !== "admin" && <table className="permission-table" aria-label="Права по страницам">
        <thead><tr><th scope="col">Страница</th><th scope="col">Просмотр</th><th scope="col">Управление</th></tr></thead>
        <tbody>{Object.entries(PANEL_SECTIONS).map(([key, title]) => {
          const level = form.permissions[key] || "none";
          const editable = !["dashboard", "map", "history"].includes(key);
          const change = (value: string) => setForm({ ...form, permissions: { ...form.permissions, [key]: value } });
          return <tr key={key}><th scope="row">{title}</th>
            <td><input type="checkbox" aria-label={`Просмотр: ${title}`} checked={level === "view" || level === "manage"} onChange={e => change(e.target.checked ? "view" : "none")} /></td>
            <td>{editable ? <input type="checkbox" aria-label={`Управление: ${title}`} checked={level === "manage"} onChange={e => change(e.target.checked ? "manage" : "view")} /> : <span className="faint" title="На этой странице нет настроек для изменения">—</span>}</td>
          </tr>;
        })}</tbody>
      </table>}
      <p className="hint">Изменение прав или пароля завершит все сессии этого пользователя. Управление пользователями, резервные копии и обновление доступны только администратору.</p>
      <div className="row-actions"><button className="btn" onClick={() => setForm(null)}>Отмена</button><button className="btn primary" disabled={!form.username || (creating && form.password.length < 12)} onClick={() => void save()}>Сохранить пользователя</button></div>
    </fieldset>}
  </Card>;
}
