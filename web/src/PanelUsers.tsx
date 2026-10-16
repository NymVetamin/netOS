import { useEffect, useState } from "react";
import { api } from "./api";
import { PANEL_SECTIONS } from "./permissions";
import { Card, Field, Notice } from "./ui";
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
  return <Card title="Пользователи панели" subtitle="Доступ к управлению netOS; учётные записи файлового сервера настраиваются отдельно">
    {error && <Notice tone="danger" title={error} />}
    <div className="stack">
      {users.map(user => <div key={user.username} className="row-actions">
        <strong>{user.username}</strong><span className="dim">{user.role === "admin" ? "Администратор" : "Ограниченный доступ"} · {user.enabled ? "Включён" : "Отключён"}</span>
        <button className="btn sm" disabled={busy} onClick={() => edit(user)}>Изменить</button>
        <button className="btn sm danger" disabled={busy} onClick={() => void remove(user)}>Удалить</button>
      </div>)}
      {!form && <div><button className="btn" onClick={() => { setCreating(true); setForm(emptyUser()); }}>Добавить пользователя панели</button></div>}
    </div>
    {form && <fieldset disabled={busy} style={{ border: 0, padding: "16px 0 0", margin: 0 }}>
      <div className="form-grid">
        <Field label="Логин"><input aria-label="Логин пользователя панели" autoComplete="off" disabled={!creating} value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></Field>
        <Field label={creating ? "Пароль" : "Новый пароль"} hint={creating ? "Не менее 12 символов" : "Оставьте пустым, чтобы сохранить текущий пароль"}><input aria-label="Пароль пользователя панели" type="password" autoComplete="new-password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></Field>
        <Field label="Права"><select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="limited">По разделам</option><option value="admin">Администратор</option></select></Field>
        <label><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> Пользователь включён</label>
      </div>
      {form.role !== "admin" && <div className="form-grid">{Object.entries(PANEL_SECTIONS).map(([key, title]) => <Field key={key} label={title}>
        <select aria-label={`Доступ: ${title}`} value={form.permissions[key] || "none"} onChange={e => setForm({ ...form, permissions: { ...form.permissions, [key]: e.target.value } })}>
          <option value="none">Нет доступа</option><option value="view">Просмотр</option>
          {!["dashboard", "map", "history"].includes(key) && <option value="manage">Управление</option>}
        </select>
      </Field>)}</div>}
      <p className="hint">Изменение прав или пароля завершит все сессии этого пользователя. Управление пользователями, резервные копии и обновление доступны только администратору.</p>
      <div className="row-actions"><button className="btn" onClick={() => setForm(null)}>Отмена</button><button className="btn primary" disabled={!form.username || (creating && form.password.length < 12)} onClick={() => void save()}>Сохранить пользователя</button></div>
    </fieldset>}
  </Card>;
}
