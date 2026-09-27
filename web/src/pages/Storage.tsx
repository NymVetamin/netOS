import { useEffect, useState } from "react";
import { api } from "../api";
import { newID } from "../id";
import { Badge, Card, Empty, Field, Notice, Switch } from "../ui";

type Props = { config: any; patch: (mutate: (draft: any) => void) => void; admin: boolean };
const initial = () => ({ enabled: false, discovery: true, workgroup: "WORKGROUP", networks: [], vpns: [], volumes: [], users: [], shares: [] });

export function StoragePage({ config, patch, admin }: Props) {
  const s = { ...initial(), ...config.samba };
  const installed = (config.components || []).some((c: any) => c.id === "samba" && c.installed);
  const [devices, setDevices] = useState<any[]>([]);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    if (!admin) return;
    let alive = true, timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    const load = async () => {
      try { const result = await api.storageDevices(controller.signal); if (alive) { setDevices(result.devices || []); setError(""); } }
      catch (e) { if (alive) setError(e instanceof Error ? e.message : "Не удалось прочитать накопители"); }
      finally { if (alive) timer = setTimeout(load, 5000); }
    };
    void load();
    return () => { alive = false; clearTimeout(timer); controller.abort(); };
  }, [admin, refresh]);
  const edit = (fn: (v: any) => void) => patch(d => { d.samba = { ...initial(), ...d.samba }; for (const key of ["networks", "vpns", "volumes", "users", "shares"]) d.samba[key] ||= []; fn(d.samba); });
  const toggle = (field: string, id: string, on: boolean) => edit(d => { d[field] = on ? [...(d[field] || []), id] : (d[field] || []).filter((x: string) => x !== id); });
  const networks = (config.networks || []).filter((n: any) => n.enabled && !n.isolated && n.zone !== "wan");
  const vpns = (config.vpn_servers || []).filter((v: any) => v.enabled && v.type !== "xray");
  const server = networks.find((n: any) => (s.networks || []).includes(n.id))?.router_address?.split("/")[0] || vpns.find((v: any) => (s.vpns || []).includes(v.id))?.subnet?.split("/")[0] || config.system?.hostname || "netos";
  return <>
    <div className="page-head"><h1>Диски и файлы</h1><p>Файлы на USB-дисках по SMB из локальной сети и VPN</p></div>
    {!installed && <Notice tone="info" title="Нужен компонент Samba">Включите «Samba — диски и сетевые папки» в разделе «Компоненты».</Notice>}
    <Notice tone="info" title="Как подключиться">После применения настроек откройте <span className="mono">{`\\\\${server}`}</span> в Проводнике Windows или <span className="mono">{`smb://${server}`}</span> в файловом менеджере. Используйте отдельный логин Samba. Можно просматривать и скачивать файлы, а при разрешённой записи — загружать, переименовывать и удалять их. Для VPN в маршруты клиента должен входить адрес роутера; обнаружение в сетевом окружении работает в LAN.</Notice>
    <fieldset className="storage-settings" disabled={!admin} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      <Card title="Файловый сервер">
        <div className="form-grid">
          <Field label="Samba"><Switch checked={!!s.enabled} disabled={!installed} label="Включить доступ к файлам" onChange={v => edit(d => d.enabled = v)} /></Field>
          <Field label="Рабочая группа"><input value={s.workgroup || ""} placeholder="WORKGROUP" maxLength={15} onChange={e => edit(d => d.workgroup = e.target.value)} /></Field>
          <Field label="Сетевое окружение"><Switch checked={!!s.discovery} label="Обнаружение Windows (WS-Discovery)" onChange={v => edit(d => d.discovery = v)} /></Field>
        </div>
        <Field label="Локальные сети с доступом">{networks.length ? networks.map((n: any) => <Switch key={n.id} label={`${n.name} (${n.router_address})`} checked={(s.networks || []).includes(n.id)} onChange={v => toggle("networks", n.id, v)} />) : <Empty>Нет подходящих локальных сетей.</Empty>}</Field>
        <Field label="VPN-серверы с доступом" hint="WireGuard, OpenConnect, IKEv2 и L2TP. Права Samba действуют и для VPN-клиентов.">{vpns.length ? vpns.map((v: any) => <Switch key={v.id} label={`${v.name} (${v.type}, ${v.subnet})`} checked={(s.vpns || []).includes(v.id)} onChange={on => toggle("vpns", v.id, on)} />) : <Empty>Сначала включите VPN-сервер в разделе «VPN-доступ».</Empty>}</Field>
      </Card>
      <Card title="Накопители" subtitle="Настройка сохраняется по UUID и действует после повторного подключения" actions={<button className="btn" onClick={() => setRefresh(v => v + 1)}>Обновить</button>}>
        {error && <Notice tone="danger" title="Список дисков недоступен">{error}</Notice>}
        {devices.length === 0 && <Empty>Вставьте USB-диск с файловой системой ext2/3/4, FAT, exFAT или NTFS. Форматирование не выполняется.</Empty>}
        {devices.filter(d => !(s.volumes || []).some((v: any) => v.uuid.toLowerCase() === d.uuid.toLowerCase())).map(d => <div className="row" key={d.path} style={{ justifyContent: "space-between", margin: "0.8rem 0" }}><span><strong>{d.label || d.path}</strong> · {d.fstype} · {(Number(d.size) / 1073741824).toFixed(1)} ГБ · {d.tran || "диск"}<br /><small>{d.reason || d.uuid}</small></span><button className="btn" disabled={!installed || !d.available} onClick={() => edit(v => v.volumes.push({ id: newID("volume"), uuid: d.uuid, filesystem: d.fstype, enabled: true }))}>Подключить</button></div>)}
        {(s.volumes || []).map((v: any) => {
          const live = devices.find(d => d.uuid.toLowerCase() === v.uuid.toLowerCase());
          const mounted = live?.mountpoints?.some((p: string | null) => p?.startsWith("/srv/netos/"));
          return <div key={v.id} style={{ borderTop: "1px solid var(--line)", padding: "1rem 0" }}><div className="row" style={{ justifyContent: "space-between" }}><span><strong>{live?.label || v.uuid}</strong> · {v.filesystem}</span><Badge tone={mounted ? "ok" : "neutral"}>{mounted ? "Подключён в системе" : live ? "Диск обнаружен" : "Диск отсутствует"}</Badge></div><div className="row" style={{ marginTop: ".5rem" }}><Switch checked={!!v.enabled} disabled={!installed} label="Автоподключение" onChange={on => edit(d => { d.volumes.find((x: any) => x.id === v.id).enabled = on; if (!on) d.shares.forEach((x: any) => { if (x.volume === v.id) x.enabled = false; }); })} /><button className="btn ghost sm" disabled={v.enabled || (s.shares || []).some((x: any) => x.volume === v.id)} onClick={() => edit(d => d.volumes = d.volumes.filter((x: any) => x.id !== v.id))}>Забыть том</button></div></div>;
        })}
        <p className="muted">Для извлечения выключите автоподключение и примените изменения: связанные папки отключатся. Дождитесь успешного применения. Занятый диск не отключается принудительно. На ext2/3/4 сохраняются существующие права файлов: для записи нужен доступ системному пользователю netos-storage. NTFS, FAT и exFAT подключаются с правами этого пользователя.</p>
      </Card>
      <Card title="Пользователи Samba" subtitle="Отдельные учётные записи для доступа к файлам" actions={<button className="btn" onClick={() => edit(d => d.users.push({ id: newID("smbuser"), name: "", password: "" }))}>Добавить пользователя</button>}>
        {(s.users || []).length === 0 && <Empty>Добавьте логин и пароль для подключения к папкам.</Empty>}
        {(s.users || []).map((u: any) => <div className="form-grid" key={u.id}><Field label="Логин"><input value={u.name} maxLength={20} autoComplete="off" onChange={e => edit(d => d.users.find((x: any) => x.id === u.id).name = e.target.value)} /></Field><Field label="Пароль" hint="Минимум 8 символов. Пустое поле сохраняет ранее заданный пароль."><input type="password" autoComplete="new-password" value={u.password || ""} onChange={e => edit(d => d.users.find((x: any) => x.id === u.id).password = e.target.value)} /></Field><Field label="Действия"><button className="btn ghost" disabled={(s.shares || []).some((sh: any) => (sh.users || []).includes(u.id))} onClick={() => edit(d => d.users = d.users.filter((x: any) => x.id !== u.id))}>Удалить</button></Field></div>)}
      </Card>
      <Card title="Сетевые папки" subtitle="Одна папка открывает содержимое выбранного тома" actions={<button className="btn" disabled={!(s.volumes || []).length || !(s.users || []).length} onClick={() => edit(d => d.shares.push({ id: newID("share"), name: "USB" + (d.shares.length + 1), volume: d.volumes.find((v: any) => v.enabled)?.id || "", enabled: false, read_only: true, users: [] }))}>Добавить папку</button>}>
        {(s.shares || []).length === 0 && <Empty>Выберите том и создайте сетевую папку.</Empty>}
        {(s.shares || []).map((sh: any) => {
          const update = (fn: (x: any) => void) => edit(d => fn(d.shares.find((x: any) => x.id === sh.id)));
          return <div key={sh.id} style={{ borderTop: "1px solid var(--line)", padding: "1rem 0" }}><div className="row" style={{ justifyContent: "space-between" }}><span className="mono">{`\\\\${server}\\${sh.name}`}</span><div className="row"><Switch label="Опубликовать" checked={!!sh.enabled} disabled={!installed} onChange={v => update(x => x.enabled = v)} /><button className="btn ghost sm" disabled={sh.enabled} onClick={() => edit(d => d.shares = d.shares.filter((x: any) => x.id !== sh.id))}>Удалить</button></div></div><div className="form-grid"><Field label="Имя папки"><input value={sh.name} maxLength={20} onChange={e => update(x => x.name = e.target.value)} /></Field><Field label="Том"><select value={sh.volume} onChange={e => update(x => x.volume = e.target.value)}><option value="">Выберите том</option>{(s.volumes || []).map((v: any) => <option key={v.id} value={v.id} disabled={!v.enabled}>{devices.find(d => d.uuid === v.uuid)?.label || v.uuid}{!v.enabled ? " — отключён" : ""}</option>)}</select></Field><Field label="Права"><Switch label="Только чтение" checked={!!sh.read_only} onChange={v => update(x => x.read_only = v)} /></Field></div><Field label="Кто может подключаться">{(s.users || []).map((u: any) => <Switch key={u.id} label={u.name || "Без имени"} checked={(sh.users || []).includes(u.id)} onChange={on => update(x => x.users = on ? [...(x.users || []), u.id] : (x.users || []).filter((id: string) => id !== u.id))} />)}</Field></div>;
        })}
      </Card>
    </fieldset>
  </>;
}
