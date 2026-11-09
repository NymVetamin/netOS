import { useEffect, useRef, useState } from "react";
import { api } from "./api";

export function WakeClient({ mac, network, networks }: { mac: string; network?: string; networks: any[] }) {
  const [selected, setSelected] = useState(network || (networks.length === 1 ? networks[0].id : ""));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => { pending.current?.abort(); }, []);
  async function wake() {
    if (pending.current || !selected) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true); setMessage("");
    try {
      const result = await api.wakeClient(mac, selected, controller.signal);
      if (!controller.signal.aborted) setMessage(`Пакет отправлен через ${result.interface}. Это не подтверждает пробуждение устройства.`);
    } catch (error: any) {
      if (!controller.signal.aborted) setMessage(error.message || String(error));
    } finally {
      pending.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return <div>
    <div className="row-actions">
      <select aria-label="Сегмент Wake-on-LAN" value={selected} disabled={busy} onChange={e => { setSelected(e.target.value); setMessage(""); }}>
        <option value="">Выберите локальный сегмент</option>
        {networks.map(n => <option key={n.id} value={n.id}>{n.name || n.id}</option>)}
      </select>
      <button className="btn sm" disabled={busy || !networks.some(n => n.id === selected)} onClick={wake}>{busy ? "Отправка…" : "Разбудить (Wake-on-LAN)"}</button>
    </div>
    <p className="hint">На устройстве должен быть включён Wake-on-LAN. Пакет отправляется сразу, через применённые настройки сети.</p>
    {message && <p role="status">{message}</p>}
  </div>;
}
