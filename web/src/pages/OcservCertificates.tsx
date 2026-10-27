import { confirmAction } from "../confirm";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Field, Notice, Switch } from "../ui";
import { createCertificateSubscriptions, createServerCertificateSubscriptions } from "../certificatePolling";

const subscribeCertificates = createCertificateSubscriptions(api.ocCertificates);
const subscribeServerCertificates = createServerCertificateSubscriptions(api.certificates);

export function OcservClientCertificate({ server, peer, active }: { server: any; peer: any; active: boolean }) {
  const [status, setStatus] = useState<any>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const statusRevision = useRef(0);
  useEffect(() => {
    setPassword(""); setStatus(null); setError("");
  }, [server.id, peer.id, server.config?.auth_mode]);
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const unsubscribe = subscribeCertificates(server.id, request => {
      const revision = statusRevision.current;
      void request.then(values => {
        if (alive && revision === statusRevision.current) { setStatus(values[peer.id] || { pending: true }); setLoadError(""); }
      }).catch(err => { if (alive && revision === statusRevision.current) setLoadError(err.message); });
    });
    return () => { alive = false; unsubscribe(); };
  }, [active, server.id, peer.id, server.config?.auth_mode]);
  useEffect(() => { setPassword(""); }, [status?.serial, status?.revoked]);
  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError("");
    try { await fn(); } catch (err) { setError(err instanceof Error ? err.message : "Не удалось выполнить действие"); }
    finally { setBusy(false); }
  };
  const download = async () => {
    const response = await fetch(`/api/vpn-servers/${encodeURIComponent(server.id)}/peers/${encodeURIComponent(peer.id)}/certificate/download`, { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) { const body = await response.json(); throw new Error(body.error || body.message || "Не удалось скачать P12"); }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a"); link.href = url; link.download = "openconnect-client.p12"; link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const change = async (action: "revoke" | "reissue") => {
    const question = action === "revoke" ? "Отозвать сертификат? Старый P12 больше не будет работать." : "Перевыпустить профиль? Старый P12 будет отозван. Клиенту потребуется новый файл.";
    if (!await confirmAction(`${question} OpenConnect будет перезапущен; подключённые к этому серверу клиенты переподключатся.`, action === "revoke" ? "Отозвать сертификат" : "Перевыпустить профиль")) return;
    void run(async () => {
      // An older shared read must not overwrite the result of a revocation.
      statusRevision.current++;
      try { setPassword(""); setStatus(await api.ocCertificateAction(server.id, peer.id, action)); }
      finally { statusRevision.current++; }
    });
  };
  return <div className="peer-profile">
    <strong>Сертификат клиента</strong>
    {status?.pending && <p className="hint">Сначала примените настройки сервера и устройства — после этого будет доступен P12.</p>}
    {status && !status.pending && <div className="hint">{status.revoked ? "Отозван" : `Действует до ${new Date(status.expires).toLocaleString()}`} · Логин: <span className="mono">{status.username}</span></div>}
    <div className="row-actions">
      <button type="button" className="btn sm" disabled={busy || !status || status.pending || status.revoked} onClick={() => void run(download)}>Скачать P12</button>
      <button type="button" className="btn ghost sm" disabled={busy || !status || status.pending || status.revoked} onClick={() => password ? setPassword("") : void run(async () => setPassword((await api.ocCertificatePassword(server.id, peer.id)).password))}>{password ? "Скрыть пароль P12" : "Показать пароль P12"}</button>
      <button type="button" className="btn ghost sm" disabled={busy || !status || status.pending} onClick={() => change("reissue")}>Перевыпустить профиль</button>
      <button type="button" className="btn ghost sm" disabled={busy || !status || status.pending || status.revoked} onClick={() => change("revoke")}>Отозвать сертификат</button>
    </div>
    {password && <Field label="Пароль для импорта P12"><div className="row-actions"><input className="mono" readOnly value={password} /><button type="button" className="btn sm" onClick={() => void run(() => navigator.clipboard.writeText(password))}>Копировать</button></div></Field>}
    <p className="hint">Файл и пароль можно получить повторно. Импортируйте P12 в клиент OpenConnect. Пароль P12 защищает файл и не заменяет пароль входа в VPN.</p>
    {error && <Notice tone="warn" title="Сертификат клиента">{error}</Notice>}
    {loadError && <Notice tone="warn" title="Не удалось проверить сертификат">{loadError}</Notice>}
  </div>;
}

export function OcservTLSSettings({ server, setConfig }: { server: any; setConfig: (key: string, value: unknown) => void }) {
  const tls = server.config?.tls || { mode: "selfsigned" };
  const [error, setError] = useState("");
  const [status, setStatus] = useState<any>(null);
  const edit = (field: string, value: unknown) => setConfig("tls", { ...tls, [field]: value });
  useEffect(() => {
    let alive = true;
    const unsubscribe = subscribeServerCertificates(request => {
      void request.then(items => { if (alive) setStatus(items.get(`vpn:${server.id}`)); }).catch(() => {});
    });
    return () => { alive = false; unsubscribe(); };
  }, [server.id]);
  const upload = async (field: string, file?: File) => {
    if (!file) return;
    try {
      if (file.size > 128 * 1024) throw new Error("Файл слишком большой: максимум 128 КБ");
      const value = await file.text();
      if (!value.includes("-----BEGIN ")) throw new Error("Нужен файл в формате PEM");
      edit(field, value); setError("");
    } catch (err) { setError(err instanceof Error ? err.message : "Не удалось прочитать файл"); }
  };
  return <>
    <div className="form-grid">
      <Field label="Сертификат OpenConnect"><select value={tls.mode || "selfsigned"} onChange={(e) => edit("mode", e.target.value)}>
        <option value="selfsigned">Самоподписанный</option>
        <option value="panel">Использовать сертификат netOS</option>
        <option value="acme">Let’s Encrypt для VPN</option>
        <option value="custom">Загрузить свой сертификат</option>
      </select></Field>
      {tls.mode === "acme" && <>
        <Field label="Домен сертификата VPN" hint="Должен совпадать с доменом публичного адреса OpenConnect"><input value={tls.domain || ""} placeholder="vpn.example.com" onChange={(e) => edit("domain", e.target.value.trim())} /></Field>
        <Field label="Email для Let’s Encrypt"><input type="email" value={tls.email || ""} onChange={(e) => edit("email", e.target.value.trim())} /></Field>
        <Field label="Условия выпуска"><Switch checked={!!tls.accept_tos} label="Принимаю условия Let’s Encrypt" onChange={(value) => edit("accept_tos", value)} /></Field>
      </>}
      {tls.mode === "custom" && <>
        <Field label="Сертификат и цепочка PEM" hint={tls.cert_pem ? "Сертификат загружен" : "Файл ещё не выбран"}><input type="file" accept=".pem,.crt,.cer" onChange={(e) => { void upload("cert_pem", e.target.files?.[0]); e.target.value = ""; }} /></Field>
        <Field label="Закрытый ключ PEM" hint={tls.private_key || server.secrets_set?.["tls.private_key"] ? "•••••••• — ключ задан. Выберите файл только для замены." : "Ключ не задан"}><input type="file" accept=".pem,.key" onChange={(e) => { void upload("private_key", e.target.files?.[0]); e.target.value = ""; }} /></Field>
      </>}
    </div>
    {tls.mode === "panel" && <Notice tone="info" title="Общий сертификат">Сертификат netOS должен покрывать домен публичного адреса VPN. Продление выполняется совместно; повторный выпуск для того же домена не нужен.</Notice>}
    {tls.mode === "acme" && <Notice tone="info" title="Автоматический выпуск и продление">Домен должен вести на этот роутер, а TCP-порт 80 — быть доступен из интернета. Выпуск начнётся при применении. Продление работает в фоне.</Notice>}
    {status?.expires && tls.mode !== "selfsigned" && <div className="hint">Применённый сертификат действует до {new Date(status.expires).toLocaleString()}. Отпечаток: <span className="mono">{status.fingerprint}</span></div>}
    {status?.error && <Notice tone="warn" title="Не удалось обновить сертификат">{status.error}</Notice>}
    {error && <Notice tone="danger" title="Не удалось загрузить сертификат">{error}</Notice>}
  </>;
}
