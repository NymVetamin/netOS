import { useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Notice, Switch } from "../ui";

type Props = { config: any; patch: (mutate: (draft: any) => void) => void };

function randomHex(bytes: number) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Array.from(value, (item) => item.toString(16).padStart(2, "0")).join("");
}

export function VPNServersPage({ config, patch }: Props) {
  const servers = config.vpn_servers || [];
  const wireguardInstalled = (config.components || []).some((item: any) => item.id === "wireguard" && item.installed);
  const xrayInstalled = (config.components || []).some((item: any) => item.id === "xray" && item.installed);
  const ocservInstalled = (config.components || []).some((item: any) => item.id === "ocserv" && item.installed);
	const strongswanInstalled = (config.components || []).some((item: any) => item.id === "strongswan" && item.installed);
  const [clientSecrets, setClientSecrets] = useState<Record<string, string>>({});
  const [error, setError] = useState("");

	function addServer(type: "wireguard" | "xray" | "ocserv" | "ikev2") {
    patch((draft) => {
      draft.vpn_servers = draft.vpn_servers || [];
      const used = new Set(draft.vpn_servers.map((item: any) => item.index));
      let index = 1;
      while (used.has(index)) index++;
      const common = { id: `${type}-server-${Date.now()}`, index, enabled: false, type, subnet: `10.${8 + index}.0.1/24`, default_channel: "direct", peers: [] };
      const server = type === "wireguard" ? {
        ...common, name: `WireGuard ${index}`, port: 51819 + index,
        config: { private_key: "", mtu: 1420, public_endpoint: "", client_dns: [], client_allowed_ips: ["0.0.0.0/0"] },
      } : type === "xray" ? {
        ...common, name: `VLESS Reality ${index}`, port: 443,
        config: { private_key: "", public_endpoint: "", destination: "www.cloudflare.com:443", server_names: ["www.cloudflare.com"], short_ids: [randomHex(8)], flow: "xtls-rprx-vision" },
		} : type === "ocserv" ? {
        ...common, name: `OpenConnect ${index}`, port: 443,
        config: { public_endpoint: "", dns: [], routes: [], mtu: 1380, banner: "netOS VPN" },
		} : {
			...common, name: `IKEv2 ${index}`, port: 500,
			config: { public_endpoint: "", server_identity: config.system?.hostname || "netos", dns: [], split_routes: [], mtu: 1400 },
      };
      draft.vpn_servers.push(server);
    });
  }

  return <>
    <div className="page-head"><h1>VPN-серверы</h1><p>Безопасный удалённый доступ к роутеру и интернету через него</p></div>
    {error && <Notice tone="danger" title="Не удалось выполнить действие">{error}</Notice>}
	{!wireguardInstalled && !xrayInstalled && !ocservInstalled && !strongswanInstalled && <Notice tone="info" title="Нужен VPN-компонент">Установите нужный VPN-компонент в разделе «Компоненты». Черновики серверов можно подготовить заранее.</Notice>}
	<Card title="Входящие подключения" subtitle="Каждому клиенту назначается отдельный ключ или пароль и канал выхода" actions={<div className="row wrap vpn-add-actions"><button className="btn ghost" onClick={() => addServer("wireguard")}>+ WireGuard</button><button className="btn ghost" onClick={() => addServer("xray")}>+ Reality</button><button className="btn ghost" onClick={() => addServer("ikev2")}>+ IKEv2</button><button className="btn" onClick={() => addServer("ocserv")}>+ OpenConnect</button></div>}>
      {servers.length === 0 ? <Empty>VPN-серверов пока нет.</Empty> : servers.map((server: any) =>
        server.type === "wireguard" ? <WireGuardServer key={server.id} server={server} config={config} installed={wireguardInstalled} patch={patch} clientSecrets={clientSecrets} setClientSecrets={setClientSecrets} setError={setError} /> :
        server.type === "xray" ? <XrayServer key={server.id} server={server} config={config} installed={xrayInstalled} patch={patch} setError={setError} /> :
        server.type === "ocserv" ? <OcservServer key={server.id} server={server} config={config} installed={ocservInstalled} patch={patch} /> :
		server.type === "ikev2" ? <IKEv2Server key={server.id} server={server} config={config} installed={strongswanInstalled} patch={patch} /> :
          <Notice key={server.id} tone="warn" title={`Сервер ${server.type} пока недоступен`}>Сохранённый черновик не будет запущен.</Notice>)}
    </Card>
  </>;
}

function IKEv2Server({ server, config, installed, patch }: any) {
	const cfg = server.config || {};
	const channels = (config.channels || []).filter((item: any) => item.enabled);
	const referenced = (config.policies || []).some((item: any) => item.vpn_server === server.id);
	const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
	const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
	function addPeer() {
		update((draft) => {
			const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
			draft.peers = draft.peers || [];
			const number = draft.peers.length + 1;
			draft.peers.push({ id: `peer-${Date.now()}`, name: `Пользователь ${number}`, enabled: false, address: `${prefix}.${number + 1}`, channel: "", credentials: { username: `user${number}`, password: "" }, comment: "" });
		});
	}
	return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
		{!installed && <Notice tone="info" title="Нужен компонент strongSwan">Установите strongSwan перед включением сервера IKEv2.</Notice>}
		<div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
			<div className="row"><strong>{server.name}</strong><Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "работает" : "черновик"}</Badge></div>
			<div className="row"><Switch checked={!!server.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
		</div>
		<div className="form-grid">
			<Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
			<Field label="Пул адресов" hint="Адрес сервера и маска"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
			<Field label="Публичный адрес" hint="Домен или IP без порта"><input className="mono" placeholder="vpn.example.com" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
			<Field label="Идентификатор сервера" hint="Должен совпадать с адресом в профиле клиента"><input className="mono" value={cfg.server_identity || ""} onChange={(e) => setConfig("server_identity", e.target.value)} /></Field>
			<Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
			<Field label="MTU"><input type="number" min={1280} max={9000} value={cfg.mtu || 1400} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
			<Field label="DNS для клиентов" hint="По одному IPv4-адресу в строке"><textarea className="mono" value={(cfg.dns || []).join("\n")} onChange={(e) => setConfig("dns", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
			<Field label="Маршруты" hint="Пусто — весь интернет через VPN"><textarea className="mono" value={(cfg.split_routes || []).join("\n")} onChange={(e) => setConfig("split_routes", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
		</div>
		<Notice tone="info" title="Настройка клиента">Импортируйте сертификат как доверенный корневой, затем создайте IKEv2-подключение к публичному адресу с логином и паролем EAP-MSCHAPv2. <button type="button" className="btn ghost sm" disabled={!server.enabled} onClick={() => window.location.assign(`/api/vpn-servers/${encodeURIComponent(server.id)}/certificate`)}>Скачать сертификат</button></Notice>
		<div className="row" style={{ justifyContent: "space-between", marginTop: "1.2rem" }}><strong>Пользователи</strong><button type="button" className="btn ghost sm" onClick={addPeer}>Добавить пользователя</button></div>
		{(server.peers || []).length === 0 ? <Empty>Добавьте пользователя IKEv2.</Empty> : (server.peers || []).map((peer: any) =>
			<OcservPeer key={peer.id} peer={peer} channels={channels} update={update} />)}
	</form>;
}

function OcservServer({ server, config, installed, patch }: any) {
  const cfg = server.config || {};
  const channels = (config.channels || []).filter((item: any) => item.enabled);
  const referenced = (config.policies || []).some((item: any) => item.vpn_server === server.id);
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
  function addPeer() {
    update((draft) => {
      const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      draft.peers = draft.peers || [];
      const number = draft.peers.length + 1;
      draft.peers.push({ id: `peer-${Date.now()}`, name: `Пользователь ${number}`, enabled: false, address: `${prefix}.${number + 1}`, channel: "", credentials: { username: `user${number}`, password: "" }, comment: "" });
    });
  }
  return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
    {!installed && <Notice tone="info" title="Нужен компонент ocserv">Установите ocserv перед включением сервера OpenConnect.</Notice>}
    <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
      <div className="row"><strong>{server.name}</strong><Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "работает" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!server.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
    </div>
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="Пул адресов" hint="Адрес сервера и маска"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="TCP/UDP-порт"><input type="number" min={1} max={65535} value={server.port || 443} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Публичный адрес" hint="vpn.example.com:443"><input className="mono" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1380} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="DNS для клиентов" hint="По одному IPv4-адресу в строке"><textarea className="mono" value={(cfg.dns || []).join("\n")} onChange={(e) => setConfig("dns", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Маршруты" hint="Пусто — весь интернет через VPN"><textarea className="mono" value={(cfg.routes || []).join("\n")} onChange={(e) => setConfig("routes", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Приветствие"><input value={cfg.banner || ""} onChange={(e) => setConfig("banner", e.target.value)} /></Field>
    </div>
    <Notice tone="info" title="Сертификат сервера">netOS автоматически выпускает отдельный самоподписанный сертификат. После первого применения импортируйте его в доверенные на клиентском устройстве. <button type="button" className="btn ghost sm" disabled={!server.enabled} onClick={() => window.location.assign(`/api/vpn-servers/${encodeURIComponent(server.id)}/certificate`)}>Скачать сертификат</button></Notice>
    <div className="row" style={{ justifyContent: "space-between", marginTop: "1.2rem" }}><strong>Пользователи</strong><button type="button" className="btn ghost sm" onClick={addPeer}>Добавить пользователя</button></div>
    {(server.peers || []).length === 0 ? <Empty>Добавьте пользователя OpenConnect.</Empty> : (server.peers || []).map((peer: any) =>
      <OcservPeer key={peer.id} peer={peer} channels={channels} update={update} />)}
  </form>;
}

function OcservPeer({ peer, channels, update }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  return <div style={{ borderTop: "1px solid var(--line)", marginTop: "1rem", paddingTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between" }}><strong>{peer.name}</strong><div className="row"><Switch checked={!!peer.enabled} label="Разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={peer.enabled} onClick={() => update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); })}>Удалить</button></div></div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Название"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      <Field label="Логин"><input className="mono" autoComplete="off" value={peer.credentials?.username || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.username = e.target.value; })} /></Field>
      <Field label="Пароль" hint="Не меньше 8 символов"><input type="password" autoComplete="new-password" value={peer.credentials?.password || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.password = e.target.value; })} /></Field>
      <Field label="VPN-адрес"><input className="mono" value={peer.address || ""} onChange={(e) => edit((draft) => draft.address = e.target.value)} /></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
    </div>
  </div>;
}

function XrayServer({ server, config, installed, patch, setError }: any) {
  const cfg = server.config || {};
  const channels = (config.channels || []).filter((item: any) => item.enabled);
  const referenced = (config.policies || []).some((item: any) => item.vpn_server === server.id);
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });

  async function generateKey() {
    setError("");
    try {
      const pair = await api.xrayKeypair();
      setConfig("private_key", pair.private_key);
    } catch (err: any) { setError(err?.message || "Не удалось создать ключ Reality"); }
  }

  function addPeer() {
    update((draft) => {
      const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      draft.peers = draft.peers || [];
      draft.peers.push({ id: `peer-${Date.now()}`, name: `Устройство ${draft.peers.length + 1}`, enabled: false, address: `${prefix}.${draft.peers.length + 2}`, channel: "", credentials: { uuid: crypto.randomUUID() }, comment: "" });
    });
  }

  return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
    {!installed && <Notice tone="info" title="Нужен компонент Xray">Установите Xray перед включением этого сервера.</Notice>}
    <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
      <div className="row"><strong>{server.name}</strong><Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "работает" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!server.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
    </div>
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="TCP-порт"><input type="number" min={1} max={65535} value={server.port || 443} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Публичный адрес" hint="Домен или IP роутера с портом"><input className="mono" placeholder="vpn.example.com:443" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="Сайт-маскировка" hint="Доступный TLS-сайт с портом"><input className="mono" value={cfg.destination || ""} onChange={(e) => setConfig("destination", e.target.value)} /></Field>
      <Field label="Имена сервера (SNI)" hint="По одному домену в строке"><textarea className="mono" value={(cfg.server_names || []).join("\n")} onChange={(e) => setConfig("server_names", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Short ID" hint="Чётное число hex-символов, до 16"><textarea className="mono" value={(cfg.short_ids || []).join("\n")} onChange={(e) => setConfig("short_ids", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Flow"><select value={cfg.flow || "xtls-rprx-vision"} onChange={(e) => setConfig("flow", e.target.value)}><option value="xtls-rprx-vision">XTLS Vision</option><option value="">Без flow</option></select></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Закрытый ключ Reality" hint="Хранится в конфигурации с правами 0600"><div className="row"><input className="mono" type="password" autoComplete="new-password" value={cfg.private_key || ""} onChange={(e) => setConfig("private_key", e.target.value)} /><button type="button" className="btn ghost sm" onClick={generateKey}>Сгенерировать</button></div></Field>
    </div>
    <div className="row" style={{ justifyContent: "space-between", marginTop: "1.2rem" }}><strong>Клиенты</strong><button type="button" className="btn ghost sm" onClick={addPeer}>Добавить устройство</button></div>
    {(server.peers || []).length === 0 ? <Empty>Добавьте клиента и скачайте готовую ссылку подключения.</Empty> : (server.peers || []).map((peer: any) =>
      <XrayPeerEditor key={peer.id} server={server} peer={peer} channels={channels} update={update} setError={setError} />)}
  </form>;
}

function XrayPeerEditor({ server, peer, channels, update, setError }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  async function download() {
    const cfg = server.config || {};
    if (!cfg.private_key || !cfg.public_endpoint || !cfg.server_names?.[0] || !cfg.short_ids?.[0]) { setError("Заполните ключ, публичный адрес, SNI и Short ID сервера."); return; }
    try {
      const pair = await api.xrayKeypair(cfg.private_key);
      const query = new URLSearchParams({ encryption: "none", security: "reality", sni: cfg.server_names[0], fp: "chrome", pbk: pair.public_key, sid: cfg.short_ids[0], type: "tcp" });
      if (cfg.flow) query.set("flow", cfg.flow);
      const body = `vless://${peer.credentials?.uuid}@${cfg.public_endpoint}?${query.toString()}#${encodeURIComponent(peer.name || peer.id)}`;
      const url = URL.createObjectURL(new Blob([body + "\n"], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = `${peer.name || peer.id}.txt`; link.click(); URL.revokeObjectURL(url);
    } catch (err: any) { setError(err?.message || "Не удалось создать ссылку подключения"); }
  }
  return <div style={{ borderTop: "1px solid var(--line)", marginTop: "1rem", paddingTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between" }}><strong>{peer.name}</strong><div className="row"><Switch checked={!!peer.enabled} label="Разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={peer.enabled} onClick={() => update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); })}>Удалить</button></div></div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Устройство"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      <Field label="UUID клиента"><div className="row"><input className="mono" value={peer.credentials?.uuid || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.uuid = e.target.value; })} /><button type="button" className="btn ghost sm" onClick={() => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.uuid = crypto.randomUUID(); })}>Новый</button></div></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
    </div>
    <button type="button" className="btn sm" onClick={download}>Скачать VLESS-ссылку</button>
  </div>;
}

function WireGuardServer({ server, config, installed, patch, clientSecrets, setClientSecrets, setError }: any) {
  const cfg = server.config || {};
  const channels = (config.channels || []).filter((item: any) => item.enabled);
  const referenced = (config.policies || []).some((item: any) => item.vpn_server === server.id);
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });

  async function generateServerKey() {
    setError("");
    try {
      const pair = await api.wireGuardKeypair();
      setConfig("private_key", pair.private_key);
    } catch (err: any) { setError(err?.message || "Генерация ключа завершилась ошибкой"); }
  }

  function addPeer() {
    update((draft) => {
      const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      const used = new Set((draft.peers || []).map((peer: any) => peer.address));
      let host = 2;
      while (used.has(`${prefix}.${host}`) && host < 255) host++;
      draft.peers = draft.peers || [];
      draft.peers.push({ id: `peer-${Date.now()}`, name: `Устройство ${draft.peers.length + 1}`, enabled: false, address: `${prefix}.${host}`, channel: "", credentials: { public_key: "", preshared_key: "" }, comment: "" });
    });
  }

  return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
      <div className="row"><strong>{server.name}</strong><Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "работает" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!server.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
    </div>
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="Адрес сервера в VPN" hint="Например, 10.9.0.1/24"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="UDP-порт"><input type="number" min={1} max={65535} value={server.port || 51820} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Публичный адрес" hint="Домен или IP роутера с портом"><input className="mono" placeholder="vpn.example.com:51820" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1420} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="DNS для клиентов" hint="По одному адресу в строке"><textarea className="mono" value={(cfg.client_dns || []).join("\n")} onChange={(e) => setConfig("client_dns", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Маршруты клиента" hint="0.0.0.0/0 — весь интернет через VPN"><textarea className="mono" value={(cfg.client_allowed_ips || ["0.0.0.0/0"]).join("\n")} onChange={(e) => setConfig("client_allowed_ips", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Закрытый ключ сервера" hint="Хранится в конфигурации с правами 0600"><div className="row"><input className="mono" type="password" autoComplete="new-password" value={cfg.private_key || ""} onChange={(e) => setConfig("private_key", e.target.value)} /><button type="button" className="btn ghost sm" onClick={generateServerKey}>Сгенерировать</button></div></Field>
    </div>
    <div className="row" style={{ justifyContent: "space-between", marginTop: "1.2rem" }}><strong>Клиенты</strong><button type="button" className="btn ghost sm" onClick={addPeer}>Добавить устройство</button></div>
    {(server.peers || []).length === 0 ? <Empty>Добавьте телефон, ноутбук или другой роутер.</Empty> : (server.peers || []).map((peer: any) =>
      <PeerEditor key={peer.id} server={server} peer={peer} channels={channels} update={update} clientPrivate={clientSecrets[peer.id]} setClientPrivate={(value: string) => setClientSecrets((old: any) => ({ ...old, [peer.id]: value }))} setError={setError} />)}
  </form>;
}

function PeerEditor({ server, peer, channels, update, clientPrivate, setClientPrivate, setError }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  async function generateClient() {
    setError("");
    try {
      const pair = await api.wireGuardKeypair();
      edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.public_key = pair.public_key; });
      setClientPrivate(pair.private_key);
    } catch (err: any) { setError(err?.message || "Генерация ключа завершилась ошибкой"); }
  }
  async function download() {
    if (!clientPrivate) { setError("Закрытый ключ клиента не хранится на роутере. Сгенерируйте новую пару ключей для этого устройства."); return; }
    if (!server.config?.public_endpoint) { setError("Сначала укажите публичный адрес VPN-сервера."); return; }
    try {
      const serverPair = await api.wireGuardKeypair(server.config.private_key);
      const dns = (server.config.client_dns || []).length ? `DNS = ${server.config.client_dns.join(", ")}\n` : "";
      const allowed = (server.config.client_allowed_ips || []).length ? server.config.client_allowed_ips : ["0.0.0.0/0"];
      const body = `[Interface]\nPrivateKey = ${clientPrivate}\nAddress = ${peer.address}/32\n${dns}\n[Peer]\nPublicKey = ${serverPair.public_key}\nEndpoint = ${server.config.public_endpoint}\nAllowedIPs = ${allowed.join(", ")}\nPersistentKeepalive = 25\n`;
      const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = `${peer.name || peer.id}.conf`; link.click(); URL.revokeObjectURL(url);
    } catch (err: any) { setError(err?.message || "Не удалось создать конфигурацию клиента"); }
  }
  return <div style={{ borderTop: "1px solid var(--line)", marginTop: "1rem", paddingTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between" }}><div className="row"><strong>{peer.name}</strong>{clientPrivate && <Badge tone="accent">ключ готов — скачайте сейчас</Badge>}</div><div className="row"><Switch checked={!!peer.enabled} label="Разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={peer.enabled} onClick={() => update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); })}>Удалить</button></div></div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Устройство"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-адрес"><input className="mono" value={peer.address || ""} onChange={(e) => edit((draft) => draft.address = e.target.value)} /></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Публичный ключ клиента"><input className="mono" value={peer.credentials?.public_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.public_key = e.target.value; })} /></Field>
    </div>
    <div className="row"><button type="button" className="btn ghost sm" onClick={generateClient}>Новая пара ключей</button><button type="button" className="btn sm" disabled={!clientPrivate} onClick={download}>Скачать конфигурацию</button></div>
  </div>;
}
