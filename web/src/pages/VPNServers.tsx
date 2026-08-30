import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Notice, Switch } from "../ui";

type Props = { config: any; patch: (mutate: (draft: any) => void) => void };
type ClientSecret = { privateKey: string; serverPublicKey: string };

function randomHex(bytes: number) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Array.from(value, (item) => item.toString(16).padStart(2, "0")).join("");
}

function randomWireGuardKey() {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  let binary = "";
  value.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary);
}

function wireGuardClientConfig(server: any, peer: any, privateKey: string, serverPublicKey: string) {
  const dns = (server.config?.client_dns || []).length
    ? `DNS = ${server.config.client_dns.join(", ")}\n`
    : "";
  const mtu = server.config?.mtu ? `MTU = ${server.config.mtu}\n` : "";
  const allowed = (server.config?.client_allowed_ips || []).length
    ? server.config.client_allowed_ips
    : ["0.0.0.0/0"];
  const address = String(peer.address || "").includes("/") ? peer.address : `${peer.address}/32`;
  const preshared = peer.credentials?.preshared_key
    ? `PresharedKey = ${peer.credentials.preshared_key}\n`
    : "";
  return `[Interface]\nPrivateKey = ${privateKey}\nAddress = ${address}\n${dns}${mtu}\n[Peer]\nPublicKey = ${serverPublicKey}\n${preshared}Endpoint = ${server.config?.public_endpoint || ""}\nAllowedIPs = ${allowed.join(", ")}\nPersistentKeepalive = 25\n`;
}

export function VPNServersPage({ config, patch }: Props) {
  const servers = config.vpn_servers || [];
  const wireguardInstalled = (config.components || []).some((item: any) => item.id === "wireguard" && item.installed);
  const xrayInstalled = (config.components || []).some((item: any) => item.id === "xray" && item.installed);
  const ocservInstalled = (config.components || []).some((item: any) => item.id === "ocserv" && item.installed);
	const strongswanInstalled = (config.components || []).some((item: any) => item.id === "strongswan" && item.installed);
  const [clientSecrets, setClientSecrets] = useState<Record<string, ClientSecret>>({});
  const [error, setError] = useState("");

  async function addServer(type: "wireguard" | "xray" | "ocserv" | "ikev2") {
    setError("");
    let generatedWireGuardKey = "";
    if (type === "wireguard") {
      try {
        generatedWireGuardKey = (await api.wireGuardKeypair()).private_key;
      } catch (err: any) {
        setError(err?.message || "Не удалось безопасно создать ключ WireGuard-сервера");
        return;
      }
    }
    patch((draft) => {
      draft.vpn_servers = draft.vpn_servers || [];
      const used = new Set(draft.vpn_servers.map((item: any) => item.index));
      let index = 1;
      while (used.has(index)) index++;
      const common = { id: `${type}-server-${Date.now()}`, index, enabled: false, type, subnet: `10.${8 + index}.0.1/24`, default_channel: "direct", peers: [] };
      const server = type === "wireguard" ? {
        ...common, name: `WireGuard ${index}`, port: 51819 + index,
        config: { private_key: generatedWireGuardKey, mtu: 1420, public_endpoint: `${window.location.hostname}:${51819 + index}`, client_dns: [], client_allowed_ips: ["0.0.0.0/0"] },
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
    <div className="page-head"><h1>VPN-доступ</h1><p>Безопасное подключение телефонов и компьютеров к роутеру из интернета</p></div>
    {error && <Notice tone="danger" title="Не удалось выполнить действие">{error}</Notice>}
	{!wireguardInstalled && !xrayInstalled && !ocservInstalled && !strongswanInstalled && <Notice tone="info" title="Нужен VPN-компонент">Установите нужный VPN-компонент в разделе «Компоненты». Черновики серверов можно подготовить заранее.</Notice>}
	<Card title="VPN-доступ" subtitle="Создайте сервер, затем выдавайте каждому устройству отдельный готовый профиль" actions={<div className="row wrap vpn-add-actions"><button className="btn primary" onClick={() => void addServer("wireguard")}>Добавить WireGuard</button><button className="btn" onClick={() => void addServer("xray")}>Добавить Reality</button><button className="btn" onClick={() => void addServer("ikev2")}>Добавить IKEv2</button><button className="btn" onClick={() => void addServer("ocserv")}>Добавить OpenConnect</button></div>}>
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
      <Field label="Flow"><select value={cfg.flow ?? "xtls-rprx-vision"} onChange={(e) => setConfig("flow", e.target.value)}><option value="xtls-rprx-vision">XTLS Vision</option><option value="">Без flow</option></select></Field>
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
  const [addingClient, setAddingClient] = useState(false);
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });

  async function generateServerKey() {
    setError("");
    if ((server.peers || []).length > 0 && !window.confirm("Перевыпуск ключа сервера отключит все ранее выданные профили. Продолжить?")) return;
    try {
      const pair = await api.wireGuardKeypair();
      setConfig("private_key", pair.private_key);
      setClientSecrets((old: Record<string, ClientSecret>) => {
        const next = { ...old };
        (server.peers || []).forEach((peer: any) => delete next[peer.id]);
        return next;
      });
    } catch (err: any) { setError(err?.message || "Генерация ключа завершилась ошибкой"); }
  }

  async function addPeer() {
    setError("");
    setAddingClient(true);
    try {
      const serverPair = await api.wireGuardKeypair(cfg.private_key || undefined);
      const clientPair = await api.wireGuardKeypair();
      const id = `peer-${crypto.randomUUID()}`;
      const prefix = String(server.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      const used = new Set((server.peers || []).map((peer: any) => peer.address));
      let host = 2;
      while (used.has(`${prefix}.${host}`) && host < 255) host++;
      if (host >= 255) throw new Error("В адресном пуле WireGuard не осталось свободных адресов");
      const endpoint = cfg.public_endpoint || `${window.location.hostname}:${server.port || 51820}`;
      const peer = {
        id,
        name: `Устройство ${(server.peers || []).length + 1}`,
        enabled: true,
        address: `${prefix}.${host}`,
        channel: "",
        credentials: { public_key: clientPair.public_key, preshared_key: randomWireGuardKey() },
        comment: "",
      };
      update((draft) => {
        draft.config = draft.config || {};
        draft.config.private_key = serverPair.private_key || draft.config.private_key;
        draft.config.public_endpoint = endpoint;
        draft.peers = draft.peers || [];
        draft.peers.push(peer);
      });
      setClientSecrets((old: Record<string, ClientSecret>) => ({
        ...old,
        [id]: {
          privateKey: clientPair.private_key,
          serverPublicKey: serverPair.public_key,
        },
      }));
    } catch (err: any) {
      setError(err?.message || "Не удалось создать готовый профиль WireGuard");
    } finally {
      setAddingClient(false);
    }
  }

  return <form className="vpn-server" onSubmit={(event) => event.preventDefault()}>
    {!installed && <Notice tone="info" title="Нужен компонент WireGuard">Установите WireGuard в разделе «Компоненты» перед включением сервера. Профили клиентов можно подготовить заранее.</Notice>}
    <div className="server-head">
      <div className="row"><strong>{server.name}</strong><Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "работает" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!server.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
    </div>
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-подсеть" hint="Адрес роутера и маска, например 10.9.0.1/24"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="UDP-порт"><input type="number" min={1} max={65535} value={server.port || 51820} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Адрес подключения" hint="Домен или внешний IP роутера с портом"><input className="mono" placeholder="vpn.example.com:51820" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1420} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="DNS в профиле" hint="Необязательно; по одному адресу в строке"><textarea className="mono" value={(cfg.client_dns || []).join("\n")} onChange={(e) => setConfig("client_dns", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Трафик через VPN" hint="0.0.0.0/0 — направлять весь интернет через VPN"><textarea className="mono" value={(cfg.client_allowed_ips || ["0.0.0.0/0"]).join("\n")} onChange={(e) => setConfig("client_allowed_ips", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Ключ сервера" hint="Создаётся автоматически и хранится только на роутере"><div className="row"><input aria-label="Закрытый ключ сервера" className="mono" type="password" autoComplete="new-password" value={cfg.private_key || ""} readOnly /><button type="button" className="btn sm" onClick={generateServerKey}>Перевыпустить</button></div></Field>
    </div>
    <div className="section-head"><div><strong>Устройства</strong><div className="hint">Одно нажатие создаёт ключи, адрес и готовый профиль</div></div><button type="button" className="btn primary" disabled={addingClient} onClick={() => void addPeer()}>{addingClient ? "Создаём профиль…" : "Добавить устройство"}</button></div>
    {(server.peers || []).length === 0 ? <Empty>Добавьте телефон, ноутбук или другой роутер — netOS сам подготовит всё необходимое.</Empty> : (server.peers || []).map((peer: any) =>
      <PeerEditor key={peer.id} server={server} peer={peer} channels={channels} update={update} secret={clientSecrets[peer.id]} setSecret={(value: ClientSecret) => setClientSecrets((old: Record<string, ClientSecret>) => ({ ...old, [peer.id]: value }))} removeSecret={() => setClientSecrets((old: Record<string, ClientSecret>) => { const next = { ...old }; delete next[peer.id]; return next; })} setError={setError} />)}
  </form>;
}

function PeerEditor({ server, peer, channels, update, secret, setSecret, removeSecret, setError }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  const preparedConfig = secret ? wireGuardClientConfig(server, peer, secret.privateKey, secret.serverPublicKey) : "";
  async function generateClient() {
    setError("");
    try {
      if (!server.config?.public_endpoint) throw new Error("Сначала укажите адрес подключения к VPN-серверу");
      if (!server.config?.private_key) throw new Error("Сначала создайте ключ WireGuard-сервера");
      const [pair, serverPair] = await Promise.all([
        api.wireGuardKeypair(),
        api.wireGuardKeypair(server.config.private_key),
      ]);
      const presharedKey = randomWireGuardKey();
      edit((draft) => {
        draft.enabled = true;
        draft.credentials = draft.credentials || {};
        draft.credentials.public_key = pair.public_key;
        draft.credentials.preshared_key = presharedKey;
      });
      setSecret({ privateKey: pair.private_key, serverPublicKey: serverPair.public_key });
    } catch (err: any) { setError(err?.message || "Генерация ключа завершилась ошибкой"); }
  }
  function download() {
    if (!preparedConfig) { setError("Закрытый ключ клиента не хранится на роутере. Перевыпустите профиль для этого устройства."); return; }
    const url = URL.createObjectURL(new Blob([preparedConfig], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${peer.name || peer.id}.conf`;
    link.click();
    URL.revokeObjectURL(url);
  }
  async function copyConfig() {
    if (!preparedConfig) return;
    try { await navigator.clipboard.writeText(preparedConfig); } catch { setError("Браузер не разрешил скопировать профиль. Скачайте файл конфигурации."); }
  }
  return <div className="peer-card">
    <div className="peer-head"><div className="row wrap"><strong>{peer.name}</strong>{secret ? <Badge tone="ok">профиль готов</Badge> : <Badge tone="warn">нужно перевыпустить</Badge>}</div><div className="row wrap"><Switch checked={!!peer.enabled} label="Доступ разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={peer.enabled} onClick={() => { removeSecret(); update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); }); }}>Удалить</button></div></div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Название устройства"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-адрес"><input className="mono" value={peer.address || ""} onChange={(e) => edit((draft) => draft.address = e.target.value)} /></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
    </div>
    {secret ? <div className="client-package">
      <div className="qr-card"><QRCodeSVG value={preparedConfig} size={176} level="M" marginSize={2} title={`WireGuard-профиль ${peer.name || peer.id}`} /></div>
      <div className="client-package-copy"><strong>Профиль готов к импорту</strong><p>Отсканируйте QR-код в приложении WireGuard или скачайте файл. Закрытый ключ показан только в этой вкладке и не сохраняется на роутере.</p><div className="row wrap"><button type="button" className="btn primary" onClick={download}>Скачать .conf</button><button type="button" className="btn" onClick={() => void copyConfig()}>Скопировать</button><button type="button" className="btn ghost" onClick={() => void generateClient()}>Перевыпустить</button></div></div>
    </div> : <Notice tone="warn" title="Готовый профиль нельзя восстановить">Роутер хранит только публичный ключ. Нажмите «Перевыпустить профиль», чтобы безопасно создать новый закрытый ключ, QR-код и файл конфигурации.<div style={{ marginTop: "0.65rem" }}><button type="button" className="btn" onClick={() => void generateClient()}>Перевыпустить профиль</button></div></Notice>}
    <details className="advanced"><summary>Технические данные</summary><div className="form-grid"><Field label="Публичный ключ устройства"><input className="mono" value={peer.credentials?.public_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.public_key = e.target.value; })} /></Field><Field label="Предварительный общий ключ"><input className="mono" type="password" autoComplete="off" value={peer.credentials?.preshared_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.preshared_key = e.target.value; })} /></Field></div></details>
  </div>;
}
