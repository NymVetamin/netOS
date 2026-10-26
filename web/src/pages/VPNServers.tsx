import { CopyButton } from "../CopyButton";
import { realityClientConfig } from "../xrayProfile";
import { confirmAction } from "../confirm";
import { secretInput } from "../secrets";
import { OcservClientCertificate, OcservTLSSettings } from "./OcservCertificates";
import { createContext, useContext, useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { api, ApiError, formatMiB } from "../api";
import { effectiveWireGuardProfile, newWireGuardProfile, wireGuardClientConfig } from "../wireGuardProfiles";
import { newID } from "../id";
import { AddMenu, Badge, Card, Empty, Field, Notice, openOnCreate, Row, Rows, Switch } from "../ui";
import { Icon, vpnServerIcon } from "../icons";

type Props = { beforeRead: () => Promise<void>; config: any; patch: (mutate: (draft: any) => void) => void };
type ClientSecret = { publicKey: string; privateKey: string; serverPublicKey: string; presharedKey?: string };

const ClientCreators = createContext<{ current: Record<string, () => void | Promise<void>> }>({ current: {} });
function useClientCreator(id: string, create: () => void | Promise<void>) {
  const registry = useContext(ClientCreators);
  const latest = useRef(create);
  latest.current = create;
  useEffect(() => {
    registry.current[id] = () => latest.current();
    return () => { delete registry.current[id]; };
  }, [id, registry]);
}

function useClientStatuses(serverID: string) {
  const [clientStatus, setClientStatus] = useState<ClientStatus[]>([]);
  const [statusFailed, setStatusFailed] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const rows = await api.vpnClientStatus(serverID, controller.signal);
        if (!controller.signal.aborted) { setClientStatus(rows); setStatusFailed(false); }
      } catch { if (!controller.signal.aborted) { setClientStatus([]); setStatusFailed(true); } }
      finally { if (!controller.signal.aborted) timer = setTimeout(poll, 5000); }
    }
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [serverID]);
  return { clientStatus, statusFailed };
}

function ClientBadge({ server, peer, status }: any) {
  const state = !peer.enabled || !server.enabled ? "disabled" : status?.state || "unknown";
  const online = state === "recent" || state === "online";
  const label = state === "disabled" || state === "server_disabled" ? "Отключён"
    : online ? "Онлайн" : state === "idle" || state === "never" || state === "offline" ? "Оффлайн" : "Нет данных";
  return <span title={label === "Нет данных" ? "Нет сведений о текущем подключении клиента" : undefined}><Badge tone={online ? "ok" : "neutral"}>{label}</Badge>
    {(state === "idle" || state === "offline") && (status?.last_seen || status?.last_handshake) > 0 && <small className="faint" style={{ display: "block" }}>Последняя связь: {new Date((status.last_seen || status.last_handshake) * 1000).toLocaleString("ru-RU")}</small>}
  </span>;
}

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

function saveClientFile(name: string, body: string) {
  const url = URL.createObjectURL(new Blob([body], { type: name.endsWith(".json") ? "application/json;charset=utf-8" : "text/plain;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

async function certificateFingerprint(pem: string) {
  const encoded = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/)?.[1].replace(/\s/g, "");
  if (!encoded) throw new Error("Не удалось прочитать TLS-сертификат сервера");
  const der = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
  return Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
}


function VPNCertificate({ server }: { server: any }) {
  const [error, setError] = useState("");
  const [certificateBusy, setCertificateBusy] = useState(false);

  async function downloadCertificate() {
    setError("");
    setCertificateBusy(true);
    try {
      const body = await api.vpnServerCertificate(server.id);
      const url = URL.createObjectURL(new Blob([body], { type: "application/x-x509-ca-cert" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `netos-${server.type}-${server.index}.crt`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 404
        ? "Сертификат ещё не создан. Сначала примените настройки VPN-сервера."
        : err instanceof Error ? err.message : "Не удалось скачать сертификат");
    } finally {
      setCertificateBusy(false);
    }
  }

  return <><button type="button" className="btn ghost sm" disabled={!server.enabled || certificateBusy} onClick={() => void downloadCertificate()}>Скачать сертификат</button>{error && <span role="alert" style={{ display: "block", color: "var(--danger)" }}>{error}</span>}</>;
}


const XRAY_NAMES: Record<string, string> = { reality: "VLESS Reality", vless: "VLESS TLS", vmess: "VMess", trojan: "Trojan TLS", shadowsocks: "Shadowsocks", socks: "SOCKS", http: "HTTP proxy", wireguard: "Xray WireGuard", hysteria: "Hysteria 2" };

export function VPNServersPage({ config, patch, beforeRead }: Props) {
  const creators = useRef<Record<string, () => void | Promise<void>>>({});
  const [addingTo, setAddingTo] = useState("");
  async function addClient(id: string) {
    if (addingTo) return;
    setAddingTo(id);
    setError("");
    try {
      const create = creators.current[id];
      if (!create) throw new Error("Сервер больше недоступен. Выберите другой сервер.");
      await create();
    }
    catch (err) { setError(err instanceof Error ? err.message : "Не удалось добавить клиента"); }
    finally { setAddingTo(""); }
  }
  const servers = config.vpn_servers || [];
  const wireguardInstalled = (config.components || []).some((item: any) => item.id === "wireguard" && item.installed);
  const xrayInstalled = (config.components || []).some((item: any) => item.id === "xray" && item.installed);
  const ocservInstalled = (config.components || []).some((item: any) => item.id === "ocserv" && item.installed);
	const strongswanInstalled = (config.components || []).some((item: any) => item.id === "strongswan" && item.installed);
	const l2tpInstalled = (config.components || []).some((item: any) => item.id === "l2tp" && item.installed);
  const [clientSecrets, setClientSecrets] = useState<Record<string, ClientSecret>>({});
  const [error, setError] = useState("");
  useEffect(() => {
    let frame = 0;
    const reveal = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const [page, query] = window.location.hash.slice(1).split("?");
        if (page !== "vpn-servers") return;
        const params = new URLSearchParams(query);
        const server = params.get("server"), client = params.get("client");
        if (!server || !client) return;
        const row = Array.from(document.querySelectorAll<HTMLElement>(".peer-card[data-vpn-server][data-vpn-client]"))
          .find(item => item.dataset.vpnServer === server && item.dataset.vpnClient === client);
        const details = row?.querySelector<HTMLDetailsElement>("details.xd");
        if (!details) { setError("Этот VPN-клиент больше не найден. Возможно, он был удалён."); return; }
        details.open = true;
        const summary = details.querySelector<HTMLElement>("summary");
        summary?.focus({ preventScroll: true });
        summary?.scrollIntoView({ block: "center", behavior: "instant" });
      });
    };
    reveal();
    window.addEventListener("hashchange", reveal);
    return () => { cancelAnimationFrame(frame); window.removeEventListener("hashchange", reveal); };
  }, []);

  async function addServer(type: "wireguard" | "xray" | "ocserv" | "ikev2" | "l2tp", protocol = "reality") {
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
    const id = newID(`${type}-server`);
    openOnCreate(id);
    patch((draft) => {
      draft.vpn_servers = draft.vpn_servers || [];
      const used = new Set(draft.vpn_servers.map((item: any) => item.index));
      let index = 1;
      while (used.has(index)) index++;
      const common = { id, index, enabled: false, type, subnet: `10.${8 + index}.0.1/24`, default_channel: "direct", peers: [] };
      const server = type === "wireguard" ? {
        ...common, name: `WireGuard ${index}`, port: 51819 + index,
        config: { private_key: generatedWireGuardKey, mtu: 1420, public_endpoint: `${window.location.hostname}:${51819 + index}` },
      } : type === "xray" ? {
		...common, name: `${XRAY_NAMES[protocol]} ${index}`,
		port: protocol === "reality" ? 443 : 18000 + index,
		config: { protocol, listen: protocol === "socks" || protocol === "http" ? "127.0.0.1" : "", method: "aes-256-gcm", private_key: "", wg_private_key: "", mtu: 1420, public_endpoint: "", destination: "www.cloudflare.com:443", server_names: ["www.cloudflare.com"], short_ids: [randomHex(8)], flow: protocol === "reality" ? "xtls-rprx-vision" : "" },
		} : type === "ocserv" ? {
        ...common, name: `OpenConnect ${index}`, port: 443,
        config: { public_endpoint: "", dns: [], use_router_dns: true, routes: [], mtu: 1380, banner: "netOS VPN" },
		} : type === "l2tp" ? {
			...common, name: `L2TP ${index}`, port: 1701,
			config: { listen: "", mtu: 1400 },
		} : {
			...common, name: `IKEv2 ${index}`, port: 500,
			config: { public_endpoint: "", server_identity: config.system?.hostname || "netos", dns: [], split_routes: [], mtu: 1400 },
      };
      draft.vpn_servers.push(server);
    });
  }

  const needs = (installed: boolean) => installed ? undefined : "нужен компонент";
  const xrayItem = (protocol: string, name: string) => ({ label: XRAY_NAMES[protocol], ariaLabel: `Добавить ${name}`, icon: vpnServerIcon("xray", protocol), note: needs(xrayInstalled), onSelect: () => void addServer("xray", protocol) });
  const addItems = [
    { label: "WireGuard", ariaLabel: "Добавить WireGuard", icon: vpnServerIcon("wireguard"), note: needs(wireguardInstalled), onSelect: () => void addServer("wireguard") },
    xrayItem("reality", "Reality"), xrayItem("vless", "VLESS TLS"), xrayItem("vmess", "VMess"), xrayItem("trojan", "Trojan TLS"),
    xrayItem("shadowsocks", "Shadowsocks"), xrayItem("socks", "SOCKS"), xrayItem("http", "HTTP proxy"), xrayItem("wireguard", "Xray WireGuard"), xrayItem("hysteria", "Hysteria 2"),
    { label: "IKEv2", ariaLabel: "Добавить IKEv2", icon: vpnServerIcon("ikev2"), note: needs(strongswanInstalled), onSelect: () => void addServer("ikev2") },
    { label: "OpenConnect", ariaLabel: "Добавить OpenConnect", icon: vpnServerIcon("ocserv"), note: needs(ocservInstalled), onSelect: () => void addServer("ocserv") },
    { label: "L2TP", ariaLabel: "Добавить L2TP", icon: vpnServerIcon("l2tp"), note: needs(l2tpInstalled), onSelect: () => void addServer("l2tp") },
  ];

  const clientItems = servers
    .filter((s: any) => ["wireguard", "xray", "ocserv", "ikev2", "l2tp"].includes(s.type))
    .map((s: any) => ({
      label: s.name || s.id,
      ariaLabel: `Добавить клиента на ${s.name || s.id}`,
      icon: vpnServerIcon(s.type, s.config?.protocol),
      note: s.type === "xray" ? XRAY_NAMES[s.config?.protocol || "reality"]
        : ({ wireguard: "WireGuard", ocserv: "OpenConnect", ikev2: "IKEv2", l2tp: "L2TP" } as Record<string, string>)[s.type],
      disabled: !!addingTo,
      onSelect: () => void addClient(s.id),
    }));

  return <>
    <div className="page-head"><h1><Icon name="shield-check" />VPN-доступ</h1><p>Безопасное подключение телефонов и компьютеров к роутеру из интернета</p></div>
    {error && <Notice tone="danger" title="Не удалось выполнить действие">{error}</Notice>}
	{!wireguardInstalled && !xrayInstalled && !ocservInstalled && !strongswanInstalled && !l2tpInstalled && <Notice tone="info" title="Нужен VPN-компонент">Установите нужный VPN-компонент в разделе «Компоненты». Черновики серверов можно подготовить заранее.</Notice>}
    <ClientCreators.Provider value={creators}><Card split title="VPN-доступ" subtitle="Создайте сервер, затем выдавайте каждому клиенту отдельный готовый профиль" actions={<AddMenu label="Добавить сервер" items={addItems} />}>
      <div className="card-part">{servers.length === 0 ? <Empty>VPN-серверов пока нет.</Empty> : <Rows cols={["Сервер", "Тип", "Адрес подключения", "Клиентов", "Состояние"]} toggle="Включён">{servers.map((server: any) =>
        server.type === "wireguard" ? <WireGuardServer key={server.id} server={server} config={config} installed={wireguardInstalled} patch={patch} setClientSecrets={setClientSecrets} setError={setError} /> :
        server.type === "xray" ? <XrayServer key={server.id} server={server} config={config} installed={xrayInstalled} patch={patch} setError={setError} /> :
        server.type === "ocserv" ? <OcservServer key={server.id} server={server} config={config} installed={ocservInstalled} patch={patch} /> :
        server.type === "ikev2" ? <IKEv2Server key={server.id} server={server} config={config} installed={strongswanInstalled} patch={patch} /> :
        server.type === "l2tp" ? <L2TPServer key={server.id} server={server} config={config} installed={l2tpInstalled} patch={patch} /> :
          <Notice key={server.id} tone="warn" title={`Сервер ${server.type} пока недоступен`}>Сохранённый черновик не будет запущен.</Notice>)}</Rows>}</div>
      {servers.length > 0 && <><div className="card-sub"><h3>Клиенты</h3><span className="sub">Профили и пользователи каждого сервера</span><AddMenu label={addingTo ? "Создаём клиента…" : "Добавить клиента"} items={clientItems} /></div>
      <div className="vpn-client-groups">{servers.map((server: any) =>
        server.type === "wireguard" ? <WireGuardPeers beforeRead={beforeRead} key={server.id} server={server} config={config} patch={patch} clientSecrets={clientSecrets} setClientSecrets={setClientSecrets} setError={setError} /> :
        server.type === "xray" ? <XrayPeers beforeRead={beforeRead} key={server.id} server={server} config={config} patch={patch} setError={setError} /> :
        server.type === "ocserv" ? <PasswordPeers key={server.id} server={server} config={config} patch={patch} empty="Добавьте пользователя OpenConnect." /> :
        server.type === "ikev2" ? <PasswordPeers key={server.id} server={server} config={config} patch={patch} empty="Добавьте пользователя IKEv2." /> :
        server.type === "l2tp" ? <PasswordPeers key={server.id} server={server} config={config} patch={patch} singleActive empty="Добавьте пользователя L2TP." /> : null)}</div></>}
    </Card></ClientCreators.Provider>
  </>;
}

// Каркас сервера: строка с главным и настройки под ней. Устройства сервера
// лежат отдельным разделом ниже — список серверов не растягивается на экраны.
function ServerRow({ server, type, endpoint, installed, referenced, update, patch, children }: any) {
  return <Row as="form" className="vpn-server" icon={vpnServerIcon(server.type, server.config?.protocol)} id={server.id} data-server-id={server.id} onSubmit={(event: { preventDefault: () => void }) => event.preventDefault()}
    cells={[<strong>{server.name}</strong>, type, <span className="mono">{endpoint || "—"}</span>, (server.peers || []).length, <Badge tone={server.enabled ? "ok" : "neutral"}>{server.enabled ? "Включён" : "Отключён"}</Badge>]}
    toggle={<Switch checked={!!server.enabled} disabled={!installed} label="" ariaLabel="Включить" onChange={(value) => update((draft: any) => draft.enabled = value)} />}>
    {children}
    <Field label="Изоляция" hint="Запрещает доступ к другим локальным и VPN-сетям и из них. Выход в интернет сохраняется.">
      <Switch checked={!!server.isolated} label="Изолировать от других локальных и VPN-сетей" onChange={(value) => update((draft: any) => draft.isolated = value)} />
    </Field>
    <div className="row-actions server-head"><button type="button" className="btn ghost sm to-right" disabled={server.enabled || referenced} onClick={() => patch((draft: any) => { draft.vpn_servers = draft.vpn_servers.filter((item: any) => item.id !== server.id); })}>Удалить</button></div>
  </Row>;
}

function PeerGroup({ server, children }: any) {
  const type = server.type === "xray" ? XRAY_NAMES[server.config?.protocol || "reality"] : ({ wireguard: "WireGuard", ocserv: "OpenConnect", ikev2: "IKEv2", l2tp: "L2TP" } as Record<string, string>)[server.type];
  return <section className="peer-group" data-peers-of={server.id} aria-label={`Клиенты сервера ${server.name || server.id}`}>
    <header className="peer-group-heading"><div><span className="faint">Сервер</span><h3>{server.name || server.id}</h3></div><Badge>{type}</Badge><span className="dim">Клиентов: {(server.peers || []).length}</span></header>
    <Rows cols={["Клиент", "VPN-адрес", "Внешний адрес", "Канал выхода", "Состояние"]} toggle="Доступ">{children}</Rows>
  </section>;
}

function channelName(channels: any[], peer: any) {
  return peer.channel ? channels.find((item: any) => item.id === peer.channel)?.name || peer.channel : "как у сервера";
}

function serverTools(server: any, config: any, patch: any) {
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.vpn_servers.find((item: any) => item.id === server.id)));
  return {
    cfg: server.config || {},
    channels: (config.channels || []).filter((item: any) => item.enabled),
    referenced: (config.policies || []).some((item: any) => item.vpn_server === server.id),
    update,
    setConfig: (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; }),
  };
}

function L2TPServer({ server, config, installed, patch }: any) {
  const { cfg, channels, referenced, update, setConfig } = serverTools(server, config, patch);
  return <ServerRow server={server} type="L2TP" endpoint={cfg.listen} installed={installed} referenced={referenced} update={update} patch={patch}>
    {!installed && <Notice tone="info" title="Нужен компонент L2TP">Установите L2TP перед включением сервера.</Notice>}
    <Notice tone="warn" title="L2TP без шифрования">Сервер слушает только выбранный частный адрес. Подключайте клиентов из доверенной сети или через отдельный защищённый транспорт.</Notice>
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-подсеть"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="Адрес прослушивания" hint="Частный IPv4 адрес интерфейса, без порта"><input className="mono" placeholder="192.168.1.1" value={cfg.listen || ""} onChange={(e) => setConfig("listen", e.target.value)} /></Field>
      <Field label="UDP-порт"><input type="number" value={1701} readOnly /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="MTU"><input type="number" min={576} max={1460} value={cfg.mtu || 1400} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
    </div>
  </ServerRow>;
}

function IKEv2Server({ server, config, installed, patch }: any) {
  const { cfg, channels, referenced, update, setConfig } = serverTools(server, config, patch);
  return <ServerRow server={server} type="IKEv2" endpoint={cfg.public_endpoint} installed={installed} referenced={referenced} update={update} patch={patch}>
		{!installed && <Notice tone="info" title="Нужен компонент strongSwan">Установите strongSwan перед включением сервера IKEv2.</Notice>}
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
		<Notice tone="info" title="Настройка клиента">Импортируйте сертификат как доверенный корневой, затем создайте IKEv2-подключение к публичному адресу с логином и паролем EAP-MSCHAPv2. <VPNCertificate server={server} /></Notice>
  </ServerRow>;
}

function OcservServer({ server, config, installed, patch }: any) {
  const { cfg, channels, referenced, update, setConfig } = serverTools(server, config, patch);
  return <ServerRow server={server} type="OpenConnect" endpoint={cfg.public_endpoint} installed={installed} referenced={referenced} update={update} patch={patch}>
    {!installed && <Notice tone="info" title="Нужен компонент ocserv">Установите ocserv перед включением сервера OpenConnect.</Notice>}
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="Пул адресов" hint="Адрес сервера и маска"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="TCP/UDP-порт"><input type="number" min={1} max={65535} value={server.port || 443} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Публичный адрес" hint="vpn.example.com:443"><input className="mono" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1380} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="DNS для клиентов" hint={cfg.use_router_dns ? "Клиент получит адрес роутера в VPN-подсети. DNS-служба роутера должна быть включена." : "По одному IPv4-адресу в строке"}>
        <Switch checked={!!cfg.use_router_dns} label="Использовать DNS роутера" onChange={(enabled) => setConfig("use_router_dns", enabled)} />
        {!cfg.use_router_dns && <textarea aria-label="DNS OpenConnect" className="mono" value={(cfg.dns || []).join("\n")} onChange={(e) => setConfig("dns", e.target.value.split(/\s+/).filter(Boolean))} />}
      </Field>
      <Field label="Маршруты" hint="Пусто — весь интернет через VPN"><textarea className="mono" value={(cfg.routes || []).join("\n")} onChange={(e) => setConfig("routes", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Приветствие"><input value={cfg.banner || ""} onChange={(e) => setConfig("banner", e.target.value)} /></Field>
    </div>
    <Field label="Авторизация клиентов"><select value={cfg.auth_mode || "password"} onChange={(e) => setConfig("auth_mode", e.target.value)}><option value="password">Логин и пароль</option><option value="certificate">Сертификат клиента</option><option value="certificate_password">Сертификат клиента и пароль</option></select></Field>
    <OcservTLSSettings server={server} setConfig={setConfig} />
    {(!cfg.tls || !cfg.tls.mode || cfg.tls.mode === "selfsigned") && <Notice tone="info" title="Самоподписанный сертификат">После первого применения импортируйте сертификат в доверенные на клиентском устройстве. <VPNCertificate server={server} /></Notice>}
  </ServerRow>;
}

// Пользователи с логином и паролем: OpenConnect, IKEv2 и L2TP устроены одинаково.
function PasswordPeers({ server, config, patch, singleActive, empty }: any) {
  const { clientStatus } = useClientStatuses(server.id);
  const { channels, update } = serverTools(server, config, patch);
  const enabledPeers = (server.peers || []).filter((item: any) => item.enabled).length;
  function addPeer() {
    const id = newID("peer");
    openOnCreate(id);
    update((draft) => {
      const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      draft.peers = draft.peers || [];
      const number = draft.peers.length + 1;
      draft.peers.push({ id, name: `Клиент ${number}`, enabled: false, address: `${prefix}.${number + 1}`, channel: "", credentials: { username: `user${number}`, password: "" }, comment: "" });
    });
  }
  useClientCreator(server.id, addPeer);
  return <PeerGroup server={server}>
    {(server.peers || []).length === 0 ? <Empty>{empty}</Empty> : (server.peers || []).map((peer: any) =>
      <OcservPeer status={clientStatus.find(row => row.id === peer.id)} key={peer.id} server={server} peer={peer} referenced={isPeerReferenced(config, server.id, peer.id)} channels={channels} update={update} canEnable={!singleActive || peer.enabled || enabledPeers === 0} />)}
  </PeerGroup>;
}

function OcservPeer({ status, server, peer, referenced, channels, update, canEnable = true }: any) {
  const [open, setOpen] = useState(false);
  const certAuth = server.type === "ocserv" && ["certificate", "certificate_password"].includes(server.config?.auth_mode);
  const passwordAuth = !certAuth || server.config?.auth_mode === "certificate_password";
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  return <Row onOpenChange={setOpen} className="peer-card" icon="monitor-smartphone" id={peer.id} data-vpn-server={server.id} data-vpn-client={peer.id}
    cells={[<strong>{peer.name}</strong>, <span className="mono">{peer.address || "—"}</span>, <span className="mono">{status?.endpoint || "—"}</span>, channelName(channels, peer), <ClientBadge server={server} peer={peer} status={status} />]}
    toggle={<Switch checked={!!peer.enabled} disabled={!canEnable} label="" ariaLabel="Разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} />}>
    <ClientConnection status={status} session />
    <div className="form-grid">
      <Field label="Название"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      {!certAuth && <Field label="Логин"><input className="mono" autoComplete="off" value={peer.credentials?.username || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.username = e.target.value; })} /></Field>}
      {passwordAuth && <Field label="Пароль" hint="Не меньше 8 символов"><input type="password" autoComplete="new-password" {...secretInput(peer, "password")} value={peer.credentials?.password || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.password = e.target.value; })} /></Field>}
      <Field label="VPN-адрес"><input className="mono" value={peer.address || ""} onChange={(e) => edit((draft) => draft.address = e.target.value)} /></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Комментарий"><input value={peer.comment || ""} onChange={(e) => edit((draft) => draft.comment = e.target.value)} /></Field>
    </div>
    {certAuth && <OcservClientCertificate server={server} peer={peer} active={open} />}
    <div className="row-actions peer-head"><button type="button" className="btn ghost sm to-right" disabled={peer.enabled || referenced} onClick={() => update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); })}>Удалить</button></div>
  </Row>;
}

function XrayServer({ server, config, installed, patch, setError }: any) {
  const { cfg, channels, referenced, update, setConfig } = serverTools(server, config, patch);
  const protocol = cfg.protocol || "reality";

  async function generateKey() {
    setError("");
    try {
      const pair = await api.xrayKeypair();
      setConfig("private_key", pair.private_key);
    } catch (err: any) { setError(err?.message || "Не удалось создать ключ Reality"); }
  }

  async function generateWGServerKey() {
    setError("");
    try {
      const pair = await api.wireGuardKeypair();
      setConfig("wg_private_key", pair.private_key);
    } catch (err: any) { setError(err?.message || "Не удалось создать ключ WireGuard"); }
  }

  return <ServerRow server={server} type={XRAY_NAMES[protocol] || protocol} endpoint={cfg.public_endpoint || cfg.listen} installed={installed} referenced={referenced} update={update} patch={patch}>
    {!installed && <Notice tone="info" title="Нужен компонент Xray">Установите Xray перед включением этого сервера.</Notice>}
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="Протокол"><input value={protocol} readOnly /></Field>
      <Field label={protocol === "wireguard" || protocol === "hysteria" ? "UDP-порт" : "TCP-порт"}><input type="number" min={1} max={65535} value={server.port || 443} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Публичный адрес" hint="Домен или IP роутера с портом"><input className="mono" placeholder="vpn.example.com:443" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      {(protocol === "socks" || protocol === "http") && <Field label="Адрес прослушивания" hint="Только локальный или частный IPv4"><input className="mono" value={cfg.listen || ""} onChange={(e) => setConfig("listen", e.target.value)} /></Field>}
      {protocol === "shadowsocks" && <Field label="Шифр"><select value={cfg.method || "aes-256-gcm"} onChange={(e) => setConfig("method", e.target.value)}><option value="aes-256-gcm">AES-256-GCM</option><option value="aes-128-gcm">AES-128-GCM</option><option value="chacha20-poly1305">ChaCha20-Poly1305</option></select></Field>}
      {protocol === "reality" && <>
      <Field label="Сайт-маскировка" hint="Доступный TLS-сайт с портом"><input className="mono" value={cfg.destination || ""} onChange={(e) => setConfig("destination", e.target.value)} /></Field>
      <Field label="Имена сервера (SNI)" hint="По одному домену в строке"><textarea className="mono" value={(cfg.server_names || []).join("\n")} onChange={(e) => setConfig("server_names", e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      <Field label="Short ID" hint="Чётное число hex-символов, до 16"><textarea className="mono" value={(cfg.short_ids || []).join("\n")} onChange={(e) => setConfig("short_ids", e.target.value.split(/\s+/).filter(Boolean))} /><button type="button" className="btn ghost sm" onClick={async () => { if (!(cfg.short_ids || []).length || await confirmAction("Заменить все Short ID? После применения старые ссылки перестанут работать. Передайте клиентам новые ссылки или QR-коды.", "Заменить Short ID")) setConfig("short_ids", [randomHex(8)]); }}>Перегенерировать Short ID</button></Field>
      <Field label="Flow"><select value={cfg.flow ?? "xtls-rprx-vision"} onChange={(e) => setConfig("flow", e.target.value)}><option value="xtls-rprx-vision">XTLS Vision</option><option value="">Без flow</option></select></Field>
      <Field label="Диагностика Reality" hint="Показывать отладочные сведения Reality в журнале Xray">
        <Switch checked={!!cfg.show} label="Включить show" onChange={(value) => setConfig("show", value)} />
      </Field>
      </>}
      <Field label="Анализ трафика (sniffing)" hint="Распознаёт протокол и адрес назначения для применения правил маршрутизации.">
        <Switch checked={!!cfg.sniffing} label="Включить sniffing" onChange={(value) => setConfig("sniffing", value)} />
      </Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      {protocol === "reality" && <Field label="Закрытый ключ Reality" hint={cfg.private_key || server.reality_key_set ? "Ключ задан. Пустое поле сохраняет прежний ключ." : "Ключ ещё не создан"}><div className="row"><input className="mono" type="password" autoComplete="new-password" {...secretInput(server, "private_key")} value={cfg.private_key || ""} onChange={(e) => setConfig("private_key", e.target.value)} /><button type="button" className="btn ghost sm" onClick={generateKey}>Сгенерировать</button></div></Field>}
      {protocol === "wireguard" && <><Field label="Закрытый ключ Xray WireGuard"><div className="row"><input className="mono" type="password" autoComplete="new-password" {...secretInput(server, "wg_private_key")} value={cfg.wg_private_key || ""} onChange={(e) => setConfig("wg_private_key", e.target.value)} /><button type="button" className="btn ghost sm" onClick={() => void generateWGServerKey()}>Сгенерировать</button></div></Field><Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1420} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field></>}
      {(protocol === "vless" || protocol === "trojan" || protocol === "hysteria") && <Field label="TLS-сертификат" hint="После применения скачайте сертификат и доверьте ему на клиенте"><VPNCertificate server={server} /></Field>}
    </div>
  </ServerRow>;
}

function XrayPeers({ beforeRead, server, config, patch, setError }: any) {
  const { clientStatus } = useClientStatuses(server.id);
  const { cfg, channels, update } = serverTools(server, config, patch);
  const protocol = cfg.protocol || "reality";
  const [wgClientKeys, setWGClientKeys] = useState<Record<string, string>>({});
  const [peerCredentials, setPeerCredentials] = useState<Record<string, Record<string, string>>>({});

  async function addPeer() {
    const peerID = newID("peer");
    openOnCreate(peerID);
    let wgPair: { private_key: string; public_key: string } | undefined;
    if (protocol === "wireguard") {
      try { wgPair = await api.wireGuardKeypair(); }
      catch (err: any) { setError(err?.message || "Не удалось создать ключ клиента"); return; }
    }
    const peerNumber = (server.peers || []).length + 1;
    const credentials: Record<string, string> = protocol === "wireguard" ? { public_key: wgPair!.public_key } : protocol === "reality" || protocol === "vless" || protocol === "vmess" ? { uuid: crypto.randomUUID() } : protocol === "trojan" || protocol === "shadowsocks" || protocol === "hysteria" ? { password: randomHex(16) } : { username: `user${peerNumber}`, password: randomHex(12) };
    update((draft) => {
      const prefix = String(draft.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      draft.peers = draft.peers || [];
      draft.peers.push({ id: peerID, name: `Клиент ${draft.peers.length + 1}`, enabled: false, address: `${prefix}.${draft.peers.length + 2}`, channel: "", credentials, comment: "" });
    });
    setPeerCredentials((old) => ({ ...old, [peerID]: credentials }));
    if (wgPair) setWGClientKeys((old) => ({ ...old, [peerID]: wgPair.private_key }));
  }

  useClientCreator(server.id, addPeer);
  return <PeerGroup server={server}>
    {(server.peers || []).length === 0 ? <Empty>Добавьте клиента и скачайте готовую ссылку подключения.</Empty> : (server.peers || []).map((peer: any) =>
      <XrayPeerEditor status={clientStatus.find(row => row.id === peer.id && (!peer.credentials?.public_key || row.public_key === peer.credentials.public_key))} beforeRead={beforeRead} key={peer.id} server={server} peer={peer} protocol={protocol} wgPrivateKey={wgClientKeys[peer.id]} issuedCredentials={peerCredentials[peer.id]} rememberCredentials={(next: Record<string, string>) => setPeerCredentials((old) => ({ ...old, [peer.id]: { ...old[peer.id], ...next } }))} referenced={isPeerReferenced(config, server.id, peer.id)} channels={channels} update={update} setError={setError} />)}
  </PeerGroup>;
}

function XrayPeerEditor({ status, beforeRead, server, peer, protocol, wgPrivateKey, issuedCredentials, rememberCredentials, referenced, channels, update, setError }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  async function downloadClient() {
    setError("");
    const endpoint = server.config?.public_endpoint;
    if (!endpoint) { setError("Укажите публичный адрес сервера с портом."); return; }
    try {
      const url = new URL(`https://${endpoint}`);
      const address = url.hostname.replace(/^\[|\]$/g, "");
      // URL normalizes the default HTTPS port away, but the VPN endpoint still needs it.
      const port = Number(endpoint.slice(endpoint.lastIndexOf(":") + 1));
      if (!address || !port) throw new Error("Укажите адрес сервера в формате host:port");
      const credentials = { ...(peer.credentials || {}), ...(issuedCredentials || {}) };
      if ((protocol === "vless" || protocol === "vmess") && !credentials.uuid) throw new Error("UUID клиента недоступен");
      if ((protocol === "trojan" || protocol === "shadowsocks" || protocol === "hysteria" || protocol === "socks" || protocol === "http") && !credentials.password) throw new Error("Пароль клиента недоступен; выдайте новый пароль");
      if (protocol === "socks" || protocol === "http") {
        const scheme = protocol === "socks" ? "socks5" : "http";
        saveClientFile(`${peer.name || peer.id}.txt`, `${scheme}://${encodeURIComponent(credentials.username)}:${encodeURIComponent(credentials.password)}@${endpoint}\n`);
        return;
      }
      const settings: Record<string, unknown> = { address, port };
      if (protocol === "vless") Object.assign(settings, { id: credentials.uuid, encryption: "none" });
      if (protocol === "vmess") Object.assign(settings, { id: credentials.uuid, security: "auto" });
      if (protocol === "trojan") settings.password = credentials.password;
      if (protocol === "shadowsocks") Object.assign(settings, { method: server.config?.method || "aes-256-gcm", password: credentials.password });
      if (protocol === "hysteria") Object.assign(settings, { version: 2 });
      const outbound: Record<string, unknown> = { protocol, settings };
      if (protocol === "vless" || protocol === "trojan" || protocol === "hysteria") {
        const pem = await api.vpnServerCertificate(server.id);
        const tlsSettings = { ...(protocol !== "hysteria" && peer.tls_fingerprint ? {fingerprint:peer.tls_fingerprint} : {}), serverName: address, pinnedPeerCertSha256: await certificateFingerprint(pem) };
        outbound.streamSettings = protocol === "hysteria"
          ? { method: "hysteria", hysteriaSettings: { version: 2, auth: credentials.password }, security: "tls", tlsSettings }
          : { network: "tcp", security: "tls", tlsSettings };
      }
      const profile = { log: { loglevel: "warning" }, inbounds: [{ listen: "127.0.0.1", port: 10808, protocol: "socks", settings: { auth: "noauth", udp: false } }], outbounds: [outbound] };
      saveClientFile(`${peer.name || peer.id}.json`, JSON.stringify(profile, null, 2) + "\n");
    } catch (err: any) { setError(err?.message || "Не удалось скачать клиентский профиль"); }
  }
  async function downloadWG() {
    setError("");
    if (!wgPrivateKey || !server.config?.public_endpoint) { setError("Ключ клиента доступен только во вкладке, где он создан; укажите публичный адрес сервера."); return; }
    try {
      const pair = await api.wireGuardServerPublicKey(server.id);
      const body = wireGuardClientConfig(server, peer, wgPrivateKey, pair.public_key, peer.credentials?.preshared_key);
      const url = URL.createObjectURL(new Blob([body], { type: "text/plain;charset=utf-8" }));
      const link = document.createElement("a"); link.href = url; link.download = `${peer.name || peer.id}.conf`; link.click(); URL.revokeObjectURL(url);
    } catch (err: any) { setError(err?.message || "Не удалось скачать WireGuard-профиль"); }
  }
  const [realityLink, setRealityLink] = useState("");
  const [realityBusy, setRealityBusy] = useState(false);
  useEffect(() => { setRealityLink(""); }, [JSON.stringify(server.config), JSON.stringify(peer.credentials), peer.name, peer.tls_fingerprint]);
  async function openReality(downloadFile = false) {
    setError(""); setRealityBusy(true);
    try {
      await beforeRead();
      const profile = await api.realityClientProfile(server.id, peer.id);
      setRealityLink(profile.link);
      if (downloadFile) saveClientFile(`${peer.name || peer.id}.json`, JSON.stringify(realityClientConfig(profile.link), null, 2) + "\n");
    } catch (err: any) { setError(err?.message || "Не удалось создать ссылку подключения"); }
    finally { setRealityBusy(false); }
  }
  return <Row className="peer-card" icon="monitor-smartphone" id={peer.id} data-vpn-server={server.id} data-vpn-client={peer.id}
    cells={[<strong>{peer.name}</strong>, <span className="mono">{peer.address || "—"}</span>, <span className="mono">{status?.endpoint || "—"}</span>, channelName(channels, peer), <ClientBadge server={server} peer={peer} status={status} />]}
    toggle={<Switch checked={!!peer.enabled} label="" ariaLabel="Разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} />}>
    <ClientConnection status={status} session />
    <div className="form-grid">
      <Field label="Клиент"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      {(protocol === "reality" || protocol === "vless" || protocol === "vmess") && <Field label="UUID клиента"><div className="row"><input className="mono" {...secretInput(peer, "uuid")} value={peer.credentials?.uuid || ""} onChange={(e) => { const uuid = e.target.value; rememberCredentials({ uuid }); edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.uuid = uuid; }); }} /><button type="button" className="btn ghost sm" onClick={() => { const uuid = crypto.randomUUID(); rememberCredentials({ uuid }); edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.uuid = uuid; }); }}>Новый</button></div></Field>}
      {(protocol === "socks" || protocol === "http") && <Field label="Логин"><input className="mono" value={peer.credentials?.username || ""} onChange={(e) => { const username = e.target.value; rememberCredentials({ username }); edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.username = username; }); }} /></Field>}
      {(protocol === "trojan" || protocol === "shadowsocks" || protocol === "socks" || protocol === "http") && <Field label="Пароль"><input className="mono" type="password" autoComplete="new-password" {...secretInput(peer, "password")} value={peer.credentials?.password || ""} onChange={(e) => { const password = e.target.value; rememberCredentials({ password }); edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.password = password; }); }} /></Field>}
      {protocol === "hysteria" && <Field label="Пароль Hysteria 2"><input className="mono" type="password" autoComplete="new-password" {...secretInput(peer, "password")} value={peer.credentials?.password || ""} onChange={(e) => { const password = e.target.value; rememberCredentials({ password }); edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.password = password; }); }} /></Field>}
      {protocol === "wireguard" && <><Field label="Публичный ключ клиента"><input className="mono" value={peer.credentials?.public_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.public_key = e.target.value; })} /></Field><Field label="Предварительный ключ"><input className="mono" type="password" autoComplete="new-password" {...secretInput(peer, "preshared_key")} value={peer.credentials?.preshared_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.preshared_key = e.target.value; })} /></Field></>}
      {["reality", "vless", "trojan"].includes(protocol) && <Field label="TLS fingerprint" hint="Какой TLS-отпечаток имитирует приложение клиента. После изменения скачайте новый профиль или обновите ссылку в приложении.">
        <select aria-label="TLS fingerprint клиента" value={peer.tls_fingerprint || ""} onChange={e => edit((draft) => draft.tls_fingerprint = e.target.value)}>
          <option value="">{protocol === "reality" ? "По умолчанию (Chrome)" : "По умолчанию приложения"}</option>
          {[["chrome","Chrome"],["firefox","Firefox"],["safari","Safari"],["ios","iOS"],["edge","Edge"],["random","Случайный браузер"],["randomized","Случайный отпечаток"]].map(([value,label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </Field>}
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Комментарий"><input value={peer.comment || ""} onChange={(e) => edit((draft) => draft.comment = e.target.value)} /></Field>
    </div>
    {protocol === "reality" && realityLink && <div className="client-package"><div className="qr-card"><QRCodeSVG value={realityLink} size={176} level="M" marginSize={2} title={`Reality-профиль ${peer.name || peer.id}`} /></div><div className="client-package-copy"><strong>Профиль Reality</strong><p>Отсканируйте QR-код в VPN-приложении. Изменения черновика начнут работать после применения настроек.</p><CopyButton text={realityLink} label="Скопировать ссылку" onError={setError} /></div></div>}
    <div className="row-actions peer-head">
    {protocol === "reality" && <><button type="button" className="btn sm" disabled={realityBusy} onClick={() => void openReality(true)}>Скачать JSON Xray</button>{!realityLink && <button type="button" className="btn sm" disabled={realityBusy} onClick={() => void openReality()}>Открыть QR-код</button>}</>}
    {protocol === "wireguard" && <button type="button" className="btn sm" onClick={() => void downloadWG()}>Скачать WireGuard-профиль</button>}
    {protocol !== "reality" && protocol !== "wireguard" && <button type="button" className="btn sm" onClick={() => void downloadClient()}>Скачать профиль подключения</button>}
      <button type="button" className="btn ghost sm to-right" disabled={peer.enabled || referenced} onClick={() => update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); })}>Удалить</button>
    </div>
  </Row>;
}

type ClientStatus = { id: string; public_key: string; state: string; endpoint: string; last_handshake: number; last_seen?: number; traffic_known?: boolean; received: number; sent: number };

function ProfileListInput({ label, values, disabled, onChange }: { label: string; values: string[]; disabled?: boolean; onChange: (values: string[]) => void }) {
  const serialized = values.join("\n");
  const [text, setText] = useState(serialized);
  const parse = (value: string) => value.split(/[\s,]+/).filter(Boolean);
  useEffect(() => {
    setText((current) => parse(current).join("\n") === serialized ? current : serialized);
  }, [serialized]);
  // Keep trailing newlines while typing so a second address can be entered.
  return <textarea aria-label={label} className="mono" disabled={disabled} value={text} onChange={(event) => {
    setText(event.target.value);
    onChange(parse(event.target.value));
  }} />;
}


// Живое состояние клиента. Сама отметка и внешний адрес стоят в строке
// устройства; здесь то, что нужно реже.
function ClientConnection({ status, session = false }: { status?: ClientStatus; session?: boolean }) {
  const known = ["recent", "idle", "never", "online", "offline"].includes(status?.state || "pending");
  const last = session ? status?.last_seen : status?.last_handshake;
  const trafficKnown = known && (status?.traffic_known ?? !session);
  return <div className="client-connection form-grid">
    <Field label={session ? "Последний раз замечен онлайн" : "Последнее рукопожатие"}><span>{last ? new Date(last * 1000).toLocaleString("ru-RU") : "—"}</span></Field>
    <Field label="Получено от клиента"><span>{trafficKnown ? formatMiB(status?.received || 0) : "—"}</span></Field>
    <Field label="Отправлено клиенту"><span>{trafficKnown ? formatMiB(status?.sent || 0) : "—"}</span></Field>
  </div>;
}

function WireGuardServer({ server, config, installed, patch, setClientSecrets, setError }: any) {
  const { cfg, channels, referenced, update, setConfig } = serverTools(server, config, patch);

  async function generateServerKey() {
    setError("");
    if ((server.peers || []).length > 0 && !await confirmAction("Перевыпуск ключа сервера отключит все ранее выданные профили.", "Перевыпустить ключ")) return;
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

  return <ServerRow server={server} type="WireGuard" endpoint={cfg.public_endpoint} installed={installed} referenced={referenced} update={update} patch={patch}>
    {!installed && <Notice tone="info" title="Нужен компонент WireGuard">Установите WireGuard в разделе «Компоненты» перед включением сервера. Профили клиентов можно подготовить заранее.</Notice>}
    <div className="form-grid">
      <Field label="Название"><input value={server.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-подсеть" hint="Адрес роутера и маска, например 10.9.0.1/24"><input className="mono" value={server.subnet || ""} onChange={(e) => update((draft) => draft.subnet = e.target.value)} /></Field>
      <Field label="UDP-порт"><input type="number" min={1} max={65535} value={server.port || 51820} onChange={(e) => update((draft) => draft.port = Number(e.target.value))} /></Field>
      <Field label="Адрес подключения" hint="Домен или внешний IP роутера с портом"><input className="mono" placeholder="vpn.example.com:51820" value={cfg.public_endpoint || ""} onChange={(e) => setConfig("public_endpoint", e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1420} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="Канал по умолчанию"><select value={server.default_channel || "direct"} onChange={(e) => update((draft) => draft.default_channel = e.target.value)}>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Ключ сервера" hint="Создаётся автоматически и хранится только на роутере"><div className="row"><input aria-label="Закрытый ключ сервера" className="mono" type="password" autoComplete="new-password" {...secretInput(server, "private_key")} value={cfg.private_key || ""} readOnly /><button type="button" className="btn sm" onClick={generateServerKey}>Перевыпустить</button></div></Field>
    </div>
  </ServerRow>;
}

function WireGuardPeers({ beforeRead, server, config, patch, clientSecrets, setClientSecrets, setError }: any) {
  const { cfg, channels, update } = serverTools(server, config, patch);
  const { clientStatus, statusFailed } = useClientStatuses(server.id);

  async function addPeer() {
    setError("");
    try {
      const serverPair = cfg.private_key
        ? await api.wireGuardKeypair(cfg.private_key)
        : await api.wireGuardServerPublicKey(server.id);
      const clientPair = await api.wireGuardKeypair();
      const id = `peer-${crypto.randomUUID()}`;
      openOnCreate(id);
      const prefix = String(server.subnet || "10.9.0.1/24").split("/")[0].split(".").slice(0, 3).join(".");
      const used = new Set((server.peers || []).map((peer: any) => peer.address));
      let host = 2;
      while (used.has(`${prefix}.${host}`) && host < 255) host++;
      if (host >= 255) throw new Error("В адресном пуле WireGuard не осталось свободных адресов");
      const endpoint = cfg.public_endpoint || `${window.location.hostname}:${server.port || 51820}`;
      const peer = {
        id,
        name: `Клиент ${(server.peers || []).length + 1}`,
        enabled: true,
        address: `${prefix}.${host}`,
        channel: "",
        wireguard_profile: newWireGuardProfile(),
        credentials: { private_key: clientPair.private_key, public_key: clientPair.public_key, preshared_key: randomWireGuardKey() },
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
          publicKey: clientPair.public_key,
          serverPublicKey: serverPair.public_key,
          presharedKey: peer.credentials.preshared_key,
        },
      }));
    } catch (err: any) {
      setError(err?.message || "Не удалось создать готовый профиль WireGuard");
    }
  }

  useClientCreator(server.id, addPeer);
  return <PeerGroup server={server}>
    {(server.peers || []).length === 0 ? <Empty>Добавьте телефон, ноутбук или другой роутер — netOS сам подготовит всё необходимое.</Empty> : (server.peers || []).map((peer: any) =>
      <PeerEditor beforeRead={beforeRead} key={peer.id} status={statusFailed ? { state: "unknown" } : clientStatus.find((row) => row.id === peer.id && row.public_key === peer.credentials?.public_key)} server={server} peer={peer} referenced={isPeerReferenced(config, server.id, peer.id)} channels={channels} update={update} secret={clientSecrets[peer.id]} setSecret={(value: ClientSecret) => setClientSecrets((old: Record<string, ClientSecret>) => ({ ...old, [peer.id]: value }))} removeSecret={() => setClientSecrets((old: Record<string, ClientSecret>) => { const next = { ...old }; delete next[peer.id]; return next; })} setError={setError} />)}
  </PeerGroup>;
}

function PeerEditor({ beforeRead, status, server, peer, referenced, channels, update, secret, setSecret, removeSecret, setError }: any) {
  const profile = effectiveWireGuardProfile(server, peer);
  const editProfile = (mutate: (value: ReturnType<typeof effectiveWireGuardProfile>) => void) => edit((draft) => {
    const saved = draft.wireguard_profile;
    draft.wireguard_profile = saved
      ? { ...saved, dns: [...(saved.dns || [])], allowed_ips: [...(saved.allowed_ips || [])] }
      : effectiveWireGuardProfile(server, draft);
    mutate(draft.wireguard_profile);
  });
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.peers.find((item: any) => item.id === peer.id)));
  secret = secret?.publicKey === peer.credentials?.public_key ? secret : undefined;
  const [profileBusy, setProfileBusy] = useState(false);
  const preparedConfig = secret ? wireGuardClientConfig(server, peer, secret.privateKey, secret.serverPublicKey, secret.presharedKey) : "";
  async function openProfile() {
    setProfileBusy(true);
    setError("");
    try { await beforeRead(); setSecret(await api.vpnClientProfile(server.id, peer.id)); }
    catch (err: any) { setError(err?.message || "Не удалось получить профиль"); }
    finally { setProfileBusy(false); }
  }
  async function importProfile(file?: File) {
    if (!file) return;
    setError("");
    try {
      const body = await file.text();
      const privateKey = body.match(/^\s*PrivateKey\s*=\s*(\S+)\s*$/m)?.[1];
      if (!privateKey) throw new Error("В файле не найден закрытый ключ клиента");
      const pair = await api.wireGuardKeypair(privateKey);
      if (pair.public_key !== peer.credentials?.public_key) throw new Error("Этот профиль принадлежит другому клиенту");
      edit((draft) => { draft.credentials.private_key = privateKey; });
    } catch (err: any) { setError(err?.message || "Не удалось импортировать профиль"); }
  }
  async function generateClient() {
    if (!await confirmAction("Перевыпуск заменит ключи клиента. После применения прежний профиль перестанет работать.", "Перевыпустить профиль")) return;
    setError("");
    try {
      if (!server.config?.public_endpoint) throw new Error("Сначала укажите адрес подключения к VPN-серверу");
      const [pair, serverPair] = await Promise.all([
        api.wireGuardKeypair(),
        server.config?.private_key
          ? api.wireGuardKeypair(server.config.private_key)
          : api.wireGuardServerPublicKey(server.id),
      ]);
      const presharedKey = randomWireGuardKey();
      edit((draft) => {
        draft.enabled = true;
        draft.credentials = draft.credentials || {};
        draft.credentials.public_key = pair.public_key;
        draft.credentials.private_key = pair.private_key;
        draft.credentials.preshared_key = presharedKey;
      });
      setSecret({ publicKey: pair.public_key, privateKey: pair.private_key, serverPublicKey: serverPair.public_key, presharedKey });
    } catch (err: any) { setError(err?.message || "Генерация ключа завершилась ошибкой"); }
  }
  function download() {
    if (!preparedConfig) { setError("Сначала откройте сохранённый профиль."); return; }
    const url = URL.createObjectURL(new Blob([preparedConfig], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `${peer.name || peer.id}.conf`;
    link.click();
    URL.revokeObjectURL(url);
  }
  const state = status?.state || "pending";
  const known = ["recent", "idle", "never"].includes(state);
  return <Row className="peer-card" icon="monitor-smartphone" id={peer.id} data-vpn-server={server.id} data-vpn-client={peer.id}
    cells={[<strong>{peer.name}</strong>, <span className="mono">{peer.address || "—"}</span>, <span className="mono">{known ? status?.endpoint || "Неизвестен" : "—"}</span>, channelName(channels, peer), <ClientBadge server={server} peer={peer} status={status} />]}
    toggle={<Switch checked={!!peer.enabled} label="" ariaLabel="Доступ разрешён" onChange={(value) => edit((draft) => draft.enabled = value)} />}>
    <ClientConnection status={status} />
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Название клиента"><input value={peer.name || ""} onChange={(e) => edit((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-адрес"><input className="mono" value={peer.address || ""} onChange={(e) => edit((draft) => draft.address = e.target.value)} /></Field>
      <Field label="Канал выхода"><select value={peer.channel || ""} onChange={(e) => edit((draft) => draft.channel = e.target.value)}><option value="">По настройке сервера</option>{channels.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Комментарий"><input value={peer.comment || ""} onChange={(e) => edit((draft) => draft.comment = e.target.value)} /></Field>
    </div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Трафик через VPN (AllowedIPs)" hint="Подсети, которые это устройство направляет в туннель. 0.0.0.0/0 — весь IPv4-трафик; по одной подсети в строке."><ProfileListInput label="Трафик через VPN (AllowedIPs)" values={profile.allowed_ips} onChange={(items) => editProfile((value) => { value.allowed_ips = items; })} /></Field>
      <Field label="DNS в профиле" hint="DNS роутера — адрес его WireGuard-интерфейса. Для своих DNS отключите переключатель; пустой список оставит DNS устройства. При выборочной маршрутизации включите адрес DNS роутера в AllowedIPs."><Switch checked={profile.use_router_dns} label="DNS роутера" onChange={(enabled) => editProfile((value) => { value.use_router_dns = enabled; })} /><ProfileListInput label="DNS в профиле" disabled={profile.use_router_dns} values={profile.dns} onChange={(items) => editProfile((value) => { value.dns = items; })} /></Field>
    </div>
    <p className="hint">После изменения этих настроек скачайте профиль заново или отсканируйте QR-код на устройстве.</p>
    {secret ? <div className="client-package">
      <div className="qr-card"><QRCodeSVG value={preparedConfig} size={176} level="M" marginSize={2} title={`WireGuard-профиль ${peer.name || peer.id}`} /></div>
      <div className="client-package-copy"><strong>Профиль готов к импорту</strong><p>Отсканируйте QR-код в приложении WireGuard или скачайте файл. Профиль сохраняется на роутере после применения настроек. Его можно повторно открыть и скачать без замены ключей.</p><div className="row wrap"><button type="button" className="btn primary" onClick={download}>Скачать .conf</button><CopyButton text={preparedConfig} onError={setError} /><button type="button" className="btn ghost" onClick={() => void generateClient()}>Перевыпустить</button></div></div>
    </div> : Object.hasOwn(peer.credentials || {}, "private_key") ? <div className="row wrap" style={{ marginTop: "0.8rem" }}><button type="button" className="btn primary" disabled={profileBusy} onClick={() => void openProfile()}>{profileBusy ? "Загрузка…" : "Открыть профиль и QR-код"}</button><button type="button" className="btn ghost" onClick={() => void generateClient()}>Перевыпустить профиль</button></div> : <Notice tone="info" title="Профиль создан в прежней версии">Подключение клиента продолжает работать. Для повторной выдачи загрузите его прежний .conf: ключ будет сохранён без изменения подключения. Если файла нет, перевыпустите профиль и передайте новый клиенту.<div className="row wrap" style={{ marginTop: "0.65rem" }}><label className="btn">Загрузить прежний .conf<input aria-label="Загрузить прежний .conf" type="file" accept=".conf" hidden onChange={(event) => { void importProfile(event.target.files?.[0]); event.target.value = ""; }} /></label><button type="button" className="btn" onClick={() => void generateClient()}>Перевыпустить профиль</button></div></Notice>}

    <details className="advanced"><summary>Технические данные</summary><div className="form-grid"><Field label="Публичный ключ устройства"><input className="mono" value={peer.credentials?.public_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.public_key = e.target.value; delete draft.credentials.private_key; removeSecret(); })} /></Field><Field label="Предварительный общий ключ"><input className="mono" type="password" autoComplete="off" {...secretInput(peer, "preshared_key")} value={peer.credentials?.preshared_key || ""} onChange={(e) => edit((draft) => { draft.credentials = draft.credentials || {}; draft.credentials.preshared_key = e.target.value; })} /></Field></div></details>
    <div className="row-actions peer-head">{(secret || Object.hasOwn(peer.credentials || {}, "private_key")) && <Badge tone="ok">профиль доступен</Badge>}<button type="button" className="btn ghost sm to-right" disabled={peer.enabled || referenced} onClick={() => { removeSecret(); update((draft: any) => { draft.peers = draft.peers.filter((item: any) => item.id !== peer.id); }); }}>Удалить</button></div>
  </Row>;
}

function isPeerReferenced(config: any, serverID: string, peerID: string) {
  return (config.policies || []).some((policy: any) =>
    policy.vpn_server === serverID && policy.vpn_peer === peerID);
}
