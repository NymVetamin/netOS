import { useState } from "react";
import { Badge, Card, Empty, Field, Notice, Switch, TableWrap } from "../ui";

type Props = {
  config: any;
  patch: (mutate: (draft: any) => void) => void;
};

const enabledChannels = (config: any) =>
  (config.channels || []).filter((channel: any) => channel.enabled);

export function ChannelsPage({ config, patch }: Props) {
  const channels = config.channels || [];
  const policies = config.policies || [];
  const wireguardInstalled = (config.components || []).some(
    (component: any) => component.id === "wireguard" && component.installed,
  );
  const openconnectInstalled = (config.components || []).some(
    (component: any) => component.id === "openconnect" && component.installed,
  );
  const xrayInstalled = (config.components || []).some(
    (component: any) => component.id === "xray" && component.installed,
  );

  function updateChannel(id: string, mutate: (channel: any) => void) {
    patch((draft) => mutate(draft.channels.find((channel: any) => channel.id === id)));
  }

  function addWireGuard() {
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id: `wg-${Date.now()}`,
        index,
        name: `WireGuard ${index}`,
        enabled: false,
        type: "wireguard",
        mode: "tun",
        fail_mode: "block",
        fallback: "",
        probe: { enabled: true, type: "icmp", targets: ["1.1.1.1"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: {
          address: "",
          private_key: "",
          peer_public_key: "",
          preshared_key: "",
          endpoint: "",
          allowed_ips: ["0.0.0.0/0"],
          persistent_keepalive: 25,
          mtu: 1420,
        },
      });
    });
  }

  function addOpenConnect() {
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id: `oc-${Date.now()}`, index, name: `OpenConnect ${index}`, enabled: false,
        type: "openconnect", mode: "tun", fail_mode: "block", fallback: "",
        probe: { enabled: true, type: "icmp", targets: ["1.1.1.1"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: { server: "", username: "", password: "", protocol: "anyconnect", authgroup: "", servercert: "", mtu: 1400, no_dtls: false, no_system_trust: false },
      });
    });
  }

  function addXray() {
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id: `xray-${Date.now()}`, index, name: `Xray ${index}`, enabled: false,
        type: "xray", mode: "tun", fail_mode: "block", fallback: "",
        probe: { enabled: true, type: "tcp", targets: ["1.1.1.1:443"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: { mtu: 1400, outbound: { protocol: "vless", settings: { vnext: [] }, streamSettings: { network: "tcp", security: "none" } } },
      });
    });
  }

  return (
    <>
      <div className="page-head">
        <h1>Каналы и политики</h1>
        <p>Выбор выхода в интернет для сегментов, устройств и отдельных потоков</p>
      </div>

      <Card
        title="Каналы выхода"
        subtitle="Прямой выход всегда доступен; VPN-каналы защищены настраиваемым kill-switch"
        actions={<div className="row channel-add-actions"><button className="btn" onClick={addWireGuard}>WireGuard</button><button className="btn" onClick={addOpenConnect}>OpenConnect</button><button className="btn" onClick={addXray}>Xray</button></div>}
      >
        {channels.map((channel: any) =>
          channel.type === "direct" ? (
            <div className="row" key={channel.id} style={{ justifyContent: "space-between" }}>
              <div>
                <strong>{channel.name}</strong>
                <div className="hint">Обычная таблица маршрутизации провайдера</div>
              </div>
              <Badge tone="ok">активен</Badge>
            </div>
          ) : channel.type === "wireguard" ? (
            <WireGuardEditor
              key={channel.id}
              channel={channel}
              channels={channels}
              installed={wireguardInstalled}
              referenced={isChannelReferenced(config, channel.id)}
              update={(mutate) => updateChannel(channel.id, mutate)}
              remove={() =>
                patch((draft) => {
                  draft.channels = draft.channels.filter((item: any) => item.id !== channel.id);
                })
              }
            />
          ) : channel.type === "openconnect" ? (
            <OpenConnectEditor
              key={channel.id}
              channel={channel}
              channels={channels}
              installed={openconnectInstalled}
              referenced={isChannelReferenced(config, channel.id)}
              update={(mutate) => updateChannel(channel.id, mutate)}
              remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); })}
            />
          ) : channel.type === "xray" ? (
            <XrayEditor
              key={channel.id}
              channel={channel}
              channels={channels}
              installed={xrayInstalled}
              referenced={isChannelReferenced(config, channel.id)}
              update={(mutate) => updateChannel(channel.id, mutate)}
              remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); })}
            />
          ) : (
            <Notice key={channel.id} tone="warn" title={`Неподдерживаемый канал: ${channel.type || "без типа"}`}>
              Этот сохранённый канал нельзя включить в текущей версии. Удалите его из конфигурации или выберите поддерживаемый тип.
            </Notice>
          ),
        )}
      </Card>

      <SegmentDefaults config={config} patch={patch} />
      <Policies config={config} patch={patch} policies={policies} />
    </>
  );
}

function XrayEditor({ channel, channels, installed, referenced, update, remove }: {
  channel: any; channels: any[]; installed: boolean; referenced: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void;
}) {
  const [raw, setRaw] = useState(() => JSON.stringify(channel.config?.outbound || {}, null, 2));
  const [link, setLink] = useState("");
  const [error, setError] = useState("");
  const setOutbound = (outbound: any) => {
    setRaw(JSON.stringify(outbound, null, 2));
    update((draft) => { draft.config = draft.config || {}; draft.config.outbound = outbound; });
  };
  const importLink = () => {
    try {
      setOutbound(parseXrayLink(link.trim()));
      setLink(""); setError("");
    } catch (err: any) { setError(err?.message || "Ссылка не распознана"); }
  };
  return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
      <div className="row"><strong>{channel.name}</strong><Badge tone={channel.enabled ? "ok" : "neutral"}>{channel.enabled ? "включён" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!channel.enabled} disabled={!installed || !!error} onChange={(enabled) => update((draft) => draft.enabled = enabled)} label="Использовать" /><button type="button" className="btn ghost sm" disabled={channel.enabled || referenced} onClick={remove}>Удалить</button></div>
    </div>
    {!installed && <Notice tone="info" title="Нужен компонент Xray">Установите проверенную сборку Xray в разделе «Компоненты» перед включением.</Notice>}
    {error && <Notice tone="warn" title="Конфигурация Xray не разобрана">{error}</Notice>}
    <div className="form-grid">
      <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={channel.config?.mtu || 1400} onChange={(e) => update((draft) => { draft.config.mtu = Number(e.target.value); })} /></Field>
      <Field label="Ссылка подключения" hint="vless://, vmess://, trojan:// или ss://"><div className="row"><input className="mono" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://…" /><button type="button" className="btn ghost sm" disabled={!link.trim()} onClick={importLink}>Импорт</button></div></Field>
      <Field label="При отказе"><select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => draft.fail_mode = e.target.value)}><option value="block">Блокировать</option><option value="fallback">Запасной канал</option><option value="direct">Напрямую</option></select></Field>
      {channel.fail_mode === "fallback" && <Field label="Запасной канал"><select value={channel.fallback || ""} onChange={(e) => update((draft) => draft.fallback = e.target.value)}><option value="">Выберите канал</option>{channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>}
      <Field label="Проверка канала"><Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe = draft.probe || {}; draft.probe.enabled = enabled; })} /></Field>
      {channel.probe?.enabled !== false && <>
        <Field label="Тип проверки"><select value={channel.probe?.type || "tcp"} onChange={(e) => update((draft) => draft.probe.type = e.target.value)}><option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option></select></Field>
        <Field label="Цели" hint="По одной в строке"><textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean))} /></Field>
        <Field label="Интервал, сек"><input type="number" min={1} value={channel.probe?.interval || 10} onChange={(e) => update((draft) => draft.probe.interval = Number(e.target.value))} /></Field>
        <Field label="Таймаут, сек"><input type="number" min={1} value={channel.probe?.timeout || 3} onChange={(e) => update((draft) => draft.probe.timeout = Number(e.target.value))} /></Field>
        <Field label="Ошибок до отказа"><input type="number" min={1} value={channel.probe?.fail_threshold || 3} onChange={(e) => update((draft) => draft.probe.fail_threshold = Number(e.target.value))} /></Field>
        <Field label="Успехов до возврата"><input type="number" min={1} value={channel.probe?.rise_threshold || 2} onChange={(e) => update((draft) => draft.probe.rise_threshold = Number(e.target.value))} /></Field>
      </>}
    </div>
    <Field label="Outbound Xray (JSON)" hint="Можно использовать любой поддержанный Xray transport: Reality, XTLS, XHTTP, WebSocket, gRPC, mKCP и другие.">
      <textarea className="mono" style={{ minHeight: 260 }} spellCheck={false} value={raw} onChange={(e) => {
        const value = e.target.value; setRaw(value);
        try { const parsed = JSON.parse(value); setError(""); update((draft) => { draft.config.outbound = parsed; }); }
        catch (err: any) { setError(err.message); }
      }} />
    </Field>
  </form>;
}

function parseXrayLink(value: string): any {
  if (value.startsWith("vmess://")) {
    const data = JSON.parse(decodeBase64(value.slice(8)));
    const outbound: any = { protocol: "vmess", settings: { vnext: [{ address: data.add, port: Number(data.port), users: [{ id: data.id, alterId: Number(data.aid || 0), security: data.scy || "auto" }] }] } };
    outbound.streamSettings = streamSettings(data.net || "tcp", data.tls || "none", { host: data.host, path: data.path, sni: data.sni, serviceName: data.path, fingerprint: data.fp });
    return outbound;
  }
  if (value.startsWith("ss://") && !value.slice(5).includes("@")) {
    const decoded = decodeBase64(value.slice(5).split("#")[0]);
    const at = decoded.lastIndexOf("@");
    if (at < 1) throw new Error("Некорректная Shadowsocks-ссылка");
    return shadowsocksOutbound(decoded.slice(0, at), decoded.slice(at + 1));
  }
  const url = new URL(value);
  const port = Number(url.port);
  if (!url.hostname || !port) throw new Error("В ссылке нет сервера или порта");
  if (url.protocol === "ss:") {
    const credentials = decodeBase64(decodeURIComponent(url.username));
    return shadowsocksOutbound(credentials, `${url.hostname}:${port}`);
  }
  const protocol = url.protocol.slice(0, -1);
  if (protocol !== "vless" && protocol !== "trojan") throw new Error("Поддерживаются vless://, vmess://, trojan:// и ss://");
  const user = decodeURIComponent(url.username);
  const server: any = { address: url.hostname, port };
  if (protocol === "vless") server.users = [{ id: user, encryption: url.searchParams.get("encryption") || "none", ...(url.searchParams.get("flow") ? { flow: url.searchParams.get("flow") } : {}) }];
  else server.password = user;
  const settings = protocol === "vless" ? { vnext: [server] } : { servers: [server] };
  return { protocol, settings, streamSettings: streamSettings(url.searchParams.get("type") || "tcp", url.searchParams.get("security") || "none", {
    host: url.searchParams.get("host"), path: url.searchParams.get("path"), sni: url.searchParams.get("sni"),
    serviceName: url.searchParams.get("serviceName"), fingerprint: url.searchParams.get("fp"),
    publicKey: url.searchParams.get("pbk"), shortId: url.searchParams.get("sid"), spiderX: url.searchParams.get("spx"),
  }) };
}

function streamSettings(network: string, security: string, options: any): any {
  const out: any = { network, security };
  if (network === "ws") out.wsSettings = { path: options.path || "/", headers: options.host ? { Host: options.host } : {} };
  if (network === "grpc") out.grpcSettings = { serviceName: options.serviceName || "" };
  if (network === "xhttp") out.xhttpSettings = { path: options.path || "/", host: options.host || "" };
  if (security === "tls") out.tlsSettings = { serverName: options.sni || options.host || "", fingerprint: options.fingerprint || "chrome" };
  if (security === "reality") out.realitySettings = { serverName: options.sni || "", fingerprint: options.fingerprint || "chrome", password: options.publicKey || "", shortId: options.shortId || "", spiderX: options.spiderX || "" };
  return out;
}

function shadowsocksOutbound(credentials: string, endpoint: string): any {
  const split = credentials.indexOf(":");
  const lastColon = endpoint.lastIndexOf(":");
  if (split < 1 || lastColon < 1) throw new Error("Некорректная Shadowsocks-ссылка");
  return { protocol: "shadowsocks", settings: { servers: [{ method: credentials.slice(0, split), password: credentials.slice(split + 1), address: endpoint.slice(0, lastColon), port: Number(endpoint.slice(lastColon + 1)) }] } };
}

function decodeBase64(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

function OpenConnectEditor({ channel, channels, installed, referenced, update, remove }: {
  channel: any; channels: any[]; installed: boolean; referenced: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void;
}) {
  const cfg = channel.config || {};
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
  return (
    <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
        <div className="row"><strong>{channel.name}</strong><Badge tone={channel.enabled ? "ok" : "neutral"}>{channel.enabled ? "включён" : "черновик"}</Badge></div>
        <div className="row"><Switch checked={!!channel.enabled} disabled={!installed} onChange={(enabled) => update((draft) => (draft.enabled = enabled))} label="Использовать" /><button type="button" className="btn ghost sm" disabled={channel.enabled || referenced} onClick={remove}>Удалить</button></div>
      </div>
      {!installed && <Notice tone="info" title="Нужен компонент OpenConnect">Установите его перед включением канала.</Notice>}
      <div className="form-grid">
        <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => (draft.name = e.target.value))} /></Field>
        <Field label="VPN-сервер"><input className="mono" placeholder="https://vpn.example.com" value={cfg.server || ""} onChange={(e) => setConfig("server", e.target.value)} /></Field>
        <Field label="Протокол"><select value={cfg.protocol || "anyconnect"} onChange={(e) => setConfig("protocol", e.target.value)}><option value="anyconnect">AnyConnect</option><option value="pulse">Pulse</option><option value="gp">GlobalProtect</option><option value="fortinet">Fortinet</option><option value="f5">F5</option><option value="array">Array</option><option value="nc">Network Connect</option></select></Field>
        <Field label="Группа / realm"><input value={cfg.authgroup || ""} onChange={(e) => setConfig("authgroup", e.target.value)} /></Field>
        <Field label="Пользователь"><input autoComplete="off" value={cfg.username || ""} onChange={(e) => setConfig("username", e.target.value)} /></Field>
        <Field label="Пароль"><input type="password" autoComplete="new-password" value={cfg.password || ""} onChange={(e) => setConfig("password", e.target.value)} /></Field>
        <Field label="Отпечаток сертификата" hint="Необязательно; pin-sha256:…"><input className="mono" value={cfg.servercert || ""} onChange={(e) => setConfig("servercert", e.target.value)} /></Field>
        <Field label="MTU"><input type="number" min={576} max={9000} value={cfg.mtu || 1400} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
        <Field label="Транспорт"><Switch checked={!cfg.no_dtls} label="Использовать DTLS" onChange={(enabled) => setConfig("no_dtls", !enabled)} /></Field>
        <Field label="Доверие TLS"><Switch checked={!cfg.no_system_trust} label="Системные CA" onChange={(enabled) => setConfig("no_system_trust", !enabled)} /></Field>
        <Field label="При отказе"><select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => (draft.fail_mode = e.target.value))}><option value="block">Блокировать</option><option value="fallback">Запасной канал</option><option value="direct">Напрямую</option></select></Field>
        {channel.fail_mode === "fallback" && <Field label="Запасной канал"><select value={channel.fallback || ""} onChange={(e) => update((draft) => (draft.fallback = e.target.value))}><option value="">Выберите канал</option>{channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>}
        <Field label="Проверка канала"><Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe.enabled = enabled; })} /></Field>
        {channel.probe?.enabled !== false && <>
          <Field label="Тип проверки"><select value={channel.probe?.type || "icmp"} onChange={(e) => update((draft) => (draft.probe.type = e.target.value))}><option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option></select></Field>
          <Field label="Цели"><textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => (draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean)))} /></Field>
          <Field label="Интервал, сек"><input type="number" min={1} value={channel.probe?.interval || 10} onChange={(e) => update((draft) => (draft.probe.interval = Number(e.target.value)))} /></Field>
          <Field label="Таймаут, сек"><input type="number" min={1} value={channel.probe?.timeout || 3} onChange={(e) => update((draft) => (draft.probe.timeout = Number(e.target.value)))} /></Field>
          <Field label="Ошибок до отказа"><input type="number" min={1} value={channel.probe?.fail_threshold || 3} onChange={(e) => update((draft) => (draft.probe.fail_threshold = Number(e.target.value)))} /></Field>
          <Field label="Успехов до возврата"><input type="number" min={1} value={channel.probe?.rise_threshold || 2} onChange={(e) => update((draft) => (draft.probe.rise_threshold = Number(e.target.value)))} /></Field>
        </>}
      </div>
    </form>
  );
}

function WireGuardEditor({
  channel,
  channels,
  installed,
  referenced,
  update,
  remove,
}: {
  channel: any;
  channels: any[];
  installed: boolean;
  referenced: boolean;
  update: (mutate: (channel: any) => void) => void;
  remove: () => void;
}) {
  const cfg = channel.config || {};
  const setConfig = (key: string, value: unknown) =>
    update((draft) => {
      draft.config = draft.config || {};
      draft.config[key] = value;
    });

  return (
    <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
      <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
        <div className="row">
          <strong>{channel.name}</strong>
          <Badge tone={channel.enabled ? "ok" : "neutral"}>
            {channel.enabled ? "включён" : "черновик"}
          </Badge>
        </div>
        <div className="row">
          <Switch
            checked={!!channel.enabled}
            disabled={!installed}
            onChange={(enabled) => update((draft) => (draft.enabled = enabled))}
            label="Использовать"
          />
          <button type="button" className="btn ghost sm" disabled={channel.enabled || referenced} onClick={remove}>
            Удалить
          </button>
        </div>
      </div>
      <div className="form-grid">
        <Field label="Название">
          <input value={channel.name || ""} onChange={(e) => update((draft) => (draft.name = e.target.value))} />
        </Field>
        <Field label="Адрес туннеля" hint="Адрес клиента из конфигурации провайдера">
          <input className="mono" placeholder="10.8.0.2/32" value={cfg.address || ""} onChange={(e) => setConfig("address", e.target.value)} />
        </Field>
        <Field label="Endpoint">
          <input className="mono" placeholder="vpn.example.com:51820" value={cfg.endpoint || ""} onChange={(e) => setConfig("endpoint", e.target.value)} />
        </Field>
        <Field label="AllowedIPs" hint="Исходящий канал должен содержать 0.0.0.0/0">
          <input className="mono" value={(cfg.allowed_ips || []).join(", ")} onChange={(e) => setConfig("allowed_ips", e.target.value.split(",").map((value) => value.trim()).filter(Boolean))} />
        </Field>
        <Field label="Приватный ключ">
          <input type="password" className="mono" autoComplete="off" value={cfg.private_key || ""} onChange={(e) => setConfig("private_key", e.target.value.trim())} />
        </Field>
        <Field label="Публичный ключ сервера">
          <input type="password" className="mono" autoComplete="off" value={cfg.peer_public_key || ""} onChange={(e) => setConfig("peer_public_key", e.target.value.trim())} />
        </Field>
        <Field label="Preshared key" hint="Необязательно">
          <input type="password" className="mono" autoComplete="off" value={cfg.preshared_key || ""} onChange={(e) => setConfig("preshared_key", e.target.value.trim())} />
        </Field>
        <Field label="MTU">
          <input type="number" min={576} max={9000} value={cfg.mtu || 1420} onChange={(e) => setConfig("mtu", Number(e.target.value))} />
        </Field>
        <Field label="Persistent keepalive, сек">
          <input type="number" min={0} max={65535} value={cfg.persistent_keepalive || 0} onChange={(e) => setConfig("persistent_keepalive", Number(e.target.value))} />
        </Field>
        <Field label="При отказе">
          <select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => (draft.fail_mode = e.target.value))}>
            <option value="block">Блокировать (kill-switch)</option>
            <option value="fallback">Запасной канал</option>
            <option value="direct">Напрямую</option>
          </select>
        </Field>
        {channel.fail_mode === "fallback" && (
          <Field label="Запасной канал">
            <select value={channel.fallback || ""} onChange={(e) => update((draft) => (draft.fallback = e.target.value))}>
              <option value="">Выберите канал</option>
              {channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
          </Field>
        )}
        <Field label="Проверка канала">
          <Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe = draft.probe || {}; draft.probe.enabled = enabled; })} />
        </Field>
        {channel.probe?.enabled !== false && <>
          <Field label="Тип проверки">
            <select value={channel.probe?.type || "icmp"} onChange={(e) => update((draft) => (draft.probe.type = e.target.value))}>
              <option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option>
            </select>
          </Field>
          <Field label="Цели" hint="По одной в строке">
            <textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => (draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean)))} />
          </Field>
          <Field label="Интервал, сек"><input type="number" min={1} value={channel.probe?.interval || 10} onChange={(e) => update((draft) => (draft.probe.interval = Number(e.target.value)))} /></Field>
          <Field label="Таймаут, сек"><input type="number" min={1} value={channel.probe?.timeout || 3} onChange={(e) => update((draft) => (draft.probe.timeout = Number(e.target.value)))} /></Field>
          <Field label="Ошибок до отказа"><input type="number" min={1} value={channel.probe?.fail_threshold || 3} onChange={(e) => update((draft) => (draft.probe.fail_threshold = Number(e.target.value)))} /></Field>
          <Field label="Успехов до возврата"><input type="number" min={1} value={channel.probe?.rise_threshold || 2} onChange={(e) => update((draft) => (draft.probe.rise_threshold = Number(e.target.value)))} /></Field>
        </>}
      </div>
      <div className="hint">Проверка идёт через интерфейс самого туннеля; переключение выполняется только после заданного числа ошибок.</div>
    </form>
  );
}

function SegmentDefaults({ config, patch }: Props) {
  const choices = enabledChannels(config);
  if (!(config.networks || []).length) return null;
  return (
    <Card title="Канал сегмента" subtitle="Используется, если нет более точной политики или настройки устройства" tight>
      <TableWrap>
        <table>
          <thead><tr><th>Сегмент</th><th>Подсеть</th><th>Канал по умолчанию</th></tr></thead>
          <tbody>
            {config.networks.map((network: any) => (
              <tr key={network.id}>
                <td>{network.name}</td>
                <td className="mono faint">{network.router_address}</td>
                <td>
                  <select value={network.default_channel || "direct"} onChange={(e) => patch((draft) => {
                    draft.networks.find((item: any) => item.id === network.id).default_channel = e.target.value;
                  })}>
                    {choices.map((channel: any) => <option key={channel.id} value={channel.id}>{channel.name}</option>)}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Card>
  );
}

function Policies({ config, patch, policies }: Props & { policies: any[] }) {
  const [name, setName] = useState("");
  const [channel, setChannel] = useState("direct");
  const choices = enabledChannels(config);

  return (
    <Card title="Политики" subtitle="Меньшее число — более высокий приоритет">
      {policies.length === 0 ? <Empty>Явных политик нет</Empty> : (
        <TableWrap>
          <table>
            <thead><tr><th>Вкл.</th><th>Приоритет</th><th>Название</th><th>Источник</th><th>Назначение</th><th>Протокол / порт</th><th>Канал</th><th /></tr></thead>
            <tbody>
              {policies.map((policy: any) => (
                <tr key={policy.id}>
                  <td><input type="checkbox" checked={!!policy.enabled} onChange={(e) => updatePolicy(patch, policy.id, "enabled", e.target.checked)} /></td>
                  <td><input type="number" style={{ width: 85 }} value={policy.priority || 0} onChange={(e) => updatePolicy(patch, policy.id, "priority", Number(e.target.value))} /></td>
                  <td><input value={policy.name || ""} onChange={(e) => updatePolicy(patch, policy.id, "name", e.target.value)} /></td>
                  <td><input className="mono" placeholder="IP/CIDR" value={policy.src_ip || ""} onChange={(e) => updatePolicy(patch, policy.id, "src_ip", e.target.value)} /></td>
                  <td><input className="mono" placeholder="IP/CIDR" value={policy.dst_ip || ""} onChange={(e) => updatePolicy(patch, policy.id, "dst_ip", e.target.value)} /></td>
                  <td><div className="row"><select value={policy.protocol || "any"} onChange={(e) => updatePolicy(patch, policy.id, "protocol", e.target.value)}><option value="any">any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select><input className="mono" style={{ width: 90 }} placeholder="порт" value={policy.dst_port || ""} onChange={(e) => updatePolicy(patch, policy.id, "dst_port", e.target.value)} /></div></td>
                  <td><select value={policy.channel} onChange={(e) => updatePolicy(patch, policy.id, "channel", e.target.value)}>{choices.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></td>
                  <td><button className="btn ghost sm" onClick={() => patch((draft) => { draft.policies = draft.policies.filter((item: any) => item.id !== policy.id); })}>Убрать</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <div className="row policy-add-row" style={{ marginTop: "1rem" }}>
        <input placeholder="Название новой политики" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={channel} onChange={(e) => setChannel(e.target.value)}>{choices.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <button className="btn primary" disabled={!name.trim()} onClick={() => {
          patch((draft) => {
            const priority = Math.max(0, ...(draft.policies || []).map((item: any) => item.priority || 0)) + 100;
            draft.policies = draft.policies || [];
            draft.policies.push({ id: `policy-${Date.now()}`, name: name.trim(), enabled: false, priority, channel, src_ip: "", src_mac: "", network: "", vpn_server: "", vpn_peer: "", protocol: "any", dst_port: "", dst_ip: "", domains: [], comment: "" });
          });
          setName("");
        }}>Добавить</button>
      </div>
    </Card>
  );
}

function updatePolicy(patch: Props["patch"], id: string, key: string, value: unknown) {
  patch((draft) => { draft.policies.find((policy: any) => policy.id === id)[key] = value; });
}

function isChannelReferenced(config: any, id: string) {
  return (config.clients || []).some((item: any) => item.channel === id) ||
    (config.networks || []).some((item: any) => item.default_channel === id) ||
    (config.policies || []).some((item: any) => item.channel === id);
}
