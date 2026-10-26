import { SectionLink } from "../permissions";
import { useStatusPolling } from "../StatusPollingContext";
import { channelReferences, canReplaceChannel } from "../channelReferences";
import { secretInput } from "../secrets";
import { createContext, Fragment, ReactNode, useContext, useEffect, useState } from "react";
import { api } from "../api";
import { channelComponents, channelComponentReady } from "../channelComponents";
import { newID } from "../id";
import { parseXrayLink } from "../xrayLink";
import { changeProbeType } from "../probeType";
import { channelNAT, setChannelNAT, removeChannelNAT } from "../channelNAT";
import { AddMenu, Badge, Cap, Card, Empty, Field, Notice, openOnCreate, Row, Rows, Switch } from "../ui";
import { CHANNEL_ICONS, Icon } from "../icons";

type Props = {
  config: any;
  patch: (mutate: (draft: any) => void) => void;
};

const enabledChannels = (config: any) =>
  (config.channels || []).filter((channel: any) => channel.enabled);

const POLICY_DAYS = [
  ["Mon", "Пн"], ["Tue", "Вт"], ["Wed", "Ср"], ["Thu", "Чт"],
  ["Fri", "Пт"], ["Sat", "Сб"], ["Sun", "Вс"],
];

export function ChannelsPage({ config, patch }: Props) {
  const statusPolling = useStatusPolling();
  const [installed, setInstalled] = useState<Record<string, boolean> | null>(null);
  const [componentError, setComponentError] = useState(false);
  useEffect(() => {
    let active = true;
    let timer: number | undefined;
    let controller: AbortController | undefined;
    const load = async () => {
      controller = new AbortController();
      const timeout = window.setTimeout(() => controller?.abort(), 15000);
      try {
        const catalog = await api.componentStatus(channelComponents.map(c => c.id), controller.signal);
        if (active) { setInstalled(catalog.installed || {}); setComponentError(false); }
      } catch {
        if (active) { setInstalled(null); setComponentError(true); }
      } finally {
        window.clearTimeout(timeout);
        if (active) timer = window.setTimeout(load, 5000);
      }
    };
    void load();
    return () => { active = false; controller?.abort(); window.clearTimeout(timer); };
  }, []);
  const [liveChannels, setLiveChannels] = useState<any[] | null>(null);
  const [liveError, setLiveError] = useState(false);
  useEffect(() => {
    let active = true;
    const unsubscribe = statusPolling.subscribe(5000, false, request => {
      void request.then(status => {
        if (active) { setLiveChannels(status.channels || []); setLiveError(false); }
      }).catch(() => {
        if (active) setLiveError(true);
      });
    });
    return () => { active = false; unsubscribe(); };
  }, [statusPolling]);
  const channels = config.channels || [];
  const policies = config.policies || [];
  const ready = (type: string) => channelComponentReady(config, installed, type);
  const wireguardInstalled = ready("wireguard");
  const openconnectInstalled = ready("openconnect");
  const xrayInstalled = ready("xray");
  const l2tpInstalled = ready("l2tp");
  const strongswanInstalled = ready("ikev2");
  const missing = channelComponents.filter(component => !ready(component.type));

  const [disableID, setDisableID] = useState("");
  const [replacement, setReplacement] = useState("");
  const disabling = channels.find((c: any) => c.id === disableID);
  const dependencies = disabling ? channelReferences(config, disableID) : [];

  useEffect(() => {
    if (disableID) document.getElementById("channel-disable-choice")?.scrollIntoView({ block: "center" });
  }, [disableID]);

  function updateChannel(id: string, mutate: (channel: any) => void) {
    const current = channels.find((c: any) => c.id === id);
    if (!current) return;
    const next = structuredClone(current);
    mutate(next);
    if (current.enabled && !next.enabled && channelReferences(config, id).length) {
      setDisableID(id);
      setReplacement("");
      return;
    }
    patch((draft) => mutate(draft.channels.find((channel: any) => channel.id === id)));
  }

  function addWireGuard() {
    if (!ready("wireguard")) return;
    const id = newID("wg");
    openOnCreate(id);
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id,
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
    if (!ready("openconnect")) return;
    const id = newID("oc");
    openOnCreate(id);
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id, index, name: `OpenConnect ${index}`, enabled: false,
        type: "openconnect", mode: "tun", fail_mode: "block", fallback: "",
        probe: { enabled: true, type: "icmp", targets: ["1.1.1.1"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: { server: "", username: "", password: "", protocol: "anyconnect", authgroup: "", servercert: "", mtu: 1400, no_dtls: false, no_system_trust: false },
      });
    });
  }

  function addXray() {
    if (!ready("xray")) return;
    const id = newID("xray");
    openOnCreate(id);
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id, index, name: `Xray ${index}`, enabled: false,
        type: "xray", mode: "tun", fail_mode: "block", fallback: "",
        probe: { enabled: true, type: "http", targets: ["https://www.cloudflare.com/cdn-cgi/trace"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: { mtu: 1400, outbound: { protocol: "vless", settings: { vnext: [] }, streamSettings: { network: "tcp", security: "none" } } },
      });
    });
  }

  function addL2TP() {
    if (!ready("l2tp")) return;
    const id = newID("l2tp");
    openOnCreate(id);
    patch((draft) => {
      const used = new Set((draft.channels || []).map((channel: any) => channel.index));
      let index = 1;
      while (used.has(index)) index++;
      draft.channels.push({
        id, index, name: `L2TP ${index}`, enabled: false,
        type: "l2tp", mode: "tun", fail_mode: "block", fallback: "",
        probe: { enabled: true, type: "http", targets: ["https://www.cloudflare.com/cdn-cgi/trace"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
        config: { server: "", username: "", password: "", mtu: 1400 },
      });
    });
  }

	function addIKEv2() {
    if (!ready("ikev2")) return;
    const id = newID("ikev2");
    openOnCreate(id);
		patch((draft) => {
			const used = new Set((draft.channels || []).map((channel: any) => channel.index));
			let index = 1;
			while (used.has(index)) index++;
			draft.channels.push({
				id, index, name: `IKEv2 ${index}`, enabled: false,
				type: "ikev2", mode: "tun", fail_mode: "block", fallback: "",
				probe: { enabled: true, type: "http", targets: ["https://www.cloudflare.com/cdn-cgi/trace"], interval: 10, timeout: 3, fail_threshold: 3, rise_threshold: 2 },
				config: { server: "", server_identity: "", username: "", password: "", ca_cert: "", mtu: 1200 },
			});
		});
	}

  // В меню только те типы, чей компонент установлен: создать канал, который
  // нельзя включить, панель не даёт.
  const adders: Record<string, () => void> = { wireguard: addWireGuard, openconnect: addOpenConnect, xray: addXray, ikev2: addIKEv2, l2tp: addL2TP };
  const addItems = channelComponents.filter(component => ready(component.type)).map(component => {
    const name = component.type === "ikev2" ? "IKEv2" : component.title;
    return { label: name, ariaLabel: name, icon: CHANNEL_ICONS[component.type], onSelect: adders[component.type] };
  });

  return (
    <>
      {disabling && <div id="channel-disable-choice"><Notice tone="warn" title={`Канал «${disabling.name || disabling.id}» используется`}>
        <p>Перед отключением выберите новый выход для связанных настроек:</p>
        <ul>{dependencies.map((ref, i) => <li key={i}>{ref.label}</li>)}</ul>
        <div className="form-grid"><Field label="Новый канал выхода"><select aria-label="Новый канал вместо отключаемого" value={replacement} onChange={e => setReplacement(e.target.value)}>
          <option value="">— выберите —</option>
          {channels.filter((c: any) => canReplaceChannel(config, disableID, c.id)).map((c: any) => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
        </select></Field></div>
        {replacement === "direct" && <p>Связанный трафик пойдёт напрямую, без этого VPN-канала.</p>}
        <div className="row wrap">
          <button type="button" className="btn" onClick={() => { setDisableID(""); setReplacement(""); }}>Отмена</button>
          <button type="button" className="btn danger" disabled={!canReplaceChannel(config, disableID, replacement)} onClick={() => {
            patch(draft => {
              const target = draft.channels.find((c: any) => c.id === disableID);
              if (!target || !canReplaceChannel(draft, disableID, replacement)) return;
              for (const ref of channelReferences(draft, disableID)) ref.owner[ref.key] = replacement;
              target.enabled = false;
            });
            setDisableID(""); setReplacement("");
          }}>Переназначить и выключить</button>
        </div>
        <p className="hint">Изменения вступят в силу после применения. Можно также отменить действие и изменить назначения по отдельности.</p>
      </Notice></div>}
      <div className="page-head">
        <h1><Icon name="globe" />Интернет-каналы</h1>
        <p>VPN-выходы и правила выбора подключения для устройств и сетей</p>
      </div>

      <Card
        tight
        title="Каналы выхода"
        subtitle="Прямой выход всегда доступен; VPN-каналы защищены настраиваемым kill-switch"
        actions={addItems.length > 0 && <AddMenu label="Добавить канал" items={addItems} />}
      >
        <div className="rows-notes">
        {componentError ? <Notice tone="warn" title="Не удалось проверить компоненты">Создание и включение VPN-каналов временно недоступно. Проверка повторится автоматически.</Notice> : installed === null ?
          <div className="hint" role="status">Проверяем установленные VPN-компоненты…</div> : missing.length > 0 &&
          <Notice tone="info" title="Для других типов каналов нужны компоненты">Сначала установите и примените нужный компонент в разделе <SectionLink section="components">«Компоненты»</SectionLink>: {missing.map(item => item.title).join(", ")}. После успешной установки появится кнопка создания канала.</Notice>}
        {liveError && <Notice tone="warn" title="Не удалось обновить состояние каналов">{liveChannels === null ? "Состояние пока неизвестно." : "Показаны последние полученные данные; они могут быть устаревшими."} Повторная попытка выполняется автоматически.</Notice>}
        {liveChannels === null && <div className="hint" role="status">{liveError ? "Состояние каналов недоступно" : "Загрузка состояния каналов…"}</div>}
        </div>
        <NATSettings.Provider value={{config, patch}}>
        <Live.Provider value={liveChannels}>
        <Rows cols={["Канал", "Тип", "Интерфейс", "Проверка", "Состояние"]} toggle="Включён">
        {channels.map((channel: any) => <Fragment key={channel.id}>
          {installed !== null && channelComponents.some(item => item.type === channel.type) && !ready(channel.type) &&
            <Notice tone="warn" title={`${channel.name}: включение недоступно`}>
              {`Для этого канала нужен установленный и выбранный компонент ${channelComponents.find(item => item.type === channel.type)?.title}.`}
              {" "}<SectionLink section="components">Раздел «Компоненты»</SectionLink>. Настройки канала сохранены.
            </Notice>}
          {channel.type === "direct" ? (
            <Row key={channel.id} icon="arrow-right-left" cells={[<strong>{channel.name}</strong>, <span className="dim">через провайдера</span>, "—", "—", <Badge tone="ok">активен</Badge>]} />
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
                  draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id);
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
              remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id); })}
            />
          ) : channel.type === "xray" ? (
            <XrayEditor
              key={channel.id}
              channel={channel}
              channels={channels}
              installed={xrayInstalled}
              referenced={isChannelReferenced(config, channel.id)}
              update={(mutate) => updateChannel(channel.id, mutate)}
              remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id); })}
            />
          ) : channel.type === "l2tp" ? (
            <L2TPEditor
              key={channel.id}
              channel={channel}
              channels={channels}
              installed={l2tpInstalled}
              referenced={isChannelReferenced(config, channel.id)}
              update={(mutate) => updateChannel(channel.id, mutate)}
              remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id); })}
            />
		  ) : channel.type === "ikev2" ? (
			<IKEv2Editor key={channel.id} channel={channel} channels={channels} installed={strongswanInstalled}
				referenced={isChannelReferenced(config, channel.id)} update={(mutate) => updateChannel(channel.id, mutate)}
				remove={() => patch((draft) => { draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id); })} />
          ) : (
            <Notice key={channel.id} tone="warn" title={`Неподдерживаемый канал: ${channel.type || "без типа"}`}>
              <strong>{channel.name || channel.id}</strong>
              <p>Этот сохранённый канал нельзя включить в текущей версии. Его настройки сохранены; канал можно удалить.</p>
              {isChannelReferenced(config, channel.id) && <p>Сначала уберите ссылки на канал в настройках устройств, сегментов, политик, запасных каналов, DNS и VPN-доступа.</p>}
              <button type="button" className="btn ghost sm" aria-label={`Удалить канал ${channel.name || channel.id}`} disabled={isChannelReferenced(config, channel.id)} onClick={() => patch((draft) => {
                draft.channels = draft.channels.filter((item: any) => item.id !== channel.id); removeChannelNAT(draft, channel.id);
              })}>Удалить</button>
            </Notice>
          )}
        </Fragment>)}
        </Rows>
        </Live.Provider>
        </NATSettings.Provider>
      </Card>

      <Policies config={config} patch={patch} policies={policies} />
    </>
  );
}

const TYPE_NAMES: Record<string, string> = { wireguard: "WireGuard", openconnect: "OpenConnect", xray: "Xray", ikev2: "IKEv2", l2tp: "L2TP" };

// Живое состояние каналов из /api/status: его показывает строка самого канала.
const Live = createContext<any[] | null>(null);
const NATSettings = createContext<Props | null>(null);

function ChannelRow({ channel, installed, referenced, blocked, update, remove, children }: {
  channel: any; installed: boolean; referenced: boolean; blocked?: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void; children: ReactNode;
}) {
  const live = (useContext(Live) || []).find((item: any) => item.id === channel.id);
  const settings = useContext(NATSettings);
  const nat = settings ? channelNAT(settings.config, channel) : null;
  const probe = channel.probe?.enabled === false ? "выключена" : `${String(channel.probe?.type || "").toUpperCase()}, каждые ${channel.probe?.interval || 10} с`;
  const state = !channel.enabled ? <Badge tone="neutral">выключен</Badge>
    : !live ? <Badge tone="ok">включён</Badge>
    : <Badge tone={live.up ? "ok" : "warn"}>{live.probe_down ? "проба не прошла" : live.up ? "поднят" : "нет связи"}</Badge>;
  return <Row as="form" className="channel-row" icon={CHANNEL_ICONS[channel.type]} id={channel.id} data-channel-id={channel.id} onSubmit={(event: { preventDefault: () => void }) => event.preventDefault()}
    cells={[<strong>{channel.name}</strong>, TYPE_NAMES[channel.type] || channel.type, <span className="mono">{live?.interface || "—"}</span>, <span className="dim">{probe}</span>, state]}
    toggle={<Switch checked={!!channel.enabled} disabled={!channel.enabled && (!installed || !!blocked)} onChange={(enabled) => update((draft) => draft.enabled = enabled)} label="" ariaLabel="Использовать" />}>
    {children}
    {settings && nat?.iface && <div className="form-grid">
      <Field label="NAT канала" hint={channel.type === "xray" ? "Подмена адресов перед передачей трафика в Xray." : "Без NAT на другой стороне нужен маршрут к подсетям клиентов."}>
        <Switch label="Подменять адреса клиентов (NAT)" ariaLabel={`NAT канала ${channel.name}`} checked={nat.enabled} disabled={nat.manual}
          onChange={enabled => settings.patch(draft => setChannelNAT(draft, draft.channels.find((c: any) => c.id === channel.id), enabled))} />
        {nat.manual && <SectionLink className="hint" section="firewall">Маскарад задан ручным правилом — изменить в защите сети</SectionLink>}
      </Field>
    </div>}
    <div className="row-actions"><button type="button" className="btn ghost sm to-right" disabled={channel.enabled || referenced} onClick={remove}>Удалить</button></div>
  </Row>;
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
  return <ChannelRow blocked={!!error} channel={channel} installed={installed} referenced={referenced} update={update} remove={remove}>
    {error && <Notice tone="warn" title="Конфигурация Xray не разобрана">{error}</Notice>}
    <div className="form-grid">
      <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={9000} value={channel.config?.mtu || 1400} onChange={(e) => update((draft) => { draft.config.mtu = Number(e.target.value); })} /></Field>
      <Field label="При отказе"><select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => draft.fail_mode = e.target.value)}><option value="block">Блокировать</option><option value="fallback">Запасной канал</option><option value="direct">Напрямую</option></select></Field>
      {channel.fail_mode === "fallback" && <Field label="Запасной канал"><select value={channel.fallback || ""} onChange={(e) => update((draft) => draft.fallback = e.target.value)}><option value="">Выберите канал</option>{channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>}
    </div>
    <section className="channel-link-import" aria-label="Импорт подключения">
      <h4>Импорт подключения из ссылки</h4>
      <p className="hint">VLESS, VMess, Trojan или Shadowsocks — заполнить настройки подключения.</p>
      <div className="channel-link-actions"><input aria-label="Ссылка подключения" className="mono" value={link} onChange={(e) => setLink(e.target.value)} placeholder="vless://…" /><button type="button" className="btn primary" disabled={!link.trim()} onClick={importLink}>Импортировать</button></div>
    </section>
    <section className="channel-probe-settings" aria-label="Проверка канала">
      <div className="channel-probe-heading"><h4>Проверка канала</h4><Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe = draft.probe || {}; draft.probe.enabled = enabled; })} /></div>
      {channel.probe?.enabled !== false && <><div className="form-grid">
        {channel.probe?.type === "icmp" && <Notice tone="warn" title="Выберите HTTP или TCP">ICMP получает локальный ответ Xray даже при недоступном VPN-сервере и не проверяет канал.</Notice>}
        <Field label="Тип проверки"><select value={channel.probe?.type || "tcp"} onChange={(e) => update((draft) => changeProbeType(draft.probe, e.target.value))}>{channel.probe?.type === "icmp" && <option value="icmp" disabled>ICMP (недоступно для Xray)</option>}<option value="tcp">TCP</option><option value="http">HTTP</option></select></Field>
        {channel.probe?.type === "tcp" && <>
          <Notice tone="info" title="Нужен ответ удалённой службы">Укажите запрос, понятный выбранной службе, и ожидаемое начало её ответа. Если служба сама присылает приветствие, запрос можно оставить пустым. Молчание до таймаута считается отказом.</Notice>
          <Field label="Запрос TCP" hint="Текст отправляется как введён, включая переводы строк. До 4096 байт."><textarea className="mono" value={channel.probe.tcp_request || ""} onChange={(e) => update((draft) => draft.probe.tcp_request = e.target.value)} /></Field>
          <Field label="Начало ответа TCP" hint="Обязательный точный текст в начале ответа удалённой службы. До 4096 байт."><textarea className="mono" value={channel.probe.tcp_response || ""} onChange={(e) => update((draft) => draft.probe.tcp_response = e.target.value)} /></Field>
        </>}
        <Field label="Цели" hint="По одной в строке"><textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean))} /></Field>
      </div><div className="form-grid channel-probe-timing">
        <Field label="Интервал, сек"><input type="number" min={1} value={channel.probe?.interval || 10} onChange={(e) => update((draft) => draft.probe.interval = Number(e.target.value))} /></Field>
        <Field label="Таймаут, сек"><input type="number" min={1} value={channel.probe?.timeout || 3} onChange={(e) => update((draft) => draft.probe.timeout = Number(e.target.value))} /></Field>
        <Field label="Ошибок до отказа"><input type="number" min={1} value={channel.probe?.fail_threshold || 3} onChange={(e) => update((draft) => draft.probe.fail_threshold = Number(e.target.value))} /></Field>
        <Field label="Успехов до возврата"><input type="number" min={1} value={channel.probe?.rise_threshold || 2} onChange={(e) => update((draft) => draft.probe.rise_threshold = Number(e.target.value))} /></Field>
      </div></>}
    </section>
    <details className="more"><summary>Outbound Xray (JSON)</summary>
    {Object.values(channel.secrets_set || {}).some(Boolean) && <Notice tone="info" title="Секреты подключения сохранены">Пустые значения скрытых полей сохраняют прежние секреты. Для замены импортируйте новую ссылку или введите новое значение.
      <ul>{Object.entries(channel.secrets_set || {}).filter(([, saved]) => saved).map(([field]) => <li key={field}><span className="mono">{field}</span>: ••••••••</li>)}</ul>
    </Notice>}
    <Field label="Outbound Xray (JSON)" hint="Можно использовать любой поддержанный Xray transport: Reality, XTLS, XHTTP, WebSocket, gRPC, mKCP и другие.">
      <textarea className="mono" style={{ minHeight: 260 }} spellCheck={false} value={raw} onChange={(e) => {
        const value = e.target.value; setRaw(value);
        try { const parsed = JSON.parse(value); setError(""); update((draft) => { draft.config.outbound = parsed; }); }
        catch (err: any) { setError(err.message); }
      }} />
    </Field>
    </details>
  </ChannelRow>;
}

function IKEv2Editor({ channel, channels, installed, referenced, update, remove }: {
  channel: any; channels: any[]; installed: boolean; referenced: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void;
}) {
  const cfg = channel.config || {};
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
  return <ChannelRow channel={channel} installed={installed} referenced={referenced} update={update} remove={remove}>
    <div className="form-grid">
      <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-сервер"><input className="mono" placeholder="vpn.example.com" value={cfg.server || ""} onChange={(e) => setConfig("server", e.target.value)} /></Field>
      <Field label="Идентификатор сервера" hint="Имя или IP из сертификата сервера"><input className="mono" placeholder="vpn.example.com" value={cfg.server_identity || ""} onChange={(e) => setConfig("server_identity", e.target.value)} /></Field>
      <Field label="EAP-логин"><input autoComplete="off" value={cfg.username || ""} onChange={(e) => setConfig("username", e.target.value)} /></Field>
      <Field label="EAP-пароль"><input type="password" autoComplete="new-password" {...secretInput(channel, "password")} value={cfg.password || ""} onChange={(e) => setConfig("password", e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={1400} value={cfg.mtu || 1400} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="При отказе"><select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => draft.fail_mode = e.target.value)}><option value="block">Блокировать</option><option value="fallback">Запасной канал</option><option value="direct">Напрямую</option></select></Field>
      {channel.fail_mode === "fallback" && <Field label="Запасной канал"><select value={channel.fallback || ""} onChange={(e) => update((draft) => draft.fallback = e.target.value)}><option value="">Выберите канал</option>{channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>}
      <Field label="Проверка канала"><Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe.enabled = enabled; })} /></Field>
      {channel.probe?.enabled !== false && <><Field label="Тип проверки"><select value={channel.probe?.type || "http"} onChange={(e) => update((draft) => draft.probe.type = e.target.value)}><option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option></select></Field><Field label="Цели"><textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean))} /></Field></>}
    </div>
    <Field label="Доверенный CA-сертификат (PEM)" hint="Скачайте сертификат IKEv2-сервера и вставьте его целиком; соединение проверяет также идентификатор сервера."><textarea className="mono" style={{ minHeight: 160 }} value={cfg.ca_cert || ""} onChange={(e) => setConfig("ca_cert", e.target.value)} /></Field>
  </ChannelRow>;
}

function L2TPEditor({ channel, channels, installed, referenced, update, remove }: {
  channel: any; channels: any[]; installed: boolean; referenced: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void;
}) {
  const cfg = channel.config || {};
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
  return <ChannelRow channel={channel} installed={installed} referenced={referenced} update={update} remove={remove}>
    <Notice tone="warn" title="L2TP без шифрования">Используйте этот канал только в доверенной сети или поверх отдельного защищённого транспорта.</Notice>
    <div className="form-grid">
      <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => draft.name = e.target.value)} /></Field>
      <Field label="VPN-сервер"><input className="mono" placeholder="vpn.example.com" value={cfg.server || ""} onChange={(e) => setConfig("server", e.target.value)} /></Field>
      <Field label="Пользователь"><input autoComplete="off" value={cfg.username || ""} onChange={(e) => setConfig("username", e.target.value)} /></Field>
      <Field label="Пароль"><input type="password" autoComplete="new-password" {...secretInput(channel, "password")} value={cfg.password || ""} onChange={(e) => setConfig("password", e.target.value)} /></Field>
      <Field label="MTU"><input type="number" min={576} max={1460} value={cfg.mtu || 1400} onChange={(e) => setConfig("mtu", Number(e.target.value))} /></Field>
      <Field label="При отказе"><select value={channel.fail_mode || "block"} onChange={(e) => update((draft) => draft.fail_mode = e.target.value)}><option value="block">Блокировать</option><option value="fallback">Запасной канал</option><option value="direct">Напрямую</option></select></Field>
      {channel.fail_mode === "fallback" && <Field label="Запасной канал"><select value={channel.fallback || ""} onChange={(e) => update((draft) => draft.fallback = e.target.value)}><option value="">Выберите канал</option>{channels.filter((item: any) => item.enabled && item.id !== channel.id).map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>}
      <Field label="Проверка канала"><Switch checked={channel.probe?.enabled !== false} label="Включена" onChange={(enabled) => update((draft) => { draft.probe.enabled = enabled; })} /></Field>
      {channel.probe?.enabled !== false && <><Field label="Тип проверки"><select value={channel.probe?.type || "http"} onChange={(e) => update((draft) => draft.probe.type = e.target.value)}><option value="icmp">ICMP</option><option value="tcp">TCP</option><option value="http">HTTP</option></select></Field><Field label="Цели"><textarea className="mono" value={(channel.probe?.targets || []).join("\n")} onChange={(e) => update((draft) => draft.probe.targets = e.target.value.split(/\s+/).filter(Boolean))} /></Field></>}
    </div>
  </ChannelRow>;
}

function OpenConnectEditor({ channel, channels, installed, referenced, update, remove }: {
  channel: any; channels: any[]; installed: boolean; referenced: boolean;
  update: (mutate: (channel: any) => void) => void; remove: () => void;
}) {
  const cfg = channel.config || {};
  const setConfig = (key: string, value: unknown) => update((draft) => { draft.config = draft.config || {}; draft.config[key] = value; });
  return (
    <ChannelRow channel={channel} installed={installed} referenced={referenced} update={update} remove={remove}>
      <div className="form-grid">
        <Field label="Название"><input value={channel.name || ""} onChange={(e) => update((draft) => (draft.name = e.target.value))} /></Field>
        <Field label="VPN-сервер"><input className="mono" placeholder="https://vpn.example.com" value={cfg.server || ""} onChange={(e) => setConfig("server", e.target.value)} /></Field>
        <Field label="Протокол"><input value="AnyConnect" readOnly /></Field>
        <Field label="Группа / realm"><input value={cfg.authgroup || ""} onChange={(e) => setConfig("authgroup", e.target.value)} /></Field>
        <Field label="Пользователь"><input autoComplete="off" value={cfg.username || ""} onChange={(e) => setConfig("username", e.target.value)} /></Field>
        <Field label="Пароль"><input type="password" autoComplete="new-password" {...secretInput(channel, "password")} value={cfg.password || ""} onChange={(e) => setConfig("password", e.target.value)} /></Field>
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
    </ChannelRow>
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
    <ChannelRow channel={channel} installed={installed} referenced={referenced} update={update} remove={remove}>
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
          <input type="password" className="mono" autoComplete="off" {...secretInput(channel, "private_key")} value={cfg.private_key || ""} onChange={(e) => setConfig("private_key", e.target.value.trim())} />
        </Field>
        <Field label="Публичный ключ сервера">
          <input type="password" className="mono" autoComplete="off" value={cfg.peer_public_key || ""} onChange={(e) => setConfig("peer_public_key", e.target.value.trim())} />
        </Field>
        <Field label="Preshared key" hint="Необязательно">
          <input type="password" className="mono" autoComplete="off" {...secretInput(channel, "preshared_key")} value={cfg.preshared_key || ""} onChange={(e) => setConfig("preshared_key", e.target.value.trim())} />
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
    </ChannelRow>
  );
}

function Policies({ config, patch, policies }: Props & { policies: any[] }) {
  const [name, setName] = useState("");
  const [channel, setChannel] = useState("direct");
  const choices = enabledChannels(config);

  return (
    <Card tight title="Политики" subtitle="Меньшее число — более высокий приоритет">
      {policies.length === 0 ? <Empty>Явных политик нет</Empty> : (
        <Rows cols={["Политика", "Источник", "Назначение", "Канал", "Приоритет"]} toggle="Вкл.">
          {policies.map((policy: any) => (
              <Row
                key={policy.id}
                id={policy.id}
                cells={[<strong>{policy.name || "без названия"}</strong>,
                  policy.src_ip ? <span className="mono">{policy.src_ip}</span> : <span className="dim">любой</span>,
                  policy.dst_ip || policy.dst_port || (policy.domains || []).length
                    ? <span className="mono">{[policy.dst_ip, policy.dst_port && `порт ${policy.dst_port}`, (policy.domains || []).length ? `доменов: ${policy.domains.length}` : ""].filter(Boolean).join(", ")}</span>
                    : <span className="dim">любое</span>,
                  choices.find((item: any) => item.id === policy.channel)?.name || policy.channel,
                  <span className="mono">{policy.priority || 0}</span>]}
                toggle={<Switch checked={!!policy.enabled} label="" ariaLabel={`Политика ${policy.name || policy.id} включена`} onChange={(enabled) => updatePolicy(patch, policy.id, "enabled", enabled)} />}
              >
                <div className="form-grid">
                  <Cap label="Приоритет"><input aria-label={`Приоритет политики ${policy.name || policy.id}`} type="number" value={policy.priority || 0} onChange={(e) => updatePolicy(patch, policy.id, "priority", Number(e.target.value))} /></Cap>
                  <Cap label="Название"><input aria-label="Название политики" value={policy.name || ""} onChange={(e) => updatePolicy(patch, policy.id, "name", e.target.value)} /></Cap>
                  <Cap label="Источник"><input aria-label={`IP источника политики ${policy.name || policy.id}`} className="mono" placeholder="IP/CIDR" value={policy.src_ip || ""} onChange={(e) => updatePolicy(patch, policy.id, "src_ip", e.target.value)} /></Cap>
                  <Cap label="Назначение"><input aria-label={`IP назначения политики ${policy.name || policy.id}`} className="mono" placeholder="IP/CIDR" value={policy.dst_ip || ""} onChange={(e) => updatePolicy(patch, policy.id, "dst_ip", e.target.value)} /></Cap>
                  <Cap label="Протокол"><select aria-label={`Протокол политики ${policy.name || policy.id}`} value={policy.protocol || "any"} onChange={(e) => updatePolicy(patch, policy.id, "protocol", e.target.value)}><option value="any">any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></Cap>
                  <Cap label="Порт назначения"><input aria-label={`Порт назначения политики ${policy.name || policy.id}`} className="mono" placeholder="порт" value={policy.dst_port || ""} onChange={(e) => updatePolicy(patch, policy.id, "dst_port", e.target.value)} /></Cap>
                  <Cap label="Канал"><select aria-label={`Канал политики ${policy.name || policy.id}`} value={policy.channel} onChange={(e) => updatePolicy(patch, policy.id, "channel", e.target.value)}>{choices.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Cap>
                </div>
                <details className="advanced">
                      <summary>Все условия и служебные поля</summary>
                      <div className="form-grid" style={{ marginTop: ".8rem" }}>
                        <Field label="MAC источника">
                          <input className="mono" value={policy.src_mac || ""} onChange={(e) => updatePolicy(patch, policy.id, "src_mac", e.target.value)} />
                        </Field>
                        <Field label="Сегмент-источник">
                          <select value={policy.network || ""} onChange={(e) => updatePolicy(patch, policy.id, "network", e.target.value)}>
                            <option value="">Любой сегмент</option>
                            {(config.networks || []).map((network: any) => <option key={network.id} value={network.id}>{network.name || network.id}</option>)}
                          </select>
                        </Field>
                        <Field label="Входящий VPN-сервер">
                          <select value={policy.vpn_server || ""} onChange={(e) => {
                            updatePolicy(patch, policy.id, "vpn_server", e.target.value);
                            updatePolicy(patch, policy.id, "vpn_peer", "");
                          }}>
                            <option value="">Любой / не VPN</option>
                            {(config.vpn_servers || []).map((server: any) => <option key={server.id} value={server.id}>{server.name || server.id}</option>)}
                          </select>
                        </Field>
                        <Field label="VPN-пир">
                          <select disabled={!policy.vpn_server} value={policy.vpn_peer || ""} onChange={(e) => updatePolicy(patch, policy.id, "vpn_peer", e.target.value)}>
                            <option value="">Любой пир</option>
                            {((config.vpn_servers || []).find((server: any) => server.id === policy.vpn_server)?.peers || []).map((peer: any) => <option key={peer.id} value={peer.id}>{peer.name || peer.id}</option>)}
                          </select>
                        </Field>
                        <Field label="Домены политики" hint="По одному домену в строке. DNS-ответы обновляют маршрут автоматически; время жизни записи — до 5 минут.">
                          <textarea aria-label={`Домены политики ${policy.name || policy.id}`} className="mono" placeholder={"example.com\nsub.example.org"} value={(policy.domains || []).join("\n")} onChange={(e) => updatePolicy(patch, policy.id, "domains", e.target.value.split(/\s+/).filter(Boolean))} />
                        </Field>
                        <Field label="Комментарий">
                          <input value={policy.comment || ""} onChange={(e) => updatePolicy(patch, policy.id, "comment", e.target.value)} />
                        </Field>
                      </div>
                      <div style={{ marginTop: ".8rem" }}>
                        <Switch checked={!!policy.schedule} label="Ограничить расписанием" onChange={(enabled) => updatePolicy(patch, policy.id, "schedule", enabled ? { days: [], time_start: "", time_stop: "" } : null)} />
                      </div>
                      {policy.schedule && <div className="form-grid" style={{ marginTop: ".8rem" }}>
                        <Field label="Дни недели" hint="Пусто — каждый день">
                          <div className="row wrap">
                            {POLICY_DAYS.map(([day, title]) => <label key={day} className="row" style={{ gap: ".25rem" }}>
                              <input type="checkbox" aria-label={title} checked={(policy.schedule.days || []).includes(day)} onChange={(e) => updatePolicyDay(patch, policy.id, day, e.target.checked)} /> {title}
                            </label>)}
                          </div>
                        </Field>
                        <Field label="Начало (UTC)"><input type="time" value={policy.schedule.time_start || ""} onChange={(e) => updatePolicySchedule(patch, policy.id, "time_start", e.target.value)} /></Field>
                        <Field label="Окончание (UTC)"><input type="time" value={policy.schedule.time_stop || ""} onChange={(e) => updatePolicySchedule(patch, policy.id, "time_stop", e.target.value)} /></Field>
                      </div>}
                    </details>
                <div className="row-actions end"><button className="btn ghost sm" onClick={() => patch((draft) => { draft.policies = draft.policies.filter((item: any) => item.id !== policy.id); })}>Убрать</button></div>
              </Row>
          ))}
        </Rows>
      )}
      <div className="rows-foot row policy-add-row">
        <input aria-label="Название новой политики" placeholder="Название новой политики" value={name} onChange={(e) => setName(e.target.value)} />
        <select aria-label="Канал новой политики" value={channel} onChange={(e) => setChannel(e.target.value)}>{choices.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select>
        <button className="btn primary" disabled={!name.trim()} onClick={() => {
          patch((draft) => {
            const priority = Math.max(0, ...(draft.policies || []).map((item: any) => item.priority || 0)) + 100;
            draft.policies = draft.policies || [];
            draft.policies.push({ id: openOnCreate(newID("policy")), name: name.trim(), enabled: false, priority, channel, src_ip: "", src_mac: "", network: "", vpn_server: "", vpn_peer: "", protocol: "any", dst_port: "", dst_ip: "", domains: [], comment: "" });
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

function updatePolicySchedule(patch: Props["patch"], id: string, key: string, value: string) {
  patch((draft) => {
    const policy = draft.policies.find((item: any) => item.id === id);
    policy.schedule = policy.schedule || { days: [], time_start: "", time_stop: "" };
    policy.schedule[key] = value;
  });
}

function updatePolicyDay(patch: Props["patch"], id: string, day: string, checked: boolean) {
  patch((draft) => {
    const policy = draft.policies.find((item: any) => item.id === id);
    policy.schedule = policy.schedule || { days: [], time_start: "", time_stop: "" };
    const days: string[] = policy.schedule.days || [];
    policy.schedule.days = checked ? [...days, day] : days.filter((item) => item !== day);
  });
}

function isChannelReferenced(config: any, id: string) {
  return channelReferences(config, id).length > 0;
}
