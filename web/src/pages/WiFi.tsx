import { secretInput } from "../secrets";
import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Card, Empty, Field, Notice, openOnCreate, Row, Rows, Switch } from "../ui";
import { Icon } from "../icons";
import { newID } from "../id";

type Props = { config: any; patch: (mutate: (draft: any) => void) => void };
const SECURITY: Record<string, string> = { "wpa2/wpa3": "WPA2/WPA3", wpa3: "WPA3", wpa2: "WPA2", open: "открытая" };
const countryNames = new Intl.DisplayNames(["ru"], { type: "region" });
function defaults(hw: any, country: string) {
  const band = hw.bands.find((b: any) => b.channels.length);
  return { id: `radio-${hw.phy}`, device: hw.device, enabled: false, band: hw.bands.find((b: any) => b.channels.length)?.name || "2.4", channel: hw.auto_channel ? 0 : band?.channels[0]?.number || 0, width: 20, country, tx_power: 0, ssids: [] };
}

export function WiFiPage({ config, patch }: Props) {
  const [hardware, setHardware] = useState<any>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setError("");
    api.wifiHardware("", controller.signal).then(setHardware).catch(e => { if (!controller.signal.aborted) setError(e.message); });
    return () => controller.abort();
  }, [refresh]);
  const saved = config.wifi || [];
  const installed = (config.components || []).some((item: any) => item.id === "hostapd" && item.installed);
  const detected = (hardware?.radios || []).filter((r: any) => r.ap && r.device);
  const entries = detected.map((hw: any) => ({ hw, radio: saved.find((r: any) => hw.interfaces.includes(r.device)) || defaults(hw, hardware.country) }));
  for (const radio of saved) if (!entries.some((e: any) => e.radio.id === radio.id)) entries.push({ radio, hw: null });
  return <>
    <div className="page-head"><h1><Icon name="wifi" />Wi-Fi</h1><p>Точки доступа, защита сети и привязка к сегментам роутера</p></div>
    {!installed && <Notice hint tone="info" title="Нужен компонент hostapd">Установите «Точку доступа Wi-Fi» в разделе «Компоненты».</Notice>}
    {error && <Notice tone="warn" title="Не удалось определить радиоустройства">{error}</Notice>}
    <Card tight title="Радиоустройства" subtitle="Одно радио может транслировать несколько сетей" actions={<button className="btn" onClick={() => setRefresh(v => v + 1)}>Обновить</button>}>
      {!hardware && !error ? <Empty>Определяем радиоустройства…</Empty> : entries.length === 0 ? <Empty>{hardware?.radios.length ? "Обнаруженные адаптеры не поддерживают режим точки доступа или не имеют сетевого интерфейса." : "Wi-Fi-адаптеры не обнаружены."}</Empty> :
        <Rows cols={["Радио", "Диапазон", "Канал", "Сети", "Состояние"]} toggle="Включено">{entries.map(({ radio, hw }: any) =>
          <RadioEditor key={radio.id} radio={radio} hardware={hw} countries={hardware?.countries || []} initialCountry={hardware?.country} config={config} installed={installed} patch={patch} />)}</Rows>}
    </Card>
  </>;
}

function RadioEditor({ radio, hardware, countries, initialCountry, config, installed, patch }: any) {
  const [options, setOptions] = useState(hardware);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    setError(""); setOptions(hardware);
    if (!hardware || radio.country === initialCountry) { setLoading(false); return () => controller.abort(); }
    setLoading(true);
    api.wifiHardware(radio.country, controller.signal).then(result => {
      if (!controller.signal.aborted) setOptions(result.radios.find((r: any) => r.phy === hardware.phy));
    }).catch(e => { if (!controller.signal.aborted) { setError(e.message); setOptions(null); } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [hardware, radio.country, initialCountry]);
  const networks = (config.networks || []).filter((item: any) => item.enabled).map((item: any) => ({
    ...item, wifiBridge: (config.interfaces || []).some((iface: any) => iface.id === item.interface && iface.type === "bridge"),
  }));
  const update = (mutate: (item: any) => void) => patch((draft: any) => {
    draft.wifi ||= [];
    let item = draft.wifi.find((item: any) => item.id === radio.id);
    if (!item) { item = { ...radio, ssids: [...(radio.ssids || [])] }; draft.wifi.push(item); }
    mutate(item);
  });
  const bands = options?.bands || [];
  const channels = bands.find((b: any) => b.name === radio.band)?.channels || [];
  const channel = channels.find((c: any) => c.number === radio.channel);
  const widths: number[] = radio.channel ? channel?.widths || [] : [20, 40, 80].filter(w => channels.some((c: any) => c.widths.includes(w)));
  const unavailable = !hardware || loading || !options;
  function addSSID() {
    update((draft: any) => {
      draft.ssids ||= [];
      draft.ssids.push({ id: openOnCreate(newID("ssid")), ssid: `netOS ${draft.ssids.length + 1}`, enabled: false, security: "wpa2/wpa3", password: "", network: networks.find((item: any) => item.wifiBridge)?.id || "", hidden: false, isolate: false });
    });
  }
  return <Row as="form" className="radio-row" icon="radio" id={radio.id} onSubmit={(event: { preventDefault: () => void }) => event.preventDefault()}
    cells={[<strong className="mono">{radio.device}</strong>, `${radio.band} ГГц`, radio.channel ? `${radio.channel}${channel ? ` (${channel.frequency} МГц)` : ""}` : "Авто", `сетей: ${(radio.ssids || []).length}`, <Badge tone={hardware && radio.enabled ? "ok" : "neutral"}>{!hardware ? "не обнаружен" : radio.enabled ? "включено" : "выключено"}</Badge>]}
    toggle={<Switch checked={!!radio.enabled} disabled={!radio.enabled && (!installed || unavailable || !channels.length || (!radio.channel && !options?.auto_channel) || (!!radio.channel && !channel))} label="" ariaLabel="Включить" onChange={(value) => update(draft => draft.enabled = value)} />}>
    {!hardware && <Notice tone="warn" title="Радиоустройство не обнаружено">Сохранённые сети останутся в настройках до подключения адаптера.</Notice>}
    {error && <Notice tone="warn" title="Настройки радио недоступны">{error}</Notice>}
    <div className="form-grid">
      <Field label="Страна" hint="Где используется роутер"><select disabled={!hardware} value={radio.country} onChange={e => update(d => { d.country = e.target.value; d.width = 20; })}>
        {!countries.includes(radio.country) && <option value={radio.country}>{radio.country} — нет в базе</option>}
        {[...countries].sort((a: string,b: string) => (countryNames.of(a) || a).localeCompare(countryNames.of(b) || b, "ru")).map((c: string) => <option key={c} value={c}>{countryNames.of(c)} ({c})</option>)}
      </select></Field>
      <Field label="Диапазон"><select disabled={unavailable} value={radio.band} onChange={e => update(d => { d.band = e.target.value; d.channel = options?.auto_channel ? 0 : bands.find((b: any) => b.name === d.band)?.channels[0]?.number || 0; d.width = 20; })}>
        {!bands.some((b: any) => b.name === radio.band) && <option value={radio.band}>{radio.band} ГГц — недоступен</option>}
        {bands.map((b: any) => <option key={b.name} value={b.name}>{b.name === "2.4" ? "2,4" : b.name} ГГц</option>)}
      </select></Field>
      <Field label="Канал"><select disabled={unavailable || !channels.length} value={radio.channel} onChange={e => update(d => { d.channel = Number(e.target.value); if (d.channel && !channels.find((c: any) => c.number === d.channel)?.widths.includes(d.width)) d.width = 20; })}>
        {(options?.auto_channel || radio.channel === 0) && <option value={0} disabled={!options?.auto_channel}>Авто{options?.auto_channel ? "" : " — недоступно"}</option>}
        {radio.channel !== 0 && !channel && <option value={radio.channel}>{radio.channel} — недоступен</option>}
        {channels.map((c: any) => <option key={c.number} value={c.number}>{c.number} ({c.frequency} МГц){c.dfs ? " · DFS" : ""}</option>)}
      </select></Field>
      <Field label="Ширина канала"><select disabled={unavailable || !widths.length} value={radio.width} onChange={e => update(d => d.width = Number(e.target.value))}>
        {!widths.includes(radio.width) && <option value={radio.width}>{radio.width} МГц — недоступна</option>}
        {widths.map(w => <option key={w} value={w}>{w} МГц</option>)}
      </select></Field>
      <Field label="Мощность" hint="От допустимого максимума, с учётом шага драйвера"><select disabled={unavailable || !channels.length} value={radio.tx_power ? "legacy" : radio.power_percent || 0} onChange={e => update(d => { d.tx_power = 0; d.power_percent = Number(e.target.value); })}>
        {radio.tx_power > 0 && <option value="legacy">Ранее заданная мощность</option>}
        <option value={0}>Авто</option>
        {[10,25,50,75,100,...(radio.power_percent && ![10,25,50,75,100].includes(radio.power_percent) ? [radio.power_percent] : [])].sort((a,b) => a-b).map(p => <option key={p} value={p}>{p}%</option>)}
      </select></Field>
    </div>
    {hardware && !loading && !channels.length && <Notice tone="warn" title="Нет доступных каналов">Драйвер не разрешает точку доступа в этом диапазоне с выбранной страной. Текущие ограничения драйвера также учитываются.</Notice>}
    <div className="card-part inner">
      <div className="xgroup"><strong>Беспроводные сети</strong><span className="faint">{(radio.ssids || []).length}</span><button type="button" className="btn ghost sm" disabled={!hardware} onClick={addSSID}>Добавить сеть</button></div>
      <Rows cols={["Сеть (SSID)", "Сегмент", "Защита", "", "Состояние"]} toggle="В эфире">
        {(radio.ssids || []).length === 0 ? <Empty>Добавьте основную или гостевую сеть.</Empty> : (radio.ssids || []).map((ssid: any) => <SSIDEditor key={ssid.id} ssid={ssid} networks={networks} update={update} />)}
      </Rows>
    </div>
    {!hardware && <div className="row-actions end"><button type="button" className="btn ghost sm" disabled={radio.enabled} onClick={() => patch((draft: any) => { draft.wifi = draft.wifi.filter((item: any) => item.id !== radio.id); })}>Удалить сохранённые настройки</button></div>}
  </Row>;
}

function SSIDEditor({ ssid, networks, update }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.ssids.find((item: any) => item.id === ssid.id)));
  return <Row className="ssid-row" icon="wifi" id={ssid.id}
    cells={[<strong>{ssid.ssid || "Новая сеть"}</strong>, networks.find((item: any) => item.id === ssid.network)?.name || <span className="dim">не выбран</span>, SECURITY[ssid.security || "wpa2/wpa3"] || ssid.security,
      <span className="dim">{[ssid.hidden && "скрыта", ssid.isolate && "клиенты изолированы"].filter(Boolean).join(", ")}</span>,
      <Badge tone={ssid.enabled ? "ok" : "neutral"}>{ssid.enabled ? "в эфире" : "выключена"}</Badge>]}
    toggle={<Switch checked={!!ssid.enabled} label="" ariaLabel="Транслировать" onChange={(value) => edit((draft) => draft.enabled = value)} />}>
    <div className="form-grid">
      <Field label="Имя сети (SSID)"><input value={ssid.ssid || ""} maxLength={32} onChange={(e) => edit((draft) => draft.ssid = e.target.value)} /></Field>
      <Field label="Сегмент" hint="Для Wi-Fi нужен сегмент на мосте. Мост можно создать в разделе «Сеть»."><select value={ssid.network || ""} onChange={(e) => edit((draft) => draft.network = e.target.value)}><option value="">Выберите сегмент</option>{networks.map((item: any) => <option key={item.id} value={item.id} disabled={!item.wifiBridge}>{item.name}{item.wifiBridge ? "" : " — нужен мост"}</option>)}</select></Field>
      <Field label="Защита"><select value={ssid.security || "wpa2/wpa3"} onChange={(e) => edit((draft) => draft.security = e.target.value)}><option value="wpa2/wpa3">WPA2/WPA3</option><option value="wpa3">WPA3</option><option value="wpa2">WPA2</option><option value="open">Открытая сеть</option></select></Field>
      {ssid.security !== "open" && <Field label="Пароль" hint="От 8 до 63 символов"><input type="password" minLength={8} maxLength={63} autoComplete="new-password" {...secretInput(ssid, "password")} value={ssid.password || ""} onChange={(e) => edit((draft) => draft.password = e.target.value)} /></Field>}
      <Field label="Дополнительно"><div className="row"><Switch checked={!!ssid.hidden} label="Скрывать SSID" onChange={(value) => edit((draft) => draft.hidden = value)} /><Switch checked={!!ssid.isolate} label="Изолировать клиентов" onChange={(value) => edit((draft) => draft.isolate = value)} /></div></Field>
    </div>
    <div className="row-actions end"><button type="button" className="btn ghost sm" disabled={ssid.enabled} onClick={() => update((draft: any) => { draft.ssids = draft.ssids.filter((item: any) => item.id !== ssid.id); })}>Удалить</button></div>
  </Row>;
}
