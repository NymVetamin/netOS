import { Badge, Card, Empty, Field, Notice, Switch } from "../ui";
import { newID } from "../id";

type Props = { config: any; patch: (mutate: (draft: any) => void) => void };

export function WiFiPage({ config, patch }: Props) {
  const radios = config.wifi || [];
  const installed = (config.components || []).some((item: any) => item.id === "hostapd" && item.installed);

  function addRadio() {
    patch((draft) => {
      draft.wifi = draft.wifi || [];
      draft.wifi.push({ id: newID("radio"), device: "wlan0", enabled: false, band: "2.4", channel: 6, width: 20, country: "RU", tx_power: 0, ssids: [] });
    });
  }

  return <>
    <div className="page-head"><h1>Wi-Fi</h1><p>Точки доступа, защита сети и привязка к сегментам роутера</p></div>
    {!installed && <Notice tone="info" title="Нужен компонент hostapd">Установите «Точку доступа Wi-Fi» в разделе «Компоненты». Настройки можно подготовить заранее.</Notice>}
    <Notice tone="info" title="Совместимость оборудования">Радиокарта и драйвер должны поддерживать режим AP. Доступные режимы можно проверить командой <span className="mono">iw list</span>.</Notice>
    <Card title="Радиоустройства" subtitle="Одно радио может транслировать несколько сетей" actions={<button className="btn" onClick={addRadio}>Добавить радио</button>}>
      {radios.length === 0 ? <Empty>Радиоустройства ещё не настроены.</Empty> : radios.map((radio: any) =>
        <RadioEditor key={radio.id} radio={radio} config={config} installed={installed} patch={patch} />)}
    </Card>
  </>;
}

function RadioEditor({ radio, config, installed, patch }: any) {
  const networks = (config.networks || []).filter((item: any) => item.enabled);
  const update = (mutate: (item: any) => void) => patch((draft: any) => mutate(draft.wifi.find((item: any) => item.id === radio.id)));

  function addSSID() {
    update((draft) => {
      draft.ssids = draft.ssids || [];
      draft.ssids.push({ id: newID("ssid"), ssid: `netOS ${draft.ssids.length + 1}`, enabled: false, security: "wpa2/wpa3", password: "", network: networks[0]?.id || "", hidden: false, isolate: false });
    });
  }

  return <form onSubmit={(event) => event.preventDefault()} style={{ borderTop: "1px solid var(--line)", paddingTop: "1rem", marginTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between", marginBottom: "1rem" }}>
      <div className="row"><strong>{radio.device || "Новое радио"}</strong><Badge tone={radio.enabled ? "ok" : "neutral"}>{radio.enabled ? "включено" : "черновик"}</Badge></div>
      <div className="row"><Switch checked={!!radio.enabled} disabled={!installed} label="Включить" onChange={(value) => update((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={radio.enabled} onClick={() => patch((draft: any) => { draft.wifi = draft.wifi.filter((item: any) => item.id !== radio.id); })}>Удалить</button></div>
    </div>
    <div className="form-grid">
      <Field label="Устройство" hint="Имя из iw dev, например wlan0"><input className="mono" value={radio.device || ""} onChange={(e) => update((draft) => draft.device = e.target.value)} /></Field>
      <Field label="Страна" hint="Определяет разрешённые частоты"><input className="mono" maxLength={2} value={radio.country || ""} onChange={(e) => update((draft) => draft.country = e.target.value.toUpperCase())} /></Field>
      <Field label="Диапазон"><select value={radio.band || "2.4"} onChange={(e) => update((draft) => { draft.band = e.target.value; draft.channel = e.target.value === "2.4" ? 6 : 36; if (e.target.value === "2.4" && draft.width === 80) draft.width = 40; })}><option value="2.4">2,4 ГГц</option><option value="5">5 ГГц</option></select></Field>
      <Field label="Канал"><input type="number" min={radio.band === "2.4" ? 1 : 32} max={radio.band === "2.4" ? 13 : 177} value={radio.channel || 1} onChange={(e) => update((draft) => draft.channel = Number(e.target.value))} /></Field>
      <Field label="Ширина канала"><select value={radio.width || 20} onChange={(e) => update((draft) => draft.width = Number(e.target.value))}><option value={20}>20 МГц</option><option value={40}>40 МГц</option>{radio.band === "5" && <option value={80}>80 МГц</option>}</select></Field>
      <Field label="Мощность" hint="0 — настройка драйвера, иначе dBm"><input type="number" min={0} max={40} value={radio.tx_power || 0} onChange={(e) => update((draft) => draft.tx_power = Number(e.target.value))} /></Field>
    </div>
    <div className="row" style={{ justifyContent: "space-between", marginTop: "1.2rem" }}><strong>Беспроводные сети</strong><button type="button" className="btn ghost sm" onClick={addSSID}>Добавить сеть</button></div>
    {(radio.ssids || []).length === 0 ? <Empty>Добавьте основную или гостевую сеть.</Empty> : (radio.ssids || []).map((ssid: any) =>
      <SSIDEditor key={ssid.id} ssid={ssid} networks={networks} update={update} />)}
  </form>;
}

function SSIDEditor({ ssid, networks, update }: any) {
  const edit = (mutate: (item: any) => void) => update((draft: any) => mutate(draft.ssids.find((item: any) => item.id === ssid.id)));
  return <div style={{ borderTop: "1px solid var(--line)", marginTop: "1rem", paddingTop: "1rem" }}>
    <div className="row" style={{ justifyContent: "space-between" }}><strong>{ssid.ssid || "Новая сеть"}</strong><div className="row"><Switch checked={!!ssid.enabled} label="Транслировать" onChange={(value) => edit((draft) => draft.enabled = value)} /><button type="button" className="btn ghost sm" disabled={ssid.enabled} onClick={() => update((draft: any) => { draft.ssids = draft.ssids.filter((item: any) => item.id !== ssid.id); })}>Удалить</button></div></div>
    <div className="form-grid" style={{ marginTop: "0.8rem" }}>
      <Field label="Имя сети (SSID)"><input value={ssid.ssid || ""} maxLength={32} onChange={(e) => edit((draft) => draft.ssid = e.target.value)} /></Field>
      <Field label="Сегмент"><select value={ssid.network || ""} onChange={(e) => edit((draft) => draft.network = e.target.value)}><option value="">Выберите сегмент</option>{networks.map((item: any) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field>
      <Field label="Защита"><select value={ssid.security || "wpa2/wpa3"} onChange={(e) => edit((draft) => draft.security = e.target.value)}><option value="wpa2/wpa3">WPA2/WPA3</option><option value="wpa3">WPA3</option><option value="wpa2">WPA2</option><option value="open">Открытая сеть</option></select></Field>
      {ssid.security !== "open" && <Field label="Пароль" hint="От 8 до 63 символов"><input type="password" minLength={8} maxLength={63} autoComplete="new-password" value={ssid.password || ""} onChange={(e) => edit((draft) => draft.password = e.target.value)} /></Field>}
      <Field label="Дополнительно"><div className="row"><Switch checked={!!ssid.hidden} label="Скрывать SSID" onChange={(value) => edit((draft) => draft.hidden = value)} /><Switch checked={!!ssid.isolate} label="Изолировать клиентов" onChange={(value) => edit((draft) => draft.isolate = value)} /></div></Field>
    </div>
  </div>;
}
