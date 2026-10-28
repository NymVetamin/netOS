import { Card, Field, Notice, Switch } from "../ui";
import { useEffect, useState } from "react";

const sourceLines = (text: string) => text.split(/\s+/).filter(Boolean);

export function IPTVSection({config,patch}: {config:any;patch:(fn:(draft:any)=>void)=>void}) {
  const value=config.iptv || {enabled:false,upstream:"",networks:[],sources:[]};
  const sources = (value.sources || []).join("\n");
  const [sourceText, setSourceText] = useState(sources);
  useEffect(() => {
    setSourceText((text: string) => sourceLines(text).join("\n") === sources ? text : sources);
  }, [sources]);
  const set=(key:string,next:any)=>patch(d=>{ d.iptv={...value,[key]:next}; });
  const installed=(config.components||[]).some((c:any)=>c.id==="igmpproxy" && c.installed);
  const wans=(config.wans||[]).filter((w:any)=>w.enabled && ["dhcp","static"].includes(w.proto));
  return <Card title="Телевидение провайдера">
    {!installed && <Notice hint tone="info" title="Нужен компонент IPTV">Установите его в разделе «Компоненты».</Notice>}
    <Switch checked={!!value.enabled} onChange={v=>set("enabled",v)} label="Включить IGMP proxy" />
    <div className="form-grid">
      <Field label="Аплинк IPTV" hint="Если провайдер использует отдельный VLAN, создайте для него аплинк в разделе «Сеть».">
        <select value={value.upstream||""} onChange={e=>set("upstream",e.target.value)}>
          <option value="">Выберите аплинк</option>{wans.map((w:any)=><option key={w.id} value={w.id}>{w.name||w.id}</option>)}
        </select>
      </Field>
      <Field label="Локальные сети с приставками">
        {(config.networks||[]).filter((n:any)=>n.enabled).map((n:any)=><Switch key={n.id} label={n.name||n.id} checked={(value.networks||[]).includes(n.id)} onChange={on=>set("networks",on?[...(value.networks||[]),n.id]:(value.networks||[]).filter((id:string)=>id!==n.id))} />)}
      </Field>
    </div>
    <details><summary>Дополнительные настройки</summary>
      <Field label="Сети источников провайдера" hint="IPv4-подсети, по одной в строке. Пусто — любые источники только с выбранного аплинка.">
        <textarea className="mono" value={sourceText} placeholder="10.0.0.0/8" onChange={e=>{ setSourceText(e.target.value); set("sources",sourceLines(e.target.value)); }} />
      </Field>
    </details>
    <p className="muted">Для мультикастового IPTV (IGMPv1/v2). Интернет-ТВ через HTTP/HLS этой настройки не требует.</p>
  </Card>;
}
