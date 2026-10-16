import { useState } from "react";
import { api } from "../api";
import { Field, Notice } from "../ui";
export function linkSpeed(i:any,compact=false):string {
 if(!i?.physical)return "";
 if(!i.up)return "Нет линка";
 const speed=i.speed_mbps>0 ? i.speed_mbps>=1000 ? `${i.speed_mbps/1000} Гбит/с` : `${i.speed_mbps} Мбит/с` : "Скорость неизвестна";
 if(compact)return speed;
 return speed+(i.duplex==="full"?" · полный дуплекс":i.duplex==="half"?" · полудуплекс":"");
}
function modeTitle(mode:string):string {
 const match=mode.match(/^(\d+)base[^/]+\/(Full|Half)$/);
 if(!match)return mode;
 const speed=Number(match[1]);
 return `${speed>=1000 ? `${speed/1000} Гбит/с` : `${speed} Мбит/с`} · ${match[2]==="Full"?"полный дуплекс":"полудуплекс"}`;
}
export function PortLinkSettings({iface,onChange}:{iface:any;onChange:(v:string)=>void}){
 const [data,setData]=useState<any>(null),[error,setError]=useState(""),[loading,setLoading]=useState(false);
 const load=async()=>{setLoading(true);setError("");try{setData(await api.portModes(iface.name))}catch(e:any){setError(e.message)}finally{setLoading(false)}};
 return <div className="port-link-settings"><Field label="Режим Ethernet" hint="При смене режима связь может ненадолго прерваться.">
  <div className="port-link-controls">
  <select aria-label={`Режим порта ${iface.name}`} value={iface.link_mode || ""} disabled={!data?.can_autoneg || !data?.supported?.length} onChange={e=>onChange(e.target.value)}>
   <option value="">Исходные настройки порта</option>
   <option value="auto">Автоматически</option>
   {(data?.supported || []).map((mode:string)=><option key={mode} value={mode}>{modeTitle(mode)}</option>)}
   {iface.link_mode && iface.link_mode!=="auto" && !data?.supported?.includes(iface.link_mode) && <option value={iface.link_mode}>{modeTitle(iface.link_mode)}</option>}
  </select>
  <button type="button" className="btn sm" disabled={loading} onClick={()=>void load()}>{loading?"Читаем режимы…":"Проверить режимы порта"}</button>
  </div>
  {error&&<Notice tone="warn" title="Режимы недоступны">{error}</Notice>}

  {data && (!data.can_autoneg || !data.supported?.length) && <span className="hint">Драйвер не предоставляет выбор режимов Ethernet.</span>}
  {data && <details className="port-link-details">
   <summary>Технические подробности</summary>
   <div className="hint">Автосогласование: {data.autoneg?"включено":"выключено"}</div>
   <div className="hint">Объявленные режимы: {data.advertised?.map(modeTitle).join("; ") || "—"}</div>
  </details>}
 </Field></div>;
}
