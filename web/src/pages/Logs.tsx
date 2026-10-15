import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Empty, Notice, TableWrap } from "../ui";
const tabs = [{id:"all",name:"Общий"},{id:"dns",name:"DNS"},{id:"firewall",name:"Firewall"},{id:"services",name:"Службы"}];
const fromHash=()=>{const kind=new URLSearchParams(window.location.hash.split("?")[1] || "").get("log");return tabs.some(t=>t.id===kind)?kind!:"all"};
export function Logs() {
 const [kind,setKind]=useState(fromHash),[attempt,setAttempt]=useState(0),[query,setQuery]=useState("");
 const [data,setData]=useState<any>(null),[error,setError]=useState(""),[loading,setLoading]=useState(true);
 useEffect(()=>{const change=()=>setKind(fromHash());window.addEventListener("hashchange",change);return()=>window.removeEventListener("hashchange",change)},[]);
 useEffect(()=>{let active=true;setLoading(true);setData(null);setError("");
  api.logs(kind).then(d=>{if(active)setData(d)}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false};
 },[kind,attempt]);
 const rows=(data?.entries || []).filter((e:any)=>`${e.time} ${e.source} ${e.unit} ${e.message}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 function download(){const text=rows.map((e:any)=>`${e.time || "Время неизвестно"}\t${e.source}\t${e.unit}\t${e.message}`).join("\n");const url=URL.createObjectURL(new Blob([text],{type:"text/plain;charset=utf-8"}));const a=document.createElement("a");a.href=url;a.download=`netos-${kind}.log`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 return <Card title="Журналы" subtitle="DNS, срабатывания firewall и службы netOS">
  <div role="tablist" aria-label="Источники журнала" className="row wrap">{tabs.map(t=><button type="button" role="tab" aria-selected={kind===t.id} key={t.id} className={`btn sm ${kind===t.id?"primary":""}`} onClick={()=>{setQuery("");window.location.hash=`diagnostics?log=${t.id}`}}>{t.name}</button>)}</div>
  <div className="row wrap" style={{margin:"0.8rem 0",gap:"0.5rem"}}>
   <input aria-label="Поиск в журнале" placeholder="Поиск в загруженных записях" value={query} onChange={e=>setQuery(e.target.value)}/>
   <button className="btn sm" disabled={loading} onClick={()=>setAttempt(n=>n+1)}>Обновить журнал</button>
   <button className="btn sm" disabled={loading || !!error || !rows.length} onClick={download}>Скачать журнал</button>
  </div>
  <p className="hint">До 300 последних записей каждого источника; DNS-файл — не более 256 КиБ. Поиск и скачивание относятся к загруженной выборке. Записи идут от старых к новым; без времени — в конце. Firewall — за текущую загрузку ОС.</p>
  {loading?<Empty>Загрузка журнала…</Empty>:error?<Notice tone="danger" title="Не удалось загрузить журнал">{error}</Notice>:<>
   {data?.warnings?.map((text:string,i:number)=><Notice key={i} tone="warn" title={text}/>)}
   <p className="hint">Показано {rows.length} из {data?.entries?.length || 0} · Снимок: {data?.captured_at ? new Date(data.captured_at).toLocaleString("ru-RU") : "—"}</p>
   {rows.length===0?<Empty>{query?"Совпадений нет":"Записей нет. Для DNS и firewall включите журналирование в настройках и примените изменения."}</Empty>:<div style={{maxHeight:"32rem",overflow:"auto"}}><TableWrap><table>
    <thead><tr><th>Время</th><th>Источник</th><th>Сообщение</th></tr></thead>
    <tbody>{rows.map((e:any,i:number)=><tr key={i}><td style={{whiteSpace:"nowrap"}}>{e.time?new Date(e.time).toLocaleString("ru-RU"):"Время неизвестно"}</td><td>{tabs.find(t=>t.id===e.source)?.name || e.source}<div className="hint">{e.unit}</div></td><td style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxWidth:"65vw"}}>{e.message}</td></tr>)}</tbody>
   </table></TableWrap></div>}
  </>}
 </Card>;
}
