import { useEffect, useState } from "react";
import { api } from "../api";
import { Empty, Notice, TableWrap } from "../ui";
const tabs = [{id:"all",name:"Общий"},{id:"dns",name:"DNS"},{id:"firewall",name:"Firewall"},{id:"services",name:"Службы"}];
const fromHash=()=>{const kind=new URLSearchParams(window.location.hash.split("?")[1] || "").get("log");return tabs.some(t=>t.id===kind)?kind!:"all"};
export function Logs({ dnsLogging }: { dnsLogging: boolean }) {
 const [open,setOpen]=useState(false);
 return <details className="logs-section" onToggle={e=>setOpen(e.currentTarget.open)}>
  <summary>Журналы</summary>
  {open && <LogEntries dnsLogging={dnsLogging} />}
 </details>;
}
function LogEntries({ dnsLogging }: { dnsLogging: boolean }) {
 const [selectedKind,setKind]=useState(fromHash),[attempt,setAttempt]=useState(0),[query,setQuery]=useState("");
 const kind=selectedKind==="dns" && !dnsLogging ? "all" : selectedKind;
 useEffect(()=>{if(!dnsLogging && selectedKind==="dns")setKind("all")},[dnsLogging,selectedKind]);
 const [snapshot,setSnapshot]=useState<{kind:string;value:any}|null>(null),[error,setError]=useState(""),[loading,setLoading]=useState(true);
 const data=snapshot?.kind===kind?snapshot.value:null;
 useEffect(()=>{const change=()=>setKind(fromHash());window.addEventListener("hashchange",change);return()=>window.removeEventListener("hashchange",change)},[]);
 useEffect(()=>{let active=true;setLoading(true);setError("");
  api.logs(kind).then(d=>{if(active)setSnapshot({kind,value:d})}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false};
 },[kind,attempt]);
 const rows=(data?.entries || []).filter((e:any)=>`${e.time} ${e.source} ${e.unit} ${e.message}`.toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 function download(){const text=rows.map((e:any)=>`${e.time || "Время неизвестно"}\t${e.source}\t${e.unit}\t${e.message}`).join("\n");const url=URL.createObjectURL(new Blob([text],{type:"text/plain;charset=utf-8"}));const a=document.createElement("a");a.href=url;a.download=`netos-${kind}.log`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 return <div className="logs-content" aria-busy={loading}>
  <div role="tablist" aria-label="Источники журнала" className="row wrap">{tabs.filter(t=>t.id!=="dns" || dnsLogging).map(t=><button type="button" role="tab" aria-selected={kind===t.id} key={t.id} className={`btn sm ${kind===t.id?"primary":""}`} onClick={()=>{setQuery("");window.location.hash=`diagnostics?log=${t.id}`}}>{t.name}</button>)}</div>
  <div className="row wrap" style={{margin:"0.8rem 0",gap:"0.5rem"}}>
   <input aria-label="Поиск в журнале" placeholder="Поиск в загруженных записях" value={query} onChange={e=>setQuery(e.target.value)}/>
   <button className="btn sm" disabled={loading} onClick={()=>setAttempt(n=>n+1)}>Обновить журнал</button>
   <button className="btn sm" disabled={loading || !!error || !rows.length} onClick={download}>Скачать журнал</button>
  </div>

  {error&&<Notice tone="danger" title="Не удалось загрузить журнал">{error}{data&&" Показан предыдущий снимок журнала."}</Notice>}
  {!data?(loading?<Empty>Загрузка журнала…</Empty>:null):<>
   {data?.warnings?.map((text:string,i:number)=><Notice key={i} tone="warn" title={text}/>)}
   <p className="hint">Показано {rows.length} из {data?.entries?.length || 0} · Снимок: {data?.captured_at ? new Date(data.captured_at).toLocaleString("ru-RU") : "—"}</p>
   {rows.length===0?<Empty>{query?"Совпадений нет":kind==="dns"?"Запросов DNS пока нет":"Записей пока нет"}</Empty>:<div style={{maxHeight:"32rem",overflow:"auto"}}><TableWrap><table className="logs-table">
    <thead><tr><th>Время</th><th>Источник</th><th>Сообщение</th></tr></thead>
    <tbody>{rows.map((e:any,i:number)=><tr key={i}><td style={{whiteSpace:"nowrap"}}>{e.time?new Date(e.time).toLocaleString("ru-RU"):"Время неизвестно"}</td><td className="logs-source">{tabs.find(t=>t.id===e.source)?.name || e.source}{e.unit&&<span className="logs-unit faint">{e.unit}</span>}</td><td style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxWidth:"65vw"}}>{e.message}</td></tr>)}</tbody>
   </table></TableWrap></div>}
  </>}
 </div>;
}
