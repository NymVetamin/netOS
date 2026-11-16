import { useEffect, useState } from "react";
import { api, type LogEvent } from "../api";
import { Empty, Notice, TableWrap } from "../ui";

// Разделы совпадают с eventlog.Topics; «Общий» — все разделы вместе.
const tabs = [
 {id:"all",name:"Общий"},{id:"services",name:"Службы"},{id:"vpn",name:"VPN"},{id:"access",name:"Доступ"},{id:"firewall",name:"Firewall"},{id:"dns",name:"DNS"},
];
const LIMIT=1000;
const fromHash=()=>{const kind=new URLSearchParams(window.location.hash.split("?")[1] || "").get("log");return tabs.some(t=>t.id===kind)?kind!:"all"};
// Новые события приходят первыми; reset означает, что клиент отстал (ротация,
// перезапуск netosd) и список заменяется целиком.
export function mergeLog(old:LogEvent[]|null,p:{reset:boolean;events:LogEvent[]}){
 if(p.reset)return p.events;
 if(!p.events.length)return old||[];
 return [...p.events,...(old||[])].slice(0,LIMIT);
}
const levelBadge:{[k:string]:[string,string]}={warning:["warn","внимание"],error:["danger","ошибка"]};

// Живой журнал: долгий опрос, как у графика трафика. Сервер отвечает сразу,
// когда есть новые события, иначе ждёт до 25 с. Скрытая вкладка браузера не
// опрашивает; при возврате журнал продолжается с последнего номера.
function useLiveLog(topic:string){
 const [events,setEvents]=useState<LogEvent[]|null>(null),[error,setError]=useState("");
 useEffect(()=>{
  setEvents(null);setError("");
  let cancelled=false,busy=false,after=0,epoch="";let retry:ReturnType<typeof setTimeout>;const controller=new AbortController();
  const load=async()=>{
   if(cancelled||busy||document.hidden)return;busy=true;
   try{while(!cancelled&&!document.hidden){
    const p=await api.logs(topic,after,epoch,controller.signal);if(cancelled)return;
    setError("");
    setEvents(old=>mergeLog(old,p));
    after=p.latest;epoch=p.epoch;
   }}catch(e:any){if(!cancelled){setError(e?.message||"Нет связи с роутером");retry=setTimeout(load,2000)}}finally{busy=false}
  };
  void load();document.addEventListener("visibilitychange",load);
  return()=>{cancelled=true;controller.abort();clearTimeout(retry);document.removeEventListener("visibilitychange",load)};
 },[topic]);
 return {events,error};
}

export function LogEntries({ dnsLogging }:{ dnsLogging: boolean }) {
 const [selected,setKind]=useState(fromHash),[query,setQuery]=useState("");
 // Вкладка DNS есть, только пока включён журнал запросов.
 const kind=selected==="dns"&&!dnsLogging?"all":selected;
 const visible=tabs.filter(t=>t.id!=="dns"||dnsLogging);
 useEffect(()=>{const change=()=>setKind(fromHash());window.addEventListener("hashchange",change);return()=>window.removeEventListener("hashchange",change)},[]);
 const {events,error}=useLiveLog(kind);
 const name=(id:string)=>tabs.find(t=>t.id===id)?.name||id;
 const needle=query.toLocaleLowerCase();
 const rows=(events||[]).filter(e=>!needle||`${e.source} ${e.message}`.toLocaleLowerCase().includes(needle));
 const time=(ms:number)=>new Date(ms).toLocaleString("ru-RU");
 function download(){const text=rows.map(e=>`${new Date(e.time).toISOString()}\t${name(e.topic)}\t${e.level}\t${e.source}\t${e.message}`).join("\n");const url=URL.createObjectURL(new Blob([text],{type:"text/plain;charset=utf-8"}));const a=document.createElement("a");a.href=url;a.download=`netos-${kind}.log`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 return <div className="logs-content" aria-busy={events===null}>
  <div role="tablist" aria-label="Источники журнала" className="row wrap navigation-subtabs">{visible.map(t=><button type="button" role="tab" aria-selected={kind===t.id} key={t.id} className={`btn sm ${kind===t.id?"primary":""}`} onClick={()=>{setQuery("");window.location.hash=`diagnostics?tab=logs&log=${t.id}`}}>{t.name}</button>)}</div>
  <div className="row wrap" style={{margin:"0.8rem 0",gap:"0.5rem"}}>
   <input aria-label="Поиск в журнале" placeholder="Поиск" value={query} onChange={e=>setQuery(e.target.value)}/>
   <button className="btn sm" disabled={!rows.length} onClick={download}>Скачать журнал</button>
  </div>
  {error&&<Notice tone="warn" title="Нет связи с роутером, переподключение…">{error}</Notice>}
  {events===null?(!error&&<Empty>Загрузка журнала…</Empty>):<>
   <p className="hint">{query?`Найдено ${rows.length} из ${events.length}`:`Последние ${events.length} событий`} · обновляется сразу, хранится до {LIMIT} событий на раздел</p>
   {rows.length===0?<Empty>{query?"Совпадений нет":"Событий пока нет"}</Empty>:<div style={{maxHeight:"32rem",overflow:"auto"}}><TableWrap><table className="logs-table">
    <thead><tr><th>Время</th><th>Источник</th><th>Событие</th></tr></thead>
    <tbody>{rows.map(e=>{const badge=levelBadge[e.level];return <tr key={e.seq}><td style={{whiteSpace:"nowrap"}}>{time(e.time)}</td><td className="logs-source">{kind==="all"&&<span>{name(e.topic)}</span>}<span className={kind==="all"?"logs-unit faint":""}>{e.source}</span></td><td style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxWidth:"65vw"}}>{badge&&<span className={`badge ${badge[0]}`} style={{marginRight:8}}>{badge[1]}</span>}{e.message}</td></tr>})}</tbody>
   </table></TableWrap></div>}
  </>}
 </div>;
}
