import { useEffect, useState } from "react";
import { api } from "../api";
import { Empty, Notice, TableWrap } from "../ui";
const tabs = [{id:"all",name:"Общий"},{id:"dns",name:"DNS"},{id:"firewall",name:"Firewall"},{id:"services",name:"Службы"},{id:"access",name:"Доступ"},{id:"vpn",name:"VPN"}];
const defaultFilters={hours:"24",result:"",object:""};
const fromHash=()=>{const kind=new URLSearchParams(window.location.hash.split("?")[1] || "").get("log");return tabs.some(t=>t.id===kind)?kind!:"all"};
export function Logs({ dnsLogging }: { dnsLogging: boolean }) {
 const [open,setOpen]=useState(false);
 return <details className="logs-section" onToggle={e=>setOpen(e.currentTarget.open)}>
  <summary>Журналы</summary>
  {open && <LogEntries dnsLogging={dnsLogging} />}
 </details>;
}
export function LogEntries({ dnsLogging }: { dnsLogging: boolean }) {
 const [selectedKind,setKind]=useState(fromHash),[attempt,setAttempt]=useState(0),[query,setQuery]=useState("");
 const kind=selectedKind==="dns" && !dnsLogging ? "all" : selectedKind;
 useEffect(()=>{if(!dnsLogging && selectedKind==="dns")setKind("all")},[dnsLogging,selectedKind]);
 const [snapshot,setSnapshot]=useState<{kind:string;value:any}|null>(null),[error,setError]=useState(""),[loading,setLoading]=useState(true);
 const [sourceFilters,setSourceFilters]=useState<Record<string,typeof defaultFilters>>({}),[page,setPage]=useState({kind:"",cursor:""});
 const filters=sourceFilters[kind] || defaultFilters;
 const paged=kind==="vpn" || kind==="services" || kind==="firewall" || kind==="access";
 const scope=paged?JSON.stringify([kind,filters]):kind;
 const cursor=page.kind===scope?page.cursor:"";
 const data=snapshot?.kind===scope?snapshot.value:null;
 useEffect(()=>{const change=()=>{setKind(fromHash());setPage({kind:"",cursor:""})};window.addEventListener("hashchange",change);return()=>window.removeEventListener("hashchange",change)},[]);
 useEffect(()=>{let active=true;const controller=new AbortController();setLoading(true);setError("");
  const params:Record<string,string>={};
  if(paged) {params.result=filters.result;params.object=filters.object;if(cursor)params.cursor=cursor;else {const now=Date.now();params.to=new Date(now).toISOString();params.from=new Date(now-Number(filters.hours)*3600000).toISOString()}}
  api.logs(kind,params,controller.signal).then(d=>{if(active)setSnapshot({kind:scope,value:d})}).catch(e=>{if(active)setError(e.message)}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false;controller.abort()};
 },[kind,scope,cursor,attempt]);
 const needle=query.toLocaleLowerCase();
 const rows=(data?.entries || []).filter((e:any)=>`${e.time} ${e.source} ${e.unit} ${e.event||""} ${e.server||""} ${e.user||""} ${e.address||""} ${e.protocol||""} ${e.message}`.toLocaleLowerCase().includes(needle));
 function download(){const text=rows.map((e:any)=>`${e.time || "Время неизвестно"}\t${e.source}\t${e.unit}\t${e.message}`).join("\n");const url=URL.createObjectURL(new Blob([text],{type:"text/plain;charset=utf-8"}));const a=document.createElement("a");a.href=url;a.download=`netos-${kind}.log`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
 return <div className="logs-content" aria-busy={loading}>
  <div role="tablist" aria-label="Источники журнала" className="row wrap navigation-subtabs">{tabs.filter(t=>t.id!=="dns" || dnsLogging).map(t=><button type="button" role="tab" aria-selected={kind===t.id} key={t.id} className={`btn sm ${kind===t.id?"primary":""}`} onClick={()=>{setQuery("");window.location.hash=`diagnostics?tab=logs&log=${t.id}`}}>{t.name}</button>)}</div>
  <div className="row wrap" style={{margin:"0.8rem 0",gap:"0.5rem"}}>
   <input aria-label="Поиск в журнале" placeholder="Поиск в загруженных записях" value={query} onChange={e=>setQuery(e.target.value)}/>
   <button className="btn sm" disabled={loading} onClick={()=>{setPage({kind:scope,cursor:""});setAttempt(n=>n+1)}}>Обновить журнал</button>
   <button className="btn sm" disabled={loading || !!error || !rows.length} onClick={download}>{paged?"Скачать страницу":"Скачать журнал"}</button>
  </div>

  {paged&&<form key={kind} className="row wrap" onSubmit={e=>{e.preventDefault();const f=new FormData(e.currentTarget);setSourceFilters(old=>({...old,[kind]:{hours:String(f.get("hours")),result:String(f.get("result") || ""),object:String(f.get("object")).trim()}}));setPage({kind:scope,cursor:""});setAttempt(n=>n+1)}}>
   <label>Период <select name="hours" defaultValue={filters.hours}><option value="24">24 часа</option><option value="168">7 дней</option><option value="744">31 день</option></select></label>
   {kind!=="firewall"&&<label>{kind==="services"?"Тип события":"Результат"} <select name="result" defaultValue={filters.result}><option value="">Все</option>{kind==="services"?<><option value="error">Ошибки</option><option value="warning">Предупреждения</option><option value="info">Состояние служб</option></>:<><option value="success">Успешно</option><option value="failure">Отказ</option><option value="info">Прочие события</option></>}</select></label>}
   <input name="object" aria-label={kind==="services"?"Служба":kind==="firewall"?"Правило или адрес":kind==="access"?"Объект доступа":"Объект VPN"} placeholder={kind==="services"?"Имя службы":kind==="firewall"?"Правило, адрес или текст записи":kind==="access"?"Пользователь, адрес или протокол":"Сервер, пользователь, адрес или протокол"} maxLength={128} defaultValue={filters.object}/>
   <button className="btn sm" type="submit">Применить фильтры</button>
  </form>}
  {kind==="vpn"&&<p className="hint">События OpenConnect, IKEv2 и L2TP. Установка соединения и аутентификация пользователя — отдельные события. Отсутствие записи не означает отсутствия попытки подключения.</p>}
  {kind==="firewall"&&<p className="hint">Записи правил с включённым логированием. Запись показывает совпадение с правилом, но не подтверждает разрешение или блокировку пакета. Частота записей ограничена.</p>}
  {error&&<Notice tone="danger" title="Не удалось загрузить журнал">{error}{data&&" Показана предыдущая страница."}<button className="btn sm" disabled={loading} onClick={()=>setAttempt(n=>n+1)}>Повторить запрос</button></Notice>}
  {!data?(loading?<Empty>Загрузка журнала…</Empty>:null):<>
   {data?.warnings?.map((text:string,i:number)=><Notice key={i} tone="warn" title={text}/>)}
   <p className="hint">Показано {rows.length} из {data?.entries?.length || 0} · Снимок: {data?.captured_at ? new Date(data.captured_at).toLocaleString("ru-RU") : "—"}</p>
   {paged&&<p className="hint">С {new Date(data.from).toLocaleString("ru-RU")} · Просмотрено записей источников: {data.scanned} · До 100 событий на странице, в порядке {kind==="access"?"источников":"журнала"}.{data.incomplete?" Часть источников недоступна. Продолжение приостановлено до успешного повтора.":data.next_cursor?" Есть более старые записи.":" Конец выбранного периода в доступном журнале."}</p>}
   {data.incomplete&&!error&&<button className="btn sm" disabled={loading} onClick={()=>setAttempt(n=>n+1)}>Повторить запрос</button>}
   {data.next_cursor&&<button className="btn sm" disabled={loading || !!error} onClick={()=>setPage({kind:scope,cursor:data.next_cursor})}>{rows.length?"Более старые события":"Продолжить поиск"}</button>}
   {rows.length===0?<Empty>{query?"Совпадений нет":data.incomplete?"Страница загружена не полностью":data.next_cursor?"На этой странице событий по фильтру нет":kind==="dns"?"Запросов DNS пока нет":"Записей пока нет"}</Empty>:<div style={{maxHeight:"32rem",overflow:"auto"}}><TableWrap><table className="logs-table">
    <thead><tr><th>Время</th><th>Источник</th><th>Сообщение</th></tr></thead>
    <tbody>{rows.map((e:any,i:number)=><tr key={e.id ? `${e.source}:${e.id}` : i}><td style={{whiteSpace:"nowrap"}}>{e.time?new Date(e.time).toLocaleString("ru-RU"):"Время неизвестно"}</td><td className="logs-source">{tabs.find(t=>t.id===e.source)?.name || e.source}{e.protocol&&<span> · {e.protocol==="panel"?"Панель":e.protocol.toUpperCase()}</span>}{e.unit&&<span className="logs-unit faint">{e.unit}</span>}</td><td style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere",maxWidth:"65vw"}}>{e.event?<><strong>{e.event}</strong>{e.result==="failure"?" · Отказ":e.result==="success"?" · Успешно":e.severity==="error"?" · Ошибка":e.severity==="warning"?" · Предупреждение":""}{e.server&&<div>Сервер: {e.server}</div>}{(e.user||e.address)&&<div>{e.user&&<span>Пользователь: {e.user}</span>}{e.user&&e.address&&" · "}{e.address&&<span>Адрес: {e.address}</span>}</div>}<details><summary>Исходная запись</summary>{e.message}</details></>:e.message}</td></tr>)}</tbody>
   </table></TableWrap></div>}
  </>}
 </div>;
}
