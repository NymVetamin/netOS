import { probeChart } from "../chartProbe";
import { LiveChart, useRealtimeTraffic } from "./RealtimeTraffic";
import { continueTrafficHistory } from "../trafficTimeline";
import { DomainChart, domainCountsByClient } from "./DomainChart";
import { useEffect, useRef, useState } from "react";
import { api, formatBitrate, formatBytes } from "../api";
import { Card, Empty, Switch, Notice, TableWrap } from "../ui";
import { useAccess } from "../permissions";

const periods: [number, string][] = [[-1,"Сейчас"],[5,"5 мин"],[10,"10 мин"],[30,"30 мин"],[60,"1 час"],[120,"2 часа"],[360,"6 часов"],[720,"12 часов"],[1440,"Сутки"],[10080,"7 дней"]];
const colors = ["#55d395", "#ffbb3c", "#69adff", "#de8fff", "#ff8397", "#71dfdf", "#b6d56b", "#df9c6e"];
type Line = { id: string; name: string; color: string; points: { at: number; value: number|null; gap?:number;peak?:number }[] };
function timeLabel(t: number) { return new Date(t * 1000).toLocaleString([], { month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit" }); }
const localTime = (t: number) => { const d = new Date(t); return new Date(t - d.getTimezoneOffset() * 60000).toISOString().slice(0,16); };

export function TrafficMonitor({config,patch,interfaces}:{config:any;patch:(fn:(d:any)=>void)=>void;interfaces:string[];status:any}) {
 const can=useAccess();const [period,setPeriod]=useState(-1);
 const [start,setStart]=useState(localTime(Date.now()-86400000)),[end,setEnd]=useState(localTime(Date.now()));
 const [custom,setCustom]=useState<{from:number;to:number}|null>(null),[rangeError,setRangeError]=useState("");
 const [selected,setSelected]=useState<string[]|null>(null),[direction,setDirection]=useState("sum"),[details,setDetails]=useState(false);
 const clientColors=useRef(new Map<string,string>());
 const [internet,setInternet]=useState<any>(null),[clients,setClients]=useState<any>(null);
 const [error,setError]=useState(""),[clientError,setClientError]=useState("");
 const [hold,setHold]=useState<{to:number;from:number;frames:any[];interval:number;clients:any;interfaces:string[]}|null>(null);
 const realtime=period===-1;
 const current=useRealtimeTraffic(!custom);
 const enabled=!!config.traffic_monitor?.enabled;
 const query=hold?`from=${Math.floor(hold.from)}&to=${Math.floor(hold.to)}`:custom?`from=${custom.from}&to=${custom.to}`:`minutes=${realtime?3:period||1440}`;
 useEffect(()=>{
  let cancelled=false,busy=false;
  const controller=new AbortController();
  const load=async()=>{if(busy)return;busy=true;await Promise.all([
   api.secondHistory(query,controller.signal).then(v=>{if(!cancelled){setInternet(v);setError("")}}).catch(()=>{if(!cancelled)setError("Не удалось обновить скорость интернета")}),
   api.clientStatistics(query,selected||[],details,controller.signal).then(v=>{if(!cancelled){setClients(v);setClientError("")}}).catch(()=>{if(!cancelled)setClientError("Не удалось обновить историю клиентов")})
  ]);busy=false;};void load();const timer=setInterval(load,30000);return()=>{cancelled=true;controller.abort();clearInterval(timer)};
 },[query,interfaces.join(","),(selected||[]).join(","),details]);
 const to=hold?.to||custom?.to||current.batches.at(-1)?.at||Math.floor(Date.now()/1000),from=hold?.from||custom?.from||to-(realtime?3:period||1440)*60;
 const frames=hold?.frames||continueTrafficHistory(internet?.points||[],custom?[]:current.batches,(b:any)=>b.at,from,to);
 const recent=frames.map((b:any)=>({at:b.at,clients:(b.values||[]).filter((v:any)=>!v.id.startsWith("if:")).map((v:any)=>({id:v.id,name:v.name,rx:v.rx_bps,tx:v.tx_bps}))}));
 const shownClients=hold?hold.clients:clients;
 const allTotals:any[]=shownClients?.clients||[];
 const active=new Map<string,any>();
 for(const c of allTotals)if(c.rx>0||c.tx>0||c.connections>0||c.queries>0)active.set(c.id,c);
 for(const batch of recent)for(const c of batch.clients||[])if((c.rx>0||c.tx>0)&&!active.has(c.id))active.set(c.id,{...c,rx:0,tx:0,queries:0});
 const totals=[...active.values()].sort((a,b)=>(b.rx+b.tx)-(a.rx+a.tx));
 useEffect(()=>{
  if(!clients||!selected?.length)return;
  const valid=selected.filter(id=>active.has(id));
  if(valid.length!==selected.length)setSelected(valid);
 },[clients,(selected||[]).join(","),totals.map(c=>c.id).join(",")]);
 const ids=selected===null?totals.slice(0,5).map(c=>c.id):selected.filter(id=>active.has(id));
 for(const id of clientColors.current.keys())if(!ids.includes(id))clientColors.current.delete(id);
 for(const id of ids)if(!clientColors.current.has(id))clientColors.current.set(id,colors.find(c=>![...clientColors.current.values()].includes(c))||colors[clientColors.current.size%colors.length]);
 const domainRecords=(clients?.domains||[]).filter((r:any)=>ids.includes(r.client));
 const domainCounts=domainCountsByClient(domainRecords);
 const interval=hold?.interval||internet?.interval_seconds||1;
 const gap=interval>1?interval*1.5:3;
 const clientLines=(frames:any[]):Line[]=>ids.map(id=>({id,name:active.get(id)?.name||id,color:clientColors.current.get(id)!,points:frames.map((b:any)=>{
  const v=b.values?.find((v:any)=>v.id===id);
  return {at:b.at,gap,peak:v?(direction==="down"?v.rx_peak:direction==="up"?v.tx_peak:(v.rx_peak||0)+(v.tx_peak||0)):0,value:!v?null:direction==="down"?v.rx_bps:direction==="up"?v.tx_bps:v.rx_bps!=null&&v.tx_bps!=null?v.rx_bps+v.tx_bps:null};
 })}));
 const internetLines=(frames:any[]):Line[]=>["rx_bps","tx_bps"].map((key,index)=>({id:index?"up":"down",name:index?"Исходящий":"Входящий",color:index?"#55d395":"#71c7ed",points:frames.map((b:any)=>{
  const rows=(hold?.interfaces||interfaces).map(iface=>b.values?.find((v:any)=>v.id==="if:"+iface));
  return {at:b.at,gap,peak:rows.reduce((sum,row)=>sum+(row?.[index?"tx_peak":"rx_peak"]||0),0),value:rows.length&&rows.every(row=>row?.[key]!=null)?rows.reduce((sum,row)=>sum+row[key],0):null};
 })}));
 const lines=clientLines(frames),wanLines=internetLines(frames);
 const moving=!custom&&(realtime||period<=10);

 return <>
  <Card title="Скорость интернета" subtitle="Трафик аплинков за выбранный период" actions={<><button className="btn sm" disabled={!!custom||!internet} aria-pressed={!!hold} onClick={()=>setHold(hold?null:{to,from,frames,interval,clients,interfaces:[...interfaces]})}>{hold?"Продолжить":"Пауза"}</button><select aria-label="Период статистики" value={period} onChange={e=>{setHold(null);setPeriod(Number(e.target.value));if(Number(e.target.value)!==0)setCustom(null)}}>{periods.map(([n,label])=><option key={n} value={n}>{label}</option>)}<option value={0}>Свой период</option></select></>}>
   {period===0&&<div className="monitor-range"><label>С <input aria-label="Начало периода" type="datetime-local" value={start} onChange={e=>setStart(e.target.value)}/></label><label>По <input aria-label="Конец периода" type="datetime-local" value={end} onChange={e=>setEnd(e.target.value)}/></label><button className="btn sm" onClick={()=>{const a=new Date(start).getTime()/1000,b=new Date(end).getTime()/1000,now=Date.now()/1000;if(!Number.isFinite(a)||!Number.isFinite(b)||a>=b||a<now-604800||b>now+60){setRangeError("Выберите начало и конец в пределах последних 7 дней");return}setRangeError("");setHold(null);setCustom({from:a,to:b})}}>Показать</button>{rangeError&&<span role="alert">{rangeError}</span>}</div>}
   {error&&!hold?<Empty>{error}</Empty>:internet?moving?<LiveChart lines={wanLines} at={to} seconds={realtime?180:period*60} paused={!!hold}/>:<TimeChart lines={wanLines} from={from} to={to} height={190} mapFrames={internetLines}/>:<Empty>Загрузка статистики…</Empty>}
  </Card>
  <Card title="Трафик клиентов" subtitle="LAN и VPN · скачивание и отправка" actions={can("dashboard",true)?<Switch checked={enabled} onChange={value=>patch(d=>{d.traffic_monitor={enabled:value}})} label="Собирать историю"/>:undefined}>
   <p className="faint">{enabled?"Секундная история хранится 7 дней. Настройка сбора действует после применения.":"Сбор клиентов выключен. Накопленная история доступна до истечения срока хранения."}</p>
   {current.error&&!custom&&<p role="status" className="faint">{current.error}</p>}
   {clientError&&!hold?<Empty>{clientError}</Empty>:!clients?<Empty>Загрузка истории…</Empty>:<>
    {clients.problem&&<Notice tone="warn" title={clients.problem}/>}
    {clients.limited&&<Notice tone="warn" title="Достигнут лимит истории — часть подробностей не сохранена"/>}
    {totals.length===0?<Empty>{enabled?"За выбранный период нет клиентов с трафиком. После включения сбора дождитесь двух замеров.":"За этот период данных нет"}</Empty>:<>
     <div className="monitor-toolbar"><select aria-label="Направление трафика клиентов" value={direction} onChange={e=>setDirection(e.target.value)}><option value="sum">Суммарно</option><option value="down">Скачивание</option><option value="up">Отправка</option></select><button className="btn sm" onClick={()=>setSelected(null)}>Топ-5 за период</button><span className="faint">Выбрано {ids.length} из {totals.length} · максимум 16</span></div>
     <div className="monitor-clients">{totals.map(c=><label key={c.id}><input type="checkbox" checked={ids.includes(c.id)} disabled={!ids.includes(c.id)&&ids.length>=16} onChange={()=>{const next=ids.includes(c.id)?ids.filter(id=>id!==c.id):[...ids,c.id];setSelected(next)}}/><span>{c.name}<small className="faint"> {c.rx||c.tx?<>↓ {formatBytes(c.rx)} · ↑ {formatBytes(c.tx)}</>:c.connections||c.queries?"Есть обращения · нет замера трафика":"Есть трафик · итог ещё собирается"}</small></span></label>)}</div>
     {moving?<LiveChart lines={lines} at={to} seconds={realtime?180:period*60} paused={!!hold}/>:<TimeChart lines={lines} from={from} to={to} height={320} mapFrames={clientLines}/>}
    </>}
    <button type="button" className="btn sm" aria-expanded={details} onClick={()=>setDetails(!details)}>{details?"Скрыть подробности":"Подробнее"}</button>
    {details&&<div className="monitor-details">
     <p className="faint">Учитывается маршрутизируемый IP-трафик, включая обмен между сегментами. Обмен внутри одного сегмента и трафик к службам роутера (Samba, SOCKS5) здесь не видны. После запуска сбора и смены адреса первый интервал может отсутствовать.</p><h3>Клиенты за выбранный период</h3><TableWrap><table><thead><tr><th>Клиент</th><th>Скачано</th><th>Отправлено</th><th>Обращений к доменам</th><th>Соединений Xray</th></tr></thead><tbody>{totals.filter(c=>ids.includes(c.id)).map(c=><tr key={c.id}><td>{c.name}</td><td>{formatBytes(c.rx)}</td><td>{formatBytes(c.tx)}</td><td>{domainCounts.get(c.id)||0}</td><td>{c.connections||0}</td></tr>)}</tbody></table></TableWrap>
     <h3>Запрашиваемые домены</h3><p className="faint">Поддомены объединены. Доли по числу DNS-запросов и соединений Xray с определённым доменом, не по объёму трафика. Только загруженная выборка за период.</p>
     <DomainChart records={domainRecords}/>

    </div>}
   </>}
  </Card>
 </>
}

function TimeChart({lines,from,to,height,mapFrames}:{lines:Line[];from:number;to:number;height:number;mapFrames:(frames:any[])=>Line[]}) {
 const [hover,setHover]=useState<number|null>(null);const width=1000,pad=12;
 const [exact,setExact]=useState<any[]|null>(null);
 useEffect(()=>{
  setExact(null);if(hover==null)return;
  const controller=new AbortController();let cancelled=false;
  const timer=setTimeout(()=>{void api.secondHistory(`from=${Math.floor(hover)-2}&to=${Math.min(Math.ceil(hover)+2,Math.floor(Date.now()/1000))}`,controller.signal).then(data=>{if(!cancelled)setExact(data.points||[])}).catch(()=>{});},60);
  return()=>{cancelled=true;clearTimeout(timer);controller.abort()};
 },[hover]);
 let peak=1;for(const l of lines)for(const p of l.points)peak=Math.max(peak,p.value||0,p.peak||0);
 const x=(t:number)=>pad+(t-from)/Math.max(1,to-from)*(width-2*pad),y=(n:number)=>height-pad-n/peak*(height-2*pad);
 const path=(line:Line)=>line.points.map((p,i)=>p.value==null?"":`${i&&line.points[i-1].value!=null&&p.at-line.points[i-1].at<=Math.max(p.gap||3,line.points[i-1].gap||3)?"L":"M"}${x(p.at).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
 if(!lines.some(l=>l.points.length))return <Empty>В выбранном периоде пока нет замеров</Empty>;
 const exactLines=exact?mapFrames(exact):null;
 const values=hover===null?[]:lines.map(line=>{
  const raw=exactLines?.find(v=>v.id===line.id);const value=raw?probeChart(raw.points.map(p=>({...p,gap:3})),hover):null;
  return {line,point:value==null?null:{at:hover,value}};
 });
 const cursor=hover===null?0:x(hover);
 return <div className="monitor-chart">
  <div className="chart-legend">{lines.map(l=><span key={l.id} style={{color:l.color}}>━ {l.name}</span>)}<span className="faint">Шкала до {formatBitrate(peak)}</span></div>
  <div className="monitor-plot" onPointerLeave={()=>setHover(null)}>
  <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="График скорости за выбранный период" style={{width:"100%",height,display:"block"}} onPointerMove={e=>{
   const box=e.currentTarget.getBoundingClientRect(),position=(e.clientX-box.left)/box.width*width;
   const at=from+Math.max(0,Math.min(1,(position-pad)/(width-2*pad)))*(to-from);
   setHover(at);
  }}>
   {[.25,.5,.75,1].map(n=><line key={n} x1={pad} x2={width-pad} y1={y(peak*n)} y2={y(peak*n)} stroke="var(--border)" vectorEffect="non-scaling-stroke"/>)}
   {lines.map(l=><path key={l.id} d={path(l)} fill="none" stroke={l.color} strokeWidth={1.8} vectorEffect="non-scaling-stroke"/>)}
   {hover!==null&&<g className="monitor-crosshair"><line x1={cursor} x2={cursor} y1={pad} y2={height-pad} stroke="var(--text-dim)" strokeDasharray="4 4" vectorEffect="non-scaling-stroke"/></g>}
  </svg>
  {values.filter(v=>v.point).map(({line,point})=><span key={line.id} className="monitor-point" aria-hidden="true" style={{left:`${x(point!.at)/width*100}%`,top:y(point!.value!),background:line.color}}/>)}
  {hover!==null&&<div className="monitor-tooltip" role="tooltip" style={{left:`${Math.max(1,Math.min(99,cursor/width*100))}%`,transform:cursor>width/2?"translateX(calc(-100% - 10px))":"translateX(10px)"}}><strong>{new Date(hover*1000).toLocaleTimeString()}</strong>{values.map(({line,point})=><span key={line.id} style={{color:line.color}}>{line.name}: {point?formatBitrate(point.value!):"нет замера"}</span>)}</div>}
  </div>
  <div className="monitor-axis"><span>{timeLabel(from)}</span><span>{timeLabel((from+to)/2)}</span><span>{timeLabel(to)}</span></div>
 </div>
}
