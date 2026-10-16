import { useEffect, useState } from "react";
import { api, formatBitrate, formatBytes } from "../api";
import { Card, Empty, Switch, Notice, TableWrap } from "../ui";
import { useAccess } from "../permissions";

const periods: [number, string][] = [[5,"5 мин"],[10,"10 мин"],[30,"30 мин"],[60,"1 час"],[120,"2 часа"],[360,"6 часов"],[720,"12 часов"],[1440,"Сутки"],[10080,"7 дней"]];
const colors = ["#55d395", "#ffbb3c", "#69adff", "#de8fff", "#ff8397", "#71dfdf", "#b6d56b", "#df9c6e"];
type Line = { id: string; name: string; color: string; points: { at: number; value: number }[] };
function timeLabel(t: number) { return new Date(t * 1000).toLocaleString([], { month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit" }); }
const localTime = (t: number) => { const d = new Date(t); return new Date(t - d.getTimezoneOffset() * 60000).toISOString().slice(0,16); };

export function TrafficMonitor({config,patch,interfaces}:{config:any;patch:(fn:(d:any)=>void)=>void;interfaces:string[]}) {
 const can=useAccess();const [period,setPeriod]=useState(1440);
 const [start,setStart]=useState(localTime(Date.now()-86400000)),[end,setEnd]=useState(localTime(Date.now()));
 const [custom,setCustom]=useState<{from:number;to:number}|null>(null),[rangeError,setRangeError]=useState("");
 const [selected,setSelected]=useState<string[]>([]),[direction,setDirection]=useState("sum"),[details,setDetails]=useState(false);
 const [internet,setInternet]=useState<any>(null),[clients,setClients]=useState<any>(null);
 const [error,setError]=useState(""),[clientError,setClientError]=useState("");
 const query=custom?`from=${custom.from}&to=${custom.to}`:`minutes=${period||1440}`;
 useEffect(()=>{
  let cancelled=false,busy=false;
  setInternet(null);setClients(null);
  const load=async()=>{if(busy)return;busy=true;await Promise.all([
   api.trafficWindow(query,interfaces).then(v=>{if(!cancelled){setInternet(v);setError("")}}).catch(()=>{if(!cancelled)setError("Не удалось обновить скорость интернета")}),
   api.clientStatistics(query,selected,details).then(v=>{if(!cancelled){setClients(v);setClientError("")}}).catch(()=>{if(!cancelled)setClientError("Не удалось обновить историю клиентов")})
  ]);busy=false;};void load();const timer=setInterval(load,30000);return()=>{cancelled=true;clearInterval(timer)};
 },[query,interfaces.join(","),selected.join(","),details]);
 const to=custom?.to||clients?.to||Math.floor(Date.now()/1000),from=custom?.from||clients?.from||to-(period||1440)*60;
 const totals:any[]=clients?.clients||[];const ids=selected.length?selected:totals.slice(0,5).map(c=>c.id);
 const lines:Line[]=ids.map((id,index)=>({id,name:totals.find(c=>c.id===id)?.name||id,color:colors[index%colors.length],points:(clients?.points||[]).filter((p:any)=>p.id===id).map((p:any)=>({at:p.at,value:direction==="down"?p.rx_bps:direction==="up"?p.tx_bps:p.rx_bps+p.tx_bps}))}));
 const enabled=!!config.traffic_monitor?.enabled;
 const wanLines:Line[]=[{id:"down",name:"Входящий",color:colors[0],points:[]},{id:"up",name:"Исходящий",color:colors[1],points:[]}];
 for(const p of internet?.points||[]){let down=0,up=0;for(const iface of interfaces){down+=p.interfaces?.[iface]?.rx_bps||0;up+=p.interfaces?.[iface]?.tx_bps||0}wanLines[0].points.push({at:new Date(p.at).getTime()/1000,value:down});wanLines[1].points.push({at:new Date(p.at).getTime()/1000,value:up})}
 const domains:any[]=clients?.domains||[];const domainTotals=new Map<string,number>();for(const d of domains)domainTotals.set(d.domain,(domainTotals.get(d.domain)||0)+d.count);
 const topDomains=[...domainTotals.entries()].sort((a,b)=>b[1]-a[1]).slice(0,10);const maxDomain=topDomains[0]?.[1]||1;
 return <>
  <Card title="Скорость интернета" subtitle="Трафик аплинков за выбранный период" actions={<select aria-label="Период статистики" value={period} onChange={e=>{setPeriod(Number(e.target.value));if(Number(e.target.value)!==0)setCustom(null)}}>{periods.map(([n,label])=><option key={n} value={n}>{label}</option>)}<option value={0}>Свой период</option></select>}>
   {period===0&&<div className="monitor-range"><label>С <input aria-label="Начало периода" type="datetime-local" value={start} onChange={e=>setStart(e.target.value)}/></label><label>По <input aria-label="Конец периода" type="datetime-local" value={end} onChange={e=>setEnd(e.target.value)}/></label><button className="btn sm" onClick={()=>{const a=new Date(start).getTime()/1000,b=new Date(end).getTime()/1000,now=Date.now()/1000;if(!Number.isFinite(a)||!Number.isFinite(b)||a>=b||a<now-604800||b>now+60){setRangeError("Выберите начало и конец в пределах последних 7 дней");return}setRangeError("");setCustom({from:a,to:b})}}>Показать</button>{rangeError&&<span role="alert">{rangeError}</span>}</div>}
   {error?<Empty>{error}</Empty>:internet?<TimeChart lines={wanLines} from={from} to={to} height={190}/>:<Empty>Загрузка статистики…</Empty>}
  </Card>
  <Card title="Трафик клиентов" subtitle="LAN и VPN · скачивание и отправка" actions={can("dashboard",true)?<Switch checked={enabled} onChange={value=>patch(d=>{d.traffic_monitor={enabled:value}})} label="Собирать историю"/>:undefined}>
   <p className="faint">{enabled?"Сбор каждые 30 секунд, история до 7 дней. Настройка начинает действовать после применения.":"Сбор выключен. Накопленная история доступна до истечения срока хранения."}</p>
   {clientError?<Empty>{clientError}</Empty>:!clients?<Empty>Загрузка истории…</Empty>:<>
    {clients.problem&&<Notice tone="warn" title={clients.problem}/>}
    {clients.limited&&<Notice tone="warn" title="Достигнут лимит истории — часть подробностей не сохранена"/>}
    {totals.length===0?<Empty>{enabled?"История появится после двух замеров. DNS показывает обращения только через резолвер роутера.":"За этот период данных нет"}</Empty>:<>
     <div className="monitor-toolbar"><select aria-label="Направление трафика клиентов" value={direction} onChange={e=>setDirection(e.target.value)}><option value="sum">Суммарно</option><option value="down">Скачивание</option><option value="up">Отправка</option></select><button className="btn sm" onClick={()=>setSelected([])}>Топ-5 за период</button><span className="faint">Выбрано {ids.length} из {totals.length} · максимум 16</span></div>
     <div className="monitor-clients">{totals.map(c=><label key={c.id}><input type="checkbox" checked={ids.includes(c.id)} disabled={!ids.includes(c.id)&&ids.length>=16} onChange={()=>{const next=ids.includes(c.id)?ids.filter(id=>id!==c.id):[...ids,c.id];if(next.length)setSelected(next)}}/><span>{c.name}<small className="faint"> ↓ {formatBytes(c.rx)} · ↑ {formatBytes(c.tx)}</small></span></label>)}</div>
     <TimeChart lines={lines} from={from} to={to} height={320}/>
    </>}
    <button type="button" className="btn sm" aria-expanded={details} onClick={()=>setDetails(!details)}>{details?"Скрыть подробности":"Подробнее"}</button>
    {details&&<div className="monitor-details">
     <p className="faint">Учитывается маршрутизируемый IP-трафик, включая обмен между сегментами. Обмен внутри одного сегмента и трафик к службам роутера (Samba, SOCKS5) здесь не видны. После запуска сбора и смены адреса первый интервал может отсутствовать.</p><h3>Клиенты за выбранный период</h3><TableWrap><table><thead><tr><th>Клиент</th><th>Скачано</th><th>Отправлено</th><th>DNS-запросов</th></tr></thead><tbody>{totals.filter(c=>ids.includes(c.id)).map(c=><tr key={c.id}><td>{c.name}</td><td>{formatBytes(c.rx)}</td><td>{formatBytes(c.tx)}</td><td>{c.queries}</td></tr>)}</tbody></table></TableWrap>
     <h3>Запрашиваемые ресурсы</h3><p className="faint">Количество DNS-запросов, не объём трафика сайта. Фоновые обращения также учитываются. Сторонний DNS и домены внутри клиентского VPN здесь не видны.</p>
     {topDomains.length===0?<Empty>DNS-запросов выбранных клиентов за этот период нет</Empty>:<>
      <div className="monitor-domains">{topDomains.map(([domain,count])=><div key={domain}><span title={domain}>{domain}</span><div><i style={{width:`${count/maxDomain*100}%`}}/></div><b>{count}</b></div>)}</div>
      <p className="faint">До 200 наиболее частых пар «клиент — домен» за период.</p><TableWrap><table><thead><tr><th>Клиент</th><th>Домен</th><th>Запросов</th><th>Первый</th><th>Последний</th></tr></thead><tbody>{domains.map(d=><tr key={d.client+"|"+d.domain}><td>{totals.find(c=>c.id===d.client)?.name||d.client}</td><td>{d.domain}</td><td>{d.count}</td><td>{timeLabel(d.first)}</td><td>{timeLabel(d.last)}</td></tr>)}</tbody></table></TableWrap>
     </>}
    </div>}
   </>}
  </Card>
 </>
}

function TimeChart({lines,from,to,height}:{lines:Line[];from:number;to:number;height:number}) {
 const [hover,setHover]=useState<number|null>(null);const width=1000,pad=12;
 let peak=1;for(const l of lines)for(const p of l.points)peak=Math.max(peak,p.value);
 const x=(t:number)=>pad+(t-from)/Math.max(1,to-from)*(width-2*pad),y=(n:number)=>height-pad-n/peak*(height-2*pad);
 const gap=Math.max(90,(to-from)/150);
 const path=(line:Line)=>line.points.map((p,i)=>`${i&&p.at-line.points[i-1].at<=gap?"L":"M"}${x(p.at).toFixed(1)},${y(p.value).toFixed(1)}`).join(" ");
 if(!lines.some(l=>l.points.length))return <Empty>В выбранном периоде пока нет замеров</Empty>;
 return <div className="monitor-chart">
  <div className="chart-legend">{lines.map(l=><span key={l.id} style={{color:l.color}}>━ {l.name}</span>)}<span className="faint">Шкала до {formatBitrate(peak)}</span></div>
  <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="График скорости за выбранный период" style={{width:"100%",height,display:"block"}} onPointerMove={e=>{const box=e.currentTarget.getBoundingClientRect();setHover(from+Math.max(0,Math.min(1,(e.clientX-box.left)/box.width))*(to-from))}} onPointerLeave={()=>setHover(null)}>
   {[.25,.5,.75,1].map(n=><line key={n} x1={pad} x2={width-pad} y1={y(peak*n)} y2={y(peak*n)} stroke="var(--border)" vectorEffect="non-scaling-stroke"/>)}
   {lines.map(l=><path key={l.id} d={path(l)} fill="none" stroke={l.color} strokeWidth={1.8} vectorEffect="non-scaling-stroke"/>)}
   {hover!==null&&<line x1={x(hover)} x2={x(hover)} y1={pad} y2={height-pad} stroke="var(--text-muted)" strokeDasharray="4 4"/>}
  </svg>
  <div className="monitor-axis"><span>{timeLabel(from)}</span><span>{timeLabel((from+to)/2)}</span><span>{timeLabel(to)}</span></div>
  <div className="monitor-hover">{hover!==null?<><span>{timeLabel(hover)}</span>{lines.map(l=>{const point=l.points.reduce<{at:number;value:number}|null>((best,p)=>!best||Math.abs(p.at-hover)<Math.abs(best.at-hover)?p:best,null);return <span key={l.id} style={{color:l.color}}>{l.name}: {point&&Math.abs(point.at-hover)<gap?formatBitrate(point.value):"нет замера"}</span>})}</>:<span className="faint">Наведите на график, чтобы увидеть скорость в выбранное время</span>}</div>
 </div>
}
