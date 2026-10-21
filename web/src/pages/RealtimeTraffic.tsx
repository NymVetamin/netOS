import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api, formatBitrate } from "../api";
import { Card } from "../ui";

type Value={id:string;name:string;at:number;rx_bps:number|null;tx_bps:number|null};
type Batch={sequence:number;at:number;values:Value[];problems:string[]};
type Point={at:number;value:number|null};
type Line={id:string;name:string;color:string;points:Point[]};
const colors=["#55d395","#69adff","#ffbb3c","#de8fff","#ff8397","#71dfdf","#b6d56b","#df9c6e","#bb99ff","#f19dcc","#83c7ff","#c3b975","#91bba3","#f3a36b","#75b8c8","#ce9d9d"];

export function RealtimeTraffic({interfaces}:{interfaces:string[]}) {
 const [batches,setBatches]=useState<Batch[]>([]),[error,setError]=useState("");
 const [selected,setSelected]=useState<string[]|null>(null),[direction,setDirection]=useState("down");
 const clientColors=useRef(new Map<string,string>());
 useEffect(()=>{
  let cancelled=false,busy=false,after=0;let retry:ReturnType<typeof setTimeout>;const controller=new AbortController();
  const load=async()=>{
   if(cancelled||busy||document.hidden)return;busy=true;
   try {while(!cancelled&&!document.hidden){const b=await api.realtime(after,controller.signal);if(cancelled)return;
    after=b.sequence||0;
    setError(b.problems?.join(" · ")||"");
    if(b.at)setBatches(old=>old.at(-1)?.at===b.at?old:[...old.filter(x=>b.at-x.at<185),b].slice(-185));
   }}catch{if(!cancelled){setError("Нет свежих данных. Соединение восстанавливается…");retry=setTimeout(load,1000)}}finally{busy=false}
  };
  void load();document.addEventListener("visibilitychange",load);
  return()=>{cancelled=true;controller.abort();clearTimeout(retry);document.removeEventListener("visibilitychange",load)};
 },[]);
 const latest=batches.at(-1);
 const names=new Map<string,string>();const totals=new Map<string,number>();
 for(const b of batches)for(const v of b.values||[])if(!v.id.startsWith("if:")&&(Number(v.rx_bps)>0||Number(v.tx_bps)>0)){
  names.set(v.id,v.name);totals.set(v.id,(totals.get(v.id)||0)+Number(v.rx_bps)+Number(v.tx_bps));
 }
 const ids=selected??[...totals.keys()].sort((a,b)=>totals.get(b)!-totals.get(a)!).slice(0,5);
 for(const id of clientColors.current.keys())if(!ids.includes(id))clientColors.current.delete(id);
 for(const id of ids)if(!clientColors.current.has(id))clientColors.current.set(id,colors.find(c=>![...clientColors.current.values()].includes(c))||colors[0]);
 const wan=useMemo(()=>["rx_bps","tx_bps"].map((dir,i)=>({id:dir,name:i?"Отправка":"Скачивание",color:colors[i],points:batches.map(b=>{
  const rows=interfaces.map(name=>b.values?.find(v=>v.id==="if:"+name));
  return {at:rows[0]?.at||b.at,value:rows.length&&rows.every(v=>v?.[dir as "rx_bps"]!=null)?rows.reduce((sum,v)=>sum+v![dir as "rx_bps"]!,0):null};
 })})),[batches,interfaces.join(",")]);
 const clients:Line[]=ids.map(id=>({id,name:names.get(id)||id,color:clientColors.current.get(id)!,points:batches.map(b=>{
  const v=b.values?.find(v=>v.id===id);return {at:v?.at||b.at,value:v?(direction==="down"?v.rx_bps:direction==="up"?v.tx_bps:v.rx_bps!=null&&v.tx_bps!=null?v.rx_bps+v.tx_bps:null):null};
 })}));
 return <div className="realtime-monitor">
  {error&&<p role="status" className="faint">{error}</p>}
  <Card title="Скорость интернета" subtitle="Сейчас · последние 3 минуты · замер каждую секунду"><LiveChart lines={wan} at={latest?.at||0}/></Card>
  <Card title="Трафик клиентов" subtitle="LAN и VPN · последние 3 минуты" actions={<select aria-label="Направление текущего трафика" value={direction} onChange={e=>setDirection(e.target.value)}><option value="down">Скачивание</option><option value="up">Отправка</option><option value="sum">Суммарно</option></select>}>
   <div className="monitor-clients">{[...names].map(([id,name])=><label key={id}><input type="checkbox" checked={ids.includes(id)} disabled={!ids.includes(id)&&ids.length>=16} onChange={()=>setSelected(ids.includes(id)?ids.filter(x=>x!==id):[...ids,id])}/>{name}</label>)}</div>
   <LiveChart lines={clients} at={latest?.at||0}/>
  </Card>
 </div>;
}

// Geometry changes only when a measurement arrives. Pointer movement updates
// only the overlay. CSS moves the bounded SVG layer between measurements.
const Plot=memo(function Plot({lines,at,peak}:{lines:Line[];at:number;peak:number}){
 const node=useRef<HTMLDivElement>(null);
 useLayoutEffect(()=>{if(!node.current||matchMedia('(prefers-reduced-motion: reduce)').matches)return;const animation=node.current.animate([{transform:'translate3d(0,0,0)'},{transform:'translate3d(-0.555556%,0,0)'}],{duration:1000,easing:'linear'});return()=>animation.cancel()},[at]);
 const paths=lines.map(l=>{
  let last=0;return {...l,path:l.points.map(p=>{if(p.value==null){last=0;return ""}const command=last&&p.at-last<3?"L":"M";last=p.at;return `${command}${((p.at-at+181)/180*1000).toFixed(2)},${(180-p.value/peak*170).toFixed(2)}`}).join(" ")};
 });
 return <div ref={node} className="rt-moving"><svg viewBox="0 0 1000 190" preserveAspectRatio="none" aria-hidden="true" style={{width:'100%',height:190,overflow:'visible'}}>{paths.map(l=><path key={l.id} d={l.path} fill="none" stroke={l.color} strokeWidth="1.6" vectorEffect="non-scaling-stroke"/>)}</svg></div>;
});
function LiveChart({lines,at}:{lines:Line[];at:number}) {
 const [hover,setHover]=useState<number|null>(null);const scale=useRef({peak:1000,at:0});
 const incoming=Math.max(1000,...lines.flatMap(l=>l.points.map(p=>p.value||0)));
 if(incoming>scale.current.peak||at-scale.current.at>30){scale.current={peak:Math.pow(2,Math.ceil(Math.log2(incoming))),at}}
 const peak=scale.current.peak;
 const hovered=hover==null?null:at-181+hover*180;
 return <div className="rt-chart">
  <div className="chart-legend">{lines.map(l=><span key={l.id} style={{color:l.color}}>{l.name}: {l.points.at(-1)?.value!=null?formatBitrate(l.points.at(-1)!.value!):"—"}</span>)}<span className="faint">Шкала {formatBitrate(peak)}</span></div>
  <div className="rt-plot" role="img" aria-label="График скорости в реальном времени" onPointerLeave={()=>setHover(null)} onPointerMove={e=>{const b=e.currentTarget.getBoundingClientRect();setHover(Math.max(0,Math.min(1,(e.clientX-b.left)/b.width)))}}>
   <Plot lines={lines} at={at} peak={peak}/>
   {!at&&<span className="rt-wait">Ожидание замеров…</span>}
   {hover!=null&&<><div className="rt-cursor" style={{left:`${hover*100}%`}}/><div className="monitor-tooltip" role="tooltip" style={{left:`${hover*100}%`,transform:hover>.5?"translateX(calc(-100% - 10px))":"translateX(10px)"}}><strong>{new Date(hovered!*1000).toLocaleTimeString()}</strong>{lines.map(l=>{const p=l.points.reduce<Point|null>((best,p)=>!best||Math.abs(p.at-hovered!)<Math.abs(best.at-hovered!)?p:best,null);return <span key={l.id} style={{color:l.color}}>{l.name}: {p?.value!=null&&Math.abs(p.at-hovered!)<2?formatBitrate(p.value):"нет замера"}</span>})}</div></>}
  </div>
  <div className="monitor-axis"><span>3 минуты назад</span><span>Сейчас</span></div>
 </div>;
}
