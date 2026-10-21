import { memo, useEffect, useLayoutEffect, useRef, useState } from "react";
import { api, formatBitrate } from "../api";

type Value={id:string;name:string;at:number;rx_bps:number|null;tx_bps:number|null};
type Batch={sequence:number;at:number;values:Value[];problems:string[]};
type Point={at:number;value:number|null;gap?:number};
type Line={id:string;name:string;color:string;points:Point[]};

export function useRealtimeTraffic(enabled:boolean) {
 const [batches,setBatches]=useState<Batch[]>([]),[error,setError]=useState("");
 useEffect(()=>{
  setBatches([]);setError("");if(!enabled)return;
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
 },[enabled]);
 return {batches,error};
}

// Geometry changes only when a measurement arrives. Pointer movement updates
// only the overlay. CSS moves the bounded SVG layer between measurements.
const Plot=memo(function Plot({lines,at,peak,paused}:{lines:Line[];at:number;peak:number;paused:boolean}){
 const node=useRef<HTMLDivElement>(null);
 useLayoutEffect(()=>{if(paused||!node.current||matchMedia('(prefers-reduced-motion: reduce)').matches)return;const animation=node.current.animate([{transform:'translate3d(0,0,0)'},{transform:'translate3d(-0.555556%,0,0)'}],{duration:1000,easing:'linear'});return()=>animation.cancel()},[at,paused]);
 const paths=lines.map(l=>{
  let last=0,lastGap=3;return {...l,path:l.points.map(p=>{if(p.value==null){last=0;return ""}const command=last&&p.at-last<=Math.max(lastGap,p.gap||3)?"L":"M";last=p.at;lastGap=p.gap||3;return `${command}${((p.at-at+181)/180*1000).toFixed(2)},${(180-p.value/peak*170).toFixed(2)}`}).join(" ")};
 });
 return <div ref={node} className="rt-moving"><svg viewBox="0 0 1000 190" preserveAspectRatio="none" aria-hidden="true" style={{width:'100%',height:190,overflow:'visible'}}>{paths.map(l=><path key={l.id} d={l.path} fill="none" stroke={l.color} strokeWidth="1.6" vectorEffect="non-scaling-stroke"/>)}</svg></div>;
});
export function LiveChart({lines,at}:{lines:Line[];at:number}) {
 const [hover,setHover]=useState<number|null>(null);const scale=useRef({peak:1000,at:0});
 const incoming=Math.max(1000,...lines.flatMap(l=>l.points.map(p=>p.value||0)));
 if(incoming>scale.current.peak||at-scale.current.at>30){scale.current={peak:Math.pow(2,Math.ceil(Math.log2(incoming))),at}}
 const peak=scale.current.peak;
 const target=hover==null?null:at-180+hover*180;
 const times=lines.flatMap(l=>l.points.map(p=>p.at));
 const nearest=target==null||!times.length?target:times.reduce((best,t)=>Math.abs(t-target)<Math.abs(best-target)?t:best,times[0]);
 const hovered=target!=null&&nearest!=null&&Math.abs(nearest-target)<=15?nearest:target;
 const values=lines.map(l=>({line:l,point:hovered==null?null:l.points.reduce<Point|null>((best,p)=>!best||Math.abs(p.at-hovered)<Math.abs(best.at-hovered)?p:best,null)}));
 const cursor=hovered==null?0:Math.max(0,Math.min(1,(hovered-at+180)/180));
 return <div className="rt-chart">
  <div className="chart-legend">{lines.map(l=><span key={l.id} style={{color:l.color}}>{l.name}: {l.points.at(-1)?.value!=null?formatBitrate(l.points.at(-1)!.value!):"—"}</span>)}<span className="faint">Шкала {formatBitrate(peak)}</span></div>
  <div className="rt-plot" role="img" aria-label="График скорости в реальном времени" onPointerLeave={()=>setHover(null)} onPointerMove={e=>{const b=e.currentTarget.getBoundingClientRect();setHover(Math.max(0,Math.min(1,(e.clientX-b.left)/b.width)))}}>
   <div className="rt-lines-clip"><Plot lines={lines} at={at} peak={peak} paused={hover!=null}/></div>
   {!at&&<span className="rt-wait">Ожидание замеров…</span>}
   {hover!=null&&<><div className="rt-cursor" style={{left:`${cursor*100}%`}}/>
    {values.filter(v=>v.point?.value!=null&&Math.abs(v.point.at-hovered!)<=(v.point.gap?15:2)).map(({line,point})=><span key={line.id} className="monitor-point" aria-hidden="true" style={{left:`${cursor*100}%`,top:180-point!.value!/peak*170,background:line.color}}/>)}
    <div className="monitor-tooltip" role="tooltip" style={{left:`${cursor*100}%`,transform:cursor>.5?"translateX(calc(-100% - 10px))":"translateX(10px)"}}><strong>{new Date(hovered!*1000).toLocaleTimeString()}</strong>{values.map(({line,point})=><span key={line.id} style={{color:line.color}}>{line.name}: {point?.value!=null&&Math.abs(point.at-hovered!)<=(point.gap?15:2)?formatBitrate(point.value):"нет замера"}</span>)}</div></>}

  </div>
  <div className="monitor-axis"><span>3 минуты назад</span><span>Сейчас</span></div>
 </div>;
}
