import { MutableRefObject, memo, useEffect, useLayoutEffect, useRef, useState } from "react";
import { api, formatBitrate } from "../api";
import { probeChart } from "../chartProbe";

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
const Plot=memo(function Plot({lines,at,peak,motion,seconds,paused}:{lines:Line[];at:number;peak:number;seconds:number;motion:MutableRefObject<number>;paused:boolean}){
 const node=useRef<HTMLDivElement>(null);
 useLayoutEffect(()=>{motion.current=performance.now();if(paused||!node.current||matchMedia('(prefers-reduced-motion: reduce)').matches){motion.current=-Infinity;return;}const animation=node.current.animate([{transform:'translate3d(0,0,0)'},{transform:`translate3d(${-100/seconds}%,0,0)`}],{duration:1000,easing:'linear'});return()=>animation.cancel()},[at,motion,seconds,paused]);
 const paths=lines.map(l=>{
  let last=0,lastGap=3;return {...l,path:l.points.map(p=>{if(p.value==null){last=0;return ""}const command=last&&p.at-last<=Math.max(lastGap,p.gap||3)?"L":"M";last=p.at;lastGap=p.gap||3;return `${command}${((p.at-at+seconds+1)/seconds*1000).toFixed(2)},${(180-p.value/peak*170).toFixed(2)}`}).join(" ")};
 });
 return <div ref={node} className="rt-moving" style={{transform:`translate3d(${-100/seconds}%,0,0)`}}><svg viewBox="0 0 1000 190" preserveAspectRatio="none" aria-hidden="true" style={{width:'100%',height:190,overflow:'visible'}}>{paths.map(l=><path key={l.id} d={l.path} fill="none" stroke={l.color} strokeWidth="1.6" vectorEffect="non-scaling-stroke"/>)}</svg></div>;
});
export function LiveChart({lines,at,seconds=180,paused=false}:{lines:Line[];at:number;seconds?:number;paused?:boolean}) {
 const [hover,setHover]=useState<number|null>(null);const motion=useRef(0);const scale=useRef({peak:1000,at:0});
 const incoming=Math.max(1000,...lines.flatMap(l=>l.points.map(p=>p.value||0)));
 if(incoming>scale.current.peak||at-scale.current.at>30){scale.current={peak:Math.pow(2,Math.ceil(Math.log2(incoming))),at}}
 const peak=scale.current.peak;
 return <div className="rt-chart">
  <div className="chart-legend">{lines.map(l=><span key={l.id} style={{color:l.color}}>{l.name}: {l.points.at(-1)?.value!=null?formatBitrate(l.points.at(-1)!.value!):"—"}</span>)}<span className="faint">Шкала {formatBitrate(peak)}</span></div>
  <div className="rt-plot" role="img" aria-label="График скорости в реальном времени" onPointerLeave={()=>setHover(null)} onPointerMove={e=>{const b=e.currentTarget.getBoundingClientRect();setHover(Math.max(0,Math.min(1,(e.clientX-b.left)/b.width)))}}>
   <div className="rt-lines-clip"><Plot lines={lines} at={at} peak={peak} motion={motion} seconds={seconds} paused={paused}/></div>
   {!at&&<span className="rt-wait">Ожидание замеров…</span>}
   {hover!=null&&<ChartCursor lines={lines} at={at} peak={peak} position={hover} motion={motion} seconds={seconds} paused={paused}/>}


  </div>
  <div className="monitor-axis"><span>{seconds/60} мин назад</span><span>{paused?new Date(at*1000).toLocaleTimeString():"Сейчас"}</span></div>
 </div>;
}

function ChartCursor({lines,at,peak,position,motion,seconds,paused}:{lines:Line[];at:number;peak:number;position:number;seconds:number;motion:MutableRefObject<number>;paused:boolean}) {
 const root=useRef<HTMLDivElement>(null);
 useLayoutEffect(()=>{
  let timer:ReturnType<typeof setTimeout>,lastSecond=-1;const reduced=paused||matchMedia('(prefers-reduced-motion: reduce)').matches;
  const time=root.current?.querySelector('strong');
  const elapsed=reduced?1:Math.max(0,Math.min(1,(performance.now()-motion.current)/1000));
  const start=at-seconds-1+elapsed+position*seconds,end=at-seconds+position*seconds;
  const transform=(value:number)=>`translate(-50%,-50%) translateY(${180-value/peak*170}px)`;
  const animations:Animation[]=[];
  const entries=lines.map((line,i)=>{
   const marker=root.current?.querySelector<HTMLElement>(`[data-marker="${i}"]`),label=root.current?.querySelector<HTMLElement>(`[data-value="${i}"]`);
   const times=[start,...line.points.filter(p=>p.at>start&&p.at<end).map(p=>p.at),end];
   const values=times.map(t=>probeChart(line.points,t));
   const animated=!!marker&&!reduced&&end>start&&values.every(v=>v!=null);
   if(animated&&marker){marker.style.display='block';marker.style.transform=transform(values.at(-1)!);animations.push(marker.animate(times.map((t,i)=>({offset:(t-start)/(end-start),transform:transform(values[i]!)})),{duration:(end-start)*1000,easing:'linear',fill:'forwards'}));}
   return {line,marker,label,animated};
  });
  const draw=()=>{
   const elapsed=reduced?1:Math.max(0,Math.min(1,(performance.now()-motion.current)/1000));
   const target=at-seconds-1+elapsed+position*seconds;
   const second=Math.floor(target);
   if(time&&second!==lastSecond){time.textContent=new Date(second*1000).toLocaleTimeString();lastSecond=second;}
   entries.forEach(({line,marker,label,animated})=>{
    const value=probeChart(line.points,target);
    if(marker&&!animated){const display=value==null?'none':'block';if(marker.style.display!==display)marker.style.display=display;if(value!=null)marker.style.transform=transform(value);}
    if(label){const text=`${line.name}: ${value==null?'нет замера':formatBitrate(value)}`;if(label.textContent!==text)label.textContent=text;}
   });
   // Text does not need a layout on every display frame. Markers move on
   // the compositor, while the tooltip follows at 10 Hz and on pointer moves.
   if(!reduced&&elapsed<1)timer=setTimeout(draw,100);
  };
  draw();return()=>{clearTimeout(timer);animations.forEach(animation=>animation.cancel())};
 },[lines,at,peak,position,motion,seconds,paused]);
 return <div ref={root} className="rt-hover-layer">
  <div className="rt-cursor" style={{left:`${position*100}%`}}/>
  {lines.map((line,i)=><span key={line.id} data-marker={i} className="monitor-point" aria-hidden="true" style={{left:`${position*100}%`,top:0,background:line.color,display:'none',willChange:'transform'}}/>)}
  <div className="monitor-tooltip" role="tooltip" style={{left:`${position*100}%`,transform:position>.5?"translateX(calc(-100% - 10px))":"translateX(10px)"}}>
   <strong/>{lines.map((line,i)=><span key={line.id} data-value={i} style={{color:line.color}}/>)}
  </div>
 </div>;
}
