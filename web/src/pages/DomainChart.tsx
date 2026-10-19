import { useMemo } from "react";
import { getDomain } from "tldts";
import { Empty } from "../ui";

const colors=["#55d395","#ffbb3c","#69adff","#de8fff","#ff8397","#71dfdf","#b6d56b","#df9c6e","#9cacf4","#e3ce7b","#87939f"];
export function domainForRecord(r:any):string|null {
 if(r.source==="xray-ip" || !Number.isFinite(r.count) || r.count<=0)return null;
 const host=String(r.domain || "").toLowerCase().replace(/\.$/, "");
 if(host.includes(":") || host.endsWith(".arpa"))return null;
 return getDomain(host,{extractHostname:false});
}
export function domainCountsByClient(records:any[]):Map<string,number> {
 const counts=new Map<string,number>();
 for(const r of records)if(domainForRecord(r))counts.set(r.client,(counts.get(r.client)||0)+r.count);
 return counts;
}
export function DomainChart({records}:{records:any[]}) {
 const entries=useMemo(()=>{
  const totals=new Map<string,number>();
  for(const r of records){
   const domain=domainForRecord(r);
   if(domain)totals.set(domain,(totals.get(domain)||0)+r.count);
  }
  const sorted=[...totals.entries()].sort((a,b)=>b[1]-a[1] || a[0].localeCompare(b[0]));
  return sorted.length<=10 ? sorted : [...sorted.slice(0,10),["Остальные",sorted.slice(10).reduce((sum,d)=>sum+d[1],0)] as [string,number]];
 },[records]);
 const total=entries.reduce((sum,d)=>sum+d[1],0);
 if(!total)return <Empty>Домены за выбранный период не определены</Empty>;
 let offset=0;
 const slices=entries.map(([domain,count],i)=>{
  const start=offset;offset+=count/total*100;
  return {domain,count,color:colors[i],percent:count/total*100,gradient:`${colors[i]} ${start}% ${offset}%`};
 });
 return <div className="domain-chart">
  <div className="domain-donut" role="img" aria-label={`Обращения к доменам: ${total}`} style={{background:`conic-gradient(${slices.map(s=>s.gradient).join(",")})`}}>
   <div><strong>{total.toLocaleString()}</strong><span>обращений</span></div>
  </div>
  <ul className="domain-legend" aria-label="Домены">{slices.map(s=><li key={s.domain} title={`${s.domain}: ${s.count} обращений (${s.percent.toFixed(1)}%)`}>
   <i style={{background:s.color}}/><span>{s.domain}</span><b>{s.count.toLocaleString()}</b><small>{s.percent.toFixed(1)}%</small>
  </li>)}</ul>
 </div>;
}
