import { useEffect, useId, useMemo, useRef, useState } from "react";
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
type DomainGroup = {domain:string;count:number;hosts:[string,number][]};
export function groupDomainRecords(records:any[]):DomainGroup[] {
 const groups=new Map<string,Map<string,number>>();
 for(const r of records){
  const domain=domainForRecord(r);if(!domain)continue;
  const host=String(r.domain).toLowerCase().replace(/\.$/, "");
  if(!groups.has(domain))groups.set(domain,new Map());
  const hosts=groups.get(domain)!;hosts.set(host,(hosts.get(host)||0)+r.count);
 }
 return [...groups].map(([domain,hosts])=>({domain,count:[...hosts.values()].reduce((a,b)=>a+b,0),hosts:[...hosts].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]))})).sort((a,b)=>b.count-a.count||a.domain.localeCompare(b.domain));
}

function DomainDetails({groups,initialDomain,onClose}:{groups:DomainGroup[];initialDomain:string|null;onClose:()=>void}) {
 const dialog=useRef<HTMLDialogElement>(null),titleId=useId();
 const [domain,setDomain]=useState(initialDomain);
 useEffect(()=>{const el=dialog.current!;el.showModal();return()=>el.close()},[]);
 const close=()=>{dialog.current?.close();onClose()};
 const hosts=domain?groups.find(g=>g.domain===domain)!.hosts:null;
 const rows=hosts||groups.map(g=>[g.domain,g.count] as [string,number]);
 return <dialog ref={dialog} className="action-confirm domain-details" aria-labelledby={titleId} onCancel={e=>{e.preventDefault();close()}}>
  <header><h2 id={titleId}>{domain||"Остальные домены"}</h2><button type="button" className="btn sm" autoFocus onClick={close}>Закрыть</button></header>
  {domain&&initialDomain===null&&<button type="button" className="btn sm" onClick={()=>setDomain(null)}>← Остальные домены</button>}
  <p className="faint">{hosts?"Полные имена":"Основные домены вне первой десятки"} из выбранной выборки на момент открытия. Учтены DNS-запросы и соединения Xray с определённым доменом.</p>
  <div className="domain-detail-list"><table><thead><tr><th>{hosts?"Полное имя":"Домен"}</th><th>Обращений</th></tr></thead><tbody>{rows.map(([name,count])=><tr key={name}><td>{hosts?name:<button type="button" className="domain-link" onClick={()=>setDomain(name)}>{name}</button>}</td><td>{count.toLocaleString()}</td></tr>)}</tbody></table></div>
 </dialog>;
}

export function DomainChart({records}:{records:any[]}) {
 const groups=useMemo(()=>groupDomainRecords(records),[records]);
 const [details,setDetails]=useState<{groups:DomainGroup[];domain:string|null;opener:HTMLButtonElement}|null>(null);
 const entries:[string,number][]=groups.slice(0,10).map(g=>[g.domain,g.count]);
 if(groups.length>10)entries.push(["Остальные",groups.slice(10).reduce((sum,g)=>sum+g.count,0)]);
 const total=entries.reduce((sum,d)=>sum+d[1],0);
 let offset=0;
 const slices=entries.map(([domain,count],i)=>{
  const start=offset;offset+=count/total*100;
  return {domain,count,color:colors[i],percent:count/total*100,gradient:`${colors[i]} ${start}% ${offset}%`};
 });
 return <>{!total?<Empty>Домены за выбранный период не определены</Empty>:<div className="domain-chart">
  <div className="domain-donut" role="img" aria-label={`Обращения к доменам: ${total}`} style={{background:`conic-gradient(${slices.map(s=>s.gradient).join(",")})`}}>
   <div><strong>{total.toLocaleString()}</strong><span>обращений</span></div>
  </div>
  <ul className="domain-legend" aria-label="Домены">{slices.map((s,i)=><li key={s.domain} title={`${s.domain}: ${s.count} обращений (${s.percent.toFixed(1)}%)`}>
   <i style={{background:s.color}}/><button type="button" className="domain-link" aria-haspopup="dialog" onClick={e=>setDetails({opener:e.currentTarget,groups:i===10?groups.slice(10):[groups[i]],domain:i===10?null:s.domain})}>{s.domain}</button><b>{s.count.toLocaleString()}</b><small>{s.percent.toFixed(1)}%</small>
  </li>)}</ul>
 </div>}
 {details&&<DomainDetails groups={details.groups} initialDomain={details.domain} onClose={()=>{details.opener.focus();setDetails(null)}}/>}
 </>;
}
