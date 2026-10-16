import { SectionLink } from "../permissions";
import { interfaceDisplay } from "../interfaceDisplay";
import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Notice, Empty, TableWrap } from "../ui";

function origin(comment: string, sources: Record<string,string>): [string,string] | null {
 if (comment.startsWith("NAT аплинка")) return ["Аплинк → NAT", "network"];
 if (comment.startsWith("NAT канала")) return ["Интернет-канал → NAT", "channels"];
 if (comment.startsWith("SOCKS5:")) return ["SOCKS5 → Доступ", "services"];
 if (comment.startsWith("VPN-сервер")) return ["VPN → Настройки сервера", "vpn-servers"];
 if (comment === "intersegment default") return ["Защита сети → Обмен между сегментами", "firewall"];
 if (comment === "политика зоны") return ["Защита сети → Политика зоны", "firewall"];
 if (comment.startsWith("изоляция:") || comment.startsWith("изоляция «")) return ["Изоляция локальной или VPN-сети", ""];
 if (sources[comment] === "network") return ["Аплинк → NAT", "network"];
 if (sources[comment]) return ["Сохранённое правило", sources[comment]];
 return null;
}
const actions: Record<string, string> = {ACCEPT:"Пропустить", DROP:"Отбросить молча", REJECT:"Отклонить с ответом", RETURN:"Вернуться в вызывающую цепочку", LOG:"Записать в журнал", NFLOG:"Записать в журнал", MASQUERADE:"Подменить адрес источника", SNAT:"Подменить адрес источника", DNAT:"Перенаправить", REDIRECT:"Направить на роутер", TCPMSS:"Ограничить MSS", MARK:"Установить метку", CONNMARK:"Метка соединения", NOTRACK:"Не отслеживать соединение"};
const tableNames: Record<string,string> = {filter:"Фильтрация", nat:"Подмена адресов", mangle:"Обработка пакетов", raw:"До отслеживания соединений", security:"Политики безопасности"};
function chainTitle(name:string, config:any):string {
 const base:Record<string,string>={INPUT:"Input · трафик к роутеру",FORWARD:"Forward · транзит через роутер",OUTPUT:"Output · трафик самого роутера",PREROUTING:"До выбора маршрута",POSTROUTING:"После выбора маршрута"};
 if(base[name])return base[name];
 const m=name.match(/^(.*)-(IN|FWD|OUT)$/);
 if(!m)return "Дополнительная цепочка";
 const zone=(config.firewall?.zones || []).find((z:any)=>z.name.toUpperCase()===m[1]);
 return `${zone?.title || m[1]} · ${{IN:"к роутеру",FWD:"транзит",OUT:"от роутера"}[m[2]]}`;
}
// Read the actual command, not the current draft. Unknown conditions remain available verbatim.
function describe(line:string, config:any) {
 const tokens=(line.match(/"(?:\\.|[^"\\])*"|\S+/g)||[]).map(v=>{try{return v.startsWith('"')?JSON.parse(v):v}catch{return v}});
 const value=(flag:string)=>{const i=tokens.indexOf(flag);return i<0?"":`${tokens[i-1]==="!"?"не ":""}${tokens[i+1] || ""}`};
 const iface=(name:string)=>name.startsWith("не ") ? `не ${interfaceDisplay(config,name.slice(3))}` : interfaceDisplay(config,name);
 const parts:string[]=[];
 for(const [flag,label] of [["-i","вход"],["-o","выход"],["-s","от"],["-d","к"],["-p","протокол"],["--sport","порт источника"],["--sports","порты источника"],["--dport","порт назначения"],["--dports","порты назначения"],["--ctstate","состояние"],["--state","состояние"],["--mac-source","MAC"],["--set-mss","MSS"],["--mark","метка"],["--to-destination","перенаправить на"],["--to-source","адрес источника"],["--to-ports","на порт"]]) {
  const v=value(flag);if(v)parts.push(`${label}: ${flag==="-i"||flag==="-o"?iface(v):v}`);
 }
 if(tokens.includes("--clamp-mss-to-pmtu"))parts.push("MSS по MTU пути");
 const target=value("-j") || value("-g");
 return {target,conditions:parts.join(" · ") || "Условия — в подробностях",action:actions[target] || (target?`Перейти в ${target}`:"Продолжить проверку")};
}
function LiveRule({line,comment,sources,config,onEdit}:{line:string;comment:string;sources:Record<string,string>;config:any;onEdit:()=>void}) {
 const [open,setOpen]=useState(false);
 const source=origin(comment,sources),rule=describe(line,config);
 const title=comment==="intersegment default"?"Запрет между локальными сегментами":comment==="политика зоны"?"Действие по умолчанию для зоны":comment || rule.action;
 return <>
  <tr>
   <td className="live-rule-number" aria-hidden="true">•</td>
   <td><div>{title}</div><div className="faint live-rule-conditions">{rule.conditions}</div>
    <small className="hint">{source ? source[1] ? <SectionLink section={source[1]} onClick={()=>{if(source[1]==="firewall")onEdit()}}>{source[0]}</SectionLink> : source[0] : "Системное правило или правило вне netOS"}</small>
   </td>
   <td><Badge tone={rule.target==="ACCEPT"?"ok":["DROP","REJECT"].includes(rule.target)?"danger":"neutral"}>{rule.action}</Badge></td>
   <td className="live-rule-button"><button className="btn ghost sm" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?"Свернуть":"Подробности"}</button></td>
  </tr>
  {open && <tr><td colSpan={4}><pre className="live-rule-command">{line}</pre></td></tr>}
 </>;
}
export function FirewallLive({ config, onEdit }: { config:any; onEdit: () => void }) {
 const [data,setData]=useState<any>(null),[error,setError]=useState(""),[loading,setLoading]=useState(true),[refresh,setRefresh]=useState(0);
 useEffect(()=>{let alive=true;setLoading(true);setError("");setData(null);
  api.firewallLive().then(d=>{if(alive)setData(d)}).catch(e=>{if(alive)setError(e.message)}).finally(()=>{if(alive)setLoading(false)});
  return()=>{alive=false};
 },[refresh]);
 return <div className="firewall-live">
  <div className="rows-notes row wrap"><span className="hint">Действующие правила в порядке обработки. Только просмотр; изменение порядка недоступно.</span><button className="btn sm" disabled={loading} onClick={()=>setRefresh(n=>n+1)}>Обновить правила</button></div>
  {loading && <p className="rows-notes" role="status">Читаем правила…</p>}
  {error && <Notice tone="danger" title="Не удалось прочитать firewall">{error}</Notice>}
  {data && <p className="hint rows-notes">Снимок: {new Date(data.captured_at).toLocaleString("ru-RU")}. Несохранённые изменения не включены.</p>}
  {data?.families?.map((family:any)=><div key={family.family}>
   {family.error ? <Notice tone="warn" title={`${family.family}: правила недоступны`}>{family.error}</Notice> : family.tables.length===0 ? <Empty>{family.family}: правил нет</Empty> : family.tables.map((table:any)=><div key={table.name}>
    {table.chains.map((chain:any)=><div key={chain.name}>
     <div className="chain-header"><code>{chain.name}</code><span className="faint">{chainTitle(chain.name,config)} · {family.family}{table.name!=="filter"?` · ${tableNames[table.name] || table.name}`:""}{chain.policy!=="-"?` · по умолчанию: ${actions[chain.policy] || chain.policy}`:""}</span></div>
     {chain.rules.length===0 ? <Empty>В цепочке нет правил</Empty> : <TableWrap><table className="rules live-rules"><tbody>
      {chain.rules.map((line:string,index:number)=><LiveRule key={`${index}:${line}`} line={line} comment={data.comments?.[line] || ""} sources={data.sources || {}} config={config} onEdit={onEdit}/>)}
     </tbody></table></TableWrap>}
    </div>)}
   </div>)}
  </div>)}
 </div>;
}
