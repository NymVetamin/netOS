import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Notice, Empty } from "../ui";

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
export function FirewallLive({ onEdit }: { onEdit: () => void }) {
 const [data,setData]=useState<any>(null),[error,setError]=useState(""),[loading,setLoading]=useState(true),[refresh,setRefresh]=useState(0);
 useEffect(()=>{let alive=true;setLoading(true);setError("");setData(null);
  api.firewallLive().then(d=>{if(alive)setData(d)}).catch(e=>{if(alive)setError(e.message)}).finally(()=>{if(alive)setLoading(false)});
  return()=>{alive=false};
 },[refresh]);
 return <>
  <div className="row wrap"><p className="hint">Все действующие правила ОС, только просмотр. Для редактирования выключите этот режим.</p><button className="btn sm" disabled={loading} onClick={()=>setRefresh(n=>n+1)}>Обновить правила</button></div>
  {loading && <p role="status">Читаем firewall…</p>}
  {error && <Notice tone="danger" title="Не удалось прочитать firewall">{error}</Notice>}
  {data && <p className="hint">Снимок: {new Date(data.captured_at).toLocaleString("ru-RU")}. Изменения черновика здесь не отображаются.</p>}
  {data?.families?.map((family:any)=><div key={family.family}>
   <h2>{family.family}</h2>
   {family.error ? <Notice tone="danger" title="Правила недоступны">{family.error}</Notice> : family.tables.length===0 ? <Empty>Таблиц нет</Empty> : family.tables.map((table:any)=><Card key={table.name} title={`Таблица ${table.name}`} tight>
    {table.chains.map((chain:any)=><div key={chain.name}>
     <div className="chain-header"><strong>{chain.name}</strong><span className="hint">{chain.policy==="-"?"Пользовательская цепочка":`Политика: ${chain.policy}`} · {chain.rules.length} правил · счётчики {chain.counters}</span></div>
     {chain.rules.length===0 ? <Empty>Цепочка пуста</Empty> : <ol className="live-firewall-rules">
      {chain.rules.map((line:string,index:number)=>{const comment=data.comments?.[line] || "";const source=origin(comment,data.sources || {});
       return <li key={index}><strong>{comment==="intersegment default"?"Запрет между локальными сегментами":comment || "Правило без комментария"}</strong>
        <code style={{display:"block",whiteSpace:"pre-wrap",overflowWrap:"anywhere",margin:"0.4rem 0"}}>{line}</code>
        <small className="hint">{source ? source[1] ? <a href={`#${source[1]}`} onClick={() => { if(source[1] === "firewall") onEdit(); }}>{source[0]}</a> : source[0] : "Источник не определён: системное правило или изменение вне netOS"}</small>
       </li>})}
     </ol>}
    </div>)}
   </Card>)}
  </div>)}
 </>;
}
