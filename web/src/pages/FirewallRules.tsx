import { SectionLink } from "../permissions";
import { interfaceDisplay } from "../interfaceDisplay";


import { Badge, Switch } from "../ui";

function origin(comment: string, sources: Record<string,string>): [string,string] | null {
 if (comment.startsWith("NAT аплинка")) return ["Аплинк → NAT", "network"];
 if (comment.startsWith("NAT канала")) return ["Интернет-канал → NAT", "channels"];
 if (comment.startsWith("ACME")) return ["Система → Сертификат панели", "system"];
 if (/samba|SMB|обнаружение Windows/i.test(comment)) return ["Диски и файлы → Файловый сервер", "storage"];
 if (/DNS/i.test(comment)) return ["Сетевые службы → DNS", "services"];
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
// Describe the generator command; preserve its full text in the row tooltip.
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
 return {target,conditions:parts.join(" · ") || "Условия — в подсказке при наведении",action:actions[target] || (target?`Перейти в ${target}`:"Продолжить проверку")};
}

export type RuleGroup = {key:string; chain:string; description:string; items:{r:any;i:number;automatic?:boolean}[]};

// Match by generator IDs, never by comments/names. Keep disabled and draft-only
// rows in place, and retain the same group/row keys when the checkbox changes.
export function includeAutomatic(groups:RuleGroup[], data:any, config:any):RuleGroup[] {
 const result=groups.map(g=>({...g,items:[...g.items]}));
 const ids:Record<string,string[]> = Object.fromEntries(Object.entries(data.rule_ids || {}).map(([line,values])=>[line,[...(values as string[])]]));
 for(const family of data.families || []) for(const table of family.tables || []) for(const chain of table.chains || []) {
  const primary=family.family==='IPv4' && table.name==='filter';
  let group=primary ? result.find(g=>g.chain===chain.name) : undefined;
  if(!group) {
   if(!chain.rules.length)continue;
   group={key:`auto:${family.family}:${table.name}:${chain.name}`,chain:chain.name,description:`${chainTitle(chain.name,config)} · ${family.family}${table.name==='filter'?'':` · ${tableNames[table.name] || table.name}`}`,items:[]};
   result.push(group);
  }
  let pending:RuleGroup['items']=[];
  const seen=new Set<string>();
  chain.rules.forEach((line:string,index:number)=>{
   const id=family.family==='IPv4' ? ids[line]?.shift() : undefined;
   if(id && group!.items.some(item=>!item.automatic && item.r.id===id)) {
    if(!seen.has(id)) {
     const at=group!.items.findIndex(item=>!item.automatic && item.r.id===id);
     group!.items.splice(at,0,...pending);pending=[];seen.add(id);
    }
    return;
   }
   const match=line.match(/--comment\s+("(?:\\.|[^"\\])*"|\S+)/);
   let comment=match?.[1] || '';
   if(comment.startsWith('"')) {try{comment=JSON.parse(comment)}catch{}}
   pending.push({i:-1,automatic:true,r:{id:`auto:${family.family}:${table.name}:${chain.name}:${index}`,line,comment}});
  });
  group.items.push(...pending);
 }
 return result;
}

export function AutomaticRuleRow({rule,config}:{rule:any;config:any}) {
 const detail=describe(rule.line,config);
 const source=origin(rule.comment,{}) || (["LOG","NFLOG"].includes(detail.target) ? ["Защита сети → Журналирование правила", "firewall"] : detail.target === "TCPMSS" ? ["Защита сети → Подгонка размера пакетов", "firewall"] : null);
 const title=rule.comment==='intersegment default'?'Запрет между локальными сегментами':rule.comment==='политика зоны'?'Действие по умолчанию для зоны':rule.comment || detail.action;
 return <tr className="automatic-rule" title={rule.line}>
  <td style={{width:24,paddingRight:0}} />
  <td style={{width:46}}><Switch checked disabled label="" ariaLabel={`Автоматическое правило ${title}`} onChange={()=>{}} /></td>
  <td><div>{title}</div><div className="row rule-metadata"><Badge tone="neutral">автоматически</Badge><span className="mono faint">{detail.conditions}</span></div>
   <small className="faint">{source ? source[1] ? <SectionLink section={source[1]}>{source[0]}</SectionLink> : source[0] : detail.target.endsWith('-IN') || detail.target.endsWith('-FWD') || detail.target.endsWith('-OUT') ? 'Защита сети → Интерфейсы зоны' : 'Сформировано netOS из настроек сети'}</small>
  </td>
  <td style={{width:170}}><Badge tone={detail.target==='ACCEPT'?'ok':['DROP','REJECT'].includes(detail.target)?'danger':'neutral'}>{detail.action}</Badge></td>
  <td style={{width:210}} />
 </tr>;
}
