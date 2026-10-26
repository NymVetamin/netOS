import { useEffect, useState } from "react";
import { api } from "../api";
import { Card, Field, Notice, Switch, Badge } from "../ui";
import { secretInput } from "../secrets";
import { confirmAction } from "../confirm";
import { CopyButton } from "../CopyButton";

const WAN_WARNING = "SOCKS5 не шифрует соединение: логин, пароль и незашифрованные данные могут быть перехвачены. Открытый порт доступен из интернета и может использоваться для подбора пароля и злоупотреблений. Рекомендуется подключаться через VPN и оставить доступ с WAN выключенным.";

export function SocksSection({ config, patch }: { config:any; patch:(fn:(d:any)=>void)=>void }) {
 const p = config.socks || {};
 const [ready,setReady]=useState<boolean|null>(null), [live,setLive]=useState<any>(null);
 const [loaded,setLoaded]=useState(false), [catalogError,setCatalogError]=useState(false);
 const [error,setError]=useState(""), [shown,setShown]=useState<string|null>(null);
 useEffect(()=>{
  const controller=new AbortController();
  let inFlight=false;
  const load=async()=>{
   if(inFlight||controller.signal.aborted)return;
   inFlight=true;
   try {
    const [catalog,status]=await Promise.allSettled([api.componentStatus(["xray"],controller.signal),api.socksStatus(controller.signal)]);
    if(controller.signal.aborted)return;
    setReady(catalog.status==="fulfilled" ? !!catalog.value.installed?.xray : null);
    setCatalogError(catalog.status==="rejected");
    setLive(status.status==="fulfilled"?status.value:null);
    setLoaded(true);
   } finally { inFlight=false; }
  };
  void load();const timer=window.setInterval(load,5000);return()=>{controller.abort();clearInterval(timer)};
 },[]);
 useEffect(()=>setShown(null),[p.enabled,p.password,p.username,p.secrets_set?.password]);
 const edit=(values:any)=>patch(d=>{d.socks={port:1080,channel:"direct",auth:true,networks:[],vpns:[],...d.socks,...values,udp:false}});
 const chosen=!!config.components?.some((c:any)=>c.id==="xray"&&c.installed);
 const defaults=(config.networks||[]).filter((n:any)=>n.enabled).map((n:any)=>n.id);
 const networks=(config.networks||[]).filter((n:any)=>n.enabled);
 const vpns=(config.vpn_servers||[]).filter((v:any)=>v.enabled&&v.type!=="xray");
 const addresses=[...networks.filter((n:any)=>p.networks?.includes(n.id)).map((n:any)=>({name:n.name,address:n.router_address})),
 ...vpns.filter((v:any)=>p.vpns?.includes(v.id)).map((v:any)=>({name:v.name,address:v.subnet}))];
 function select(key:string,id:string,on:boolean){const values=p[key]||[];edit({[key]:on?[...values,id]:values.filter((v:string)=>v!==id)})}
 return <Card title="SOCKS5-прокси" subtitle="Прокси для приложений в локальной сети и VPN · TCP · IPv4"
  actions={<Badge tone={live?.running?"ok":"neutral"}>{!loaded?"проверка состояния…":live===null?"статус недоступен":live.running?"работает":live.enabled?"не запущен":"отключён"}</Badge>}>
  <div className="stack">
  {error&&<Notice tone="danger" title={error}/>}
  {catalogError&&<Notice tone="warn" title="Не удалось проверить компонент Xray">Повторная проверка выполняется автоматически.</Notice>}
  {(!chosen||ready===false)&&<Notice tone="info" title="Нужен компонент Xray">
   {!chosen?<button className="btn" onClick={()=>patch(d=>{d.components=d.components||[];const c=d.components.find((v:any)=>v.id==="xray");if(c)c.installed=true;else d.components.push({id:"xray",installed:true})})}>Установить Xray</button>:<span>Примените установку компонента и дождитесь её завершения.</span>}
  </Notice>}
  <Switch label="Включить SOCKS5" checked={!!p.enabled} disabled={!p.enabled&&(!ready||!chosen)} onChange={async enabled=>{
   if(enabled && p.allow_wan && !(await confirmAction(WAN_WARNING,"Открыть SOCKS5 в интернет")))return;
   edit({enabled,...(!p.port?{port:1080,auth:true,channel:"direct",networks:defaults}: {})});
  }}/>
  {p.enabled && <>
  <div className="form-grid">
   <Field label="Порт SOCKS5"><input type="number" min={1024} max={65535} value={p.port||1080} onChange={e=>edit({port:Number(e.target.value)})}/></Field>
   <Field label="Канал выхода прокси"><select value={p.channel||"direct"} onChange={e=>edit({channel:e.target.value})}>{(config.channels||[]).filter((c:any)=>c.enabled).map((c:any)=><option key={c.id} value={c.id}>{c.name||c.id}</option>)}</select></Field>
  </div>
  <p className="hint">Весь трафик прокси использует этот выход и его настройки резервирования. Назначение канала отдельному LAN-клиенту здесь не применяется. Передача UDP и IPv6 назначения не поддерживаются.</p>
  <div className="form-grid">
   <Field label="Локальные сети"><div className="stack">{networks.map((n:any)=><Switch key={n.id} label={n.name||n.id} checked={!!p.networks?.includes(n.id)} onChange={on=>select("networks",n.id,on)}/>)}</div></Field>
   <Field label="VPN-сети"><div className="stack">{vpns.map((v:any)=><Switch key={v.id} label={v.name||v.id} checked={!!p.vpns?.includes(v.id)} onChange={on=>select("vpns",v.id,on)}/>)}</div></Field>
  </div>
  <Switch label="Логин и пароль SOCKS5" checked={p.auth!==false} disabled={!!p.allow_wan} onChange={auth=>edit({auth})}/>
  {p.auth!==false&&<div className="form-grid">
   <Field label="Логин SOCKS5"><input autoComplete="off" value={p.username||""} onChange={e=>edit({username:e.target.value})}/></Field>
   <Field label="Пароль SOCKS5"><input type="password" autoComplete="new-password" {...secretInput(p,"password")} value={p.password||""} onChange={e=>edit({password:e.target.value})}/></Field>
  </div>}
  {p.auth===false&&<Notice tone="warn" title="Без авторизации">Прокси сможет использовать любой клиент выбранных сетей.</Notice>}
  <details className="socks-advanced"><summary>Дополнительные настройки</summary>
   <Switch label="Разрешить SOCKS5 с WAN — небезопасно" checked={!!p.allow_wan} onChange={async on=>{
    if(!on){edit({allow_wan:false});return}
    if(await confirmAction(WAN_WARNING,"Открыть SOCKS5 в интернет"))edit({allow_wan:true,auth:true});
   }}/>
  </details>
  {p.allow_wan&&<Notice tone="danger" title="ОПАСНО: SOCKS5 открыт со стороны интернета">{WAN_WARNING}</Notice>}
  <section className="socks-connection" aria-label="Подключение приложения">
  <h4>Подключение приложения</h4>
  <dl className="socks-connection-list">
  {addresses.map((a:any)=><div className="socks-connection-row" key={a.name+a.address}>
   <dt>{a.name}</dt><dd><code>{a.address?.split("/")[0]}:{p.port||1080}</code><CopyButton iconOnly text={a.address?.split("/")[0]+":"+(p.port||1080)} onError={setError}/></dd>
  </div>)}
  {p.auth!==false&&<>
   <div className="socks-connection-row"><dt>Логин</dt><dd>{p.username?<code>{p.username}</code>:<span className="faint">Не задан</span>}</dd></div>
   <div className="socks-connection-row"><dt>Пароль</dt><dd>
    <code>{shown!==null?(shown||"Не задан"):(p.password||p.secrets_set?.password)?"••••••••":"Не задан"}</code>
    {(p.password||p.secrets_set?.password)&&<button type="button" className="btn ghost sm" onClick={async()=>{if(shown!==null){setShown(null);return}try{const data=await api.socksCredentials();setShown(p.password||data.password);setError("")}catch(e:any){setError(e.message)}}}>{shown===null?"Показать пароль":"Скрыть пароль"}</button>}
    {shown&&<CopyButton iconOnly label="Скопировать пароль" text={shown} onError={setError}/>}
   </dd></div>
  </>}
  </dl>
  {p.allow_wan&&<p className="hint">Для WAN используйте внешний IPv4-адрес роутера и порт {p.port||1080}. Если роутер за NAT, доступ зависит от настроек вышестоящего устройства.</p>}
  </section>
  <p className="hint">Настройки начнут действовать после применения. Для разрешения имён через прокси включите удалённый DNS в приложении.</p>
  </>}
 </div>
 </Card>;
}
