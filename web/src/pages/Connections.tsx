import { useEffect, useRef, useState } from "react";
import { api, ConnectionRow } from "../api";
import { Card, Empty, Field, Notice, TableWrap } from "../ui";

const endpoint = (value: {address: string; port?: string}) => value.address ? `${value.address.includes(":") ? `[${value.address}]` : value.address}${value.port ? `:${value.port}` : ""}` : "—";
const counters = (forward?: number, reply?: number) => `${forward == null ? "—" : forward.toLocaleString()} / ${reply == null ? "—" : reply.toLocaleString()}`;

export function Connections() {
  const [source, setSource] = useState("tracked");
  const [address, setAddress] = useState("");
  const [ports, setPorts] = useState("");
  const [protocol, setProtocol] = useState("");
  const [state, setState] = useState("");
  const [side, setSide] = useState("either");
  const [nat, setNAT] = useState("");
  const [page, setPage] = useState(0);
  const [paused, setPaused] = useState(false);
  const [visible, setVisible] = useState(!document.hidden);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<Awaited<ReturnType<typeof api.connections>> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const lastQuery = useRef("");
  const query = new URLSearchParams({source, address:address.trim(), ports:ports.trim(), protocol, state:state.trim(), side, nat:source === "tracked" ? nat : "", page:String(page)}).toString();
  useEffect(() => {const onVisibility = () => setVisible(!document.hidden); document.addEventListener("visibilitychange", onVisibility); return () => document.removeEventListener("visibilitychange", onVisibility);}, []);
  useEffect(() => {
    if (!visible) return;
    let disposed = false;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    if (lastQuery.current !== query) {setData(null); setLoading(true); lastQuery.current = query;}
    const load = async () => {
      try {
        const result = await api.connections(query, abort.signal);
        if (disposed) return;
        setData(result); setError("");
        const maxPage = Math.max(0, Math.ceil(result.total / 100) - 1);
        if (page > maxPage) {setPage(maxPage); return;}
      } catch (e) {
        if (disposed) return;
        setError(e instanceof Error ? e.message : "Не удалось прочитать соединения");
      } finally {if (!disposed) setLoading(false);}
      // Schedule only after completion: requests never overlap.
      if (!disposed && !paused) timer = setTimeout(load, 1000);
    };
    timer = setTimeout(load, 300);
    return () => {disposed = true; abort.abort(); clearTimeout(timer);};
  }, [query, page, paused, refresh, visible]);
  const change = (setter: (value: string) => void) => (value: string) => {setter(value); setPage(0);};
  const rows: ConnectionRow[] = data?.rows || [];
  return <Card title="Соединения">
    <div className="form-grid">
      <Field label="Показывать"><select value={source} onChange={e => {change(setSource)(e.target.value); setProtocol(""); setState("");}}><option value="tracked">Отслеживаемые соединения, включая транзит</option><option value="local">Сокеты самого роутера</option></select></Field>
      <Field label="IP-адрес или подсеть"><input value={address} onChange={e => change(setAddress)(e.target.value)} placeholder="192.168.1.10 или 192.168.1.0/24" /></Field>
      <Field label="Порты" hint="Например: 53,443,8000-8100"><input value={ports} onChange={e => change(setPorts)(e.target.value)} /></Field>
      <Field label="Протокол"><select value={protocol} onChange={e => change(setProtocol)(e.target.value)}><option value="">Любой</option>{["TCP","UDP",...(source === "tracked" ? ["ICMP","ICMPV6","GRE","ESP"] : [])].map(p => <option key={p}>{p}</option>)}</select></Field>
      <Field label="Сторона фильтра"><select value={side} onChange={e => change(setSide)(e.target.value)}><option value="either">{source === "tracked" ? "Любая, включая адрес после NAT" : "Любая"}</option><option value="src">Исходный отправитель</option><option value="dst">Исходный получатель</option></select></Field>
      <Field label="Состояние"><input value={state} onChange={e => change(setState)(e.target.value)} placeholder="Например, ESTABLISHED" /></Field>
      {source === "tracked" && <Field label="NAT"><select value={nat} onChange={e => change(setNAT)(e.target.value)}><option value="">Любой</option><option value="yes">Есть NAT</option><option value="no">Без NAT</option><option value="SNAT">SNAT</option><option value="DNAT">DNAT</option></select></Field>}
    </div>
    <div className="row wrap" style={{marginTop:"1rem", gap:".5rem"}}>
      <button className="btn" onClick={() => setPaused(p => !p)}>{paused ? "Продолжить обновление" : "Приостановить обновление"}</button>
      <button className="btn" onClick={() => setRefresh(n => n + 1)}>Обновить сейчас</button>
      <span className="hint">{paused ? "Автообновление на паузе" : "Обновление каждую секунду"}{data && ` · ${new Date(data.updated).toLocaleTimeString()} · Найдено: ${data.total}`}</span>
    </div>
    {source === "tracked" && <p className="hint">Соединения из таблицы conntrack IPv4/IPv6. Пакеты и байты показаны как «прямое / ответное направление»; «—» означает, что ядро не предоставляет счётчик. Записи, исключённые из conntrack, здесь не отображаются.</p>}
    {source === "local" && <p className="hint">TCP/UDP-сокеты процессов роутера, включая слушающие порты. Это отдельный список от транзитных соединений.</p>}
    {error && <Notice tone="danger" title="Не удалось обновить соединения">{error}{data && " Показан последний успешный снимок; данные устарели."}</Notice>}
    {!!data?.unparsed && <Notice tone="warn" title="Часть записей не распознана">{data.unparsed} из {data.scanned}. Таблица может быть неполной.</Notice>}
    {loading && !data ? <Empty>Загрузка соединений…</Empty> : !data ? null : rows.length === 0 ? <Empty>Соединений по выбранным фильтрам нет</Empty> : <TableWrap><table>
      <thead><tr><th>Протокол</th><th>Состояние</th><th>Источник</th><th>Назначение</th>{source === "tracked" ? <><th>NAT / ответное направление</th><th>Осталось, с</th><th>Пакеты → / ←</th><th>Байты → / ←</th></> : <th>Процесс</th>}</tr></thead>
      <tbody>{rows.map((row,i) => <tr key={i}><td>{row.protocol}</td><td>{row.state}</td><td className="mono">{endpoint(row.source)}</td><td className="mono">{endpoint(row.destination)}</td>{source === "tracked" ? <><td>{row.nat || "—"}<div className="hint mono">{endpoint(row.reply_source)} → {endpoint(row.reply_destination)}</div></td><td>{row.timeout ?? "—"}</td><td>{counters(row.packets,row.reply_packets)}</td><td>{counters(row.bytes,row.reply_bytes)}</td></> : <td>{row.process || "—"}</td>}</tr>)}</tbody>
    </table></TableWrap>}
    {data && <div className="row wrap" style={{marginTop:".75rem",gap:".5rem"}}><button className="btn sm" disabled={page===0} onClick={() => setPage(p => p-1)}>Назад</button><span>Страница {page+1} из {Math.max(1,Math.ceil(data.total/100))}</span><button className="btn sm" disabled={(page+1)*100>=data.total} onClick={() => setPage(p => p+1)}>Далее</button></div>}
  </Card>;
}
