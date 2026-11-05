import { useEffect, useRef, useState } from "react";
import { api, ApiError, DiagnosticJob, formatBitrate } from "../api";
import { useAccess } from "../permissions";
import { Badge, Card, Empty, Field, NeedComponent, Notice, TableWrap } from "../ui";

export const DIAGNOSTIC_TOOLS = [
  {id: "ping", label: "Ping", description: "Доступность узла, задержка и потери пакетов."},
  {id: "trace", label: "Traceroute / MTR", description: "Маршрут до узла; MTR собирает потери и задержки по переходам за пять проходов."},
  {id: "dns", label: "DNS", description: "Запрос DNS с роутера через системный или указанный резолвер."},
  {id: "capture", label: "Захват пакетов", description: "Захват на выбранном интерфейсе с выгрузкой PCAP для Wireshark."},
  {id: "torch", label: "Torch", description: "Потоки IPv4 на интерфейсе: адреса, порты, пакеты и средняя скорость за время наблюдения."},
  {id: "iperf", label: "iPerf3", description: "Проверка пропускной способности между роутером и другим узлом с iPerf3."},
  {id: "connections", label: "Соединения", description: "TCP/UDP-сокеты и слушающие порты самого роутера. Транзитные соединения смотрите в Torch."},
  {id: "route", label: "Поиск маршрута", description: "Какой маршрут, интерфейс и исходный адрес ядро выберет для указанного IPv4."},
] as const;
type Tool = typeof DIAGNOSTIC_TOOLS[number];
type Capabilities = Awaited<ReturnType<typeof api.diagnosticTools>>;
const active = (job: DiagnosticJob | null) => !!job && ["running", "stopping"].includes(job.state);
const stateLabels: Record<string, string> = {running:"Выполняется", stopping:"Остановка…", stopped:"Остановлено", done:"Завершено", timeout:"Время истекло", error:"Ошибка"};

export function DiagnosticTool({tool, capabilities, refresh}: {tool: Tool; capabilities: Capabilities; refresh: () => void}) {
  const can = useAccess();
  const [kind, setKind] = useState(tool.id === "trace" ? "traceroute" : tool.id as string);
  const [host, setHost] = useState("");
  const [iface, setIface] = useState("");
  const [duration, setDuration] = useState(10);
  const [count, setCount] = useState(tool.id === "ping" ? 5 : 10000);
  const [size, setSize] = useState(tool.id === "ping" ? 56 : 256);
  const [ttl, setTTL] = useState(30);
  const [filter, setFilter] = useState("");
  const [dnsServer, setDNSServer] = useState("");
  const [queryType, setQueryType] = useState("A");
  const [mode, setMode] = useState("client");
  const [bind, setBind] = useState("");
  const [port, setPort] = useState(5201);
  const [mbps, setMbps] = useState(100);
  const [udp, setUDP] = useState(false);
  const [reverse, setReverse] = useState(false);
  const [job, setJob] = useState<DiagnosticJob | null>(null);
  const [starting, setStarting] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");
  const mounted = useRef(false);
  const current = useRef<string | null>(null);
  const pending = starting || active(job);
  const capture = tool.id === "capture" || tool.id === "torch";
  const available = capabilities.available[kind];

  // Leaving a tool stops its process. A late POST response is also cancelled.
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; if (current.current) void api.diagnosticStop(current.current).catch(() => {}); };
  }, []);
  useEffect(() => {
    if (!job || !active(job)) return;
    let disposed = false;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = await api.diagnosticJob(job.id, abort.signal);
        if (disposed) return;
        setJob(result); setError("");
        if (!active(result)) { current.current = null; return; }
      } catch (e) {
        if (disposed) return;
        setError(e instanceof Error ? e.message : "Не удалось обновить результат");
        if (e instanceof ApiError && [401,403,404].includes(e.status)) {
          current.current = null;
          setJob(j => j ? {...j, state:"error"} : j);
          return;
        }
      }
      if (!disposed) timer = setTimeout(poll, 1000);
    };
    void poll();
    return () => { disposed = true; abort.abort(); clearTimeout(timer); };
  }, [job?.id, job?.state]);

  async function start() {
    setStarting(true); setError(""); setJob(null);
    try {
      const result = await api.diagnosticStart({kind, host:host.trim(), interface:iface, duration, count, size, ttl, filter, dns_server:dnsServer.trim(), query_type:queryType, mode, bind, port, mbps, udp, reverse});
      if (!mounted.current) { await api.diagnosticStop(result.id); return; }
      current.current = result.id;
      setJob({id:result.id, kind, state:"running", output:"", error:"", elapsed:0, truncated:false, capture_bytes:0});
    } catch (e) { if (mounted.current) setError(e instanceof Error ? e.message : "Не удалось запустить инструмент"); }
    finally { if (mounted.current) setStarting(false); }
  }
  async function stop() {
    if (!current.current) return;
    try { await api.diagnosticStop(current.current); setJob(j => j ? {...j, state:"stopping"} : j); }
    catch (e) { setError(e instanceof Error ? e.message : "Не удалось остановить запуск"); }
  }
  function save(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = filename; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function downloadCapture() {
    if (!job) return;
    setDownloading(true); setError("");
    try { save(await api.diagnosticCapture(job.id), `netos-${job.id}.pcap`); }
    catch (e) { if (mounted.current) setError(e instanceof Error ? e.message : "Не удалось скачать захват"); }
    finally { if (mounted.current) setDownloading(false); }
  }
  const numeric = (label: string, value: number, change: (n: number) => void, min: number, max: number) => <Field label={label}><input type="number" min={min} max={max} required value={value} onChange={e => change(e.target.valueAsNumber)} /></Field>;
  return <Card title={tool.label}>
    <p className="hint">{tool.description}</p>
    {!can("diagnostics", true) && <Notice tone="info" title="Режим просмотра">Для запуска инструментов нужны права управления диагностикой.</Notice>}
    {!available && <><NeedComponent name={tool.id === "iperf" ? "iPerf3" : "Инструменты диагностики"} effect="Утилита не найдена на роутере" /><button className="btn sm" onClick={refresh}>Проверить после установки</button></>}
    <form onSubmit={e => { e.preventDefault(); if (!pending && available && can("diagnostics", true)) void start(); }}>
      <fieldset disabled={pending || !can("diagnostics", true)} style={{border:0, padding:0, margin:0, minWidth:0}}>
        <div className="form-grid">
          {tool.id === "trace" && <Field label="Инструмент"><select value={kind} onChange={e => setKind(e.target.value)}><option value="traceroute">Traceroute</option><option value="mtr">MTR</option></select></Field>}
          {(["ping","trace","dns","route"].includes(tool.id) || (tool.id === "iperf" && mode === "client")) && <Field label={tool.id === "dns" ? "Имя для запроса" : "Адрес назначения"}><input required maxLength={253} value={host} placeholder={tool.id === "route" ? "192.0.2.1" : "IP-адрес или имя узла"} onChange={e => setHost(e.target.value)} /></Field>}
          {(["ping","trace"].includes(tool.id) || capture) && <Field label="Интерфейс"><select required={capture} value={iface} onChange={e => setIface(e.target.value)}><option value="">{capture ? "Выберите интерфейс" : "Автоматически"}</option>{capabilities.interfaces.map(i => <option key={i.name} value={i.name}>{i.name}{i.addresses.length ? ` · ${i.addresses.join(", ")}` : ""}</option>)}</select></Field>}
          {tool.id === "ping" && <>{numeric("Количество пакетов",count,setCount,1,30)}{numeric("Размер данных, байт",size,setSize,16,1472)}</>}
          {tool.id === "trace" && numeric("Максимальный TTL",ttl,setTTL,1,64)}
          {tool.id === "dns" && <>
            <Field label="DNS-сервер" hint="Пусто — системный резолвер роутера"><input value={dnsServer} onChange={e => setDNSServer(e.target.value)} placeholder="IP-адрес" /></Field>
            <Field label="Тип записи"><select value={queryType} onChange={e => setQueryType(e.target.value)}>{["A","AAAA","MX","NS","TXT","SOA","CNAME","PTR"].map(q => <option key={q}>{q}</option>)}</select></Field>
          </>}
          {(capture || tool.id === "iperf") && numeric(mode === "server" && tool.id === "iperf" ? "Время работы сервера, с" : "Длительность, с",duration,setDuration,1,60)}
          {capture && <>
            <Field label="Фильтр BPF" hint="Например: host 192.0.2.10 and port 443; пусто — весь трафик"><input maxLength={256} value={filter} onChange={e => setFilter(e.target.value)} /></Field>
            {numeric("Лимит пакетов",count,setCount,1,10000)}
            {tool.id === "capture" && numeric("Сохранять байт из пакета",size,setSize,64,65535)}
          </>}
          {tool.id === "iperf" && <>
            <Field label="Режим"><select value={mode} onChange={e => setMode(e.target.value)}><option value="client">Клиент</option><option value="server">Временный сервер</option></select></Field>
            <Field label="Локальный адрес"><select required={mode === "server"} value={bind} onChange={e => setBind(e.target.value)}><option value="">{mode === "server" ? "Выберите адрес" : "Автоматически"}</option>{capabilities.interfaces.flatMap(i => i.addresses.map(a => <option key={`${i.name}-${a}`} value={a}>{a} · {i.name}</option>))}</select></Field>
            {numeric("Порт",port,setPort,1024,65535)}
            {mode === "client" && <>
              {numeric("Целевая скорость, Мбит/с",mbps,setMbps,1,10000)}
              <Field label="Протокол"><select value={udp ? "udp" : "tcp"} onChange={e => setUDP(e.target.value === "udp")}><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field>
              <Field label="Направление"><select value={reverse ? "reverse" : "forward"} onChange={e => setReverse(e.target.value === "reverse")}><option value="forward">Роутер → сервер</option><option value="reverse">Сервер → роутер</option></select></Field>
            </>}
          </>}
        </div>
      </fieldset>
      {tool.id === "iperf" && <p className="hint">Тест создаёт сетевую нагрузку. {mode === "server" ? "Сервер принимает один тест и работает только указанное время. Правила firewall не меняются; клиенту должен быть разрешён доступ к выбранному порту." : "На другой стороне должен работать сервер iPerf3. Скорость задаётся для всего теста."}</p>}
      {capture && <p className="hint">Захват остановится по времени или лимиту пакетов{tool.id === "capture" ? ", либо при достижении 8 МиБ" : ""}. При выходе из вкладки запуск останавливается.</p>}
      <div className="row wrap" style={{gap:"0.5rem", marginTop:"1rem"}}>
        <button className="btn primary" type="submit" disabled={pending || !available || !can("diagnostics", true)}>{starting ? "Запуск…" : "Запустить"}</button>
        {active(job) && <button type="button" className="btn" onClick={() => void stop()} disabled={job?.state === "stopping"}>Остановить</button>}
        {job && <Badge>{stateLabels[job.state] || job.state} · {Math.round(job.elapsed)} с</Badge>}
      </div>
    </form>
    {error && <Notice tone="danger" title="Ошибка диагностики">{error}{active(job) && " Результат может быть устаревшим; повторяем запрос автоматически."}</Notice>}
    {job?.error && <Notice tone="danger" title="Запуск завершён с ошибкой">{job.error}</Notice>}
    {job?.truncated && <Notice tone="warn" title="Достигнут лимит результата">Сохранён ограниченный объём данных.</Notice>}
    {job?.output && <pre className="output" style={{maxHeight:"32rem", overflow:"auto"}}>{job.output}</pre>}
    {job?.output && <button className="btn sm" onClick={() => save(new Blob([job.output], {type:"text/plain;charset=utf-8"}), `netos-${job.kind}.txt`)}>Скачать результат</button>}
    {job?.kind === "capture" && !active(job) && job.capture_bytes >= 24 && <button className="btn" disabled={downloading} onClick={() => void downloadCapture()}>Скачать PCAP ({Math.round(job.capture_bytes / 1024)} КиБ)</button>}
    {job?.torch && <>
      <p className="hint">Пакетов: {job.torch.packets} · Потоков: {job.torch.total_flows} · Пропущено: {job.torch.skipped}. До 200 крупнейших потоков; скорость средняя с начала запуска. IPv6, не-IP и потоки сверх лимита 2048 не учитываются.</p>
      {job.torch.flows.length === 0 ? <Empty>Подходящих пакетов пока нет</Empty> : <TableWrap><table><thead><tr><th>Источник</th><th>Назначение</th><th>Протокол</th><th>Пакеты</th><th>Байты</th><th>Средняя скорость</th></tr></thead><tbody>{job.torch.flows.map((f,i) => <tr key={i}><td className="mono">{f.source}{f.source_port ? `:${f.source_port}` : ""}</td><td className="mono">{f.destination}{f.destination_port ? `:${f.destination_port}` : ""}</td><td>{f.protocol}</td><td>{f.packets}</td><td>{f.bytes}</td><td>{formatBitrate(f.bitrate)}</td></tr>)}</tbody></table></TableWrap>}
    </>}
    {job && !active(job) && <p className="hint">Результат доступен до 5 минут или до вытеснения новыми запусками. При необходимости сохраните его сейчас.</p>}
  </Card>;
}
