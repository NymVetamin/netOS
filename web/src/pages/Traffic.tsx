import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { Badge, Card, Empty, Notice, Switch, TableWrap } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

export function TrafficPage({ config, patch }: { config: any; patch: Patch }) {
  const qos = config.qos || { enabled: false, wans: [] };
  const enabledWANs = (config.wans || []).filter((wan: any) => wan.enabled);
  const ddns = config.ddns || { enabled: false, provider: "duckdns", address_source: "interface", interval: 300 };
  const [ddnsStatus, setDDNSStatus] = useState<any>(null);
  const [ddnsStatusError, setDDNSStatusError] = useState("");

  useEffect(() => {
    let stopped = false;
    let timer: number | undefined;
    let controller: AbortController | undefined;
    const load = () => {
      let retryDelay = 10000;
      controller = new AbortController();
      const timeout = window.setTimeout(() => controller?.abort(), 15000);
      api.ddnsStatus(controller.signal)
        .then((status) => {
          if (!stopped) {
            setDDNSStatus(status);
            setDDNSStatusError("");
          }
        })
        .catch((error) => {
          if (!stopped) {
            retryDelay = 5000;
            setDDNSStatusError(error?.message || "Не удалось получить состояние DDNS");
          }
        })
        .finally(() => {
          window.clearTimeout(timeout);
          if (!stopped) timer = window.setTimeout(load, retryDelay);
        });
    };
    load();
    return () => {
      stopped = true;
      controller?.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, []);

  function toggle(enabled: boolean) {
    patch((draft) => {
      draft.qos = draft.qos || { enabled: false, wans: [] };
      draft.qos.enabled = enabled;
      if (enabled && (!draft.qos.wans || draft.qos.wans.length === 0)) {
        draft.qos.wans = enabledWANs.map((wan: any) => ({
          wan: wan.id,
          upload_kbit: 95000,
          download_kbit: 95000,
          diffserv: "diffserv4",
        }));
      }
    });
  }

  return (
    <>
      <div className="page-head">
        <h1>Скорость и QoS</h1>
        <p>Управление скоростью и задержкой интернет-подключений</p>
      </div>

      <Card title="Умное управление очередью" subtitle="CAKE не даёт загрузкам и резервным копиям повышать задержку для звонков и игр">
        <Switch checked={!!qos.enabled} onChange={toggle} label="Включить QoS" />
        <div style={{ height: ".8rem" }} />
        <Notice tone="info" title="Укажите реальную полезную скорость">
          Для лучшего результата задайте 90–95% скорости тарифа. Значения указываются в Кбит/с: 100 Мбит/с = 100000 Кбит/с.
        </Notice>
      </Card>

      <Card
        title="Интернет-каналы"
        tight
        actions={
          <button
            className="btn sm"
            disabled={enabledWANs.length === (qos.wans || []).length}
            onClick={() => patch((d) => {
              d.qos = d.qos || { enabled: false, wans: [] };
              const used = new Set((d.qos.wans || []).map((item: any) => item.wan));
              const wan = enabledWANs.find((item: any) => !used.has(item.id));
              if (wan) d.qos.wans.push({ wan: wan.id, upload_kbit: 95000, download_kbit: 95000, diffserv: "diffserv4" });
            })}
          >
            Добавить канал
          </button>
        }
      >
        {(qos.wans || []).length === 0 ? <Empty>Каналы для QoS не настроены</Empty> : (
          <TableWrap>
            <table>
              <thead>
                <tr><th>Канал</th><th>Отдача, Кбит/с</th><th>Загрузка, Кбит/с</th><th>Приоритеты</th><th /></tr>
              </thead>
              <tbody>
                {(qos.wans || []).map((item: any, index: number) => (
                  <tr key={item.wan + index}>
                    <td>
                      <select value={item.wan} onChange={(e) => patch((d) => (d.qos.wans[index].wan = e.target.value))}>
                        <option value="">— выберите —</option>
                        {enabledWANs.map((wan: any) => <option key={wan.id} value={wan.id}>{wan.name || wan.id}</option>)}
                      </select>
                    </td>
                    <td><input type="number" min={64} max={10000000} value={item.upload_kbit || 0} onChange={(e) => patch((d) => (d.qos.wans[index].upload_kbit = Number(e.target.value)))} /></td>
                    <td><input type="number" min={64} max={10000000} value={item.download_kbit || 0} onChange={(e) => patch((d) => (d.qos.wans[index].download_kbit = Number(e.target.value)))} /></td>
                    <td>
                      <select value={item.diffserv || "diffserv4"} onChange={(e) => patch((d) => (d.qos.wans[index].diffserv = e.target.value))}>
                        <option value="besteffort">Без приоритетов</option>
                        <option value="diffserv3">3 класса</option>
                        <option value="diffserv4">4 класса — рекомендуется</option>
                        <option value="diffserv8">8 классов</option>
                      </select>
                    </td>
                    <td><button className="btn ghost sm" onClick={() => patch((d) => d.qos.wans.splice(index, 1))}>Убрать</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Card
        title="Динамический DNS"
        subtitle="Автоматически обновляет A-запись при смене внешнего IPv4-адреса"
        actions={ddns.enabled && ddnsStatus?.last_run ? (
          <Badge tone={ddnsStatus.success ? "ok" : "danger"}>
            {ddnsStatus.success ? `обновлено ${formatTime(ddnsStatus.last_run)}` : "ошибка обновления"}
          </Badge>
        ) : undefined}
      >
        <Switch
          checked={!!ddns.enabled}
          onChange={(enabled) => patch((d) => {
            d.ddns = d.ddns || { provider: "duckdns", address_source: "interface", interval: 300 };
            d.ddns.enabled = enabled;
            if (!d.ddns.provider) d.ddns.provider = "duckdns";
            if (!d.ddns.address_source) d.ddns.address_source = "interface";
            if (!d.ddns.interval) d.ddns.interval = 300;
          })}
          label="Включить DDNS"
        />
        {ddns.enabled && (
          <>
            <div style={{ height: "1rem" }} />
            {ddnsStatusError && <Notice tone="warn" title="Состояние DDNS временно недоступно">{ddnsStatusError}</Notice>}
            {ddnsStatus?.message && <Notice tone="danger" title="Последнее обновление не удалось">{ddnsStatus.message}</Notice>}
            {ddnsStatus?.last_run && (
              <div className="hint" style={{ marginBottom: ".8rem" }}>
                {ddnsStatus.address ? `IPv4: ${ddnsStatus.address}. ` : ""}
                Последняя попытка: {formatTime(ddnsStatus.last_run)}.
                {ddnsStatus.next_run ? ` Следующая проверка: ${formatTime(ddnsStatus.next_run)}.` : ""}
              </div>
            )}
            <div className="form-grid">
              <div className="field">
                <label>Провайдер</label>
                <select aria-label="Провайдер DDNS" value={ddns.provider || "duckdns"} onChange={(e) => patch((d) => (d.ddns.provider = e.target.value))}>
                  <option value="duckdns">DuckDNS</option>
                  <option value="cloudflare">Cloudflare</option>
                  <option value="noip">No-IP</option>
                </select>
              </div>
              <div className="field">
                <label>Доменное имя</label>
                <input aria-label="Доменное имя DDNS" type="text" placeholder={ddns.provider === "duckdns" ? "router.duckdns.org" : "router.example.org"} value={ddns.hostname || ""} onChange={(e) => patch((d) => (d.ddns.hostname = e.target.value.trim()))} />
              </div>
              <div className="field">
                <label>Источник адреса</label>
                <select aria-label="Источник адреса DDNS" value={ddns.address_source || "interface"} onChange={(e) => patch((d) => (d.ddns.address_source = e.target.value))}>
                  <option value="interface">Адрес интернет-интерфейса</option>
                  <option value="web">Внешний адрес через веб-сервис</option>
                </select>
                <div className="hint">Веб-сервис нужен, если роутер находится за NAT модема.</div>
              </div>
              {ddns.address_source !== "web" && (
                <div className="field">
                  <label>Интернет-канал</label>
                  <select aria-label="Интернет-канал DDNS" value={ddns.wan || ""} onChange={(e) => patch((d) => (d.ddns.wan = e.target.value))}>
                    <option value="">— выберите —</option>
                    {enabledWANs.map((wan: any) => <option key={wan.id} value={wan.id}>{wan.name || wan.id}</option>)}
                  </select>
                </div>
              )}
              <div className="field">
                <label>Интервал, секунд</label>
                <input aria-label="Интервал DDNS, секунд" type="number" min={60} max={86400} value={ddns.interval || 300} onChange={(e) => patch((d) => (d.ddns.interval = Number(e.target.value)))} />
              </div>
              {(ddns.provider === "duckdns" || ddns.provider === "cloudflare") && (
                <div className="field">
                  <label>API-токен</label>
                  <input aria-label="API-токен DDNS" type="password" autoComplete="off" value={ddns.token || ""} onChange={(e) => patch((d) => (d.ddns.token = e.target.value))} />
                </div>
              )}
              {ddns.provider === "cloudflare" && <>
                <div className="field"><label>Zone ID</label><input aria-label="Cloudflare Zone ID" className="mono" value={ddns.zone_id || ""} onChange={(e) => patch((d) => (d.ddns.zone_id = e.target.value.trim()))} /></div>
                <div className="field"><label>Record ID</label><input aria-label="Cloudflare Record ID" className="mono" value={ddns.record_id || ""} onChange={(e) => patch((d) => (d.ddns.record_id = e.target.value.trim()))} /></div>
              </>}
              {ddns.provider === "noip" && <>
                <div className="field"><label>Имя пользователя</label><input aria-label="Имя пользователя No-IP" autoComplete="username" value={ddns.username || ""} onChange={(e) => patch((d) => (d.ddns.username = e.target.value))} /></div>
                <div className="field"><label>Пароль</label><input aria-label="Пароль No-IP" type="password" autoComplete="new-password" value={ddns.password || ""} onChange={(e) => patch((d) => (d.ddns.password = e.target.value))} /></div>
              </>}
            </div>
          </>
        )}
      </Card>
    </>
  );
}
