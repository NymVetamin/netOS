import { useEffect, useState } from "react";
import { api, formatTime } from "../api";
import { Badge, Card, Notice, Switch } from "../ui";
import { secretInput } from "../secrets";

type Patch = (mutate: (draft: any) => void) => void;

export function DDNSSection({ config, patch }: { config: any; patch: Patch }) {
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

  return (
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
              <div className="ddns-status hint">
                {ddnsStatus.address && <span>IPv4: {ddnsStatus.address}</span>}
                <span>Последняя попытка: {formatTime(ddnsStatus.last_run)}</span>
                {ddnsStatus.next_run && <span>Следующая проверка: {formatTime(ddnsStatus.next_run)}</span>}
              </div>
            )}
            <div className="ddns-grid">
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
                  <option value="interface">Интернет-интерфейс</option>
                  <option value="web">Веб-сервис</option>
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
                  <input aria-label="API-токен DDNS" type="password" autoComplete="off" {...secretInput(ddns, "token")} value={ddns.token || ""} onChange={(e) => patch((d) => (d.ddns.token = e.target.value))} />
                </div>
              )}
              {ddns.provider === "cloudflare" && <>
                <div className="field"><label>Zone ID</label><input aria-label="Cloudflare Zone ID" className="mono" value={ddns.zone_id || ""} onChange={(e) => patch((d) => (d.ddns.zone_id = e.target.value.trim()))} /></div>
                <div className="field"><label>Record ID</label><input aria-label="Cloudflare Record ID" className="mono" value={ddns.record_id || ""} onChange={(e) => patch((d) => (d.ddns.record_id = e.target.value.trim()))} /></div>
              </>}
              {ddns.provider === "noip" && <>
                <div className="field"><label>Имя пользователя</label><input aria-label="Имя пользователя No-IP" autoComplete="username" value={ddns.username || ""} onChange={(e) => patch((d) => (d.ddns.username = e.target.value))} /></div>
                <div className="field"><label>Пароль</label><input aria-label="Пароль No-IP" type="password" autoComplete="new-password" {...secretInput(ddns, "password")} value={ddns.password || ""} onChange={(e) => patch((d) => (d.ddns.password = e.target.value))} /></div>
              </>}
            </div>
          </>
        )}
      </Card>
  );
}
