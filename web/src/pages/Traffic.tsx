import { Cap, Card, Empty, Notice, openOnCreate, Row, Rows, Switch } from "../ui";

type Patch = (mutate: (draft: any) => void) => void;

const QOS_CLASSES: Record<string, string> = { besteffort: "без приоритетов", diffserv3: "3 класса", diffserv4: "4 класса", diffserv8: "8 классов" };

export function TrafficPage({ config, patch }: { config: any; patch: Patch }) {
  const qos = config.qos || { enabled: false, wans: [] };
  const enabledWANs = (config.wans || []).filter((wan: any) => wan.enabled);
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
              if (wan) openOnCreate("qos-" + wan.id);
              if (wan) d.qos.wans.push({ wan: wan.id, upload_kbit: 95000, download_kbit: 95000, diffserv: "diffserv4" });
            })}
          >
            Добавить канал
          </button>
        }
      >
        {(qos.wans || []).length === 0 ? <Empty>Каналы для QoS не настроены</Empty> : (
          <Rows cols={["Канал", "Загрузка, Кбит/с", "Отдача, Кбит/с", "Приоритеты", ""]}>
          {(qos.wans || []).map((item: any, index: number) => (
              <Row
                key={item.wan + index}
                id={"qos-" + item.wan}
                cells={[<strong>{enabledWANs.find((wan: any) => wan.id === item.wan)?.name || item.wan || "не выбран"}</strong>,
                  <span className="mono">{item.download_kbit || 0}</span>, <span className="mono">{item.upload_kbit || 0}</span>,
                  <span className="dim">{QOS_CLASSES[item.diffserv || "diffserv4"]}</span>]}
              >
                <div className="form-grid">
                  <Cap label="Канал"><select aria-label={`Интернет-канал QoS ${index + 1}`} value={item.wan} onChange={(e) => patch((d) => (d.qos.wans[index].wan = e.target.value))}>
                        <option value="">— выберите —</option>
                        {enabledWANs.map((wan: any) => <option key={wan.id} value={wan.id}>{wan.name || wan.id}</option>)}
                      </select></Cap>
                  <Cap label="Отдача, Кбит/с"><input aria-label={`Отдача QoS ${index + 1}, Кбит/с`} type="number" min={64} max={10000000} value={item.upload_kbit || 0} onChange={(e) => patch((d) => (d.qos.wans[index].upload_kbit = Number(e.target.value)))} /></Cap>
                  <Cap label="Загрузка, Кбит/с"><input aria-label={`Загрузка QoS ${index + 1}, Кбит/с`} type="number" min={64} max={10000000} value={item.download_kbit || 0} onChange={(e) => patch((d) => (d.qos.wans[index].download_kbit = Number(e.target.value)))} /></Cap>
                  <Cap label="Приоритеты"><select aria-label={`Приоритеты QoS ${index + 1}`} value={item.diffserv || "diffserv4"} onChange={(e) => patch((d) => (d.qos.wans[index].diffserv = e.target.value))}>
                        <option value="besteffort">Без приоритетов</option>
                        <option value="diffserv3">3 класса</option>
                        <option value="diffserv4">4 класса — рекомендуется</option>
                        <option value="diffserv8">8 классов</option>
                      </select></Cap>
                </div>
                <div className="row-actions end"><button className="btn ghost sm" onClick={() => patch((d) => d.qos.wans.splice(index, 1))}>Убрать</button></div>
              </Row>
          ))}
        </Rows>
        )}
      </Card>

    </>
  );
}
