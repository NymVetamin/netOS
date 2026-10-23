import { useState } from 'react';
import { Cap } from './ui';
import { newID } from './id';
import { reservationError, reservationHostname, reservationNetwork } from './clientReservation';

export function ReservationEditor({ config, client, reservation, devices, patch }: any) {
  const [ip, setIP] = useState(reservation?.ip || client.ip || '');
  const network = reservationNetwork(config, client);
  const segment = (config.networks || []).find((n: any) => n.id === network);
  const error = reservationError(config, client.mac, ip, network, devices);
  const enabled = !!reservation?.enabled;
  return <div className="client-reservation">
    <strong>Закрепление адреса DHCP</strong>
    <div className="client-reservation-controls">
      <Cap label="Закреплённый IPv4-адрес"><input aria-label="Закреплённый IPv4-адрес" className="mono" value={ip}
        aria-invalid={!!error} onChange={e => setIP(e.target.value.trim())} /></Cap>
    <div className="client-reservation-actions">
      <button className="btn sm" disabled={!!error || (enabled && ip === reservation.ip && network === reservation.network)} onClick={() => patch((d: any) => {
        d.dhcp ||= {};
        const list = d.dhcp.reservations ||= [];
        const existing = list.find((r: any) => String(r.mac).toLowerCase() === client.mac.toLowerCase());
        if (existing) Object.assign(existing, { ip, network, enabled: true });
        else list.push({ id: newID('res'), enabled: true, mac: client.mac.toLowerCase(), ip, network, hostname: reservationHostname(client.hostname || '') });
      })}>{enabled ? 'Изменить закрепление' : 'Закрепить адрес'}</button>
      {reservation && <button className="btn sm" onClick={() => patch((d: any) => {
        d.dhcp.reservations = d.dhcp.reservations.filter((r: any) => String(r.mac).toLowerCase() !== client.mac.toLowerCase());
      })}>Снять закрепление</button>}
    </div>
    </div>
    <div className="client-reservation-segment">{segment ? `${segment.name || segment.id} (${segment.router_address})` : 'Не удалось однозначно определить сегмент клиента'}</div>
    {error && <div className="client-reservation-error" role="alert">{network ? error : 'Закрепление недоступно: не удалось однозначно определить сегмент клиента'}</div>}
    <p className="client-reservation-hint">Адрес начнёт действовать после применения настроек и обновления аренды DHCP.</p>
  </div>;
}
