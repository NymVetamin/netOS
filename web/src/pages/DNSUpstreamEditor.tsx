import { useState } from "react";
import { Cap } from "../ui";
import { DNS_PRESETS, matchDNSPreset, presetAddress, presetLabel } from "../dnsPresets";

export function DNSUpstreamEditor({ upstream, index, provider, channels, onChange }: {
  upstream: any; index: number; provider: string; channels: any[];
  onChange: (values: Record<string, any>) => void;
}) {
  // Explicit custom mode must survive typing an address matching a preset.
  const [custom, setCustom] = useState(false);
  const [needsChoice, setNeedsChoice] = useState(false);
  const preset = custom ? undefined : matchDNSPreset(upstream);
  const value = preset?.id || (needsChoice && !upstream.address ? "" : "custom");
  const options = DNS_PRESETS.filter(p => presetAddress(p, upstream.type, provider));
  return <div className="dns-upstream-editor">
    <Cap label="Тип"><select aria-label={`Тип DNS-сервера ${index}`} value={upstream.type} onChange={e => {
      const type = e.target.value;
      const address = preset ? presetAddress(preset, type, provider) : upstream.address;
      setNeedsChoice(!!preset && !address);
      onChange({ type, address });
    }}>
      <option value="plain">Открытый DNS</option>
      <option value="dot">DoT</option>
      <option value="doh">DoH</option>
      <option value="doq">DoQ</option>
    </select></Cap>
    <Cap label="Резолвер"><select aria-label={`Резолвер DNS-сервера ${index}`} value={value} onChange={e => {
      const id = e.target.value;
      setCustom(id === "custom");
      setNeedsChoice(false);
      if (id !== "custom") {
        const selected = DNS_PRESETS.find(p => p.id === id)!;
        onChange({ address: presetAddress(selected, upstream.type, provider), comment: "" });
      }
    }}>
      <option value="" disabled>Выберите резолвер</option>
      {options.map(p => <option key={p.id} value={p.id}>{presetLabel(p, upstream.type)}</option>)}
      <option value="custom">Свой</option>
    </select>
      {value === "custom" && <input className="mono dns-custom-address" type="text"
        aria-label={`Адрес DNS-сервера ${index}`} value={upstream.address || ""}
        placeholder={upstream.type === "doh" ? "https://dns.example/dns-query" : upstream.type === "doq" ? "quic://dns.example" : "IP-адрес или адрес сервера"}
        onChange={e => onChange({ address: e.target.value })} />}
    </Cap>
    <Cap label="Канал"><select aria-label={`Канал DNS-сервера ${index}`} value={upstream.channel || "direct"}
      onChange={e => onChange({ channel: e.target.value })}>
      {channels.filter(c => c.enabled).map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
    </select></Cap>
  </div>;
}
