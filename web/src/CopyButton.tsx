import { useEffect, useRef, useState } from "react";

export function CopyButton({ text, label = "Скопировать", onError, iconOnly = false }: { iconOnly?: boolean; text: string; label?: string; onError: (message: string) => void }) {
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  useEffect(() => { generation.current++; setCopied(false); setBusy(false); return () => { generation.current++; }; }, [text]);
  useEffect(() => { if (!copied) return; const timer = window.setTimeout(() => setCopied(false), 2500); return () => window.clearTimeout(timer); }, [copied]);
  async function copy() {
    const current = generation.current;
    setBusy(true); setCopied(false);
    try {
      await navigator.clipboard.writeText(text);
      if (current === generation.current) { setCopied(true); onError(""); }
    } catch {
      if (current === generation.current) onError("Не удалось скопировать. Разрешите браузеру доступ к буферу обмена или скачайте конфигурацию.");
    } finally { if (current === generation.current) setBusy(false); }
  }
  return <button type="button" className="btn" title={copied ? "Скопировано" : label} aria-label={copied ? "Скопировано" : label} disabled={busy} onClick={() => void copy()}>{iconOnly && <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">{copied ? <path d="m5 12 4 4L19 6" /> : <><rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V4H4v12h4" /></>}</svg>}<span className={iconOnly ? "sr-only" : undefined} role="status">{copied ? "Скопировано" : label}</span></button>;
}
