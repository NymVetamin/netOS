import { useEffect, useRef, useState } from "react";

export function CopyButton({ text, label = "Скопировать", onError }: { text: string; label?: string; onError: (message: string) => void }) {
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
  return <button type="button" className="btn" aria-label={copied ? "Скопировано" : label} disabled={busy} onClick={() => void copy()}><span role="status">{copied ? "Скопировано" : label}</span></button>;
}
