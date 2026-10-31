import { useEffect, useState } from "react";
import { api } from "./api";

export type ComponentOperation = {
  active: boolean;
  kind?: string;
  status?: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  component?: string;
  stage?: string;
  error?: string;
  bytes?: number;
  total?: number;
  updated_at?: string;
  started_at?: string;
};

export type ComponentUpdates = {
  checked_at: string;
  error?: string;
  components: Record<
    string,
    {
      installed?: string;
      available?: string;
      update_available: boolean;
      token: string;
      error?: string;
      packages?: {
        name: string;
        installed: string;
        available: string;
        update_available: boolean;
      }[];
    }
  >;
  operation: ComponentOperation;
  operations?: Record<string, ComponentOperation>;
};

// This endpoint reads a memory snapshot; it never checks repositories.
export function useComponentUpdates(enabled: boolean, visible: boolean) {
  const [state, setState] = useState<ComponentUpdates | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    let disposed = false,
      timer: number | undefined,
      controller: AbortController | undefined;
    const load = async () => {
      if (document.hidden) {
        timer = window.setTimeout(load, 5000);
        return;
      }
      controller = new AbortController();
      const requestController = controller;
      const timeout = window.setTimeout(() => requestController.abort(), 15000);
      let active = false;
      try {
        const next = await api.componentUpdates(controller.signal);
        active = next.operation.active;
        if (!disposed) {
          setState(next);
          setError("");
        }
      } catch (e) {
        if (!disposed)
          setError(
            e instanceof Error
              ? e.message
              : "Не удалось получить состояние обновления",
          );
      } finally {
        window.clearTimeout(timeout);
      }
      if (!disposed)
        timer = window.setTimeout(
          load,
          visible && active ? 1000 : visible || active ? 5000 : 60000,
        );
    };
    void load();
    return () => {
      disposed = true;
      controller?.abort();
      window.clearTimeout(timer);
    };
  }, [enabled, visible, refresh]);
  return { state, error, reload: () => setRefresh((n) => n + 1) };
}
