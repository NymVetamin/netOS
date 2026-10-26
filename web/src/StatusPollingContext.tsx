import { createContext, ReactNode, useContext, useState } from "react";
import { api } from "./api";
import { createStatusPoller } from "./statusPolling";

const StatusContext = createContext<ReturnType<typeof createStatusPoller> | null>(null);

export function StatusPollingProvider({ children }: { children: ReactNode }) {
  const [poller] = useState(() => createStatusPoller((overview, signal) => api.status(overview, signal)));
  return <StatusContext.Provider value={poller}>{children}</StatusContext.Provider>;
}

export function useStatusPolling() {
  const poller = useContext(StatusContext);
  if (!poller) throw new Error("StatusPollingProvider is required");
  return poller;
}
