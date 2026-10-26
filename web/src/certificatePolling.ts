import { createStatusPoller } from './statusPolling';

// Share only current requests, not persisted certificate state. Revocations
// and file errors are read afresh on every poll and every new subscription.
export function createCertificateSubscriptions(fetchStatuses: (id: string, signal: AbortSignal) => Promise<any>) {
  const servers = new Map<string, { count: number; poller: ReturnType<typeof createStatusPoller> }>();
  return (id: string, receive: (request: Promise<any>) => void) => {
    let entry = servers.get(id);
    if (!entry) {
      entry = { count: 0, poller: createStatusPoller((_, signal) => fetchStatuses(id, signal)) };
      servers.set(id, entry);
    }
    entry.count++;
    const unsubscribe = entry.poller.subscribe(15000, false, receive);
    return () => {
      unsubscribe();
      if (--entry.count === 0) servers.delete(id);
    };
  };
}
