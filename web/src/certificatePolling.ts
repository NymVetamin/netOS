import { createStatusPoller } from './statusPolling';

// Every TLS editor reads the same server-certificate catalog.
export function createServerCertificateSubscriptions(fetchStatuses: (signal: AbortSignal) => Promise<any[]>) {
  const poller = createStatusPoller(async (_, signal) => {
    const items = await fetchStatuses(signal);
    if (!Array.isArray(items)) throw new Error('Invalid certificate response');
    const byDomain = new Map<string, any>();
    for (const item of items) {
      if (!byDomain.has(item.domain)) byDomain.set(item.domain, item);
    }
    return byDomain;
  });
  return (receive: (request: Promise<Map<string, any>>) => void) => poller.subscribe(30000, false, receive);
}

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
