type Subscriber = { interval: number; overview: boolean; next: number; receive: (request: Promise<any>) => void };

// One poll stream per panel session; subscribers retain their own cadence.
// Only an in-flight request is shared, never a cached response from an old poll.
export function createStatusPoller(fetchStatus: (overview: boolean, signal: AbortSignal) => Promise<any>) {
  const origin = Date.now();
  const subscribers = new Set<Subscriber>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let flight: { request: Promise<any>; controller: AbortController; overview: boolean; started: number } | null = null;
  const nextTick = (interval: number, now: number) => origin + (Math.floor((now - origin) / interval) + 1) * interval;

  function schedule() {
    clearTimeout(timer);
    timer = undefined;
    if (flight || !subscribers.size) return;
    const next = Math.min(...Array.from(subscribers, s => s.next));
    timer = setTimeout(poll, Math.max(0, next - Date.now()));
  }

  function poll() {
    const now = Date.now();
    const due = Array.from(subscribers).filter(s => s.next <= now);
    if (!due.length) { schedule(); return; }
    const overview = due.some(s => s.overview);
    const controller = new AbortController();
    const request = Promise.resolve().then(() => fetchStatus(overview, controller.signal));
    const current = { request, controller, overview, started: now };
    flight = current;
    for (const subscriber of due) {
      subscriber.next = nextTick(subscriber.interval, now);
      subscriber.receive(request);
    }
    const finished = () => {
      if (flight === current) { flight = null; schedule(); }
    };
    void request.then(finished, finished);
  }

  return {
    subscribe(interval: number, overview: boolean, receive: Subscriber["receive"]) {
      const subscriber: Subscriber = { interval, overview, receive, next: Date.now() };
      subscribers.add(subscriber);
      if (flight && (!overview || flight.overview)) {
        subscriber.next = nextTick(interval, flight.started);
        receive(flight.request);
      }
      schedule();
      return () => {
        subscribers.delete(subscriber);
        if (!subscribers.size && flight) {
          flight.controller.abort();
          flight = null;
        }
        schedule();
      };
    },
  };
}
