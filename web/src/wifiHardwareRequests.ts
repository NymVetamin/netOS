import { api } from "./api";

// Share only in-flight requests within one Wi-Fi page. Completed responses are
// never cached: a later country change or refresh must see current hardware.
export function createWiFiHardwareRequests(fetchHardware = api.wifiHardware) {
  type Request = {
    controller: AbortController;
    result: ReturnType<typeof fetchHardware>;
    readers: number;
  };
  const pending = new Map<string, Request>();
  return (country: string) => {
    let request = pending.get(country);
    if (!request) {
      const controller = new AbortController();
      request = { controller, result: fetchHardware(country, controller.signal), readers: 0 };
      pending.set(country, request);
      const current = request;
      const remove = () => { if (pending.get(country) === current) pending.delete(country); };
      request.result.then(remove, remove);
    }
    const current = request;
    current.readers++;
    let released = false;
    return {
      result: current.result,
      release() {
        if (released) return;
        released = true;
        if (--current.readers === 0) {
          if (pending.get(country) === current) pending.delete(country);
          current.controller.abort();
        }
      },
    };
  };
}
