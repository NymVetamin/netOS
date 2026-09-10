type Probe = {
  type?: string;
  targets?: string[];
  tcp_request?: string;
  tcp_response?: string;
};

function httpTargetToTCP(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    const host = url.hostname.includes(":") ? `[${url.hostname}]` : url.hostname;
    return {
      target: `${host}:${url.port || (url.protocol === "https:" ? "443" : "80")}`,
      request: `GET ${url.pathname || "/"}${url.search} HTTP/1.0\r\nHost: ${url.host}\r\n\r\n`,
    };
  } catch {
    return null;
  }
}

function ensureTCPPort(value: string) {
  if (/^\[[^\]]+\]:\d+$/.test(value) || /^[^:]+:\d+$/.test(value)) return value;
  return value.includes(":") ? `[${value}]:443` : `${value}:443`;
}

export function changeProbeType(probe: Probe, type: string) {
  const current = probe.targets || [];
  if (type === "tcp") {
    const converted = current.map(httpTargetToTCP);
    probe.targets = converted.map((item, index) => item?.target || ensureTCPPort(current[index])).filter(Boolean);
    probe.tcp_request ||= converted.find(Boolean)?.request || "";
    probe.tcp_response ||= "HTTP/";
  } else if (type === "http") {
    probe.targets = current.map((target) => /^https?:\/\//i.test(target) ? target : `http://${target}/`);
  }
  probe.type = type;
}
