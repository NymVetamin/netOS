import assert from "node:assert/strict";
import { test } from "node:test";
import { resolveConfig } from "vite";

test("dev API defaults to loopback and verifies TLS for the selected router", async t => {
  const initial = process.env.NETOS_DEV_API_HOST;
  t.after(() => {
    if (initial === undefined) delete process.env.NETOS_DEV_API_HOST;
    else process.env.NETOS_DEV_API_HOST = initial;
  });
  for (const host of [undefined, "router.test:9443"]) {
    if (host === undefined) delete process.env.NETOS_DEV_API_HOST;
    else process.env.NETOS_DEV_API_HOST = host;
    const config = await resolveConfig({}, "serve");
    const proxy = config.server.proxy["/api"];
    assert.equal(proxy.target, `https://${host || "127.0.0.1:8443"}`);
    assert.equal(proxy.secure, true);
  }
});
