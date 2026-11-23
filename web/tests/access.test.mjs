import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/access.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
vm.runInNewContext(compiled, { exports });
const { accessMatrix } = exports;

// Системные правила — как в backend/internal/config/defaults.go.
const systemRules = [
  { name: "Локальная петля", zone: "global", flow: "in", action: "accept", interface: "lo" },
  { name: "Ответы на запросы самого роутера", zone: "global", flow: "in", action: "accept", conn_state: "established,related" },
  { name: "Ответы на запросы клиентов", zone: "global", flow: "forward", action: "accept", conn_state: "established,related" },
  { name: "Отбрасывать некорректные транзитные пакеты", zone: "global", flow: "forward", action: "drop", conn_state: "invalid" },
  { name: "Доступ по SSH", zone: "global", flow: "in", action: "accept", protocol: "tcp", dst_port: "22" },
  { name: "Запросы DNS из локальной сети", zone: "lan", flow: "in", action: "accept", protocol: "udp", dst_port: "53" },
  { name: "Разрешить транзит из локальной сети в интернет", zone: "lan", flow: "forward", dst_zone: "wan", action: "accept" },
].map((r) => ({ enabled: true, ...r }));

function config(extraRules = [], patch = {}) {
  return {
    interfaces: [
      { id: "i1", name: "br-lan" },
      { id: "i2", name: "eth0.30" },
      { id: "i3", name: "eth0.40" },
    ],
    networks: [
      { id: "office", name: "Офис", interface: "i1", router_address: "192.168.10.1/24", enabled: true, zone: "lan" },
      { id: "guest", name: "Гости", interface: "i2", router_address: "10.30.0.1/24", enabled: true, zone: "lan", isolated: true },
      { id: "cams", name: "Камеры", interface: "i3", router_address: "10.40.0.1/24", enabled: true, zone: "lan" },
    ],
    firewall: {
      enabled: true,
      zones: [
        { name: "lan", title: "Локальная сеть", policy: "accept" },
        { name: "wan", title: "Интернет", policy: "drop" },
      ],
      rules: [...systemRules, ...extraRules],
      nat: [],
    },
    vpn_servers: [],
    ...patch,
  };
}

const zoneIfaces = { wan: ["ppp-wan1"] };

test("ACME HTTP-01 precedes global and zone drops and disappears when disabled", () => {
  const cfg = config([], {system:{panel:{tls:{mode:"acme"}}}});
  cfg.firewall.rules = [{enabled:true,name:"Deny all",zone:"global",flow:"any",action:"drop"}];
  for (const from of ["Интернет", "Офис"]) {
    const access=cell(cfg,from,"Роутер");
    assert.equal(access.verdict,"p");
    assert.ok(access.exceptions.some(text=>text.includes("ACME HTTP-01")&&text.includes("TCP 80")));
  }
  assert.equal(cell(cfg,"Интернет","Офис").verdict,"n");
  cfg.firewall.rules.unshift({enabled:true,name:"Deny HTTP",zone:"global",flow:"in",action:"drop",protocol:"tcp",dst_port:"80"});
  assert.equal(cell(cfg,"Интернет","Роутер").verdict,"p");
  cfg.firewall.rules[1].action="accept";
  assert.equal(cell(cfg,"Интернет","Роутер").verdict,"y","earlier ACME shadows the later TCP/80 drop");
  cfg.firewall.rules[1].action="drop";
  cfg.system.panel.tls.mode="selfsigned";
  assert.equal(cell(cfg,"Интернет","Роутер").verdict,"n");
  cfg.system.panel.tls.mode="acme";
  assert.equal(cell(cfg,"Интернет","Роутер").verdict,"p");
  cfg.firewall.enabled=false;
  assert.equal(cell(cfg,"Интернет","Роутер").verdict,"y");
});

test("ACME is needed only by enabled certificate-using VPN protocols",()=>{
  for(const [type,protocol,wanted] of [["ocserv","",true],["xray","vless",true],["xray","trojan",true],["xray","hysteria",true],["xray","reality",false],["xray","",false],["xray","shadowsocks",false],["wireguard","",false]]) {
    const cfg=config();cfg.firewall.rules=[];
    cfg.vpn_servers=[{id:"vpn",name:"VPN",enabled:true,type,config:{...(type==="xray"?{protocol}:{}),tls:{mode:"acme"}}}];
    const hasACME=()=>cell(cfg,"Интернет","Роутер").exceptions.some(text=>text.includes("ACME HTTP-01"));
    assert.equal(hasACME(),wanted,`${type}/${protocol}`);
    cfg.vpn_servers[0].enabled=false;assert.equal(hasACME(),false);
    cfg.vpn_servers[0].enabled=true;cfg.vpn_servers[0].config.tls.mode="custom";assert.equal(hasACME(),false);
  }
});

test("address sets restrict rules and empty sets match nothing", () => {
  const cfg = config([{ name: "Set access", enabled: true, zone: "global", flow: "forward", action: "accept", dst_ipset: "targets" }]);
  cfg.firewall.ipsets = [{ id: "targets", entries: [] }];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "n");
  cfg.firewall.ipsets[0].entries = ["192.168.10.42"];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "p");
  cfg.firewall.ipsets[0].entries = ["192.168.10.0/24"];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "y");
});

function cell(cfg, from, to) {
  const m = accessMatrix(cfg, zoneIfaces);
  const i = m.sources.findIndex((e) => e.title === from);
  const j = m.destinations.findIndex((e) => e.title === to);
  assert.ok(i >= 0 && j >= 0, `нет точки ${from} → ${to}`);
  return m.cells[i][j];
}

test("segments reach the Internet through the system LAN rule", () => {
  const c = cell(config(), "Офис", "Интернет");
  assert.equal(c.verdict, "y");
  assert.match(c.reason, /транзит из локальной сети/);
});

test("segments do not see each other by default, isolation is named", () => {
  assert.equal(cell(config(), "Офис", "Камеры").verdict, "n");
  assert.match(cell(config(), "Офис", "Камеры").reason, /не видят друг друга/);
  assert.match(cell(config(), "Офис", "Гости").reason, /изоляция сегмента «Гости»/);
});

test("established-only rules do not open the Internet to the LAN", () => {
  const c = cell(config(), "Интернет", "Офис");
  assert.equal(c.verdict, "n");
  assert.match(c.reason, /политика зоны «Интернет»/);
});

test("SSH from the Internet makes the router partially reachable", () => {
  const c = cell(config(), "Интернет", "Роутер");
  assert.equal(c.verdict, "p");
  assert.ok(c.exceptions.some((e) => e.includes("Доступ по SSH") && e.includes("TCP 22")));
});

test("only the first terminating rule with the same selectors decides new traffic", () => {
  const deny = { name: "first", enabled: true, zone: "wan", flow: "in", protocol: "tcp", dst_port: "8443", action: "drop" };
  const allow = { ...deny, name: "second", action: "accept", log: true };
  const cfg = config();
  const result = (...rules) => {
    cfg.firewall.rules = rules;
    return cell(cfg, "Интернет", "Роутер");
  };
  assert.equal(result(deny, allow).verdict, "n");
  assert.equal(result(allow, deny).verdict, "p");
  assert.equal(result(allow, { ...deny, zone: "global", flow: "any" }).verdict, "n");
  assert.equal(result({ ...deny, action: "continue" }, allow).verdict, "p");
  for (const condition of [
    { enabled: false }, { zone: "lan" }, { flow: "forward" }, { dst_port: "8444" },
    { src_ip: "203.0.113.1" }, { src_port: "5000" }, { protocol: "udp" },
    { conn_state: "established" }, { schedule: { time_start: "08:00", time_stop: "10:00" } },
  ]) {
    assert.equal(result({ ...deny, ...condition }, allow).verdict, "p", JSON.stringify(condition));
  }
  assert.equal(result({ ...deny, conn_state: "new" }, allow).verdict, "n");
});

test("a port forward opens a segment partially", () => {
  const cfg = config([], {});
  cfg.firewall.nat = [{ name: "NAS", enabled: true, direction: "destination", protocol: "tcp", ext_port: "5001", dest_ip: "192.168.10.20" }];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "p");
  assert.equal(cell(cfg, "Интернет", "Камеры").verdict, "n");
});

test("a rule for the whole segment decides, a narrower one is partial", () => {
  const drop = { enabled: true, name: "Камеры без интернета", zone: "lan", flow: "forward", action: "drop", src_ip: "10.40.0.0/24", dst_zone: "wan" };
  const cfg = config([drop]);
  // Системное разрешение стоит раньше, поэтому запрет ниже не срабатывает.
  assert.equal(cell(cfg, "Камеры", "Интернет").verdict, "y");
  cfg.firewall.rules = [...systemRules.slice(0, -1), drop, systemRules.at(-1)];
  assert.equal(cell(cfg, "Камеры", "Интернет").verdict, "n");
  assert.match(cell(cfg, "Камеры", "Интернет").reason, /Камеры без интернета/);
  assert.equal(cell(cfg, "Офис", "Интернет").verdict, "y");

  const web = { enabled: true, name: "Офис смотрит камеры", zone: "lan", flow: "forward", action: "accept", src_ip: "192.168.10.0/24", dst_ip: "10.40.0.0/24", protocol: "tcp", dst_port: "443" };
  assert.equal(cell(config([web]), "Офис", "Камеры").verdict, "p");
  assert.equal(cell(config([web]), "Камеры", "Офис").verdict, "n");
});

test("a disabled firewall lets everything through", () => {
  const cfg = config();
  cfg.firewall.enabled = false;
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "y");
});

test("Samba adds LAN and VPN exceptions without opening all router traffic", () => {
  const cfg = config();
  cfg.firewall.zones.find(z => z.name === "lan").policy = "drop";
  cfg.samba = { enabled: true, networks: [cfg.networks[0].id], vpns: ["wg"] };
  const allowed = cell(cfg, "Офис", "Роутер");
  assert.ok(allowed.exceptions.some(e => e.includes("Samba") && e.includes("445")));
  const blocked = cell(cfg, "Камеры", "Роутер");
  assert.ok(!blocked.exceptions.some(e => e.includes("Samba") && e.includes("445")));
  cfg.samba.enabled = false;
  assert.ok(!cell(cfg, "Офис", "Роутер").exceptions.some(e => e.includes("Samba")));
});

test("VPN isolation is bidirectional and precedes global allow", () => {
 const cfg=config([{name:"allow all",enabled:true,zone:"global",flow:"forward",action:"accept"}]);
 cfg.firewall.zones.push({name:"vpn",title:"VPN",policy:"accept"});
 cfg.vpn_servers=[{id:"wg",name:"WG",index:1,type:"wireguard",enabled:true,subnet:"10.9.0.1/24",isolated:true},{id:"oc",name:"OC",index:2,type:"ocserv",enabled:true,subnet:"10.10.0.1/24"}];
 const m=accessMatrix(cfg,{lan:["br-lan"],vpn:["wg-srv1","vpns2+"],wan:["eth0"]});
 const cell=(src,dst)=>m.cells[m.sources.findIndex(s=>s.id===src)][m.destinations.findIndex(s=>s.id===dst)];
 assert.equal(cell("vpn:wg","segment:office").verdict,"n");
 assert.equal(cell("segment:office","vpn:wg").verdict,"n");
 assert.equal(cell("vpn:wg","vpn:oc").verdict,"n");
 assert.equal(cell("vpn:oc","vpn:wg").verdict,"n");
 assert.equal(cell("vpn:wg","zone:wan").verdict,"y");
});

test("explicit output interface restricts a destination zone", () => {
 const cfg=config([{name:"exact exit",enabled:true,zone:"lan",flow:"forward",dst_zone:"lan",out_interface:"eth0.40",action:"accept"}]);
 cfg.networks.forEach(n=>n.isolated=false);
 const m=accessMatrix(cfg,{lan:["br-lan","eth0.30","eth0.40"],wan:["eth0"]});
 const src=m.sources.findIndex(s=>s.id==="segment:office");
 const to=id=>m.cells[src][m.destinations.findIndex(s=>s.id===id)];
 assert.equal(to("segment:cams").verdict,"y");
 assert.equal(to("segment:guest").verdict,"n");
});

test("prepared rules preserve global any, exact zone flow and fresh edits", () => {
 const cfg=config();
 const own={name:"own",enabled:true,zone:"lan",flow:"forward",action:"accept"};
 const global={name:"global",enabled:true,zone:"global",flow:"any",action:"drop",conn_state:"new"};
 cfg.firewall.rules=[own,global];
 assert.equal(cell(cfg,"Офис","Интернет").reason,'правило «global»');
 global.enabled=false;
 assert.equal(cell(cfg,"Офис","Интернет").reason,'правило «own»');
 global.enabled=true;global.conn_state="established,related";
 assert.equal(cell(cfg,"Офис","Интернет").reason,'правило «own»');
 global.conn_state="NEW";
 assert.equal(cell(cfg,"Офис","Интернет").reason,'правило «global»');
 global.flow="out";own.flow="any";
 assert.equal(cell(cfg,"Офис","Интернет").reason,'политика зоны «Локальная сеть»');
 global.flow="any";global.action="accept";
 assert.equal(cell(cfg,"Офис","Интернет").verdict,"y");
});

test("grouping preserves partial exception order and first full match", () => {
 const cfg=config();
 cfg.firewall.rules=[
  {name:"first",enabled:true,zone:"global",flow:"forward",action:"drop",protocol:"tcp"},
  {name:"second",enabled:true,zone:"global",flow:"any",action:"drop",protocol:"udp"},
  {name:"full",enabled:true,zone:"lan",flow:"forward",action:"accept"},
  {name:"late",enabled:true,zone:"lan",flow:"forward",action:"drop"},
 ];
 const result=cell(cfg,"Офис","Интернет");
 assert.equal(result.reason,'правило «full»');
 assert.equal(JSON.stringify(result.exceptions),JSON.stringify(['«first»: TCP','«second»: UDP']));
});

test("empty matrices and disabled firewall do not inspect irrelevant rules", () => {
 assert.equal(accessMatrix({firewall:{enabled:true,rules:[null]}},{}).sources.length,0);
 const cfg=config();cfg.firewall.enabled=false;cfg.firewall.rules=[null];
 assert.equal(cell(cfg,"Офис","Интернет").verdict,"y");
});

test("parsed addresses are fresh after rule and address-set edits", () => {
 const rule={name:"address",enabled:true,zone:"global",flow:"forward",action:"accept",dst_ip:"192.168.10.0/24"};
 const cfg=config([rule]);
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"y");
 rule.dst_ip="10.50.0.0/24";
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"n");
 rule.dst_ip="192.168.10.0/24,bad";
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"p");
 rule.dst_ip="0.0.0.0/0";
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"y");
 rule.dst_ip="";rule.dst_ipset="set";
 cfg.firewall.ipsets=[{id:"set",entries:["192.168.10.0/24"]}];
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"y");
 cfg.firewall.ipsets[0].entries=["192.168.10.42/32"];
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"p");
 cfg.firewall.ipsets[0].entries=[];
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"n");
 cfg.firewall.ipsets[0].entries=["192.168.10.0/24"];
 assert.equal(cell(cfg,"Интернет","Офис").verdict,"y");
});

test("invalid CSV and IPv4 masks keep partial-match semantics", () => {
 for(const spec of ["bad", "192.168.10.0/33", "256.1.1.1", "192.168.10.0/24,", ",", " "]){
  const cfg=config([{name:"invalid",enabled:true,zone:"global",flow:"forward",action:"accept",dst_ip:spec}]);
  assert.equal(cell(cfg,"Интернет","Офис").verdict,"p",spec);
 }
});

test("address-set lookup preserves first match and observes edits on every calculation", () => {
 const rule={name:"selected",enabled:true,zone:"global",flow:"forward",action:"accept",dst_ipset:"set"};
 const cfg={networks:[{id:"lan",name:"LAN",enabled:true,zone:"lan",interface:"br0",router_address:"10.0.0.1/24"}],
  firewall:{enabled:true,zones:[{name:"wan",policy:"drop"},{name:"lan",policy:"accept"}],rules:[rule],ipsets:[]}};
 const zones={wan:["eth0"],lan:["br0"]};
 const result=(src="zone:wan",dst="segment:lan")=>{
  const before=JSON.stringify(cfg),m=accessMatrix(cfg,zones);
  assert.equal(JSON.stringify(cfg),before);
  return m.cells[m.sources.findIndex(s=>s.id===src)][m.destinations.findIndex(d=>d.id===dst)];
 };
 assert.equal(result().verdict,"n");
 const first={id:"set",entries:[]},second={id:"set",entries:["10.0.0.0/24"]};
 cfg.firewall.ipsets=[first,second];
 assert.equal(result().verdict,"n");
 first.entries.push("10.0.0.0/24");
 assert.equal(result().verdict,"y");
 first.entries[0]="10.0.0.7/32";
 assert.equal(result().verdict,"p");
 first.entries[0]="bad";
 assert.equal(result().verdict,"p");
 first.entries[0]="";
 assert.equal(result().verdict,"y");
 first.entries=[];
 assert.equal(result().verdict,"n");
 cfg.firewall.ipsets.reverse();
 assert.equal(result().verdict,"y");
 cfg.firewall.ipsets=[];
 assert.equal(result().verdict,"n");
 cfg.firewall.ipsets=[second];
 rule.flow="in";
 assert.equal(result("zone:wan","router").verdict,"p");
 second.entries=[];
 assert.equal(result("zone:wan","router").verdict,"n");
 second.entries=["10.0.0.0/24"];
 rule.dst_ipset="";rule.src_ipset="set";rule.action="drop";
 assert.equal(result("segment:lan","router").verdict,"n");
 second.entries=["192.0.2.0/24"];
 assert.equal(result("segment:lan","router").verdict,"y");
 cfg.firewall.enabled=false;cfg.firewall.ipsets=[null];
 assert.equal(result().verdict,"y");
});

test("the WG exit switch leaves LAN access to explicit rules", () => {
  const cfg = config([], { channels: [{ type: "wireguard", index: 1, enabled: true, accept_inbound: true }] });
  const verdict = () => {
    const m = accessMatrix(cfg, { wan: ["wg-ch1", "eth0"] });
    return m.cells[m.sources.findIndex(s => s.zone === "wan")][m.destinations.findIndex(d => d.id === "segment:office")].verdict;
  };
  assert.equal(verdict(), "n");
  cfg.firewall.rules.push({ enabled: true, zone: "wan", flow: "forward", interface: "wg-ch1", dst_zone: "lan", action: "accept" });
  assert.equal(verdict(), "p");
  cfg.firewall.rules.pop();
  assert.equal(verdict(), "n");
});

test("a set covers the segment when its adjacent prefixes leave no gap", () => {
  const cfg = config([{name: "allow", enabled: true, zone: "global", flow: "forward", action: "accept", dst_ipset: "set"}]);
  const set = {id: "set", entries: ["192.168.10.128/25", "192.168.10.0/26", "192.168.10.0/26", "192.168.10.64/26"]};
  cfg.firewall.ipsets = [set];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "y");
  set.entries.pop();
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "p");
  set.entries = ["192.168.9.255", "192.168.11.0"];
  assert.equal(cell(cfg, "Интернет", "Офис").verdict, "n");
});
