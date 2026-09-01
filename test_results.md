# Полная проверка netOS

Начало прогона: 2026-08-31 17:28 MSK  
Цель: end-to-end проверка всех пользовательских функций, API, CLI и сетевых подсистем с одновременной сверкой живых конфигураций, служб и журналов.

Статусы:

- `PASS` — сценарий выполнен, ожидаемое состояние подтверждено непосредственно.
- `PARTIAL` — проверена только часть слоя или сценария.
- `BLOCKED` — отсутствует обязательная тестовая возможность или зависимость.
- `TODO` — сценарий ещё не выполнялся.
- `FAIL` — фактическое поведение противоречит ожидаемому.

## Baseline

| Время (MSK) | Проверка | Статус | Доказательство |
|---|---|---|---|
| 17:28–17:38 | Frontend: чистая установка зависимостей, TypeScript и production build | PASS | `npm ci`, `npm run build`; 45 модулей, сборка Vite завершена, `npm audit` — 0 известных уязвимостей |
| 17:30 | Backend unit suite на целевой Linux-среде | PASS | Go 1.27.0, `go test ./...`; все пакеты PASS |
| 17:32–17:38 | Живая служба и ресурсы | PASS | `netosd` active, 0 failed units, root FS 55%, 672 MB available RAM, низкая load average |
| 17:37 | Drift активной конфигурации | PASS | `sudo netos plan`: «Живая система соответствует конфигурации: применять нечего» |
| 17:38 | Журнал netosd | PARTIAL | panic/fatal/ошибок не найдено; присутствуют повторяющиеся TLS handshake warnings от внешних адресов и запись об автоматическом rollback в 14:04:49 UTC |
| 17:39–17:40 | Root integration suite подсистем | PARTIAL | Все выполненные тесты PASS; часть тестов пропущена из-за зависимостей, перечисленных ниже |
| 17:43–17:45 | Восстановление Xray после дефекта изоляции | PASS | Xray 26.7.28 переустановлен штатным apply; channel/server active; `netos plan` clean |
| 17:46–17:50 | Расширенный integration suite с системным PATH и зависимостями | PASS | iptables, CAKE, WireGuard server, ifupdown, PPPoE, L2TP, client shaping, Kea, ocserv/OpenConnect — реальные lifecycle/traffic проверки PASS |
| 17:56 | Cleanup OpenConnect/resolver после исправления | PASS | `/etc/resolv.conf` до/после побайтово одинаков; DNS работает; namespace cleanup подтверждён |
| 17:58 | IKEv2 EAP/XFRM и Wi-Fi hostapd lifecycle | PASS | Реальные адрес/traffic/XFRM и mac80211_hwsim/hostapd сценарии PASS |
| 18:03–18:05 | Возврат стенда после QA-зависимостей | PASS | Штатный component reconciliation и отдельная очистка QA-only пакетов; полный apply завершён; DNS работает; `netos plan` clean; 0 failed units |
| 18:05 | Регрессионный gate после исправлений | PASS | `go test ./... -count=1`, `go vet ./...`, frontend production build и remote `bash -n` PASS |
| 18:14–18:16 | Backup и baseline до удаления | PASS | архив `netos-backup-20260831-151456.tar.gz`, SHA-256 `526ffd298b9faf183cf6f66a86f46a878c5815fba38afd7bf45ff7794e30c839`; `gzip -t` и manifest baseline PASS |
| 18:15–18:17 | Полный uninstall и аудит системы | FAIL → FIXED | обнаружен оставшийся `nameserver 127.0.0.1` без DNS-службы; реализован legacy fallback, unit/manage tests и повторный live uninstall PASS |
| 18:26–18:36 | Чистая установка amd64 и live API | PASS | проверка checksum, стабильность службы, права initial credentials; 41/41 API-проверок PASS |
| 18:41–18:43 | Повторный clean install исправленной сборки | PASS | пароль отсутствует в journal, credentials `0600`; после исправления enable/reload предупреждение systemd исчезло |
| 18:44–18:46 | Restore исходного backup и сравнение | PASS | SHA повторно подтверждён; 10/10 render-артефактов идентичны, TLS идентичен, package delta пуст, `netos plan` clean, 0 failed units |

## Карта полного покрытия

### Панель и API

| Область | Happy path | Негативный/граничный сценарий | Сверка runtime | Статус |
|---|---|---|---|---|
| Вход, сессия, CSRF, выход | API PASS | 401/403, неверный login/CSRF, stale version | журнал/API session | PARTIAL: 41 API checks PASS; UI заблокирован браузером |
| Роли admin/viewer | TODO | TODO | 401/403 и аудит | BLOCKED: встроенный браузер недоступен |
| Сводка | TODO | TODO | status/statistics/services | BLOCKED: встроенный браузер недоступен |
| Устройства, leases, ARP | TODO | TODO | leases/ARP/iptables/tc | BLOCKED: встроенный браузер недоступен |
| Сеть: физические интерфейсы, bridge, VLAN, сегменты | TODO | TODO | `ip link/address`, networkd/ifupdown | PARTIAL: networkd integration PASS |
| Маршрутизация и policy rules | TODO | TODO | `ip route`, `ip rule` | PARTIAL: unit/integration PASS |
| WAN: DHCP, static, PPPoE, L2TP | локальная Apply-матрица PASS | missing link и ошибки link/address/route PASS | адреса, routes, ownership, ppp units/logs | PARTIAL: DHCP/static/PPPoE/L2TP Apply и fault matrix PASS; повторный live runtime ожидает QA |
| Multi-WAN failover/balance/probes | TODO | TODO | routes/rules и channel logs | PARTIAL: isolated integration PASS |
| WireGuard/OpenConnect/Xray channels | lifecycle PASS | отказ auth/cleanup/reconnect | units, links, handshakes, traffic | PARTIAL: реальные WG/Xray/OpenConnect lifecycle и traffic PASS; UI не проверен |
| VPN servers: WireGuard, Reality, OpenConnect, IKEv2 | lifecycle PASS | wrong auth/cleanup | listeners, handshakes, ACL/routes | PARTIAL: WG, ocserv/OpenConnect, IKEv2 EAP/XFRM, Reality lifecycle PASS; UI не проверен |
| Wi-Fi AP | lifecycle PASS | cleanup/no-radio | hostapd, radio, client association | PARTIAL: исторический mac80211_hwsim/hostapd lifecycle PASS; новый exact Health/ownership/idempotency локально PASS, повторный live и UI ожидают QA |
| QoS: CAKE и клиентские лимиты | runtime PASS | cleanup | `tc qdisc/class/filter`, traffic | PARTIAL: исторический CAKE/client shaping/iperf3 E2E PASS; новый exact Health/rollback/idempotency локально PASS, повторный live и UI ожидают QA |
| Firewall zones/rules/NAT/security | runtime PASS | syntax/cleanup | `iptables-save`, packet probes | PARTIAL: generator/lifecycle и все поля локально PASS; новый exact Health/rollback/idempotency ждёт повторного live, UI/полная packet matrix не завершены |
| DHCP: dnsmasq/ISC/Kea | render/syntax PASS | cleanup | units, leases, реальный клиент | PARTIAL: dnsmasq/ISC/Kea render/syntax PASS; UI и полный client matrix не завершены |
| DNS: dnsmasq/unbound/dnsproxy, records, split DNS | TODO | TODO | generated config, listeners, queries | PARTIAL: render/unit PASS |
| DDNS: Cloudflare/DuckDNS/No-IP | TODO | TODO | provider status/request/audit | PARTIAL: isolated provider integration PASS |
| Компоненты: install/remove/status | lifecycle PASS | remove/reinstall/cleanup | dpkg/systemd/catalog | PARTIAL: реальный install/remove/reconcile PASS; UI не проверен |
| Система: hostname/NTP/IPv6/TLS/password/users | TODO | TODO | sysctl, hostname, time, TLS, auth | PARTIAL: unit/render PASS |
| Draft/validate/plan/apply/confirm | TODO | TODO | revisions/generated configs/logs | PARTIAL: unit PASS, `netos plan` live PASS |
| Timeout rollback/manual rollback | TODO | TODO | revision, runtime restoration, logs | PARTIAL: live rollback log observed, controlled E2E not yet run |
| History/revisions/audit/restore | TODO | TODO | SQLite/API/runtime | PARTIAL: unit PASS |
| Diagnostics/render/routes/neighbors | TODO | TODO | compare UI/API to live files | BLOCKED: UI unavailable; CLI plan checked |
| Backup/download/delete/restore | live backup/restore PASS | hash/archive validation | archive и restored runtime | PARTIAL: CLI live E2E PASS; UI download/delete не проверены |
| Update/reinstall/reset/uninstall | clean install/update/uninstall PASS | legacy resolver/cleanup | version, service, data preservation/cleanup | PARTIAL: destructive amd64 lifecycle PASS; reset и arm64 ещё не выполнены |
| Responsive UI/theme/navigation/accessibility | TODO | TODO | console/network/layout | BLOCKED: встроенный браузер недоступен |

### CLI и установка

| Сценарий | Статус | Примечание |
|---|---|---|
| `netos status`, `version`, `plan` | PASS | Выполнено на тестовой машине; plan read-only и clean |
| `logs`, `render`, `help`, completion | TODO | Нужен отдельный проход с сопоставлением вывода |
| `backup`, `restore` | PASS | SHA-256/gzip/archive safety, safety backup, runtime и semantic state comparison |
| `update`, `reinstall` | PARTIAL | Повторное развёртывание локальной проверенной сборки PASS; release rollback ещё не проверен |
| `reset`, `uninstall` | PARTIAL | Полный uninstall выполнен несколько раз; reset live ещё не выполнен |
| `install.sh` на чистом Debian amd64/arm64 | PARTIAL | Debian 13 amd64 clean install PASS; arm64 требует отдельную машину |

## Integration run 2026-08-31 17:39 MSK

Команда: `sudo --preserve-env=PATH env NETOS_INTEGRATION=1 go test ./internal/subsys/... -count=1 -v`.

Подтверждено непосредственно:

- WireGuard channel lifecycle и kill-switch;
- Xray lifecycle и валидность systemd/config;
- Multi-WAN failover, восстановление маршрута, balance tables/rules;
- systemd-networkd apply и передача управления netOS;
- DDNS provider request/status paths;
- реальные route reconciliation и конфигурационные lifecycle-проверки подсистем;
- отсутствие падений во всех выполненных unit/integration сценариях.

Пропуски, которые нельзя считать успешным покрытием:

- OpenConnect channel E2E: нет `NETOS_OC_SERVER`/`NETOS_OC_PASSWORD`;
- Xray installer lifecycle: тест отказался перезаписывать существующий `/usr/local/bin/xray`;
- iptables ruleset и WireGuard server handshake: нет `iptables`;
- ifupdown syntax: нет `ifquery`;
- PPPoE: нет `pppd`;
- L2TP: нет `xl2tpd`;
- CAKE/client shaping: нет `tc`;
- IKEv2: нет `charon-systemd`;
- OpenConnect server: нет `ocserv`;
- Wi-Fi lifecycle: нет `hostapd`/подходящего виртуального radio.

## Наблюдения и дефекты

### OBS-001 — повторяющийся шум TLS handshake в журнале

- Статус: наблюдение, не подтверждённый дефект.
- Риск: низкий для функции, средний для наблюдаемости — сообщения могут скрывать полезные предупреждения.
- Факт: много записей `TLS handshake error` от внешних адресов; варианты unknown certificate, EOF, HTTP на HTTPS, устаревшие версии/ALPN/cipher suites.
- Ожидание: отказ небезопасным/невалидным клиентам корректен; отдельно нужно оценить rate limiting/уровень логирования.

### OBS-002 — автоматический rollback в 14:04:49 UTC

- Статус: ожидаемый механизм подтверждён журналом, причина конкретного запуска ещё не атрибутирована.
- Факт: `[пред] выполнен откат к предыдущей конфигурации`.
- Текущее состояние: `netos plan` clean, служба active, failed units отсутствуют.
- Следующее доказательство: управляемый apply без confirm и сравнение revision/config/runtime до и после.

### DEF-001 — root unit-тест удалял live-бинарник Xray

- Статус: исправлен и проверен регрессией.
- Серьёзность: высокая для тестовой инфраструктуры.
- Причина: `TestApplyReportsRemovalFailure` передавал неполный конфиг в общий component reconciler; для внешних компонентов использовались абсолютные production targets, поэтому root-запуск удалял `/usr/local/bin/xray`.
- Исправление: все external release targets в тесте перенаправлены в `t.TempDir()`.
- Доказательство: тест повторно выполнен под root; `/usr/local/bin/xray` сохранился, версия 26.7.28, обе Xray-службы active, `netos plan` clean.

### DEF-002 — OpenConnect integration оставлял чужой `/etc/resolv.conf`

- Статус: исправлен и проверен регрессией.
- Серьёзность: высокая для тестовой инфраструктуры и связности стенда.
- Причина: `openconnect` запускался в network namespace, но `/etc` оставался общим; distribution `vpnc-script` записывал DNS туннеля `10.98.0.1` в resolver хоста и не возвращал его после остановки.
- Исправление: для namespace создаётся `/etc/netns/netos-oc998/resolv.conf`; `ip netns exec` bind-mounts его, изолируя запись клиента от хоста.
- Доказательство: полный ocserv↔OpenConnect и netOS outbound-channel E2E снова PASS; host `/etc/resolv.conf` до/после совпал через `cmp`, DNS работает, `/etc/netns/netos-oc998` удалён.

### DEF-003 — uninstall оставлял машину без DNS при отсутствующем resolver state

- Статус: исправлен; unit, manager regression и повторный destructive live E2E PASS.
- Серьёзность: критическая для lifecycle — после удаления `/etc/resolv.conf` указывал на остановленный `127.0.0.1`.
- Причина: legacy-установка не содержала `/var/lib/netos/resolv-conf.state`; restore-функция молча считала файл чужим.
- Исправление: fallback с точной проверкой ownership-заголовка netOS; системные DNS берутся из runtime resolver-файлов или DHCP leases. Чужой файл не изменяется, отсутствие достоверного DNS становится явной ошибкой.
- Live-доказательство: искусственно воспроизведён netOS-owned resolver без state; `netos uninstall --yes` восстановил `1.1.1.1` из networkd lease, DNS/SSH/default route сохранились.

### DEF-004 — начальный пароль сохранялся в systemd journal

- Статус: исправлен и проверен чистой установкой.
- Серьёзность: высокая — root-only файл имел `0600`, но тот же пароль оставался в журнале stdout демона.
- Исправление: демон печатает только адрес и путь к root-only credentials; интерактивный installer по-прежнему показывает пароль непосредственно пользователю.
- Доказательство: новый clean install создал credentials `0600`; journal после старта не содержит строки `Пароль:`, содержит только безопасный путь к файлу.

### DEF-005 — clean install печатал systemd warning о несчитанном unit

- Статус: исправлен и воспроизведение закрыто повторной чистой установкой.
- Причина: `systemctl enable --no-reload` менял target dependency после предыдущего daemon-reload; первый restart видел unit как изменившийся на диске.
- Исправление: обычный `systemctl enable netosd`, выполняющий необходимый reload.

### OBS-003 — restore возвращает управление до окончания стартового apply

- Статус: наблюдение, runtime в итоге восстановлен полностью.
- Факт: сразу после команды restore служба уже `active`, но `netos plan` ещё показывал установку четырёх компонентов. После завершения стартового применения/повторной проверки plan стал clean, DNS/firewall/Xray/Unbound поднялись без warning/error.
- Риск: автоматизация может принять ранний `active` за завершённое восстановление. Нужен readiness-критерий команды restore вместо одного `systemctl start`.

### QA-DEPENDENCIES — расширение стенда без запуска штатных демонов

- Временно установлены ifupdown, PPP/PPPoE/L2TP, iperf3, полный strongSwan/EAP toolchain, OpenConnect, hostapd/iw и Kea.
- На время apt использован `policy-rc.d=101`; stock services остались inactive, `netosd` active, failed units — 0.
- После интеграционного цикла состав пакетов должен быть возвращён к активной конфигурации штатным reconciliation и подтверждён `netos plan`.
- Возврат выполнен: временные компоненты и QA-only пакеты удалены, stock services inactive/not-found, тестовые namespaces/interfaces/units/directories не найдены, policy-файл и временные скрипты удалены, `netos plan` clean.

## Ограничения текущего цикла

- In-app browser не предоставлен средой (`agent.browsers.list()` вернул пустой список), поэтому ни один UI-сценарий не помечен PASS на основании чтения исходников.
- Часть внешних provider-сценариев требует реальных учётных данных и остаётся PARTIAL; локальные реальные VPN/network/component интеграции выполнены и после них стенд очищен.
- Полное покрытие не достигнуто; цель остаётся активной.

## Дополнение: браузерный и destructive lifecycle, 20:03–20:35 MSK

Этот раздел заменяет раннее ограничение «UI недоступен»: production-панель была проверена реальным изолированным Chromium через Playwright на `https://45.38.170.119:8443`.

| Область | Статус | Непосредственное доказательство |
|---|---|---|
| Responsive UI | PASS | viewport 390×844: меню скрыто, «Открыть меню» → expanded «Закрыть меню», переход на «Сводку» автоматически закрыл drawer; возврат 1440×1000 |
| Routing tables/rules | PASS | проверены add/remove, все поля, переключатель, таблица назначения; priority 19999 заблокирован, неверный CIDR/fwmark заблокированы; Apply disabled |
| Internet policies | PASS | add/remove, priority/name/source/destination/protocol/port/channel/enabled; TCP port 70000 дал ровно одну ошибку и отключил Apply |
| DNS/Unbound | PASS → FIXED | plain, DoT, DoH, DoQ и split-DNS поля; mixed plain+DoT теперь запрещён; два DoT применены, живой TLS-сеанс `1.1.1.1:853` подтверждён |
| System | PASS | hostname, timezone, NTP, commit timeout, backend, IPv6, theme, update confirmation, password validation, backup lifecycle |
| History | PASS → FIXED | stale revision после restart автоматически повторён только при доказанно чистом server state; ревизии 3 и 2 загружены, невалидная ревизия показала ошибку |
| Diagnostics | PASS → FIXED | 8 вкладок сверены с live; clipboard fallback показал «Скопировано» без необработанной ошибки |
| Backup UI | PASS | создан, скачан и удалён архив; локальный/remote SHA-256 совпали: `442f2bae738dd5a336f4ee83881b8ad083fe788a9de2064b24a5de99bf774a92` |
| Clean uninstall | PASS → FIXED | первый проход нашёл legacy drop-in; QA8 удалил бинарники/unit/data/log/user/readiness/порты/firewall и сам drop-in; resolver/sysctl возвращены, failed units 0 |
| Clean install | PASS | `install.sh`, локальный Linux amd64 binary + обязательный SHA-256; qa8 stable/readiness, login новым паролем, initial credentials удалены после входа, plan clean |
| Reset без backup | PASS | архивов строго 12 до и 12 после `reset --yes --no-backup`; readiness, active, `NRestarts=0`, plan clean |
| Restore исходного состояния | PASS | 57.655 s до возврата команды; readiness уже присутствовал; пять ожидаемых units active/running с `NRestarts=0`; 10/10 render-конфигов идентичны |
| Сравнение до/после | PASS | routes/rules/sysctl/resolver/packages идентичны; TLS cert/key и base SQLite совпали побайтно; users/audit/sessions/devices/schema идентичны |

### DEF-006 — Unbound заявлял mixed plain+DoT, но включал TLS для всех upstream

- Статус: исправлен, unit и live E2E PASS.
- Причина: `forward-tls-upstream: yes` действует на всю `forward-zone`, поэтому смешанный список не реализуем одним блоком Unbound.
- Исправление: конфигурация Unbound отвергает одновременные enabled plain и DoT upstream; два DoT работают и подтверждены сокетом `1.1.1.1:853`.

### DEF-007 — commit timeout `0` молча нормализовался в `30`

- Статус: исправлен, regression и live UI PASS.
- Причина: `Normalize` применял legacy default до current-schema validation.
- Исправление: ноль заменяется только при миграции старой schema; в текущей schema UI получает одну ошибку, Apply disabled.

### DEF-008 — History молча терял 409 при загрузке ревизии после restart

- Статус: исправлен и live проверен.
- Исправление: один безопасный retry разрешён только если сервер не имеет draft/pending и active JSON точно совпадает с последней чистой конфигурацией клиента; остаточная ошибка отображается Notice.

### DEF-009 — Copy в Diagnostics падал при запрещённом Clipboard API

- Статус: исправлен и live проверен.
- Исправление: fallback через временный textarea/`execCommand`, явные состояния «Скопировано»/ошибка, без unhandled promise rejection.

### DEF-010 — неоднозначные поля DDNS, port-forward и Routing

- Статус: исправлен, production accessibility inventory PASS.
- Исправление: все условные input/select/switch получили контекстные `aria-label`; инвентарь routing после QA7 не содержит безымянных контролов.

### DEF-011 — uninstall оставлял legacy `netosd.service.d/90-hardening.conf`

- Статус: исправлен, regression и повторный destructive live E2E PASS.
- Исправление: удаляется только принадлежащий netOS legacy-файл; каталог удаляется только если пуст, поэтому чужие drop-in сохраняются.
- Live-доказательство: после QA8 uninstall `/etc/systemd/system/netosd.service.d` отсутствует, как и unit/binaries/state/log/readiness; DNS и sysctl восстановлены.

### Инварианты финального восстановления

- исходный архив: `526ffd298b9faf183cf6f66a86f46a878c5815fba38afd7bf45ff7794e30c839`;
- config/render для `iptables`, `dnsmasq`, `dnsproxy`, `ISC`, `Kea`, `network`, `resolv`, `sysctl`, `unbound` совпадают по SHA-256;
- `netosd`, `netos-dnsmasq`, `netos-unbound`, `netos-xray-ch1`, `netos-xray-srv1` active/running, `NRestarts=0`;
- DNS-запрос успешен, Unbound имеет TLS-соединение к `1.1.1.1:853`, Xray имеет соединение к upstream и слушает 443;
- ожидаемые runtime-различия: ifindex `tun-ch1` 20→101, счётчики/временные метки iptables, `applied_at` ревизии 96, WAL/SHM/resolver ownership и обновляемая traffic history; правила и пользовательские данные не изменились;
- QA-файлы с паролями, browser snapshots и временная распаковка удалены; backup-архивы сохранены.

Оставшиеся реальные пробелы не скрыты: arm64 требует отдельной машины; внешние DDNS/VPN-provider отрицательные сценарии требуют тестовых учётных данных; физические client/DHCP/Wi-Fi сценарии требуют дополнительных устройств. Поэтому глобальная цель пока остаётся активной.

## Дополнение: API, persistence, bootstrap и TLS, 20:35–21:10 MSK

- Полный `go test ./... -count=1` и `go vet ./...` — PASS после всех исправлений.
- Production-сборка UI (`tsc --noEmit && vite build`) — PASS; актуальные assets встроены в Linux/amd64 `dev-qa9`.
- Покрытие `internal/api` поднято с 32,0% до 65,7%; `store` — с 22,6% до 81,9%; `bootstrap` — с 3,4% до 63,1%; `tlsutil` — с 0% до 83,0%.
- API route-level regression на Windows и отдельным Linux test binary — PASS: auth/admin/viewer, CSRF, logout/revocation, security headers, SPA/API fallback, Xray keypair generate/derive/reject, config save/plan/validate/apply, revision/read/restore/discard, conflict paths, audit/render/catalog/maintenance/read-only routes, trailing и >8 MiB JSON.
- Отдельные Linux test binaries `api`, `store` и `bootstrap` выполнены на живом Debian-стенде — все тесты PASS.
- Race detector не выполнен: локально отсутствует C compiler, на стенде также нет `gcc`; обычные, platform-specific Linux и vet проверки чистые. Это ограничение среды, а не успешный race-результат.
- `dev-qa9` атомарно установлен на стенд. После readiness: `/api/ping` PASS, plan clean, пять ожидаемых unit active/running, `NRestarts=0`, failed units — 0, warning/error netosd — 0.
- TLS cert/key до и после обновления побайтно идентичны. SQLite: физический файл изменился из-за штатного WAL checkpoint при старте; `integrity_check=ok`, активная ревизия осталась 96, новых ревизий, audit-записей и сессий обновление не создало.

### DEF-012 — существующий сертификат принимался с чужим или повреждённым ключом

- Статус: исправлен, unit и Linux regression PASS.
- Причина: проверка существующей пары удостоверялась только в наличии файла ключа и SAN сертификата; несоответствие обнаруживалось позднее в `ServeTLS`, уже при запуске панели.
- Исправление: `tls.LoadX509KeyPair` проверяет пару до запуска; при mismatch/invalid key пара безопасно перевыпускается, а mode повторно ужимается до `0600`.

### DEF-013 — `MarkActive` с отсутствующим ID снимал единственную active-ревизию

- Статус: исправлен, store regression на Windows и Linux PASS.
- Причина: транзакция сначала помечала текущую active-ревизию superseded, затем UPDATE отсутствующего ID затрагивал 0 строк и всё равно commit’ился.
- Исправление: целевая ревизия активируется первой, проверяется `RowsAffected == 1`, затем superseded получают только остальные active; отсутствующий ID возвращает `ErrNotFound` без изменения состояния. Такая же проверка добавлена в `SetRevisionState`.

### DEF-014 — bootstrap мог выбрать LAN-подсеть, уже занятую не-WAN интерфейсом

- Статус: исправлен, bootstrap regression на Windows и Linux PASS.
- Причина: подбор LAN исключал только management CIDR, хотя на других физических интерфейсах могли уже существовать `192.168.10.0/24`, `192.168.50.0/24` и другие кандидаты.
- Исправление: detection собирает CIDR всех IPv4-адресов физических интерфейсов; подбор исключает весь набор занятых сетей и использует `10.77.0.0/24`, если исчерпаны стандартные кандидаты.

### DEF-015 — генератор установочного пароля падал на отрицательной длине

- Статус: исправлен, regression PASS на Windows и Linux.
- Причина: `make([]byte, length)` вызывал panic при отрицательном значении и допускал чрезмерное выделение памяти при огромном.
- Исправление: длина явно ограничена диапазоном 1…4096; проверены границы, длина, алфавит без неоднозначных символов и независимость двух генераций.

### Наблюдение при обновлении qa9

Первый readiness-check был слишком ранним: жёсткий `sleep 8` завершился до окончания стартового apply (панель начала слушать примерно через 9 секунд). netosd при этом не падал и успешно завершил запуск. Для дальнейших обновлений проверка должна опрашивать readiness до deadline, а откат бинарника обязан использовать временный файл + атомарный `mv`; прямая перезапись работающего executable закономерно получает `ETXTBSY`.

### Дополнение CLI и qa10

- Покрытие `cmd/netosd` поднято с 4,5% до 43,4%.
- Проверены адреса панели и hostname fallback, создание admin/credentials, отсутствие пароля в stdout, повторный запуск без ротации credentials, выбор active/latest revision, render/plan/summary и регистрация полного набора подсистем.
- Отдельный Linux test binary подтвердил весь CLI-набор, включая реальные права `0600` на first-boot credentials.
- Финальный бинарник текущего дерева установлен как `dev-qa10`; локальный и live SHA-256 совпали: `e8c043891c1a39ffcb6dead1ce6ab7f7dab4db85f9ce93c3716623bef32f3c30`.
- Исправленная readiness-процедура опрашивала API до готовности и успешно дождалась панели; rollback теперь использует `install` во временный файл и атомарный `mv`.
- После qa10: пять unit active/running, `NRestarts=0`, failed units — 0, plan clean, `/api/ping` PASS, warning/error netosd — 0.
- Live TLS: key `0600 root:root`, cert `0644 root:root`; SHA-256 публичного ключа из cert и private key совпадает (`128bc57a4…d3b17`).

### OBS-004 — внешний SSH brute-force и шум systemd-ssh-generator

- В общесистемном error-журнале видны повторные неуспешные SSH-попытки к несуществующим пользователям с внешнего адреса `121.134.90.172`; успешной аутентификации или влияния на netOS не обнаружено.
- Там же повторяется `systemd-ssh-generator: Failed to query local AF_VSOCK CID` на VPS без AF_VSOCK. Это системный generator-шум Debian/systemd, не сообщение и не отказ netOS.
- Журнал именно `netosd` после qa10 не содержит warning/error, все управляемые службы стабильны. Наблюдение сохранено отдельно, чтобы общесистемные ошибки не были ошибочно объявлены «чистым журналом».

## Дополнение: системные команды, systemd и пакеты, qa11

- Покрытие `internal/system` поднято с 27,6% до 90,1%.
- `Exec` проверен на success/stdout, stdin, stderr, stdout fallback при ошибке, отсутствующий executable, callback, timeout и отменённый context.
- Атомарная запись проверена на создание вложенного каталога, первичную запись, замену существующего файла, точное содержимое, POSIX mode и ошибочный parent; `FileChanged` проверен для missing/same/different.
- Systemd wrappers проверены для start/stop/restart/reload/reload-or-restart/enable/daemon-reload, ошибок команды и разбора нескольких active units.
- Package manager проверен для installed/missing, установки только отсутствующих, точных apt-аргументов, временного `policy-rc.d`, mode `0755`, cleanup после успеха и apt failure, а также сохранения чужого существующего policy-файла.
- Полный `go test ./... -count=1`, `go vet ./...` и отдельный Linux system test binary — PASS.
- Точная сборка установлена как `dev-qa11`; локальный/live SHA-256: `698f7bd9552965eb3aeccf28f152277eff3d78a4e06680074bf470ea7e8a0cf1`.
- После qa11: пять ожидаемых unit active/running, `NRestarts=0`, failed units — 0, plan clean, `/api/ping` PASS, warning/error netosd — 0; временный `/usr/sbin/policy-rc.d` отсутствует.

## Дополнение: Multi-WAN failover/balance, qa12

- Покрытие `internal/subsys/multiwan` поднято с 32,0% до 77,6%.
- Проверены metadata/plan, table/mark/priority, physical/PPPoE/L2TP interface names, ICMP/TCP/HTTP probes, IPv4/IPv6, default timeout, malformed target, fail/rise hysteresis, durable suppression, recovery, shutdown restore, paused monitor, stale state cleanup, corrupt JSON, balance tables/rules/owned state и cleanup.
- Полный `go test ./... -count=1`, `go vet ./...` и отдельный Linux test binary — PASS.
- Root Linux E2E в изолированном netns — PASS: failover действительно удалил primary default route и восстановил его после recovery; balance создал таблицы 3001/3002, fwmark-rules, healthy fallback и blackhole при all-down.
- После E2E namespace удалён; SHA-256 host routes и rules до/после совпали.
- История от `630d707e995585bc507de55fc5c150647e4f33d8` проверена для Multi-WAN: этот commit и последующие commits контроллер не меняли, циклического отката прежней Multi-WAN реализации здесь нет.
- `dev-qa12` установлен; локальный/live SHA-256: `dad661a3c5d933b4f11a5cb7cf4cd8e5042d8b6945bcbd5e787c975edc59cd91`.
- После qa12: пять unit active/running, `NRestarts=0`, failed units — 0, plan clean, `/api/ping` PASS, warning/error netosd — 0; QA namespace и Multi-WAN runtime-файлы при выключенной функции отсутствуют.

### DEF-016 — IPv6 health targets ложно считались недоступными

- Статус: исправлен, unit/Linux regression PASS.
- ICMP target IPv6 проходил validation, но probe всегда вызывал `ping -4`; теперь family выбирается по адресу.
- TCP target `[IPv6]:port` после `SplitHostPort` собирался без скобок; теперь используется `net.JoinHostPort`, результат `telnet://[IPv6]:port` корректен.

### DEF-017 — Multi-WAN мог принять две разные policy-rule за одну правильную

- Статус: исправлен, regression PASS.
- Отдельные глобальные `strings.Contains` находили нужный priority в одной строке и fwmark в другой. Теперь оба признака обязаны находиться в одной rule-строке; перекрёстные правила ремонтируются.

### DEF-018 — balance игнорировал отказ чтения default route

- Статус: исправлен, regression PASS.
- Ошибка `ip route show` отбрасывалась, после чего таблица могла остаться только с blackhole. Теперь Apply получает ошибку с именем uplink и запускает штатный rollback вместо молчаливого обрыва.

### DEF-019 — failover снимал маршрут даже при невозможности сохранить recovery state

- Статус: исправлен, regression PASS.
- После удаления default route ошибка записи `multiwan-suppressed.json` игнорировалась; crash демона мог сделать потерю маршрута постоянной. Теперь маршрут немедленно возвращается, suppression отменяется и ошибка журналируется; если restore тоже не удался, запись остаётся в памяти для повторной попытки при shutdown.

## Дополнение: статическая маршрутизация и policy rules, qa13

- История routing от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до изменения кода: сам backend-контроллер за этот период не менялся; `630d707` добавил aria-label в Routing UI и общую проверку ID, `91173d5` усилил валидацию типа маршрута, интерфейса, метрики и fwmark. Циклического отката прежней реализации в этом блоке нет.
- Покрытие `internal/subsys/routing` поднято с 33,3% до 100,0% statements: metadata/plan, реестры таблиц и протоколов, IPv4/IPv6 routes, все типы route, stale cleanup, policy selectors, reserved priorities, health, парсеры и все error-ветви каждого этапа `Apply`.
- Полный `go test ./... -count=1`, `go vet ./...`, cross-compiled Linux test binary — PASS.
- Root Linux E2E в отдельном netns — PASS: реальные IPv4 blackhole route, IPv6 unreachable route, таблица 200 и IPv4 rule 20123 созданы, health подтверждён, затем все объекты удалены. Namespace после теста отсутствует; SHA-256 всех host routes/rules до и после одинаков: `050cc8ce394d92bb5bdad6371cea307096a2f510cdfa546042ab208665f398e6`.
- `dev-qa13` установлен; локальный/live SHA-256: `013556e1cf1bf46fa0accbdb75d73bd16c6585a8063c642568287afaad7cab4f`.
- После qa13: `netosd`, `netos-dnsmasq`, `netos-unbound`, два Xray unit и `systemd-networkd` active/running, у всех `NRestarts=0`; failed units — 0, plan clean, `/api/ping` PASS. Routing применился за 35 ms без ошибки.
- Первый автоматический ping через 5 секунд попал в штатное начальное применение конфигурации: TLS listener открылся примерно через 11 секунд. После сообщения «панель доступна» повторный ping PASS. Внешние TLS-handshake warnings от клиента, не доверяющего self-signed cert, не связаны с routing/apply.

### DEF-020 — IPv6 static routes выполнялись как IPv4

- Статус: исправлен, unit/Linux E2E/live regression PASS.
- Валидатор и модель разрешали IPv6 destination/gateway, но контроллер всегда вызывал `ip -4`; IPv6 route гарантированно не применялся. Теперь family определяется по destination/gateway, а reconciliation и stale cleanup выполняются отдельно для `-4` и `-6`.

### DEF-021 — ошибка удаления policy rule игнорировалась

- Статус: исправлен, regression PASS.
- При выключении или замене правила ошибка `ip rule del` отбрасывалась. Для последнего правила Apply мог завершиться успехом, оставив stale policy routing. Теперь ошибка удаления немедленно прерывает Apply и запускает штатный rollback.

### DEF-022 — routing health мог подтвердить чужое или другое правило

- Статус: исправлен, regression PASS.
- Health искал имя таблицы как подстроку во всём выводе `ip rule`: `qa` совпадало с `qa-old`, а priority и table могли находиться в разных строках. Теперь точные priority и `lookup/table` обязаны совпасть в одной строке.

### DEF-023 — принимался маршрут со шлюзом другого семейства

- Статус: исправлен, validation regression PASS.
- Например, IPv4 destination с IPv6 gateway проходил сохранение и падал только во время `ip route replace`. Валидация теперь требует одинаковое семейство destination и gateway; matching IPv6 route принимается.

## Дополнение: sysctl, forwarding и IPv6 policy, qa14

- История `internal/subsys/sysctl` проверена: после `630d707e995585bc507de55fc5c150647e4f33d8` этот пакет не менялся, циклических правок агентов в блоке нет.
- Покрытие поднято с 36,5% до 95,7%; Core metadata/plan/apply/health и общие render/apply/check функции покрыты на 100%. Временный fake `/proc/sys`, `/sys/class/net`, sysctl.d и modules-load.d проверяет каждое значение, drift, whitespace normalization, missing keys и ошибки каждого файлового этапа.
- Полный `go test ./... -count=1`, `go vet ./...`, cross-compiled Linux test binary — PASS.
- Root Linux E2E в отдельном netns — PASS: реальный IPv6 переключён passthrough→off на dummy interface, оба состояния подтверждены Health; namespace удалён, SHA IPv6-состояния хоста до/после одинаков: `533f98f232ec82ea3027119a2d87de60e53718a5c903cf77e12b89857d1c0c16`.
- Добавлен `scripts/qa-check-sysctl.py`: он сопоставляет каждый ключ `netos render sysctl` с `/proc/sys` и отдельно проверяет disable_ipv6/accept_ra/autoconf каждого интерфейса.
- `dev-qa14` установлен; локальный/live SHA-256: `d824d2de5a66322b433c0bde60915351d1009b4f4439e3c7cfabb859ec897f90`.
- После qa14 readiness через 9 секунд, `/api/ping` PASS; шесть ожидаемых unit active/running, `NRestarts=0`, failed units — 0, plan clean. Все 39 глобальных и 6 interface-specific live-проверок sysctl PASS; warning/error netosd после старта — 0.

### DEF-024 — IPv6 Plan не замечал drift или удаление sysctl-файла

- Статус: исправлен, regression/live PASS.
- При одинаковом `old.IPv6.Mode` и `new.IPv6.Mode` Plan сразу возвращал «изменений нет», даже если `/etc/sysctl.d/99-netos-ipv6.conf` отсутствовал или был испорчен. Теперь Plan сравнивает точное live-содержимое с render и различает create/update.

### DEF-025 — Core Plan не контролировал modules-load.d

- Статус: исправлен, regression/live PASS.
- Plan сверял только `99-netos.conf`; удалённый или изменённый `/etc/modules-load.d/netos.conf` с `nf_conntrack` оставался невидимым. Теперь clean plan возможен только при точном совпадении обоих owned-файлов.

### DEF-026 — Health подтверждал только IPv4 forwarding

- Статус: исправлен, regression/Linux E2E/live PASS.
- Из более чем тридцати Core sysctl проверялся только `net.ipv4.ip_forward`; IPv6 Health смотрел только `all.disable_ipv6`. Неверные rp_filter, redirects, BBR, conntrack, buffers, RA/autoconf/default и параметры поднятых интерфейсов считались здоровыми. Теперь Health сверяет каждый существующий managed key и каждый non-loopback interface; отсутствующие в конкретном ядре ключи по-прежнему допустимы.

## Дополнение: apply transaction, health и rollback, qa15

- История от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до правок: `91173d5` менял API-валидацию apply-запроса, но `internal/apply/engine.go` за этот период не менялся. Циклического изменения engine между агентами в этом блоке нет.
- Покрытие `internal/apply` поднято с 57,7% до 97,7%. Все публичные функции, Plan/PlanFrom, validation guards, Confirm/Pending/Rollback, doRollback/restore/run/health покрыты на 100%; Apply — 95,4%, timer callback — 88,9%.
- Проверены порядок подсистем, annotation action, неизвестная подсистема, ошибки plan, запрет live-смены panel port/TLS, nil/invalid config, pending conflict, harmless/connectivity confirmation, commit callback failure/success, dry-run, current/rollback notice, manual/timeout/obsolete rollback, ошибки первого apply/health, двойной отказ new+rollback health и сохранение live context.
- Конкурентный набор выполнен 100 раз подряд; обычный полный `go test ./... -count=1`, `go vet ./...` и Linux apply test binary — PASS. `go test -race` технически недоступен: ни локальная Windows-среда, ни QA Debian не имеют C compiler `gcc`; это не отмечено как PASS.
- `dev-qa15` установлен; локальный/live SHA-256: `2a55d826389e2f45709a73fed1635d470fc6df249c1154e2974d9e42c259f1d5`.
- После qa15 readiness через 9 секунд, `/api/ping` PASS, защищённый `/api/config` без авторизации корректно вернул 401; шесть ожидаемых unit active/running и `NRestarts=0`, failed units — 0, plan clean. Стартовая ревизия 96 применена без pending/rollback; systemd warning journal после старта пуст.

### DEF-027 — rollback объявлялся успешным без Health восстановленного состояния

- Статус: исправлен, unit/Linux/live regression PASS.
- Откат после apply-error, health-error, manual или timeout выполнял только `Apply(previous)`. Если команды завершились с кодом 0, но сеть/файрволл/DNS фактически не восстановились, engine снимал pending, менял current, вызывал OnRollback и сообщал успех. Теперь единый `restore` после run обязательно вызывает health; двойная ошибка содержит причины нового состояния и отката.

### DEF-028 — неуспешный ручной rollback отменял safety timer

- Статус: исправлен, regression PASS.
- `Rollback` останавливал timer до попытки восстановления. При ошибке pending оставался, но автоматическая страховка уже никогда не срабатывала. Теперь timer останавливается только после успешного restore; тест подтверждает, что после ошибки pending и активный timer сохранены, current/rollback notice не подменены.

## Дополнение: исходящие VPN-каналы и monitor, qa16

- История от `630d707e995585bc507de55fc5c150647e4f33d8` проверена: backend-пакет `internal/subsys/channels` этим и последующими commits не менялся, циклических правок агентов здесь нет.
- Покрытие поднято с 44,6% до 79,4%: metadata/index/table/mark/priority, Plan create/update/delete, WireGuard/OpenConnect/Xray artifacts и lifecycle, ownership/type transition, foreign TUN, exact routes/rules, cleanup verification, monitor pause/tick/state, ICMP/TCP/HTTP IPv4/IPv6 probes и health.
- Полный `go test ./... -count=1`, `go vet ./...` и Linux channels test binary — PASS.
- Root Linux E2E: реальные WireGuard и Xray lifecycle, health, block/direct/fallback, idempotent apply и cleanup — PASS. OpenConnect E2E — честный SKIP: отсутствуют отдельный `NETOS_OC_SERVER` и `NETOS_OC_PASSWORD`; локальный fake-systemd/kernel lifecycle OpenConnect полностью PASS.
- SHA host links/routes/rules/systemd unit-files до/после E2E одинаков: `77c7bbff60451407099bbb3cc10310f719f325c180eec1296a6f4f176237b273`.
- `dev-qa16` установлен; локальный/live SHA-256: `c36e165a8a5ba27a4820ad75aa6aae124be74a7b44a043972bb6eb9630448f93`.
- После qa16 readiness через 10 секунд, `/api/ping` PASS, шесть unit active/running и `NRestarts=0`, failed units — 0, plan clean, warning journal пуст. Live Xray PID до/после остался `61636`, `NRestarts=0`; ownership exact (`tun-ch1`, type xray, правильный unit), то есть idempotent apply не перезапустил канал.

### DEF-029 — IPv6 channel probes выполнялись только через IPv4

- Статус: исправлен, unit/Linux regression PASS.
- Валидатор принимает IPv6 ICMP и `[IPv6]:port`, но monitor всегда использовал `ping -4`, а TCP dialer — `tcp4`. Теперь ICMP выбирает `-4/-6` по адресу, TCP использует dual-stack `tcp` и сохраняет `SO_BINDTODEVICE` на Linux.

### DEF-030 — channel Health мог собрать «правильное» правило из разных строк

- Статус: исправлен, regression/live PASS.
- Priority и fwmark искались отдельными глобальными `Contains`, а lookup-table вообще не проверялась. Теперь точные priority, fwmark и numeric/named lookup обязаны совпасть в одной строке.

### DEF-031 — конфликтующее или direct-fail правило могло не удалиться без ошибки

- Статус: исправлен, regression PASS.
- `ensureRuleTable` и fail-mode direct/fallback игнорировали ошибку `ip rule del`. Старый lookup мог остаться рядом с новым правилом, а monitor помечал канал Down, хотя трафик продолжал идти в неисправный tunnel. Теперь наличие priority сначала проверяется, а ошибка удаления прерывает transition.

### DEF-032 — смена типа Xray↔OpenConnect оставляла старый unit

- Статус: исправлен, regression/live idempotency PASS.
- Оба типа используют `tun-chN`; ownership сравнивался только по имени интерфейса, поэтому старый unit не убирался и затем забывался. Теперь сравниваются name+type+unit; несовпадающий старый lifecycle полностью очищается до запуска нового.

### DEF-033 — OpenConnect/Xray принимали чужой существующий TUN

- Статус: исправлен, regression PASS.
- В отличие от WireGuard, эти apply-функции не сверяли ownership и могли принять `tun-chN`, созданный другим процессом. Теперь существующий interface допустим только при точном retained ownership.

### DEF-034 — неуспешный cleanup навсегда терял ownership

- Статус: исправлен, regression PASS.
- `removeChannel` игнорировал все ошибки, после чего `owned-channels.json` переписывался без объекта. Оставшийся link/unit/rule/table больше никогда не убирался. Теперь cleanup верифицирует inactive unit, отсутствие link/rule и пустую table; при расхождении Apply падает, а ownership сохраняется для повтора/rollback.

### DEF-035 — route на `tun-ch10` принимался за route на `tun-ch1`

- Статус: исправлен, regression PASS.
- Ensure/Health использовали подстроку `default dev <name>`. Теперь default dev и blackhole default разбираются как точные токены отдельных route-строк.

## Дополнение: VPN-серверы WireGuard, Xray, OpenConnect и IKEv2, qa17

- История `internal/subsys/vpnservers` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до начала правок: пакет в последующих commits не менялся, круговых исправлений разных агентов в этом блоке нет.
- Покрытие пакета поднято с 47,2% до 68,8%. Проверены metadata, сортировка и Plan create/update/delete, точное сопоставление адресов, ownership, чужие unit/interface, смена типа, WireGuard/Xray/ocserv lifecycle, idempotent Apply, Health и подтверждённый cleanup.
- Полный `go test ./... -count=1`, `go vet ./...`, `git diff --check` и Linux test binary — PASS.
- Root Linux E2E на QA-хосте — PASS для всех трёх независимых транспортов: WireGuard server/client handshake и ping; ocserv↔OpenConnect с явным клиентским адресом, затем тот же сервер через lifecycle исходящего OpenConnect-канала netOS; IKEv2 EAP-MSCHAPv2, выдача адреса, XFRM и ping. Для каждого проверены Health, повторный Apply без рестарта и удаление unit/config/link.
- Для IKEv2 временно установлен точный набор strongSwan из catalog netOS плюс `charon-cmd`; для OpenConnect — клиентские зависимости. Полный снимок пакетов сделан до теста. После тестов удалены ровно 36 новых пакетов, повторная точечная IKE-проверка добавляла и затем удалила 8 пакетов. Итоговый список установленных пакетов восстановлен.
- SHA host links/routes/rules/netOS unit-files до тестов и после полного cleanup совпал: `8624b04957ddf98e89bb2c483da972c1fdf19672c2985b653e79fc5326fc734e`. Временных namespace, interfaces и test units не осталось.
- `dev-qa17` установлен; локальный/live SHA-256: `0d1bdaf2dcacdba29389a6863fa135761ce87258914db28ad40cd545816759ec`.
- После qa17: `/api/ping` 200, неавторизованный `/api/config` 401, шесть ожидаемых unit active/running, `NRestarts=0`, failed units — 0, `netos plan` clean, ownership Xray-сервера точный, warning-журнал netosd пуст. Live Xray server сохранил PID `61750` и `ActiveEnterTimestampMonotonic=14506512775`, то есть apply его не перезапустил.
- Полный защищённый live API sweep не повторён: сохранённые в `dev_server_creds.txt` данные вернули 401 на login. Публичный/неавторизованный контракт и сервисы исправны; qa17 не менял auth-код. Это отмечено как несовпадение QA credentials, а не как PASS защищённых API.

### DEF-036 — неуспешное удаление VPN-сервера теряло ownership

- Статус: исправлен, unit/Linux/live regression PASS.
- Старый `remove` игнорировал ошибки остановки/удаления и Apply всё равно переписывал `owned-vpn-servers.json`. Теперь cleanup проверяет inactive unit, отсутствие конфигов, каталогов и link; при остатке Apply возвращает ошибку и сохраняет прежний ownership.

### DEF-037 — Xray, ocserv и IKEv2 могли перезаписать чужой systemd-unit

- Статус: исправлен, regression и реальные lifecycle PASS.
- Наличие unit-файла считалось достаточным признаком уже созданного сервера. Теперь существующие Xray/ocserv units и общий `netos-strongswan.service` допустимы только при подтверждённом ownership; чужой файл отклоняется до записи. Для общего IKEv2 unit сохранена корректная миграция между принадлежащими netOS серверами.

### DEF-038 — адрес интерфейса проверялся подстрокой

- Статус: исправлен, regression/Linux E2E PASS.
- `10.0.0.1/24` мог ошибочно совпасть с частью другого вывода. Ensure и Health теперь ищут точный whitespace-token адреса; отдельно проверен отрицательный случай с похожим адресом.

### OBS-005 — Debian `charon-cmd` мог зациклить транспорт IKE в table 220

- В одном наборе плагинов тестовый клиент добавлял подключённую `192.0.2.0/30` через собственный `ipsec0`, и `IKE_SA_INIT` не покидал namespace. Packet capture и route inspection подтвердили отсутствие пакета на host veth. Linux E2E helper теперь условно удаляет только этот ошибочный helper-route и отдельно отслеживает ранний выход клиента; при штатном наборе, где route не создаётся, тест также работает. Это поведение тестового клиента, не конфигурации netOS-сервера.

## Дополнение: Interfaces, Networks и WAN — работа продолжается

- История `internal/subsys/netiface` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до начала правок: `5019389`, `a641105` и `91173d5` добавляли разные защиты и не отменяли друг друга; круговой смены одного решения между агентами в этом блоке не найдено.
- Локальное покрытие пакета поднято с 49,3% до 70,6%; package tests и `go vet` проходят. Проверены Interfaces/bridge/VLAN/bond, Networks, static/DHCP/PPPoE/L2TP, точное владение адресами и маршрутами, Health, idempotency, cleanup и ошибки каждого этапа.
- Root Linux DHCP E2E PASS после найденного дефекта генератора lease-state: реальный dnsmasq/udhcpc, адрес, default route, Health, сохранение чужого адреса, restart при смене metric и точечный stop cleanup.
- Реальные PPPoE E2E PASS: успешный PAP, адрес/имя интерфейса/default metric/IPv6 и отказ при неверном пароле. Реальный L2TP E2E PASS: PAP, адрес/имя интерфейса/default metric и MTU 1400.
- Для этих тестов временно установлены `ppp`, `pppoe`, `xl2tpd`, `libpcap0.8t64`; package/manual snapshots сохранены. Удаление пакетов и финальное сравнение ожидают восстановления SSH.

### DEF-039 — DHCP lease-state повреждался форматтером генератора

- Статус: исправлен, unit/Linux E2E PASS.
- Shell `printf '%s\n'` проходил через `fmt.Fprintf` без экранирования и превращался в `%!s(MISSING)`. DHCP ACK, адрес и маршрут появлялись, но state-файл не записывался и Health завершался timeout. Литерал заменён на `%%s`; regression проверяет готовый script и запрещает `%!`.

### DEF-040 — WAN считал своими все default routes с общим proto 201

- Статус: исправлен локально, unit regression PASS; live regression ожидает восстановления QA.
- `cleanupStaticRoutes` сканировал все default routes `proto 201` и удалял отсутствующие в текущем WAN-наборе. Но `proto 201` общий для WAN, Routing и L2TP, поэтому это не доказательство ownership. Во время нового lifecycle-теста с намеренно изолированным конфигом был удалён боевой default route QA-хоста и потерян SSH/TLS payload; TCP listener остаётся доступен, но SSH banner не возвращается.
- WAN переведён на точный persistent `owned-wan-routes.json` с полями gateway/interface/metric. Перед cleanup записывается объединение old+new; при ошибке удаления ownership не теряется. Не принадлежащие WAN маршруты больше даже не сканируются.
- Для восстановления QA нужен reboot через консоль провайдера. После загрузки netosd должен применить полный active config; затем требуется удалить тестовые PPPoE unit/veth/netns и четыре временных пакета, сравнить snapshot и повторить E2E безопасной версией.

## Дополнение: установка и удаление компонентов — работа продолжается

- История `internal/subsys/components` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до текущего состояния: `9bed3ac`, `bb5e4c9`, `91173d5`. Прямой циклической отмены правок нет, но найден межкоммитный стыковочный регресс: проверка закреплённой версии из `9bed3ac` стала недостижимой после раннего пропуска существующего файла в `componentState`, добавленного `91173d5`.
- Покрытие пакета поднято с 51,7% до 80,0% (`go tool cover` по всему backend показывает 85,4% для файлов пакета с учётом внешних тестов). На 100% покрыты `Name`, `Plan`, `Health`, `Status`, `Running`, сопоставление unit-шаблонов и точное сравнение версии.
- Проверены create/delete/no-op/essential/partial планы, актуальный/устаревший/отсутствующий внешний бинарник, реальная замена файла из архива с SHA-256, точные границы версии, статусы пакетов, активные unit-шаблоны, ошибка остановки штатного демона и запрет purge при этой ошибке.

### DEF-041 — существующий устаревший внешний бинарник никогда не переустанавливался

- Статус: исправлен локально, unit regression PASS; live regression ожидает восстановления QA.
- `componentState` считал любой существующий target внешнего компонента полностью установленным. Поэтому `Plan` и `Apply` пропускали компонент до вызова `externalCurrent`; устаревший, повреждённый или подменённый `xray`/`dnsproxy` оставался навсегда. Теперь наличие и актуальность разделены: файл означает partial installation, а полная установка требует успешного запуска version-команды и точного совпадения закреплённой версии.
- Старое сравнение `strings.Contains` принимало `126.7.280` за `26.7.28`. Новый matcher требует отдельный version-token; положительные и prefix/suffix/embedded отрицательные случаи покрыты таблицей.

### DEF-042 — ошибки отключения штатного демона скрывались, а повторный Apply не исправлял состояние

- Статус: исправлен локально, unit regression PASS; live regression ожидает восстановления QA.
- Установка и удаление игнорировали результат `Systemd.Disable`. Операция могла считаться успешной при продолжающем работать штатном daemon, занятом порте или включённом автозапуске. Теперь ошибка возвращается с именем unit; удаление останавливается до `apt purge`.
- Полнота package-компонента теперь включает состояние всех перечисленных штатных unit: они должны быть одновременно inactive и disabled/static. Поэтому если пакет уже успел установиться, но остановка не удалась, следующий `Plan` остаётся грязным и `Apply` повторяет исправление вместо вечного пропуска.

### DEF-043 — после установки внешний бинарник не запускался и не откатывался при отказе

- Статус: исправлен локально, unit regression PASS; live regression ожидает восстановления QA.
- После проверки SHA-256 и rename операция сразу возвращала успех. Повреждённый на диске, неисполнимый или сообщающий другую версию target обнаруживался только при следующем запросе статуса. Теперь установка обязана запустить version-команду с 10-секундным timeout и подтвердить точную закреплённую версию.
- Перед заменой существующий regular target сохраняется hard-link’ом. При провале post-install проверки предыдущий бинарник возвращается, а неработоспособная первая установка удаляется; временный rollback-файл не остаётся. Оба пути покрыты отдельными тестами.

### DEF-044 — выключение PPPoE могло удалить общий пакет `ppp` у включённого L2TP

- Статус: исправлен локально, unit regression PASS; live regression ожидает восстановления QA.
- `remove` удалял весь список packages выключенного компонента, не учитывая потребности остальных выбранных компонентов. L2TP и PPPoE совместно используют `ppp`: при некоторых направлениях переключения итоговая включённая функция оставалась без зависимости; в других пакет лишний раз purge/install.
- `Plan` и `Apply` теперь строят множество packages, защищённых всеми выбранными и essential компонентами. Purge получает только эксклюзивные пакеты выключаемого компонента. Оставшийся общий пакет больше не создаёт вечное delete-действие; оба направления и точные аргументы apt покрыты regression-тестами.

### DEF-045 — polling страницы компонентов накапливал параллельные запросы

- Статус: исправлен локально, TypeScript/production build PASS; browser/live regression ожидает доступной встроенной вкладки и восстановления QA.
- `setInterval(5000)` запускал новый `/api/catalog`, не дожидаясь предыдущего. Медленные `dpkg-query`, `systemctl` или version-команды могли создать очередь перекрывающихся запросов и процессов. Теперь одновременно существует ровно один запрос: он отменяется через 15 секунд, следующая попытка ставится через 5 секунд после завершения, а unmount отменяет запрос и timer.
- UI теперь различает `готов`, `будет установлен или исправлен`, `будет удалён` и `базовый пакет останется`; тип каталога включает `essential`. Поле `installed` документировано как полная готовность payload/version/stock-unit, а не простое наличие любого файла.

### DEF-046 — oversized внешний payload молча обрезался лимитом

- Статус: исправлен локально, unit/network regression PASS.
- HTTP body и распакованный ZIP/TAR читались через `LimitReader(256 MiB)` без проверки дополнительного байта. Превышение возвращало успешный усечённый результат. Единый reader теперь читает максимум `limit+1` и возвращает явную ошибку размера; exact-limit и over-limit проверены для raw/ZIP/TAR.

### Текущий итог блока Components

- Локальное statement coverage пакета поднято с 51,7% до 92,2%; `Plan`, `Apply`, metadata helpers, removable/protected-package logic, `externalCurrent`, `remove`, `Health`, `Status`, `Running` и unit-pattern matching покрыты на 100%.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web `npm run build` — PASS.
- Реальные официальные pinned-архивы Xray и dnsproxy скачаны для `amd64` и `arm64`: все четыре URL доступны, SHA-256 совпали, точные файлы извлечены, ELF magic и machine соответствуют архитектурам. Системные пути не изменялись.
- Проверка каталога проходит по каждому полю и записи: ID/title/group/description/size, packages, unit patterns, source XOR, release mapping, targets, version args, HTTPS URL, обе SHA-256, отсутствие orphan releases и непроверенных общих пакетов.
- Linux test binary собран. Реальные apt/systemd install/remove/update, post-install version, логи, API polling и UI состояния остаются на QA после восстановления доступа; встроенный Browser сейчас не имеет доступных вкладок, поэтому UI не отмечен как live PASS.

## Дополнение: hostname, timezone и NTP — работа продолжается

- История `internal/subsys/hostsettings` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена: сам пакет после этого коммита другими агентами не менялся, циклических правок в нём нет.
- Statement coverage поднято с 55,1% до 99,0%; все функции кроме одного платформенного chmod-error ответвления покрыты на 100%, `applyNTP` — 96,4%.
- Проверены initial/clean/drift Plan, hostname/timezone, tuned ordering и отказ остановки, NTP on/off, active/inactive × enabled/disabled × same/changed config, exact file, directory permissions, повторный Apply, все command/filesystem errors, Health mismatch/error каждого поля и все допустимые `systemctl is-enabled` состояния.

### DEF-047 — Plan не видел live drift hostname/timezone и пропускал initial plan

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Hostname и timezone сравнивались только между `old`/`new`; внешняя смена после Apply оставляла план чистым. При `old=nil` функция возвращалась до этих проверок и не показывала фактические начальные действия. Теперь Plan всегда сравнивает желаемые значения с `hostnamectl --static` и `timedatectl ... Timezone`; initial plan показывает только реально нужные изменения.

### DEF-048 — любой Apply безусловно менял host settings и перезапускал timesyncd

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Даже несвязанное изменение вызывало `hostnamectl set-hostname`, `timedatectl set-timezone`, перепись NTP drop-in, `enable --now` и `restart`. Теперь hostname/timezone меняются только при live drift. NTP no-op не пишет файл и не трогает unit; изменённый конфиг перезапускает только уже активный unit, неактивный запускается один раз с новым файлом, disabled-only состояние только включается.
- Два последовательных Apply на совпадающем состоянии подтверждают неизменный mtime и отсутствие всех mutating-команд. Права drop-in каталога входят в Plan/Health и исправляются без рестарта службы.

### DEF-049 — чистый установщик не гарантировал наличие systemd-timesyncd

- Статус: исправлен локально в `install.sh`; clean-install live regression ожидает полного uninstall/reinstall QA.
- NTP включён по умолчанию, но базовый `PACKAGES` не содержал `systemd-timesyncd`. На минимальном Debian/Ubuntu первый Apply мог упасть на отсутствующем unit. Пакет добавлен в обязательные зависимости установщика.

## Дополнение: Dynamic DNS — работа продолжается

- История `internal/subsys/ddns` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена: после исходного состояния контроллер менялся только в `91173d5`; круговых правок разных агентов внутри этого пакета не найдено.
- Statement coverage DDNS поднято с 56,3% до 97,3%. `Plan`, `Apply`, `Health`, `Status`, `tick`, provider-error и bounded-reader покрыты на 100%; проверены create/update/delete, все поля трёх провайдеров, web/interface/PPPoE/L2TP address source, IPv4/IPv6/битые адреса, HTTP/сеть/body, лимиты, расписание, отмена Run, логирование и конкурентная смена конфигурации.
- Контракты сверены с официальными спецификациями DuckDNS, Cloudflare и No-IP. Cloudflare использует частичный `PATCH` и не затирает `proxied`; DuckDNS использует HTTPS GET и точный `OK`; No-IP различает `good`, `nochg`, постоянные ошибки и обязательный 30-минутный backoff.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, 50 последовательных прогонов DDNS и web production build — PASS. Linux test binary собран, SHA-256 `eb6a4a700a4d2c95ea28e3d92d40449e3718c75bff2496cfcded475526226c9d`.
- Linux/live и Browser UI пока не отмечены как PASS: QA по-прежнему принимает TCP, но не выдаёт SSH banner (`No existing session` / `Error reading SSH protocol banner`), а во встроенном Browser нет доступной вкладки. Требуется восстановление/перезагрузка QA через консоль провайдера.

### DEF-050 — любой Apply сбрасывал DDNS runtime-состояние и провоцировал лишнее обновление

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Engine вызывает каждую подсистему и при несвязанном изменении. Старый DDNS `Apply` всегда стирал `LastRun`, `NextRun`, `Address`, `Success` и `Message`, после чего следующий tick немедленно повторял запрос провайдеру. Теперь точное совпадение всех DDNS-полей сохраняет runtime-состояние; реальное изменение, включая секрет, сбрасывает расписание и разрешает немедленное обновление.

### DEF-051 — запоздалый ответ старой DDNS-конфигурации перезаписывал новую

- Статус: исправлен локально, управляемый concurrent regression PASS.
- HTTP-запрос мог выполняться одновременно с новым Apply. Ответ по старому hostname/token после завершения записывал устаревшие Provider/Hostname/Success/NextRun. Контроллер теперь перед публикацией результата и логированием повторно сверяет полный DDNS snapshot; устаревший результат не меняет статус и не оставляет ложную запись в журнале. Тест блокирует provider response, применяет новую запись и затем отпускает старый ответ.

### DEF-052 — ответы DDNS тихо обрезались, а ошибки чтения игнорировались

- Статус: исправлен локально, unit regression PASS.
- Address service читал максимум 128 байт, provider — 4096 байт через `LimitReader`, но не проверял дополнительный байт и игнорировал ошибку `Read`. Усечённый ответ мог быть принят по валидному префиксу. Единый bounded reader читает `limit+1`, отвергает overflow и возвращает read error; exact-limit, overflow и faulting-reader покрыты отдельно. Для HTTP error код проверяется до body, чтобы огромное тело не маскировало обязательный backoff.

### DEF-053 — No-IP нарушал официальный retry-протокол и мог добиться блокировки клиента

- Статус: исправлен локально, provider-matrix regression PASS; реальная учётная запись No-IP не использовалась.
- Старый код отправлял update каждый интервал даже при неизменном IP и одинаково повторял `badauth`, `nohost`, `abuse`, `badagent`, `911` и HTTP 500. Теперь неизменный успешно подтверждённый адрес не отправляется повторно; постоянные ошибки приостанавливают запросы до изменения настройки; `911` и HTTP 500 назначают минимум 30 минут; UI явно показывает сообщение о приостановке.

### DEF-054 — DuckDNS принимал домен, который нельзя корректно передать как зарегистрированный subname

- Статус: исправлен локально, config/controller regression PASS.
- Общая DNS-валидация принимала, например, `router.example.test`, а update передавал его целиком в `domains`, хотя DuckDNS ожидает subname своей зоны. Для DuckDNS теперь требуется одно имя вида `router.duckdns.org`, суффикс удаляется перед запросом; произвольная зона, голая зона и вложенный sub-subdomain отвергаются.

### DEF-055 — UI polling DDNS мог накапливать параллельные запросы и скрывал отказ API

- Статус: исправлен локально, TypeScript/production build PASS; Browser/live ожидает доступной вкладки и QA.
- `setInterval(10000)` запускал новый `/api/ddns/status`, не дожидаясь старого, и проглатывал все ошибки. Теперь одновременно существует один abortable запрос с timeout 15 секунд; следующий ставится только после завершения, ошибка видна пользователю, retry ускоряется до 5 секунд, unmount отменяет запрос и timer. UI показывает фактический IPv4, last/next run и provider-specific placeholder DuckDNS.

## Дополнение: Firewall — работа продолжается

- История `internal/subsys/firewall` от `630d707e995585bc507de55fc5c150647e4f33d8` проверена до начала правок: последующие изменения `86a853c` и `91173d5` добавляли subnet parsing и выбор исходящего интерфейса; обратных или циклических правок в этом блоке не найдено.
- Statement coverage пакета поднято с 62,3% до 94,8%. Генерация ruleset, все селекторы правила, зоны и политики, все типы каналов/VPN-серверов, source/destination NAT, port-forward accept, isolation, DNS/Multi-WAN policy, IPv6 и утилиты покрыты детальной матрицей; lifecycle отдельно проверяет plan/apply/health, drift, idempotency, preflight, состояние файлов и rollback.
- В панели теперь представлены все поля `FirewallRule`: interface, protocol, source/destination IP и port, MAC, conntrack state, destination zone, action, log, comment и UTC schedule с каждым днём недели. У NAT доступны все пользовательские поля, включая comment; системное NAT-правило нельзя удалить из панели.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux firewall test binary собран, SHA-256 `b4432816ede8a03b6fca10fe710e10ac28d6e68067461ac54dcd1c5335b1929c`.
- Linux/live не отмечен как PASS: повторное соединение с QA снова завершилось `Error reading SSH protocol banner` / `No existing session`. Поэтому фактическая канонизация `iptables-save`, packet matrix, systemd/config/log monitoring и cleanup должны быть выполнены после восстановления консольного доступа.

### DEF-056 — Firewall Health подтверждал только наличие IPv4-цепочек

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Health искал имена ожидаемых цепочек как подстроки только в `iptables-save`. Изменённые, лишние или удалённые правила внутри существующей цепочки, неверные политики и весь IPv6 ruleset считались здоровыми. Теперь managed tables IPv4 и IPv6 сравниваются семантически целиком; игнорируются только счётчики, комментарии генератора и посторонние unmanaged tables. Выключенный firewall также проверяется на точное ожидаемое состояние.

### DEF-057 — Apply не имел полной транзакции и восстанавливал не обязательно живое состояние

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Правила писались и применялись последовательно без `iptables-restore --test`; отказ IPv6-файла или одной семьи оставлял частично новое состояние. Добавлены preflight обеих семей, атомарное сохранение пары файлов и rollback. Перед изменением отдельно снимается реальный `iptables-save`/`ip6tables-save`: тест намеренно задаёт файловое состояние, отличное от живого, и подтверждает восстановление каждого к своему исходному значению.

### DEF-058 — каждый Apply безусловно переписывал и повторно применял Firewall

- Статус: исправлен локально, unit regression PASS; Linux/live ожидает восстановления QA.
- Несвязанное изменение конфигурации вызывало оба restore и перепись файлов. Теперь точное совпадение runtime и защищённых файлов даёт read-only no-op с неизменным mtime; при исправном runtime и повреждённом/отсутствующем файле ремонтируется только persisted state. Plan при одинаковых конфигурациях отдельно сообщает живой drift.

### DEF-059 — destination NAT допускал неоднозначные и некорректные порты

- Статус: исправлен локально, config/generator regression PASS.
- Пустой внешний порт, списки портов и обратные диапазоны проходили общую проверку; внутренний диапазон `9000-9010` попадал в accept-правило в несовместимом с iptables виде. Для NAT теперь обязателен один внешний порт или один диапазон, списки и descending ranges запрещены, interface защищён общей проверкой имени, а оба диапазона преобразуются в синтаксис `start:end`.

### DEF-060 — расписание Firewall зависело от ненадёжной kernel timezone

- Статус: исправлен локально, generator/UI regression PASS; live time-match ожидает QA.
- Генератор всегда добавлял `--kerneltz`, хотя kernel timezone часто остаётся UTC и не обновляется при DST. Семантика теперь явно определена как UTC в модели и панели, `--kerneltz` удалён; дни и обе временные границы проверяются отдельно.

### DEF-061 — панель Firewall не позволяла задать значительную часть модели

- Статус: исправлен локально, TypeScript/production build PASS; Browser/live ожидает QA.
- В RuleForm отсутствовали interface, source port, conntrack state, schedule и редактирование comment; краткое описание также скрывало source port и schedule. Поля добавлены, проверка обязательного TCP/UDP учитывает оба порта. NAT comment стал доступен для source и destination, а системный destination NAT защищён от удаления так же, как source.

## Дополнение: QoS, CAKE и лимиты клиентов — работа продолжается

- Backend `internal/subsys/qos` после `630d707e995585bc507de55fc5c150647e4f33d8` не менялся; последующие UI-коммиты `8303e80` и `91173d5` затрагивали представление/общую конфигурацию, но не обращали QoS-поведение назад. Циклических исправлений агентов в этом блоке не найдено.
- Statement coverage поднято с 70,0% до 96,7%. `Plan`, `desiredLinks`, `applyLink`, client apply, cleanup, ownership, парсинг `tc` и все вспомогательные функции покрыты полностью или почти полностью; проверены DHCP/static/PPPoE/L2TP, все DiffServ-профили, обе скорости, IFB, HTB, download flower и upload police для каждого MAC.
- Health теперь сопоставляет ownership и фактические qdisc/class/filter: точные upload/download rate с нормализацией `Kbit/Mbit/Gbit`, DiffServ, `nat/wash/ingress`, redirect на нужный IFB, HTB class IDs, preference, MAC и отсутствие лишних фильтров. Ошибка каждой команды и каждый тип drift проверены отдельно.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux QoS test binary собран, SHA-256 `370a490aadce990039ae7e34cdb7f14255111cf890abd343a5fa78dd76d5efd8`.
- Linux/live повторно не отмечен как PASS: QA снова завершил подключение `Error reading SSH protocol banner` / `No existing session`. Предыдущий CAKE/client shaping/iperf3 E2E остаётся историческим доказательством старой реализации; новый exact Health, idempotency, cleanup и обновление классов требуют повторного live-прогона с `tc -s`, iperf, systemd и журналами после восстановления стенда.

### DEF-062 — QoS Plan путал клиентские лимиты с удалением CAKE и не видел live drift

- Статус: исправлен локально, unit regression PASS; live ожидает QA.
- Любое изменение `Clients` при выключенном `qos.enabled` возвращало действие `delete` для «CAKE на интернет-каналах». Теперь CAKE и HTB/policing дают отдельные create/update/delete actions; учитываются только поля клиента, реально влияющие на QoS. При неизменном конфиге Plan запускает точную live-проверку и сообщает drift.

### DEF-063 — QoS Health подтверждал произвольную очередь по словам `cake`, `htb` или `ingress`

- Статус: исправлен локально, exhaustive unit regression PASS; live parser ожидает QA.
- Неверная скорость, профиль, направление, IFB, MAC, class ID, preference или policing считались здоровыми. Health теперь сверяет все эти параметры и ownership, различает ожидаемые/лишние qdisc и фильтры и корректно нормализует эквивалентные единицы скорости.

### DEF-064 — чистый QoS Apply каждый раз повторно перестраивал живые очереди

- Статус: исправлен локально, idempotency regression PASS; live mtime/runtime ожидает QA.
- Повторный Apply не создавал IFB второй раз, но всё равно выполнял все `tc ... replace` и переписывал ownership. Теперь точное совпадение Health приводит только к read-only командам; тест подтверждает отсутствие add/replace/delete и неизменный mtime файла ownership.

### DEF-065 — ошибки cleanup игнорировались, а ownership стирался без проверки результата

- Статус: исправлен локально, negative regression PASS; live cleanup ожидает QA.
- Удаление WAN/client qdisc и IFB всегда считалось успешным независимо от exit status и фактического остатка. Теперь допускаются только подтверждённо отсутствующие объекты, прочие ошибки возвращаются, после успешной команды выполняется post-check, а ownership сохраняется до доказанного cleanup.

### DEF-066 — удалённый клиент мог навсегда остаться в старом HTB/flower/police

- Статус: исправлен локально, stale-filter regression PASS; live traffic ожидает QA.
- `replace` создавал/обновлял ожидаемые классы, но не удалял старые классы и фильтры клиентов, исчезнувших из конфигурации. При реальном изменении принадлежащие netOS root/ingress trees теперь очищаются и строятся заново; чистый Apply остаётся no-op. Health отвергает дополнительные MAC-фильтры и классы.

### DEF-067 — ошибка нового QoS-объекта могла оставить неучтённый IFB или qdisc

- Статус: исправлен локально, double-failure regression PASS; live fault injection ожидает QA.
- При частичном apply новый объект ещё отсутствовал в ownership. Если компенсирующая уборка также падала, следующий запуск не знал о нём. Теперь новый объект убирается при ошибке; при двойном отказе аварийно записывается в ownership для следующей попытки. Отдельно целевые WAN/client interfaces проверяются до удаления старой рабочей конфигурации, а отказ записи ownership запускает cleanup новых объектов.

### DEF-068 — клиентские лимиты не имели верхней границы

- Статус: исправлен локально, validation/UI regression PASS.
- В отличие от WAN QoS, `down_kbit`/`up_kbit` принимали произвольно большие значения. Границы унифицированы: `0` означает отсутствие лимита, положительный лимит — от 64 до 10000000 Кбит/с; обе точные границы, значения ниже и выше проверены, атрибуты UI синхронизированы с backend.

## Дополнение: Wi-Fi и hostapd — работа продолжается

- История блока после `630d707e995585bc507de55fc5c150647e4f33d8` проверена: единственный профильный commit `91173d5` добавил корректное HT40-направление, проверку всех BSS и collision-safe ID. Изменения аддитивны; обратных или циклических исправлений разных агентов не найдено.
- Statement coverage поднято с 78,3% до 96,1%. Весь renderer, все security modes, band/width/channel geometry, hidden/isolate, BSS numbering, metadata/path helpers, `Plan`, `applyRadio`, публичный `Health`, exact `iw` parser и почти весь cleanup покрыты на 100%.
- Проверены open/WPA2/WPA3/mixed, 2,4/5 GHz, 20/40/80 MHz, secondary/center channel, country, txpower, несколько и выключенные SSID, разные bridges, точные file modes, enabled/active unit, primary/secondary BSS, retry/cancellation и каждый systemd/iw/file failure.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux Wi-Fi test binary собран, SHA-256 `c74c3ac51a7c24d1fccf063edcb9d119c91d42b89f879c5524001b87a17c5060`.
- Повторный live mac80211_hwsim/hostapd E2E, client association, service/config/log monitoring и cleanup ожидают восстановления QA SSH. Предыдущий реальный четырёх-BSS lifecycle остаётся историческим PASS, но не заменяет регрессию новой exact-логики.

### DEF-069 — Wi-Fi Plan не видел live drift, а чистый Apply мутировал систему

- Статус: исправлен локально, plan/idempotency regression PASS; live ожидает QA.
- При одинаковых конфигурациях Plan всегда был пустым. Apply повторно переписывал оба файла, ставил txpower, вызывал `enable` и иногда restart. Теперь Plan делает быстрый live-check; точное состояние приводит только к read-only проверкам с неизменными mtime, а отсутствующий BSS или иной drift вызывает ремонт.

### DEF-070 — Wi-Fi Health принимал совпадения по подстрокам и игнорировал артефакты/ownership

- Статус: исправлен локально, exhaustive unit regression PASS; live parser ожидает QA.
- `channel 36` мог совпасть с другим числом, короткий SSID — с более длинным, а files, permissions, enabled state, txpower и ownership не проверялись. Новый parser требует exact Interface/type AP/channel/SSID и txpower; Health сверяет конфиг/unit побайтово, права, ownership, enable/active и каждый BSS. Ожидание поддерживает контекст и немедленно отменяется вместо безусловной задержки до девяти секунд.

### DEF-071 — Wi-Fi cleanup терял ownership независимо от ошибок и остаточного unit

- Статус: исправлен локально, negative/post-check regression PASS; live cleanup ожидает QA.
- Ошибки stop/disable/remove/daemon-reload полностью игнорировались, после чего ownership переписывался. Теперь отсутствующий объект обрабатывается идемпотентно, остальные ошибки возвращаются; дополнительно проверяются inactive unit и удаление обоих артефактов. До подтверждённого cleanup прежний ownership сохраняется.

### DEF-072 — apply мог перезаписать чужой hashed hostapd unit/config

- Статус: исправлен локально, foreign-artifact regression PASS.
- Наличие файла с вычисленным именем не сопоставлялось с `owned-wifi.json`. Теперь все желаемые radio предварительно рендерятся и проверяются до удаления старых рабочих точек; существующий config/unit без точного ownership или противоречивый unit отклоняется до записи.

### DEF-073 — двойной отказ запуска и cleanup оставлял неучтённую точку доступа

- Статус: исправлен локально, double-failure regression PASS; live fault injection ожидает QA.
- Новый radio записывался в ownership только после успешного apply. При ошибке старта и неуспешной компенсации файлы/unit выпадали из дальнейшего управления. Теперь новый объект очищается при apply/write failure; если cleanup также не удался, он аварийно записывается в ownership для следующей попытки.

### DEF-074 — включённый SSID мог ссылаться на выключенный сегмент

- Статус: исправлен локально, validation/render regression PASS.
- Общая проверка принимала ID любого сегмента, а renderer без собственной защиты мог выдать пустой `bridge=`. Включённая сеть теперь требует включённый сегмент; renderer отдельно отклоняет отсутствующий системный bridge даже при вызове вне обычного validation pipeline.

### DEF-075 — Wi-Fi UI противоречил backend и выдавал желаемое состояние за фактическое

- Статус: исправлен локально, TypeScript/production build PASS; Browser/live ожидает QA.
- Для 2,4 ГГц UI разрешал канал 14, который backend корректно запрещает с обязательным 802.11n; password input не отражал границы 8–63. Badge показывал «работает» только по config flag без runtime status. Граница канала исправлена на 13, пароль получил min/max, badge теперь честно говорит «включено».

## Дополнение: netconf и владение системной сетью — работа продолжается

- История `internal/subsys/netconf` после `630d707e995585bc507de55fc5c150647e4f33d8` проверена: пакет менялся только в `91173d5`; внутри этого блока обратных или циклических правок разных агентов не найдено. Полный межпакетный аудит всей истории остаётся отдельным следующим голом после завершения текущей полной проверки.
- Проверены renderer/model и lifecycle для `netos`, `networkd`, `ifupdown`: initial/clean/drift Plan, холодный старт networkd, переключение backend, NetworkManager ownership, wait-online, exact managed files/modes, service/socket active/enabled/masked, повторный Apply, отсутствующий backend, повреждённый и лишний файл, reload failure с восстановлением прежнего NM-файла. Statement coverage пакета поднято с 67,9% до 85,4%; публичные `Name`, `Health`, `RenderFor`, renderers и service drift покрыты на 100%.
- После блока полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux test binary собран, SHA-256 `73fcb98d9b76dff3df20179523ed790b97f8bfe6268f241f9001cf89047c0503`.
- Linux/live переключение с мониторингом `systemctl`, `networkctl`, `ip address/route/rule`, конфигов и `journalctl` пока не засчитано: QA повторно не выдаёт SSH banner (`Error reading SSH protocol banner` / `No existing session`). Требуется восстановление/перезагрузка через консоль провайдера.

### DEF-076 — Plan и Health не замечали drift управляемых сетевых файлов

- Статус: исправлен локально, exact-file regression PASS; Linux/live ожидает QA.
- При совпадающих old/new проверялись только состояния служб. Повреждённый, удалённый или лишний `05-netos-*`, неверный `/etc/network/interfaces.d/netos.conf`, NM/drop-in или wait-online оставляли Plan пустым и Health зелёным. Теперь сверяются точный набор, байты и Unix mode всех управляемых файлов, а Plan использует полный Health.

### DEF-077 — чистый netconf Apply безусловно мутировал systemd

- Статус: исправлен локально, exact idempotency regression PASS; live mtime/runtime ожидает QA.
- Каждый Apply выполнял `unmask`, `enable`, `start`, а для ifupdown повторно маскировал и останавливал networkd. Теперь команды выполняются только при фактическом drift; тесты для networkd и ifupdown подтверждают отсутствие reload/restart/enable/start/stop/mask/unmask/disable на чистом повторе.

### DEF-078 — отсутствие выбранного backend обнаруживалось после частичной перенастройки ownership

- Статус: исправлен локально, preflight regression PASS.
- `networkd`/`ifupdown` проверялись только после записи networkd ownership, NetworkManager и удаления конфигурации невыбранного механизма. Preflight выбранного unit перенесён в самое начало Apply; отрицательный тест подтверждает, что при отсутствующем пакете файловых мутаций нет.

### DEF-079 — ошибка reload NetworkManager проглатывалась и оставляла неприменённый файл

- Статус: исправлен локально, failure/rollback regression PASS; live fault injection ожидает QA.
- Ошибка `systemctl reload NetworkManager.service` была только warning, поэтому Apply считался успешным при старом runtime и новом файле. Теперь ошибка возвращается, предыдущий файл атомарно восстанавливается и выполняется компенсирующий reload; сценарии создания и удаления проверены.

### DEF-080 — холодный старт режима netos запускал networkd без пассивных файлов

- Статус: исправлен локально, cold-start regression PASS; reboot/live ожидает QA.
- Установленный, но inactive `systemd-networkd` обрабатывался как отсутствующий: netOS запускал службу, не создав `05-netos-*` с `KeepConfiguration=yes` и `RequiredForOnline`. Теперь отсутствие пакета и остановленная служба различаются; перед стартом создаётся полный пассивный набор и wait-online drop-in, затем строгий post-Health подтверждает результат.

### DEF-081 — Health не различал disabled и masked для competing networkd

- Статус: исправлен локально, service/socket ownership regression PASS; reboot/live ожидает QA.
- В режиме ifupdown незамаскированные networkd service/socket могли пройти Health, хотя socket activation или netplan generator способны вернуть конкурирующий manager. В режимах networkd/netos оставшаяся mask также не замечалась. Теперь требуются точные противоположные состояния: оба unit masked для ifupdown и unmasked для networkd/netos.

## Дополнение: DHCP, DNS и системный resolver — локальная проверка завершена

- Проверены все провайдеры DHCP (`dnsmasq`, ISC DHCP, Kea) и DNS (`dnsmasq`, Unbound, dnsproxy): render, preflight, Plan, Apply, Health, переключение провайдера, отключение, повторный Apply, cleanup, повреждение файлов, ошибки валидатора и systemd, DNSSEC и владение `/etc/resolv.conf`.
- Для каждого доступного поля подтверждено попадание в конфигурацию: DHCP gateway/DNS/domain/options/advanced options/lease bounds; DNS port/cache/query log/rebind/DNSSEC/bootstrap, upstream/split DNS и записи A/CNAME/TXT/SRV/MX. Ранее недоступные поля добавлены в UI; несовместимые сочетания теперь отклоняет backend.
- Statement coverage `internal/subsys/services` поднято с 63,8% до 84,0%. Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux test binary: `backend/services_tests_linux`, SHA-256 `f81aae7613e3ab5f8ad810d3ca18178cbba5a28e090d941133e13373ef77c815`.
- История этого блока от `630d707e995585bc507de55fc5c150647e4f33d8` просмотрена по каждому затронувшему его коммиту. Обнаруженная последовательность Unbound AAAA (`630d707` предупреждал о невозможности, `3461cba` реализовал respip-фильтр, `32059de` синхронизировал UI) является последовательным добавлением возможности, а не круговой отменой. Удаление незавершённого AdGuard в `bb5e4c9`, Debian paths/retry Kea в `7ec5b2e`/`a641105` и hardening `91173d5` также не отменяют друг друга. Полный межпакетный аудит всей истории остаётся отдельным следующим голом после текущего.
- Live-проверка портов 53/67, реальных DHCP-аренд, DNS-запросов, daemon status/config/log и cleanup ещё не засчитана: QA-хост по-прежнему не выдаёт SSH banner и требует восстановления через консоль провайдера.

### DEF-082 — Plan и Health сервисов не замечали live drift и остатки невыбранных провайдеров

- Статус: исправлен локально, exact-state regression PASS; live ожидает QA.
- Проверялся главным образом active выбранного daemon. Повреждённые config/unit, неверные права, пропавший ISC lease и остаточный активный или generated state другого провайдера могли не попасть в Plan/Health. Теперь сверяются exact bytes/modes, lease state, selected и все unselected providers; disabled feature также обнаруживает stale state.

### DEF-083 — изменение только dnsproxy hosts не перезапускало resolver

- Статус: исправлен локально, hosts-only/idempotency regression PASS.
- Hosts записывался до `FileChanged`, поэтому изменение статической A-записи считалось чистым Apply. Проверка перенесена до записи; hosts-only change вызывает restart, а следующий идентичный Apply не меняет mtime и не трогает systemd.

### DEF-084 — невалидный кандидат заменял рабочий конфиг до синтаксической проверки

- Статус: исправлен локально, negative matrix PASS для dnsmasq/ISC/Kea/Unbound.
- Конфиг сначала атомарно заменялся, затем проверялся daemon tool. Теперь кандидат валидируется во временном staging-файле с `fsync`, а рабочий файл меняется только после успеха. Тесты подтверждают побайтовую сохранность старого конфига при каждом отказе.

### DEF-085 — переключение провайдера останавливало рабочий daemon до preflight нового

- Статус: исправлен локально, provider-switch failure regression PASS.
- При ошибочном Kea/Unbound прежний dnsmasq/dnsproxy уже мог быть остановлен. Package/preflight выбранного провайдера теперь выполняется первым; отрицательные тесты подтверждают отсутствие stop старого daemon.

### DEF-086 — DNS Apply зависел от порядка DHCP Apply и мог оставить stale dnsmasq

- Статус: исправлен локально, самостоятельный DNS lifecycle regression PASS.
- DNS-подсистема полагалась на то, что DHCP ранее выключит ненужный dnsmasq. Теперь DNS Apply сам приводит dnsmasq к требуемому состоянию, поэтому прямой вызов и иной порядок подсистем дают одинаковый результат.

### DEF-087 — ошибка восстановления systemd-resolved теряла возможность повтора

- Статус: исправлен локально, release/retry regression PASS; live fault injection ожидает QA.
- Ошибка `systemctl enable --now systemd-resolved` игнорировалась, а сохранённое состояние уже удалялось. Теперь ошибка возвращается и state сохраняется для следующего Apply; неизвестный kind состояния отклоняется без его удаления, symlink восстанавливается атомарно.

### DEF-088 — SystemResolver не имел полной Health-проверки

- Статус: исправлен локально, file/service/state drift regression PASS.
- Теперь captured state требует точный regular `/etc/resolv.conf`, mode, сохранённый state и inactive+disabled `systemd-resolved`; released state требует отсутствия netOS ownership/state. Повреждение файла, запуск resolved и неизвестный state обнаруживаются отдельно.

### DEF-089 — часть полей DHCP/DNS нельзя было настроить через UI

- Статус: исправлен локально, renderer field matrix и TypeScript production build PASS; browser/live ожидает QA.
- Добавлены DHCP gateway/domain/DNS/options/lease min/max/advanced directives и DNSSEC/bootstrap/advanced directives, границы port/cache, полный CRUD записей A/CNAME/TXT/SRV/MX. Все поля связаны с фактической моделью конфигурации.

### DEF-090 — несовместимые настройки молча игнорировались провайдером

- Статус: исправлен локально, validation matrix PASS.
- Kea не применяет DHCP advanced options, dnsmasq не применяет DNSSEC, а DNS advanced directives поддерживает только Unbound. Backend теперь возвращает точную ошибку поля; UI скрывает или очищает несовместимое состояние при переключении.

### DEF-091 — чистый Apply переписывал managed-файлы и повторно создавал trust anchor

- Статус: исправлен локально, mtime/command idempotency и DNSSEC lifecycle regression PASS.
- Общий writer теперь различает content drift и permission-only drift, не заменяет inode без необходимости и не вызывает лишние restart/daemon-reload. Существующий Unbound trust anchor не пересоздаётся; его отсутствие обнаруживается Health и исправляется Apply.

## Дополнение: HTTP API — работа продолжается

- Начат маршрутный аудит всего API. Добавлены lifecycle-тесты наблюдения (`clients`, `leases`, `arp`, `routes`, traffic statistics), maintenance status/list/download/create/restore/update/delete, unavailable/busy/failure paths и скачивания сертификатов OpenConnect/IKEv2.
- API statement coverage поднято с 65,9% до 76,8%; после изменений полный backend `go test -count=1 ./...` и `go vet ./...` — PASS. Startup/HTTPS/prune и оставшиеся отрицательные ветви config transaction ещё проверяются, поэтому блок не закрыт.

### DEF-092 — API наблюдения скрывал ошибки runtime и возвращал ложное успешное состояние

- Статус: исправлен локально, failure regression PASS; live ожидает QA.
- `/api/status` игнорировал ошибки InterfaceStats/Clients и показывал пустые интерфейсы и нулевых клиентов. `/api/routes` игнорировал ошибки policy rules и второго чтения маршрутов для parser. Теперь любой недоступный обязательный источник даёт явный 5xx, а отсутствующий Collector — 503; успешные ответы проверены на фактических lease/ARP/route данных и enrichment клиента.

### DEF-093 — некорректные параметры statistics молча подменялись или отбрасывались

- Статус: исправлен локально, query matrix PASS.
- `hours=abc` превращался в 24, `hours=0` также считался значением по умолчанию, а недопустимое/слишком длинное имя интерфейса исчезало из фильтра. Теперь отсутствие параметра означает 24 часа, но любое заданное значение строго разбирается и проверяется в диапазоне 1–168; имена проходят общий `ValidInterfaceName`, ошибки возвращают 400.

### Итог локального HTTP API-блока

- Проверены все зарегистрированные маршруты, auth/role/CSRF, optimistic draft locking, validate/plan/apply/confirm/manual rollback/discard, revisions, runtime observation, maintenance, render, keypair/certificate, SPA fallback/security headers и настоящий HTTPS startup/shutdown.
- API statement coverage поднято с 65,9% до 85,3%; `Start`, confirm/rollback, pruning, routes и основные lifecycle-функции покрыты успешными и отрицательными сценариями. Linux test binary: `backend/api_tests_linux`, SHA-256 `c71ff1b2d0f1ac6d1366b704413138952a9bb98cf8960e535765ff24169ad9f3`.
- История API/runtime от `630d707e995585bc507de55fc5c150647e4f33d8` просмотрена по коммитам `630d707`, `3d9ad53`, `fbbf752`, `a641105`, `e0a7655`, `e47c724`, `77d629b`, `91173d5`: изменения последовательно добавляют лимиты auth, корректный runtime, SPA hardening, atomic cleanup, root-scoped backup и UI retry; взаимных отмен одного поведения не найдено. Гипотеза о stale `draft_version` после confirm отдельно проверена по `App.tsx` и опровергнута: UI немедленно делает `getConfig()`.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. `go test -race` локально не запущен: Windows toolchain не содержит `gcc`; собранный Linux binary и race/live запуск остаются в QA runtime-шаге после восстановления SSH.

### DEF-094 — custom TLS зависел от self-signed каталога и сообщал чужой fingerprint

- Статус: исправлен локально, real HTTPS/custom/mismatched-pair regression PASS; live browser ожидает QA.
- `Start` всегда сначала создавал self-signed cert, затем заменял пути на custom cert/key, но продолжал логировать fingerprint self-signed сертификата. Валидный custom TLS не запускался при недоступном служебном TLS-каталоге. Теперь режим выбирается первым: custom pair проверяется через `tls.LoadX509KeyPair`, fingerprint вычисляется по реально обслуживаемому X.509 cert, self-signed каталог не затрагивается. Настоящий локальный TLS-клиент подтвердил TLS ≥1.2, API response/security headers и clean shutdown.

### DEF-095 — ручной rollback мог прерваться при разрыве инициировавшего HTTP-соединения

- Статус: исправлен локально, disconnected-client transaction regression PASS; live network rollback ожидает QA.
- Handler передавал `r.Context()` в системный rollback. Возврат старой сети способен сам оборвать браузерное соединение и отменить восстановление на середине. Теперь rollback выполняется на независимом background context с двухминутным timeout. Тест заранее отменяет клиентский context и подтверждает полный restore, правильную current config и состояние revision `rolled_back`.

## Дополнение: bootstrap и startup/CLI — локальная проверка завершена

- Bootstrap проверен по всем функциям и веткам: выбор uplink из нескольких default route, gateway/address, все физические интерфейсы и занятые подсети, LAN-кандидаты, management CIDR, фильтрация виртуальных интерфейсов, ошибки sysfs/route/address, DHCP/static first boot и подбор свободной LAN-подсети. Statement coverage `internal/bootstrap`: 100,0%.
- `cmd/netosd` проверен настоящими дочерними процессами и повторно in-process: `-version`, alias `netos version`, `-init` с существующей конфигурацией, `-render`, `-dry-run -apply`, неизвестный artifact, ошибка открытия БД и отказ `-plan` при отсутствии обязательного live-инструмента. Dry-run прошёл порядок всех 18 зарегистрированных подсистем без системных изменений. Statement coverage поднято с 43,4% до 69,6%; успешный live `plan`, daemon startup/signal/HTTPS/runtime и ready-marker остаются Linux QA-шагом.
- Linux test binaries: `backend/bootstrap_tests_linux`, SHA-256 `d732e5fcd8dc93b71c18cfab1f9a1549749e903df756ab12c2d1d5a80d253855`; `backend/netosd_tests_linux`, SHA-256 `2ebb961a8a0bbfef977bf5c8e6732569e2e16aa989550e94e0455418bca5234a`.
- История этих файлов от `630d707e995585bc507de55fc5c150647e4f33d8` проверена: относящиеся изменения `e47c724` (cleanup незавершённых atomic-файлов) и `86a853c` (безопасный разбор IPv4 prefix) независимы и не отменяют друг друга; круговых правок в блоке не найдено. Полный межпакетный аудит всей истории остаётся отдельным следующим голом после текущего.

### DEF-096 — bootstrap выбирал последний default route вместо приоритетного

- Статус: исправлен локально, multi-route regression PASS; live multi-uplink ожидает QA.
- Разбор проходил по общему списку полей всего вывода `ip route` и перезаписывал `dev`/`via` каждой следующей строкой. При нескольких default route стартовая конфигурация могла выбрать резервный или худший uplink. Теперь маршруты разбираются построчно и берётся первый полноценный default route в порядке, выданном ядром.

### DEF-097 — повреждение последней ревизии маскировалось как пустая БД

- Статус: исправлен локально, corrupt-storage regression PASS.
- Когда активной ревизии не было, любая ошибка `LatestRevision`, включая повреждённый JSON, игнорировалась, после чего запускался first-boot detect и создавалась новая ревизия. Теперь только `ErrNotFound` означает пустую БД; прочие ошибки возвращаются явно. Отдельные тесты подтверждают нормальный first boot, ошибку detect и отказ при повреждённой последней ревизии без попытки bootstrap.

## Дополнение: runtime-наблюдение — локальная проверка завершена

- Проверены sysfs-поля каждого интерфейса (up/unknown+IFF_UP/down, MAC, MTU, RX/TX bytes/packets/errors), пропуск loopback и ошибка корня; сырые/разобранные IPv4 routes, таблица, gateway/dev/src/metric/proto, policy rules, ошибки runner и conntrack count; запуск, периодический sample, context cancellation, counter reset, фильтрация, retention, legacy migration и JSONL persistence traffic history.
- Statement coverage `internal/runtime` поднято с 63,9% до 88,2%. Linux test binary: `backend/runtime_tests_linux`, SHA-256 `ab2c15e6b546c26a392eb24916d89c0dee728dc10273d7b62db3a314864046f7`.
- История runtime/UI-маршрутов от `630d707e995585bc507de55fc5c150647e4f33d8` проверена по `630d707`, `3d9ad53`, `fbbf752`, `a641105`, `91173d5`: ограничение/append+compact traffic history, TUN IFF_UP, исключение WAN-соседей, Debian Kea lease path и UI hardening последовательно дополняют друг друга; круговых отмен не найдено.

### DEF-098 — runtime-парсер терял destination специальных маршрутов

- Статус: исправлен локально, parser/UI production build PASS; live routing tables ожидают QA.
- Для `blackhole 10.0.0.0/8`, `unreachable default` и аналогичных строк destination ошибочно становился `blackhole`/`unreachable`, а настоящий prefix терялся. Теперь route type хранится отдельно, корректно разбираются unicast/local/broadcast/multicast/throw/unreachable/prohibit/blackhole/nat/anycast, а UI показывает тип вместе с реальным назначением.

## Дополнение: входящие VPN-серверы — локальная lifecycle-проверка завершена

- Проверены WireGuard, Xray/Reality, OpenConnect/ocserv и IKEv2/strongSwan: все поля render, сортировка/identity/pool/DNS/split routes/peer credentials, unit hardening, ownership, foreign resources, interface/address/MTU/port, certificates, auth/users, Plan/Apply/Health, повторный Apply, live drift, cleanup и fault injection для config validation, daemon-reload, enable, restart и swanctl reload.
- IKEv2 fake lifecycle реально проходит создание XFRM, сертификата, swanctl/daemon configs, unit, enabled+active, idempotent repeat и полное удаление. Для Xray/OpenConnect/IKEv2 подтверждён побайтовый rollback файлов, каталогов пользователей/TLS и сертификатов при сбое обновления уже работающего сервера; предыдущая конфигурация после rollback снова проходит Health.
- Statement coverage `internal/subsys/vpnservers` поднято с 68,8% до 80,4%. Linux test binary: `backend/vpnservers_tests_linux`, SHA-256 `9bb7b0d292027d605a31ba802b179ec74d529975660d7f19ab53987b9f48a4b1`.
- История backend VPN-блока от `630d707e995585bc507de55fc5c150647e4f33d8` содержит относящийся к нему `f55f0aa` (добавление реального OpenConnect↔ocserv integration); отменяющих или круговых коммитов в этом блоке нет. Связанные UI-коммиты добавляли Reality flow и генерацию WireGuard-клиентов, а не откатывали lifecycle.

### DEF-099 — active VPN-unit мог пройти Health, оставаясь disabled после reboot

- Статус: исправлен локально, active/disabled и idempotency regression PASS; reboot/live ожидает QA.
- Xray, ocserv и strongSwan Health проверяли только `is-active`, а каждый Apply безусловно выполнял `systemctl enable`. Теперь Health требует одновременно active+enabled, а Apply вызывает enable только при фактическом disabled state. Чистый повтор не выполняет enable/restart/daemon-reload.

### DEF-100 — неуспешная первая установка VPN оставляла неучтённые секреты и units

- Статус: исправлен локально, daemon-reload fault matrix PASS для Xray/OpenConnect/IKEv2.
- После записи конфигов/сертификатов ошибка daemon-reload или enable возвращалась наружу до фиксации ownership, но созданные файлы и unit оставались. Теперь первая установка при любом post-write отказе останавливает/disable временный service, удаляет config/unit/auth/TLS и provisional XFRM, не создавая ownership.

### DEF-101 — VPN Health и plan не замечали повреждённые managed-конфиги

- Статус: исправлен локально, config/unit/ownership drift and repair regression PASS; live ожидает QA.
- Health видел процесс, порт и адрес, но не сверял байты/права конфигов, unit, ownership и обязательные auth/certificate artifacts. Теперь проверяется точное управляемое состояние всех четырёх типов; неизменённый JSON с live drift даёт update в Plan, Apply исправляет расхождение, следующий Plan пуст.

### DEF-102 — сбой обновления работающего VPN мог уничтожить или рассинхронизировать прежнее состояние

- Статус: исправлен локально, existing-service rollback matrix PASS для Xray/OpenConnect/IKEv2; live fault injection ожидает QA.
- Xray/ocserv при restart failure вызывали полный cleanup даже для ранее работающего owned-сервера; при daemon-reload/enable failure оставляли новые файлы со старым runtime. IKEv2 также не восстанавливал общий strongSwan state. Перед изменением теперь снимается точный snapshot управляемых файлов/деревьев; при отказе он восстанавливается, выполняются daemon-reload и restart прежней службы. Тесты сравнивают старые конфиги и сертификаты побайтово и повторно запускают полный Health.

## Дополнение: management CLI, backup/restore/update/uninstall — локальная проверка завершена

- Матрица `netos` покрывает help/version/status/logs/follow/start/stop/restart/plan, каждый artifact render, backup, restore, update/reinstall/version selection, reset, uninstall, completion, root checks и все неверные формы аргументов/флагов без запуска внешних процессов. `Execute` поднят с 40,0% до 90,0%, statement coverage `internal/manage` — с 73,0% до 81,1%.
- Проверены backup permissions/content/empty state/same-second collision/tar failure/daemon restart; restore archive traversal/absolute/link/special/foreign/size limits, выбор копии, safety backup, очистка stale state, target extraction/start/readiness и автоматический rollback. Uninstall-тесты подтверждают cleanup units/firewall/routes/rules/virtual links/sysctl/network backends/resolver/binary/data и возврат NetworkManager/default route.
- Linux test binary: `backend/manage_tests_linux`, SHA-256 `4e207a88054db1ce714560e758679c12809705625ef3393421564e073c38fc92`.
- История management/install от `630d707e995585bc507de55fc5c150647e4f33d8` проверена по `630d707` и `91173d5`: первый добавлял release/backup validation и runtime hardening, второй дополнял reset/uninstall возвратом resolver, общим cleanup и system validation. Круговой отмены одного поведения другим не найдено.

### DEF-103 — `netos render` отклонял артефакты, обещанные справкой и общим каталогом

- Статус: исправлен локально, full artifact dispatch/help/completion matrix PASS.
- Управляющий CLI держал отдельный устаревший список: `wireguard` был в help/completion, но отсутствовал в validator, а новые `xray`, `xray-servers`, `hostapd`, `ocserv`, `strongswan` не были синхронизированы. Dispatch, help и bash completion теперь генерируются из единственного `render.IDs()`.

### DEF-104 — backup мог сообщить о несуществующем файле или перезаписать копию той же секунды

- Статус: исправлен локально, empty/archive/collision regression PASS.
- При отсутствии всех data dirs функция возвращала путь без создания архива. Две копии с одинаковым timestamp также использовали один путь, и GNU tar перезаписывал первую. Теперь пустое состояние создаёт валидный приватный tar.gz, а коллизии получают последовательные суффиксы `-2`, `-3` и не уничтожают прежние копии.

### DEF-105 — неуспешный restore оставлял частично распакованное состояние и остановленный daemon

- Статус: исправлен локально, extraction-failure automatic rollback regression PASS; live disk/service fault injection ожидает QA.
- Safety backup создавался, но при ошибке очистки/распаковки/start/readiness пользователю лишь печатался его путь. Теперь target-state очищается, safety archive автоматически распаковывается, stale ready marker снимается, daemon запускается и должен снова пройти readiness. Тест инъецирует отказ target tar и подтверждает возврат прежней БД и сервиса.

## Дополнение: единый каталог диагностических render-артефактов — локальная проверка завершена

- Проверены все 16 артефактов (`iptables`, `wireguard`, `xray`, `xray-servers`, `hostapd`, `ocserv`, `strongswan`, `dnsmasq`, `isc-dhcp`, `kea-dhcp4`, `unbound`, `dnsproxy`, `resolv`, `network`, `sysctl`, `config`): полный каталог, активный поднабор, lookup по каждому ID, неизвестный ID, пустые/disabled/другого типа записи, несколько включённых объектов, точный содержательный вывод и передача ошибок невалидной конфигурации.
- Для WireGuard, Xray client/server, Wi-Fi, OpenConnect и IKEv2 пройдены обе ветки предикатов и генераторов. Каждая именованная функция `internal/render` имеет 100% coverage; statement coverage пакета — 98,4%. Связанный регресс `internal/manage`, `internal/api`, `cmd/netosd` и `go vet` — PASS.
- Linux test binary: `backend/render_tests_linux`, SHA-256 `e0317b39b690c065785ae61839f9ae65e6c01f0740621576b914f6c1dcb54ad9`.
- Ни один committed-файл `internal/render` не менялся в диапазоне от `630d707e995585bc507de55fc5c150647e4f33d8` до текущего `HEAD` (`91173d5`); относящиеся к каталогу коммиты старше контрольной точки и последовательно добавляли новые типы. Круговой committed-отмены в этом блоке нет; полный межпакетный аудит истории остаётся отдельным следующим голом.

### DEF-106 — внешний потребитель мог повредить общий каталог render для всего процесса

- Статус: исправлен локально, registry immutability и связанный CLI/API/daemon regression PASS.
- `render.All()` возвращал внутренний slice `artifacts`. Изменение элемента полученного списка меняло ID, обработчик или предикат глобального каталога, после чего CLI, панель и daemon могли видеть разные либо повреждённые артефакты до перезапуска процесса. Теперь возвращается независимая копия; отдельный тест мутирует результаты `All()` и `IDs()` и подтверждает неизменность registry, уникальность всех ID и полноту каждого элемента.

### DEF-107 — автоматический rollback restore зависел от уже отменённого контекста клиента

- Статус: исправлен локально, cancelled-context rollback regression PASS; live разрыв сессии ожидает QA.
- Очистка и распаковка safety backup использовали независимый контекст, но финальная readiness-проверка принимала исходный контекст команды. Если пользователь прерывал CLI или соединение обрывалось одновременно с ошибкой target restore, проверка немедленно завершалась по cancellation и компенсирующая транзакция не подтверждала возврат рабочего сервиса. Теперь весь rollback, включая stop/extract/start/readiness, работает в собственном трёхминутном ограниченном контексте. Тест передаёт заранее отменённый caller context, создаёт ready marker только после первого ожидания и подтверждает возврат прежних данных и active daemon.

## Дополнение: исходящие VPN-каналы и мониторинг — локальная lifecycle/fault-проверка завершена

- Проверены WireGuard, Xray TUN и OpenConnect: строгий config decode/render, secret handling, unit hardening, ownership, foreign interface, адрес/MTU/IPv6 suppression, routing table/default+blackhole, exact fwmark rule, active+enabled service, Plan/Apply/Health, idempotent repeat, type transition, delete+create, disabled state, probe ICMPv4/ICMPv6/HTTP/TCPv4/TCPv6, fail thresholds, rise thresholds и режимы `block`/`direct`/`fallback`.
- Fault injection охватывает `ip link add/delete/set`, `wg syncconf`, address/route/rule changes, Xray validation, `systemctl daemon-reload/enable/restart`, первый install, обновление существующего канала и сбой следующего элемента после уже выполненного удаления. Проверяется отсутствие orphan-файлов/interfaces/units и побайтовый возврат прежних конфигов, secret-файлов, scripts, units, WireGuard runtime, адресов, `rt_tables`, ownership и рабочего сервиса.
- Statement coverage `internal/subsys/channels` поднято с 79,4% до 82,4%; добавленные ветки преимущественно аварийные и компенсирующие. Полный `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux test binary: `backend/channels_tests_linux`, SHA-256 `6275cb5cc708f82f58bc66cfd8f75590b54b304c55240ef7b41e510cbfad8705`.
- История блока от `630d707e995585bc507de55fc5c150647e4f33d8` содержит последовательные `6b80d04` (Xray integration fixture перенесён из private `/tmp` в production state tree) и `36da15d` (TCP handshake probe вместо curl telnet, сохранение device route для recovery probe). Второй коммит не отменяет первый; оба поведения сохранены. Круговой committed-правки в блоке не найдено, полный межпакетный аудит остаётся отдельным следующим голом.
- Live systemd/interface/rule/route/probe/log fault injection не засчитан: очередная попытка подключения завершилась `Error reading SSH protocol banner`; QA-хост требует восстановления через консоль провайдера.

### DEF-108 — замена типа канала удаляла рабочий канал до валидации нового

- Статус: исправлен локально, invalid replacement regression PASS.
- Apply сначала очищал old ownership/runtime, после чего декодировал и рендерил новый WireGuard/OpenConnect/Xray config. Ошибка поля оставляла старый канал уже остановленным. Теперь все wanted-каналы проходят preflight до первого удаления; тест подтверждает неизменность старых файлов/unit и отсутствие stop-команды при невалидной замене.

### DEF-109 — Health и неизменённый Plan не обнаруживали drift managed-артефактов каналов

- Статус: исправлен локально, exact-state corruption/repair-plan regression PASS; live ожидает QA.
- Проверялись главным образом interface, active unit, route и rule. Не сверялись ownership, `rt_tables`, bytes/modes конфигов, passwords/scripts/units, enabled-state и точный WireGuard address; Plan при неизменном JSON всегда был пуст. Теперь Health требует полное ожидаемое managed-состояние, а Plan создаёт repair `update` при live drift.

### DEF-110 — неуспешное первое создание канала оставляло неучтённые секреты, units и интерфейсы

- Статус: исправлен локально, first-install failure matrix PASS для WireGuard/OpenConnect/Xray.
- Ошибка после записи файлов, но до `writeOwned`, могла оставить конфиг/password/script/unit либо созданный link без ownership. Теперь любой post-mutation отказ очищает все provisional files, service, link, rule и table; отдельно проверены link-add, syncconf, link-set, daemon-reload, enable и restart.

### DEF-111 — сбой обновления существующего канала разрушал или рассинхронизировал прежнее состояние

- Статус: исправлен локально, exact-file/runtime rollback matrix PASS.
- Xray при restart/routes/rules failure выполнял полный cleanup даже для старого owned-канала; OpenConnect оставлял новые файлы со старым runtime либо также очищался на позднем отказе; WireGuard мог оставить новый конфиг/адрес после неуспешного sync/link/route шага. Теперь снимаются snapshots, а при отказе восстанавливаются прежние bytes/modes, daemon config, WireGuard syncconf/address/MTU, routes/rule и перезапускается прежняя служба.

### DEF-112 — частичный Apply списка каналов не возвращал уже удалённые элементы и каталог таблиц

- Статус: исправлен локально, type-transition и delete+create rollback regression PASS.
- При замене/удалении нескольких каналов старые элементы очищались по очереди. Отказ последующего нового элемента оставлял предыдущие уже удалёнными, а `rt_tables` — описывающим незавершённый target state. Apply теперь сохраняет snapshots каждого удаляемого owned-канала и каталога таблиц, а при любой последующей ошибке восстанавливает их в обратном порядке, ждёт возврата TUN, возвращает routes/rules и сохраняет прежний ownership.

### DEF-113 — полностью выключенные каналы скрывали stale owned/runtime state

- Статус: исправлен локально, disabled exact-state Health/Plan regression PASS.
- Health немедленно возвращал успех при пустом wanted-списке, а Plan даже не вызывал его. Остаточные ownership, units/interfaces и старый `rt_tables` поэтому не давали repair-action. Disabled state теперь означает точный пустой ownership и точный пустой managed catalog; любое расхождение считается дефектом и попадает в Plan.

## Дополнение: Multi-WAN failover/balance — локальная lifecycle/fault-проверка завершена

- Проверены enable/disable, `failover`/`balance`, physical/PPPoE/L2TP interface names, metric/weight/sticky settings, ICMPv4/ICMPv6/HTTP/TCP probes, malformed и несколько targets, default timeout/interval/thresholds, suppress/restore основного маршрута, daemon-crash state, paused monitor, stale WAN removal, shutdown restore, balance fallback, таблицы 3000+, blackhole defaults, fwmark rules и ownership.
- Добавлена точная Health-проверка persistent suppressed state, прав 0600, допустимости WAN ID/mode, отсутствия одновременно suppressed+live route, balance ownership, blackhole tables и exact priority+mark+lookup rules. Неизменённый Plan теперь создаёт repair-action при live drift.
- Balance reconcile теперь транзакционный: до первого `flush` сохраняются все затрагиваемые route tables, rules и ownership-файл; при ошибке route/blackhole/rule/cleanup/persistence всё восстанавливается в независимом rollback context. Fault-тест подтверждает точный возврат ранее рабочего WAN и отсутствие частично созданной второй таблицы.
- Statement coverage `internal/subsys/multiwan` поднято с 77,6% до 85,1%. Полный `go test -count=1 ./...`, `go vet ./...`, `git diff --check` и web production build — PASS. Linux test binary: `backend/multiwan_tests_linux`, SHA-256 `7e90cf67343e155e6f4ce793a015d89be0502a9b5f7aaff45c7dc2e6078efe54`.
- Ни один committed-файл `internal/subsys/multiwan` не менялся в диапазоне от `630d707e995585bc507de55fc5c150647e4f33d8` до `HEAD`. Попавшие в общий path-аудит `86a853c` и `91173d5` меняли только IPv4 prefix parsing и firewall interface selector, `e93d940` — PPPoE config; balance/failover они не отменяли. Круговой committed-правки нет. При этом найден функциональный межпакетный разъезд: исправленный в `channels` TCP handshake probe оставался старым curl-telnet в `multiwan` (DEF-114).
- Live route/rule/failover/log fault injection не засчитан: QA снова завершился `No existing session`/`Error reading SSH protocol banner`.

### DEF-114 — Multi-WAN TCP probe ложно считал молчаливый TCP-сервис недоступным

- Статус: исправлен локально, silent-listener TCP regression PASS; SO_BINDTODEVICE live ожидает QA.
- Проверка использовала `curl telnet://`, который после успешного handshake ждал прикладные данные до timeout. Реализован прямой `net.Dialer` handshake; на Linux socket привязывается к WAN через `SO_BINDTODEVICE`, поддерживаются IPv4 и IPv6. Это тот же класс дефекта, который уже был исправлен в `channels`, но оставался в дублированной Multi-WAN логике.

### DEF-115 — Multi-WAN Health всегда возвращал успех

- Статус: исправлен локально, exact-state Health/Plan matrix PASS; live ожидает QA.
- Заглушка `Health(...) { return nil }` не проверяла ни одного фактического route/rule/state. Теперь corrupt state, неверные права, неизвестный suppressed WAN, state вне failover, одновременно live+suppressed route, stale/wrong balance ownership, отсутствие blackhole и неверное правило являются ошибками; Plan предлагает repair.

### DEF-116 — balance rule с правильными priority/mark, но чужой lookup принимался как валидный

- Статус: исправлен локально, exact same-line priority/mark/table tests PASS.
- Matcher искал две подстроки и не сверял таблицу. Теперь токены разбираются в пределах одной строки, masked fwmark поддерживается, lookup/table обязан точно совпасть с вычисленным `3000+index`.

### DEF-117 — ошибка посередине balance reconcile оставляла частично очищенные таблицы

- Статус: исправлен локально, kernel/file transaction rollback regression PASS; live fault injection ожидает QA.
- Каждая таблица сначала безусловно `flush`-илась; ошибка следующего route, blackhole, rule либо ownership write оставляла WAN без прежнего маршрута и иногда без учёта созданного state. Теперь снимаются kernel/file snapshots и при любой ошибке возвращаются все route lines, прежние rules и ownership bytes/mode.

### DEF-118 — monitor игнорировал ошибку загрузки persistent suppressed state

- Статус: исправлен локально, corrupt-state tick regression PASS.
- `tick` вызывал `_ = load()`: corrupt JSON сбрасывал `suppressed` в пустую map и мог забыть маршрут, снятый до crash. Загрузка теперь атомарна относительно in-memory state; ошибка логируется, tick прекращается без потери ownership и повторит загрузку позднее.

### DEF-119 — настройка `sticky_connections` не влияла на firewall

- Статус: исправлен локально, sticky true/false iptables render regression PASS.
- Поле присутствовало в config/UI, но CONNMARK restore/save генерировался всегда. При `true` сохраняется прежнее connection-sticky поведение; при `false` каждый пакет направляется в weighted chain без CONNMARK restore/save. Оба противоположных набора правил проверены.

### DEF-120 — failed dynamic balance reconcile больше никогда не повторялся

- Статус: исправлен локально, dirty/retry tick regression PASS.
- После down/up transition `tick` игнорировал ошибку reconcile, но уже менял `state.Down`. Следующие probes не создавали нового transition, поэтому таблицы могли навсегда остаться старыми. Теперь `balanceDirty` сохраняется после отказа, ошибка логируется, а reconcile повторяется каждый tick до успеха и только тогда очищает dirty-state.

## Дополнение: полный локальный аудит схемы конфигурации и каждого публичного helper

- Проверены `Normalize`, `Validate`, строгий JSON decode API, загрузка предыдущей схемы из SQLite, каталог компонентов, provider lookup, DHCP defaults, DNS channel bindings, interface master/VLAN helpers и все config codec-функции.
- Отдельными матрицами проверены все поля probe, OpenConnect, IKEv2 и ocserv, все поддержанные Xray outbound protocol, IPv4/IPv6/DNS цели, порты, MTU, таймеры, thresholds, credentials, неизвестные и не сериализуемые config-поля.
- Statement coverage `internal/config` поднято с 79,1% до 87,7%; функций с 0% и функций ниже 70% не осталось. Удалён неиспользуемый `channelIDs`, а не добавлен искусственный тест мёртвого кода.
- Полный backend `go test -count=1 ./...`, `go vet ./...`, `git diff --check`, config/API/store package tests и production web build — PASS. Linux test binary: `backend/config_tests_linux`, SHA-256 `594f57e1d981188c49e6dcace4064c6d16166913ea113fed899b09bc2e5fd9dc`. Реальный UI-клик `sticky_connections` не засчитан: встроенный браузер недоступен (список browser surfaces пуст), очередная live QA-попытка завершилась `Error reading SSH protocol banner` / `No existing session`.
- История config/API/Network UI от `630d707e995585bc507de55fc5c150647e4f33d8` просмотрена в рамках текущего блока: committed-изменения добавляли security validation, PPPoE AC, SPA hardening и UI ID/labels; взаимного отката одной и той же config-нормализации не найдено. Нерабочий sticky-switch появился до указанного диапазона в `be2bd2c4`, а backend-поведение поля было исправлено только текущей незакоммиченной проверкой. Полный межпакетный аудит всего диапазона остаётся отдельным следующим голом после завершения текущего.

### DEF-121 — API молча принимал неизвестные поля конфигурации

- Статус: исправлен локально, strict JSON regression PASS.
- `readJSON` декодировал конфигурацию без `DisallowUnknownFields`: опечатка вроде `sticky_connection` исчезала, после чего применялось другое значение. Теперь неизвестные поля отклоняются на любом уровне; проверены верхний, вложенный и реальный misspelled Multi-WAN field.

### DEF-122 — Normalize скрывал ошибки текущей схемы подстановкой defaults

- Статус: исправлен локально, current/legacy/API/store migration matrices PASS.
- Нулевые или пустые port/TLS/backend/IPv6/DNS/Multi-WAN/firewall/QoS/DDNS/WAN/channel/network/NAT значения переписывались до `Validate`, поэтому явная ошибка пользователя становилась успешной конфигурацией. JSON-схема повышена до 3: версия 2 мигрируется, получает legacy defaults и сохраняется как 3; версия 3 не переписывает семантические значения и отдаёт точную ошибку поля; будущая неизвестная версия отклоняется.

### DEF-123 — переключатель sticky_connections в UI был навсегда отключён

- Статус: обработчик исправлен локально, TypeScript production build PASS; реальный browser click ожидает доступного browser/QA.
- Switch отображал backend-значение, но имел одновременно `disabled` и пустой `onChange`, поэтому пользователь не мог включить поведение без ручного JSON. Теперь переключатель записывает оба boolean-состояния в draft и создаёт отсутствующий объект Multi-WAN с полными defaults.

### DEF-124 — валидатор запрещал уже реализованный custom TLS

- Статус: исправлен локально, config validation и настоящий HTTPS custom-certificate lifecycle PASS.
- API server уже загружал custom cert/key, проверял пару и логировал её фактический fingerprint, однако `Validate` всегда возвращал «не поддерживается». Теперь custom mode разрешён только с безопасными непустыми разными cert/key paths; пустые, одинаковые и управляющие значения отклоняются. ACME впоследствии реализован в DEF-142.

### DEF-125 — probe validation принимал неисполняемые HTTP/TCP цели

- Статус: исправлен локально, полная probe field/boundary matrix PASS.
- HTTP проверялся только строковым префиксом и принимал `http:///health`; TCP host не проверял управляющие символы. Теперь HTTP разбирается как URI с обязательными `http|https` и host, а TCP разрешает только корректный IPv4/IPv6/DNS host и порт 1–65535.

### DEF-126 — bootstrap DNS принимал явно пустой порт

- Статус: исправлен локально, bootstrap syntax matrix PASS.
- `net.SplitHostPort("1.1.1.1:")` возвращал пустой port без ошибки, после чего код считал его вариантом без порта. Теперь наличие разделителя с пустым портом отклоняется отдельно; проверены literal IPv4, IPv4:port, hostname, IPv6, empty/bad/out-of-range ports и whitespace/control input.

### DEF-127 — версия JSON-конфигурации ошибочно использовалась как версия SQLite schema

- Статус: исправлен локально, clean database и previous-config revision tests PASS.
- После повышения config schema новая установка записывала бы SQLite schema version 3 при неизменных таблицах, тогда как существующая БД оставалась на 2. Версии разведены: SQLite schema остаётся 2, JSON config независимо мигрирует 2→3 при загрузке ревизии.

### DEF-128 — ручной разбор port spec мог переполнить int

- Статус: исправлен локально, exact/range/list/malformed/overflow matrix PASS.
- `portSpecContains` накапливал цифры вручную без проверки переполнения и диапазона. В access-lockout проверке огромная строка могла завернуться в другое число и ложно совпасть с портом панели. Теперь используется checked `strconv.Atoi` и строгий диапазон 1–65535.

## Дополнение: install / uninstall / reinstall и возврат системного состояния — локальная проверка продолжается

- Добавлен отдельный root-only baseline `/var/lib/netos-system-baseline/state.json`, снимаемый новым бинарником строго до первого daemon `Apply`: IPv4/IPv6 firewall, статические и default routes, policy rules в диапазонах netOS, все реально изменяемые global/per-interface sysctl, hostname, timezone и точные enabled/active состояния `tuned`, `systemd-timesyncd`, `systemd-resolved`, а также прежний timesyncd drop-in. `reset` baseline не стирает; `uninstall --keep-data` заменяет использованный снимок маркером обязательного повторного захвата перед reinstall.
- Uninstall теперь удаляет виртуальные links только по `owned-links`, `owned-channels.json`, `owned-vpn-servers.json`, `owned-qos.json` и узким однозначным legacy-именам. Регресс подмешивает `br-foreign`, `bond-user`, `d-container`: ни один не удаляется. CAKE/HTB/ingress qdisc снимаются только с интерфейсов из `owned-qos*.json` до удаления IFB.
- Системный возврат проверен полным sandbox-сценарием: exact firewall stdin, IPv4/IPv6/static/default routes, foreign policy rule, sysctl, hostname/timezone, timesyncd config+restart, disabled/inactive resolved+tuned, QoS, owned/foreign links, binary/unit/data и одноразовый baseline. Ошибки обязательных capture-команд, повреждённый/неполный baseline, обе firewall family failures и все systemd states имеют отдельные тесты.
- Установщик валидирует `NETOS_PORT`, передаёт его только в первый bootstrap через `NETOS_INITIAL_PORT`, а итоговый update URL читает фактический сохранённый порт через `netosd -panel-port`. Capture-retry marker закрывает повторный запуск после оборванного первого снимка. Update теперь вооружает EXIT rollback до замены бинарника и возвращает прежние binary/unit/completion с restart при любом последующем отказе.
- Внешние Xray/dnsproxy больше не считаются собственностью netOS по одному имени файла. Root-only adjacent marker подтверждает ownership; чужой существующий бинарник даёт безопасную collision error, не перезаписывается, не принимается на баланс и не удаляется. Full uninstall удаляет только помеченные внешние компоненты.
- Локальные gates: полный `go test -count=1 ./...` PASS, `go vet ./...` PASS, production web build PASS, `git diff --check` PASS, Git Bash `bash -n install.sh` PASS. Statement coverage `internal/manage` после нового системного кода — 80,3%; новые restore/capture ownership helpers покрыты success/error/state matrices. Финальные Linux artifacts блока: `backend/netosd_linux` SHA-256 `f691d248441822ba5c31da07d9484359b1827160badb3de3ddd9057ce3466605`, `backend/manage_tests_linux` SHA-256 `e44b4fe9385e252d310fb303e1d66febc2a12192536f37ba9be7785af1041b30`, `backend/components_tests_linux` SHA-256 `858380ae1ca8a45d1f6529a19273b7258c9421d5e55df7be32b1c6e76a65944c`.
- Реальные systemd uninstall/reinstall и before/after snapshot пока не засчитаны: QA-подключение снова завершилось `Error reading SSH protocol banner` / `No existing session`; WSL2 на рабочей машине не запускается из-за отключённой виртуализации. Никаких разрушительных действий на недоступном хосте не выполнялось.

### DEF-129 — uninstall удалял чужие виртуальные интерфейсы по общим префиксам

- Статус: исправлен локально, exact ownership/foreign-link regression PASS; live ожидает QA.
- Любые `br-*`, `bond-*`, `vl-*` и даже `d-*` считались netOS-объектами. Контейнерный bridge или пользовательский bond мог быть уничтожен. Prefix ownership заменён точными persistent journals; legacy fallback оставлен только для нумерованных `wg-ch`, `tun-ch`, `wg-srv`, `xfrm-*`, `ifb-netos-*`.

### DEF-130 — uninstall не мог вернуть firewall, routes/rules и sysctl к состоянию до установки

- Статус: исправлен локально baseline capture/restore matrix PASS; live before/after ожидает QA.
- Firewall целиком обнулялся, все `proto static` удалялись, IPv6 static/netOS routes оставались частично, policy rules диапазона терялись, а sysctl заменялись семью предполагаемыми defaults. Новый baseline хранит и возвращает фактические значения; firewall применяется после системной уборки, пока unit/binary/data ещё доступны для аварийного повторного Apply.

### DEF-131 — hostname, timezone и состояния системных сервисов после uninstall отличались от исходных

- Статус: исправлен локально exact host/service/file-state regression PASS; live ожидает QA.
- `tuned` безусловно включался, `systemd-resolved` восстанавливался как boolean «нужен», hostname/timezone не возвращались, timesyncd drop-in мог остаться, а прежний active timesyncd не перечитывал восстановленный файл. Baseline теперь возвращает enabled/runtime/masked state, active state, host settings и содержимое/права drop-in; активный timesyncd явно restart-ится.

### DEF-132 — uninstall оставлял QoS qdisc на физических интерфейсах

- Статус: исправлен локально WAN/client ownership cleanup regression PASS; live tc inspection ожидает QA.
- IFB удалялся, но CAKE/HTB root и ingress qdisc на WAN/LAN продолжали действовать. Перед link cleanup теперь снимаются root+ingress только для interfaces из `owned-qos.json` и `owned-qos-clients.json`.

### DEF-133 — `NETOS_PORT` был декоративной переменной

- Статус: исправлен локально bootstrap override/invalid matrix и installer contract PASS; live alternate-port install ожидает QA.
- Установщик печатал выбранный порт, но daemon его не получал; при update ссылка также могла показывать 8443 вместо сохранённого custom port. Значение теперь строго 1–65535, не конфликтует с DNS 53, применяется только к новой ревизии и читается обратно из БД для вывода.

### DEF-134 — оборванный first-install/update оставлял неполную установку без надёжного повтора

- Статус: исправлен локально installer ordering/static contract и bash syntax PASS; live fault injection ожидает QA.
- После неуспешного первого capture оставшийся binary превращал повтор в upgrade и baseline навсегда пропускался. При update любой отказ после `mv` мог оставить новый binary/unit без rollback. Persistent capture marker и вооружённый EXIT rollback закрывают обе последовательности.

### DEF-135 — `uninstall --keep-data` ломал безопасность следующего reinstall

- Статус: исправлен локально keep-data existing/legacy baseline regressions PASS; live cycle ожидает QA.
- БД сохранялась и заставляла installer идти по upgrade-ветке, но использованный baseline удалялся либо отсутствовал. Следующий Apply менял систему без нового снимка. Теперь keep-data всегда оставляет только `.capture-required`; reinstall снимает свежий baseline непосредственно перед Apply.

### DEF-136 — внешний компонент мог перезаписать или удалить чужой `/usr/local/bin/xray|dnsproxy`

- Статус: исправлен локально foreign collision/preserve/remove ownership regressions PASS; live component cycle ожидает QA.
- Наличие файла ошибочно считалось ownership. Теперь install/update/remove и full product uninstall требуют точный приватный `.netos-owned` marker; unmarked target сохраняется побайтово и возвращает явную collision error.

## Дополнение: механическая сверка config schema ↔ API ↔ production web bundle

- Все JSON-поля `Config` и вложенных типов из `config.go`, `channel_config.go` и `vpn_server_config.go` сопоставлены с профильными страницами. Отдельно проверены поля, встречавшиеся в UI только при создании объекта, но не имевшие чтения/редактора. В результате обнаружены недоступные через панель, но уже исполняемые backend-поля: MAC интерфейса, расширенные условия policy, комментарии client/VPN peer и Xray Reality `show`.
- В UI добавлены редакторы MAC интерфейса; client comment; comment для WireGuard/Xray/ocserv/IKEv2 peer; policy `src_mac`, `network`, `vpn_server`, `vpn_peer`, `schedule.days/time_start/time_stop`, `comment`; первоначально read-only показ `domains`, позднее заменённый полноценным редактором в DEF-141; Xray `show`. Production bundle содержит новые элементы, TypeScript/Vite build PASS.
- Зарегистрированные HTTP routes сопоставлены с frontend client и route/lifecycle tests. Служебные `POST /api/config/validate`, `GET /api/revisions/{id}` и `GET /api/interfaces` не требуют отдельной кнопки и покрыты backend tests. Реализованный `POST /api/config/plan` имел client method, но не вызывался ни одной страницей; теперь ApplyBar после flush показывает точные actions, disruptive marker, subsystem/kind/target/detail.
- Добавлен `TestEmbeddedPanelExposesSupportedConfigFieldsAndPlan`: он проверяет именно встроенный production `webdist/app.js`, поэтому забытая web-сборка не выдаст source-only исправление за установленное. Полный `go test -count=1 ./...`, `go vet ./...`, production web build и `git diff --check` — PASS. Linux artifacts: `backend/netosd_linux` SHA-256 `89c8136d5925af14136151adc270591d7cd8aeb5b6b7c046db85c784d9f403bc`; `backend/api_tests_linux` SHA-256 `15f86ac1aece9bc754fde8523f8214504ef4d70391bf82167cbee3a55be941da`.
- Реальный click/input/save/plan/apply не засчитан: Browser skill после корректного bootstrap вернул пустой список доступных окон `[]`, а QA SSH остаётся недоступен. Статический контракт и production build — PASS, browser/live — pending.
- На момент этой сверки отдельно зафиксированы разрывы ACME, DNS blocklists, policy domains и перехода custom TLS; последующие DEF-139, DEF-140, DEF-141 и DEF-142 закрывают их локально.

### DEF-137 — реализованные config-поля были недоступны или лишь частично видимы в UI

- Статус: исправлен локально, production bundle contract и build PASS; browser click ожидает доступного окна/QA.
- Backend применял MAC интерфейса, полные policy selectors/schedule, VPN peer/client comments и Xray `show`, но панель не позволяла их изменить. Policy создавал поля с пустыми значениями и показывал только `src_ip`, `dst_ip`, protocol/port/channel`; это маскировало большую часть фактической схемы. Поддержанные поля получили явные редакторы; `domains` сначала был видим read-only, затем реализован и сделан редактируемым в DEF-141.

### DEF-138 — рабочий API плана применения не был достижим из панели

- Статус: исправлен локально, API lifecycle и production bundle regression PASS; live action list ожидает QA.
- `api.plan()` существовал, но не имел ни одного вызова. Администратор мог только сразу применить draft и не видел будущие disruptive actions. ApplyBar теперь сначала принудительно отправляет последнюю локальную правку, затем показывает план и маркирует разрывные действия до Apply.

### DEF-139 — custom TLS реализован на старте, но недостижим штатным способом настройки

- Статус: исправлен локально; API/UI/manager success, rejection, schedule-failure, stale-schedule и rollback matrices PASS; реальный systemd restart ожидает QA.
- Добавлен отдельный `POST /api/maintenance/panel`, который не выдаёт смену listener за обычный hot-Apply: он глубоко копирует активную конфигурацию, проверяет каждое поле панели, настоящую custom cert/key пару и доступность нового порта, синхронно меняет `sys-panel`, создаёт изолированную applying-ревизию и требует подтверждение `RESTART`. Обычный draft/pending apply блокирует операцию; viewer и запрос без CSRF её выполнить не могут.
- Transient root helper активирует подготовленную ревизию, перезапускает `netosd` и принимает успех только по точному `/run/netosd.ready` с ID новой ревизии. Перед каждым restart старый marker удаляется: отдельно подтверждено, что marker предыдущего процесса не может ложно засчитать rollback. При отказе запуска target помечается `rolled_back`, предыдущая ревизия снова становится active и перезапускается; если `systemd-run` принят, но helper не стартовал, stale guard снимает блокировку без активации target.
- System UI теперь редактирует port, `selfsigned|custom|acme`, cert/key paths, ACME domain/email/TOS, требует буквальное подтверждение `RESTART` и показывает адрес новой панели.

### DEF-140 — DNS blocklists присутствуют в публичной схеме, но всегда отклоняются при включении

- Статус: исправлен локально; schema/parser/download/cache/provider/UI/lifecycle/fault matrices PASS, live DNS query ожидает QA.
- `dns.blocklists[]` теперь строго проверяет ID, название, HTTPS URL без credentials/fragment, дубликаты URL и невозможность enable при выключенном DNS. UI позволяет добавить, назвать, изменить URL, включить/выключить и удалить список; production bundle contract защищает редактор от source-only сборки.
- Загрузчик принимает plain domains, hosts и Adblock `||domain^`, игнорирует comments/exceptions/localhost/IP/невалидные строки, нормализует регистр, дедуплицирует и сортирует. Ограничения: 16 MiB на ответ, 1 MiB на строку, 500000 уникальных доменов и максимум пять HTTPS redirects; HTTP status, insecure redirect, пустой эффективный список и oversized input отклоняются.
- Для dnsmasq, unbound и dnsproxy создаются разные managed-файлы, включаемые штатным синтаксисом провайдера. Изменение их содержимого принудительно перезапускает выбранный resolver; disable удаляет все provider-файлы. Health и Plan обнаруживают corrupt/missing/stale file/cache.
- Кэш имеет ключ SHA-256 полного URL и режим 0600. При сетевой/parse ошибке допускается только ранее успешно разобранный кэш того же URL. Снимок provider-файлов и всех затрагиваемых cache-файлов делается до загрузки; ошибка любого списка, preflight или restart возвращает прежние bytes/mode, а первая ошибка без кэша не касается рабочего файла.

### DEF-141 — policy domains присутствовали в схеме, но маршрутизация по доменам не была реализована

- Статус: исправлен локально; validation/render/provider/lifecycle/rollback/UI/uninstall matrices PASS, живой DNS→ipset→firewall маршрут ожидает QA.
- `policies[].domains` строго проверяет DNS-имена, канонические дубликаты и предел 128 доменов. Kernel-политики требуют включённый DNS и фильтрацию AAAA; при unbound/dnsproxy порт 5355 зарезервирован под loopback backend. Xray inbound использует собственный `domain:` matcher и не требует DNS frontend.
- Для обычной политики создаётся детерминированный IPv4 `hash:ip` set с timeout 300 секунд. Отдельное ограничение AAAA необходимо не только из-за IPv4-модели каналов: официальный dnsmasq `ipset=` не имеет family selector и иначе пишет ошибки при попытке добавить AAAA в IPv4 set. dnsmasq добавляет A-адреса ответов через `ipset=/.../`, а `max-ttl` и `max-cache-ttl` не позволяют корректному клиенту пользоваться адресом после истечения set. При unbound/dnsproxy dnsmasq слушает клиентов на публичном DNS-порту, пересылает запросы backend на `127.0.0.1:5355`; backend не выставляется в сеть и не дублирует query log.
- Транзакция разделена на `policy` до firewall и `policy-cleanup` после него: новые sets существуют к моменту загрузки правил, старые уничтожаются только когда iptables больше на них не ссылается. Повторный Apply сохраняет изученные адреса; create/ownership/cleanup failures восстанавливают kernel snapshot и точные bytes/mode ownership-файла.
- При `uninstall` после восстановления firewall удаляются только sets из валидного ownership-файла с именами, детерминированно соответствующими policy ID/family; повреждённое состояние не позволяет затронуть чужой ipset. UI редактирует домены построчно, production bundle contract не допускает source-only реализации.

### DEF-142 — режим TLS ACME был заявлен схемой, но всегда отклонялся

- Статус: исправлен локально; validation/account/challenge/issuance/readiness/renewal/rollback/UI matrices PASS, живой выпуск публичным CA ожидает QA-хост с доступным DNS и TCP/80.
- Добавлены строгие поля `domain`, необязательный `email` и обязательный `accept_tos`; зарезервированные зоны, IP, односоставные/опасные имена, неверный email и порт панели 80 отклоняются. ACME-кеш защищён режимом 0700 и разделён по аккаунту/email; другой SNI не допускается.
- HTTP-01 listener занимает TCP/80 до выпуска. Панель и exact-revision ready-marker появляются только после получения сертификата и успешного HTTPS `/api/ping`; ошибка, отмена или конфликт порта закрывают listener и не объявляют сервис готовым. Сертификат выдаётся динамически, смена fingerprint и приближение срока окончания журналируются.
- Firewall открывает только TCP/80 для HTTP-01 в ACME mode и убирает правило при смене режима. Maintenance API заранее проверяет порт, использует увеличенное окно выпуска и сохраняет штатный revision rollback.

## Дополнение: безопасная смена порта и custom TLS панели, 2026-09-01 05:27 MSK

- Проверены поля `port`, `commit_timeout`, `tls.mode`, `cert_file`, `key_file`, `domain`, `email`, `accept_tos`, неизвестный JSON, буквальное подтверждение, auth/role/CSRF, конфликт с draft/pending apply, обновление системного firewall rule и отсутствие мутации текущего in-memory config.
- Негативные сценарии: порт вне диапазона и детерминированно занятый порт; отсутствующая, неверная и несовпадающая cert/key пара; недоступный maintenance service; ошибка scheduling; неисполненный schedule; неверные revision IDs/states; target без ready marker; stale marker предыдущей ревизии; успешный rollback и rollback без подтверждения готовности.
- Локальные gates после финального исправления: `go test -count=1 ./...` PASS, `go vet ./...` PASS, `git diff --check` PASS (только предупреждения Git о будущей CRLF-конверсии), production `npm run build` PASS, Git Bash `bash -n install.sh` PASS. Bundle: `app.js` 382.48 kB, gzip 104.75 kB.
- Актуальные Linux amd64 artifacts: `netosd_linux` SHA-256 `73cd37d4b976d77e087c2ecc87c1ed2b59e353030c7c78b51dea94ff2e5a16f6`; `api_tests_linux` SHA-256 `bb602fa5cccad8b42b0b94be5b8010e0039ab9898d3755f6a240c39ea6c063fd`; `manage_tests_linux` SHA-256 `789cd6cb58ca47e8847fb51e8c02c68950b98a7ac1653e0a403e7b6f5b67b81b`.
- Реальный listener/systemd переход пока не засчитан: встроенный Browser не имеет доступного окна, QA SSH ранее не отдавал protocol banner. Следующий шаг этого же текущего гола — повторить read-only health/config/log capture на QA и, только после восстановления связи, прогнать restart/rollback под непрерывным мониторингом.
- Повторная read-only попытка в 05:29 MSK снова завершилась `Error reading SSH protocol banner` / `No existing session` до выполнения первой команды; ни сервис, ни конфигурация QA не изменялись.

## Дополнение: DNS blocklists, 2026-09-01 05:45 MSK

- Проверены все четыре поля `id/name/url/enabled`, disabled placeholder, duplicate ID/URL, DNS off, HTTP/credentials/fragment/control characters, unknown JSON через общий strict decoder, add/edit/enable/disable/remove UI и Plan reload/repair.
- Parser matrix покрывает plain, IPv4/IPv6 hosts, несколько имён в hosts-строке, Adblock rule/modifier, exception/comment/header, duplicate/case, localhost, literal IP, invalid label, пустой результат и oversized line. HTTP matrix покрывает 200, non-200, распакованный body limit и downgrade redirect.
- Provider lifecycle для dnsmasq/unbound/dnsproxy: include/hosts config, cache, exact Health, content-only restart, повторный Apply, fetch fallback, corrupt drift, disable cleanup, свежая ошибка без мутации и injected preflight failure с точным provider+cache rollback — PASS.
- Cold-cache полный `go test -count=1 ./...` и `go vet ./...` — PASS. До этого линковка честно упала при нулевом свободном месте; удалён только воспроизводимый Go build/test cache, освобождено 5,1 GiB, после чего те же пакеты и полный suite прошли заново. Production web build PASS: `app.js` 384.50 kB, gzip 105.16 kB.
- Актуальные Linux amd64 artifacts: `netosd_linux` SHA-256 `23b0312bb676ca6d815345e7893509ae85f047c9af9c0a5444e1a76948417461`; `api_tests_linux` `385c68402ecbcd21c007727dcedc2cc137992247db2b5035248a67bb8f67a099`; `manage_tests_linux` `6b4cc3f1037d7893b77d213f6103e2de00ee2f5b7c9ba4ef6bd9b40762ecb88f`; `services_tests_linux` `ae96b75ca91954a5128ca0cc40e5f4abee8729ac93eb4993552f57e3d0e894f8`.
- Реальный `dig`/blocked A+AAAA/NXDOMAIN, daemon logs и service restart пока не засчитаны из-за недоступного SSH banner QA-хоста; код и локальные симуляции не заменяют этот пункт.
- Отдельная HTTPS API-попытка в 05:49 MSK также не дошла до первого read-only `GET /api/ping`: curl завершился `schannel: failed to receive handshake`; idempotent save и остальные запросы не выполнялись, состояние QA не менялось.

## Дополнение: доменные политики маршрутизации, 2026-09-01 06:15 MSK

- Validation matrix покрывает каждое поле списка доменов: пустое/пробельное/управляющее/невалидное имя, underscore, регистр и завершающую точку, канонический дубликат, предел 128, disabled policy, DNS off, обязательный `filter_aaaa`, внутренний конфликт порта 5355 и отдельный Xray-inbound путь.
- Kernel lifecycle: детерминированный IPv4 `hash:ip` timeout 300, foreign collision, повреждённый ownership, legacy ownership migration, idempotent сохранение изученных адресов, немедленный flush при изменении fingerprint списка доменов, создание до firewall, удаление после firewall, set-in-use, injected prepare/cleanup failures и точный rollback kernel entries + ownership bytes/mode — PASS.
- DNS matrix: dnsmasq native и dnsmasq frontend перед unbound/dnsproxy; A-only learning без ошибочных IPv6 additions; `max-ttl/max-cache-ttl=300`; loopback-only backend 5355; отсутствие двойного query log; backend-before-frontend; оба preflight; first-apply и existing-state frontend failures с возвратом точных config/unit bytes и исходных active/enabled состояний — PASS.
- Firewall/Xray/UI/uninstall: IPv4 set selector комбинируется с остальными условиями; Xray получает native `domain:` matcher и не создаёт kernel/DNS frontend; панель редактирует домены построчно; production bundle contract PASS; uninstall после снятия firewall удаляет только криптографически проверенные owned set names и отказывается трогать чужие при tampered state.
- Полный `go test -count=1 ./...` PASS (26/26 пакетов), `go vet ./...` PASS, `git diff --check` PASS (только CRLF warnings), production `npm run build` PASS (`app.js` 384.68 kB, gzip 105.17 kB), Git Bash `bash -n install.sh` PASS. Системный `bash.exe` относится к недоступному WSL и не использовался как результат проверки.
- Актуальные Linux amd64 artifacts: `netosd_linux` SHA-256 `489b822885ddc4b5eaac5ab478a01df9085ae6924f262b10e1e39d528839ca28`; `api_tests_linux` `47d86b2ef8be4f93314944eacf6a8e5faab0e100bc21f179b52749000fb93c6a`; `manage_tests_linux` `4ebc7e46a7dd1d3bb65e218f4567ffa4fd42d8d571baef749fa4ac3643873a57`; `services_tests_linux` `cc36864ac230622fedf458883743c00d11d1fdf36e08e6733e124e610094f3c8`; `policy_tests_linux` `64d98d96287c3aed6391ffcc24ab6b4d091abf92216eabf729efda36e16dc3bf`.
- Live DNS→ipset→iptables, service/journal monitoring, provider switching and uninstall/reinstall before/after comparison не засчитаны локальными симуляциями и остаются обязательными пунктами текущего гола.
- Повторная read-only проверка в 06:16 MSK не выполнила ни одной удалённой команды: SSH снова завершился `Error reading SSH protocol banner`. Независимый HTTPS `/api/ping` с connect-timeout 8 секунд вернул `http=000`, `connect=0`, TLS handshake не начинался. Deploy и любые мутации на недоступном узле не выполнялись.

## Дополнение: автоматический TLS ACME панели, 2026-09-01 06:33 MSK

- Validation matrix покрывает `domain/email/accept_tos`, регистр и завершающую точку DNS-имени, пустое/односоставное/IP/зарезервированное/управляющее имя, неверный email, непринятые TOS и конфликт порта панели с HTTP-01 TCP/80. Strict JSON decoder продолжает отклонять неизвестные поля.
- После ручной сверки усилена семантика публичного имени: требуется ICANN public suffix, сам public suffix использовать нельзя, отдельно запрещены документационные `example.com/.net/.org` и `home.arpa`. Полученный X.509 обязан соответствовать запрошенному домену и быть уже действующим и не истёкшим; wrong-host/future/expired matrices PASS.
- Lifecycle matrix подтверждает порядок challenge-listener → issuance → panel-listener → живой HTTPS `/api/ping` → exact-revision ready-marker. Ошибка выпуска, занятый TCP/80, отмена контекста и ошибка ready callback не оставляют listener и никогда не объявляют новую ревизию готовой.
- Production manager использует защищённый cache directory 0700, отдельное пространство аккаунта по email, точный HostPolicy и динамический `GetCertificate`. Тест замены сертификата подтверждает выдачу новой пары без перезапуска и запись смены fingerprint монитором; приближение срока окончания и ошибки проверки также журналируются.
- Firewall matrix подтверждает ровно одно входящее правило TCP/80 только для ACME mode и его удаление при смене режима. Maintenance API принимает только полный ACME config, заранее выявляет занятый порт и даёт выпуску увеличенное окно до штатного revision rollback.
- System UI редактирует публичный домен, необязательный email и принятие TOS, предупреждает о доступности TCP/80. Production bundle contract и сборка не позволяют выдать изменение только исходников за установленную функцию.
- Локальный `go test -count=1 ./internal/api` после добавления проверки живого API и cleanup — PASS. Полный `go test -count=1 ./...` PASS (26/26 пакетов), `go vet ./...` PASS, `git diff --check` PASS (только CRLF warnings), production `npm run build` PASS (`app.js` 386.39 kB, gzip 105.61 kB), Git Bash `bash -n install.sh` и `bash -n scripts/dev-push.sh` PASS. Локальная симуляция не засчитывается как публичный выпуск сертификата.
- Актуальные Linux amd64 artifacts после усиления проверки публичного домена и X.509: `netosd_linux` SHA-256 `2c6c481eddcf1205205f641e7ac97811e6118d3e88634d4e16b2194ff883b7c7`; `api_tests_linux` `90f35ba9fc50a82bcb563d745b9f21b3f82b5f2147484bef642261a0da1899d6`; `config_tests_linux` `3dc51f42d10bce22c9e53dccd7f5366e5e0eb618e5e432f1a31d62eebe759f0f`; `manage_tests_linux` `1d4ca40af121f4150203e0fb1bd55b536a033f16f50878ea9a86d2639d881150`; `firewall_tests_linux` `ce1a7c8304c1489544ccd7c30dea9ed3d3f2a04f1ff8287f5ecbad475827fbd1`.
- Повторный read-only QA probe в 06:37 MSK снова не выполнил удалённых команд: SSH исчерпал timeout во время protocol banner. Параллельный HTTPS `/api/ping` за 8 секунд не установил TCP-соединение (`http=000`, `connect=0`, TLS не начался). Deploy, config apply и другие мутации не выполнялись.
- Race-detector не был засчитан: локальная Windows-среда требует CGO, а C-компилятор `gcc` отсутствует. Вместо ложного PASS изменённые API/config/manage/firewall пакеты прогнаны пять раз с `-shuffle=on`; все повторы PASS. Полноценный race gate остаётся пунктом Linux QA/CI.

## DEF-143 — WAN записывал невыполненную конфигурацию как принадлежащую netOS, 2026-09-01 06:56 MSK

- Статус: исправлено локально; повторная live-проверка текущей сборки ожидает восстановления QA-хоста.
- Успешная Apply-матрица покрывает `static`, `DHCP`, `PPPoE` и `L2TP` со статическим underlay: выбор интерфейса, link-up, адрес, default route, metric, создание unit/config и точное сохранение ownership.
- Дефект: enabled WAN с отсутствующим физическим link молча пропускался, но финальная синхронизация всё равно записывала желаемые адрес и маршрут как owned. Кроме того, ownership всех желаемых объектов публиковался до первой сетевой команды, поэтому ранняя ошибка создавала ложные заявления о ещё не выполненных шагах.
- Исправление: до cleanup и сетевых мутаций проверяется наличие каждого enabled WAN-интерфейса. Ownership адреса и маршрута теперь публикуется пооперационно непосредственно перед соответствующей командой; выполненная либо потенциально частично выполненная операция остаётся доступна rollback, а не начавшаяся операция не считается выполненной.
- Негативная матрица PASS: missing link — ноль команд и ownership; ошибка `ip link set up` — нет address ownership; ошибка `ip addr replace` — только ownership предпринятого адреса; ошибка `ip route replace` — ownership уже предпринятых адреса и маршрута.
- Дополнительно проверены Plan create/update/delete/repair доменных политик и lifecycle управляемых service-файлов: точные bytes/mode, отсутствие лишней записи при совпадении, drift, cleanup, validation callback и удаление временного файла после ошибки.
- Покрытие `WAN.Apply` выросло с 8,0% до 71,7%, пакета `internal/subsys/netiface` — до 84,0%. Непокрытые остатки в основном относятся к настоящим Linux runtime/Health веткам и будут проверяться на QA, а не объявляться завершёнными по fake-system.
- После исправления полный `go test -count=1 ./...` PASS (27/27 пакетов), `go vet ./...` PASS, production `npm run build` PASS (`app.js` 386.39 kB, gzip 105.61 kB), `git diff --check` PASS без whitespace-ошибок (только предупреждения Git о будущей CRLF-конверсии).

## DEF-144 — итоговый WAN link/MTU ошибочно считался drift физического интерфейса

- Статус: исправлено локально; регрессионный пакет и полный suite PASS.
- Конфигурационный контракт допускает disabled physical-interface под enabled WAN: WAN сам поднимает link. Также `wans[].mtu` намеренно переопределяет MTU несущего интерфейса. До исправления `Interfaces.Health`, выполняемый после всех Apply, сравнивал итоговое состояние только с промежуточными `interfaces[].enabled/mtu` и мог откатить исправно поднятый WAN.
- Health теперь вычисляет составное ожидаемое состояние: enabled WAN требует административный UP независимо от флага физического интерфейса, а непустой WAN MTU имеет приоритет над interface MTU. Отдельный regression test подтверждает успешное итоговое состояние и обнаружение последующего MTU drift.
- Повторный полный `go test -count=1 ./...`, `go vet ./...` и `git diff --check` после исправления — PASS.

## DEF-145 — повторный WAN/Networks Apply изменял runtime и файлы при чистом состоянии, 2026-09-01 07:12 MSK

- Статус: исправлено локально; повторный live Apply текущей сборки ожидает QA.
- Контракт `apply.Subsystem` требует, чтобы повторный Apply той же конфигурации ничего не менял и не рвал трафик. До исправления WAN безусловно выполнял `ip link set`, static `addr/route replace`, L2TP host-route replace и атомарно заменял DHCP/PPPoE/L2TP/ownership-файлы. Networks также всегда поднимал link и дважды записывал ownership.
- Добавлен общий `system.WriteFileAtomicIfChanged`: совпадающий regular-файл с правильным mode сохраняет inode/mtime, а content/mode drift и symlink/non-regular target исправляются атомарной заменой. Отдельный тест проверяет отсутствие повторной записи и исправление mode drift на поддерживающей permissions платформе.
- WAN перед мутацией сверяет административный UP/MTU, точный адрес, default route и L2TP host-route. DHCP/PPPoE/L2TP конфиги и unit-файлы записываются только при content/mode drift; уже enabled unit повторно не включается. Удалён ставший ненужным snapshot-код `pppoePrevious/readPPPoEConfs/readL2TPConfs`.
- Полная матрица второго Apply для static/DHCP/PPPoE/L2TP PASS: нет `link set`, `addr`, route replace/delete, daemon-reload, enable/disable/restart; mtime каждого созданного regular-файла не меняется. Аналогичный runtime+mtime тест Networks PASS.
- Active, но disabled DHCP unit теперь включается в автозапуск без restart и потери текущей аренды. Health отдельно отклоняет active-but-disabled DHCP/PPPoE/L2TP unit, поскольку состояние не переживёт reboot.

## DEF-146 — WAN Health не проверял обязательный маршрут L2TP до LNS, 2026-09-01 07:12 MSK

- Статус: исправлено локально; live reconnect/fault injection ожидает QA.
- До исправления активный PPP-интерфейс и default route давали PASS даже после удаления host-route до LNS через сеть провайдера. Текущий туннель мог временно жить, но следующее переподключение направляло бы трафик к концентратору через сам туннель и падало.
- Health читает persisted owned LNS routes, требует хотя бы один маршрут для физической подложки и сверяет точные destination/gateway/interface с `ip -4 route show`. Happy path и удалённый route PASS/FAIL подтверждены отдельными тестами.
- После DEF-145/146: `internal/subsys/netiface` 84,6% statements; полный последовательный `go test -count=1 ./...` PASS (27/27 пакетов), `go vet ./...` PASS, production build PASS (`app.js` 386.39 kB, gzip 105.61 kB), `git diff --check` PASS без whitespace-ошибок. Первый параллельный запуск Go suite и Vite не засчитан как product failure: Vite очищал `webdist` во время Go embed; последовательный повтор на готовом bundle полностью PASS.
- Актуальные Linux amd64 artifacts: `netosd_linux` `62a1069419ac33ccefd97689e825889dbfd64f7bf27f7a4a5706439973fb22f7`; `api_tests_linux` `acabf026b82dc708b1294f6590e2a1c91d10924216bac926677c64d9c90a6a8e`; `netiface_tests_linux` `6d129da8ae02b84e3ce42929bedccc39df643c2ee13d45f04581a2c873d376a3`; `system_tests_linux` `614c8b21d3e7fe8d0627f3a8b7518996393a0fda1d37f41b2f9b1c3d660507f6`; `services_tests_linux` `0624e32227e279b4c88273088b36133fd3c7d22edb3e0e1c8c88e738644c1d3e`; `policy_tests_linux` `5f5b6fb8add17731392df6e918341a7dc175d3a43f89f8e969bc13d8c7156848`.
- Read-only QA probe в 07:12 MSK снова не дошёл до удалённой команды: SSH завершился `Connection timed out during banner exchange`; HTTPS `/api/ping` не установил TCP-соединение за 8 секунд (`http=000`, `connect=0`, TLS не начался). Deploy/apply и любые удалённые мутации не выполнялись.

## DEF-147 — DNSSEC Health принимал пустой/необычный/подменяемый root.key, 2026-09-01 07:19 MSK

- Статус: исправлено локально; настоящий `unbound-anchor`/DNSSEC query lifecycle ожидает Linux QA.
- До исправления `ensureTrustAnchor` и Health считали валидным любой объект, для которого проходил `os.Stat`: пустой файл, каталог и symlink. Это давало ложный PASS для неработающего либо подменяемого DNSSEC anchor.
- Новый `trustAnchorHealth` требует обычный non-empty файл без symlink; на Linux также запрещает group/world-write. Пустой regular-файл восстанавливается через `unbound-anchor`; каталог и symlink отклоняются до внешней команды, symlink-target остаётся побайтово неизменным. Матрица missing/empty/directory/symlink/insecure-mode покрыта тестами (mode-ветка выполняется на Linux).
- `Unbound.Health` теперь не ограничивается совпадением bytes: после managed files и anchor запускается read-only `unbound-checkconf` именно для активного пути. Injected checkconf failure корректно даёт Health FAIL.
- `Dnsproxy.Health` матрично проверен для active/inactive selected daemon, missing binary, content drift config/hosts/systemd-unit, active unselected daemon, поэтапных stale artifacts и полного disabled cleanup. Покрытие services выросло до 85,1%, `Dnsproxy.Health` — до 93,3%, `Unbound.Health` — до 87,5%, `trustAnchorHealth` — до 90,0%.
- Полный последовательный `go test -count=1 ./...` PASS (27/27 пакетов), `go vet ./...` и `git diff --check` PASS. Актуальные Linux amd64: `netosd_linux` `bc372fd068ae72ab3ebe1331854aece85298812f8cf28cc21ff0bd9b772903fe`; `services_tests_linux` `e8a2d606793f45fe2e11716c90e301f01377948a34e9be11dafcd0a226df9eeb`.

## DEF-148 — WireGuard server не полностью соблюдал idempotency и сохранял IPv6-off после смены режима, 2026-09-01 07:24 MSK

- Статус: исправлено локально; live handshake/traffic и переход IPv6 ожидают QA.
- До исправления повторный Apply безусловно выполнял `ip link set ... mtu ... up`, повторно писал per-interface `disable_ipv6=1` и мог менять metadata secret/ownership-файлов. Health при этом не проверял UP, MTU и `disable_ipv6`.
- Более существенный transition-дефект: после создания WireGuard при глобальном IPv6 `off` смена на `passthrough` не возвращала `disable_ipv6` в `0`; интерфейс навсегда оставался без IPv6 до ручного вмешательства/пересоздания.
- Apply теперь сверяет фактические UP/MTU, меняет link только при drift, двусторонне reconciles `disable_ipv6` как `1` для `off` и `0` для `passthrough`, а совпадающие файлы сохраняет через общий atomic-if-changed. `wg syncconf` остаётся намеренной штатной reconciliation-командой.
- Health проверяет UP, точный MTU с default 1420, per-interface IPv6 state, listen port, address и exact config. Матрица PASS: чистый второй Apply без link/address/file/sysctl mutation; DOWN и MTU drift; `off → passthrough → off`; ручной IPv6 drift; matching-content secret-config symlink (Health FAIL, Apply безопасно заменяет symlink без изменения foreign target).
- Полный `go test -count=1 ./...` PASS (27/27), `go vet ./...` и `git diff --check` PASS. Актуальные Linux amd64: `netosd_linux` `d3b496e5820625764541971d4a7a867efab43d59bdb6ce4c3b026888b7179ee3`; `vpnservers_tests_linux` `7261a5248067fdd5a9143083d3d285930f02171e5e2eef3f498f149d40b7ed83`.

## DEF-149 — IKEv2 XFRM безусловно перенастраивался и не проверял UP/MTU, 2026-09-01 07:33 MSK

- Статус: исправлено локально; Linux XFRM lifecycle ожидает QA.
- До исправления каждый Apply безусловно выполнял `ip link set ... mtu ... up`, а Health проверял только наличие XFRM и адреса. Ручной `DOWN` либо неверный MTU не обнаруживались.
- Apply теперь читает `ip -o link show`, сохраняет чистое runtime-состояние при совпадении и выполняет link-set только при drift. Health требует административный `UP` и точный MTU (default 1400).
- Fake-system lifecycle PASS: первый Apply создаёт и поднимает XFRM, второй не повторяет link-set, MTU 1399 и `DOWN` дают Health FAIL и исправляются следующим Apply. Целевой `go test -count=1 ./internal/subsys/vpnservers` PASS.

## DEF-150 — IKEv2 адрес пула не закреплён за учётной записью, 2026-09-01 07:33 MSK

- Статус: опасное поведение закрыто fail-closed ограничением; полноценный multi-user IKEv2 остаётся нереализованным и текущий гол остаётся активным.
- `ikev2Pool` сортирует адреса enabled peers и передаёт strongSwan сплошной диапазон от минимального до максимального. Например, peers `.2` и `.4` создают pool `.2-.4`, включая вообще не объявленный `.3`.
- In-memory pool strongSwan выделяет адрес по пулу/identity affinity, но текущий конфиг не задаёт обязательное первоначальное соответствие `username → peer.Address`. Одновременно firewall, peer channel и policy selectors считают `peer.Address/32` достоверной личностью. В результате два пользователя могут получить правила друг друга, а неописанный адрес — обойти peer-specific правила.
- Установка strongSwan сейчас включает standard/extauth plugins, но не SQL pool plugin и не создаёт базу предварительно назначенных lease. Разделение на connections по `remote.eap_id` также нельзя считать совместимым решением для наблюдаемого на QA strongSwan 6.0.1: документированное matching по EAP identity появилось в 6.0.2.
- Официальная конфигурация Debian 13 strongSwan 6.0.1 проверена дополнительно: пакет собран без `--enable-attr-sql` и `--enable-sqlite`, а опубликованные file lists не содержат этих плагинов. Добавить штатный repository package для preassignment невозможно.
- Реализована защита: validator отклоняет второго enabled peer по точному пути `vpn_servers[i].peers[j].enabled`; renderer независимо отклоняет двусмысленный multi-user pool и для одного пользователя выдаёт ровно один адрес без диапазона/пробелов. Disabled peer остаётся допустимым черновиком.
- UI объясняет ограничение, показывает предупреждение и блокирует включение второго пользователя, пока первый активен. Backend остаётся окончательной защитой от обхода UI.
- Targeted config/VPN tests, полный `go test -count=1 ./...` (27/27), `go vet ./...`, production `npm run build` (`app.js` 386.99 kB, gzip 106.04 kB) и `git diff --check` PASS. Linux amd64 artifacts: `netosd_linux` `c5d0d80dd59220edbd84678f7c236522c5daddc31a52b40aa8b6321b6bfc7fae`; `vpnservers_tests_linux` `4b3c1ae9a59c5cffa695600d110456fba4807f42d9dce9f8430b89a355900af1`; `config_tests_linux` `653b7427fbe7ca179d992934ae5398db0efa64b3e2839edd1dd51f06b4848129`.

## DEF-151 — OpenConnect Health и повторный Apply доверяли подменённым passwd/per-user файлам, 2026-09-01 07:39 MSK

- Статус: исправлено локально; настоящее password login и live drift ожидают Linux QA.
- До исправления auth marker содержал только SHA-256 конфигурации peers. Если `.passwd` и каталог users существовали, Apply не сверял их содержимое, а Health делал только `os.Stat`. Подмена password hash, `explicit-ipv4` или добавление лишнего пользователя проходили Health и сохранялись после повторного Apply.
- Маркер заменён версионируемым по структуре JSON-состоянием с digest peers и фактически созданного passwd. Проверка требует regular passwd/auth без symlink и с mode 0600, точный набор уникальных enabled usernames без пустых hashes, обычный users-каталог mode 0700 и ровно по одному regular 0600 per-user файлу с точным `explicit-ipv4`.
- Любой drift заставляет Apply заново создать passwd через `ocpasswd`, атомарно заменить users и записать новый marker. Чистое состояние сохраняет прежние salted hashes и не вызывает restart.
- Regression matrix PASS: изменение password hash, неправильный peer IP, лишний user file и подмена marker — Health FAIL; следующий Apply восстанавливает каждый случай и возвращает Health PASS.

## DEF-152 — VPN TLS Health принимал несовпадающие ключи и генератор мог перезаписать symlink-target, 2026-09-01 07:39 MSK

- Статус: исправлено локально; live TLS handshakes IKEv2/OpenConnect ожидают QA.
- OpenConnect/IKEv2 Health раньше проверял только существование TLS-путей. Теперь общая read-only `ValidatePairForNames` требует regular cert/key без symlink, modes 0644/0600, совпадающую ключевую пару, текущий срок действия и покрытие всех обязательных hostname/public identities.
- `EnsureSelfSignedForNames` больше не открывает конечный путь с truncate: PEM записывается через atomic replace. Matching symlink заменяется обычным управляемым файлом, а чужой target остаётся побайтово неизменным.
- Tests PASS: валидная пара/fingerprint, missing SAN, mismatched key, symlink replacement без изменения target; в OpenConnect и IKEv2 сломанный private key даёт Health FAIL и исправляется Apply.
- После DEF-151/152 полный `go test -count=1 ./...` (27/27), `go vet ./...` и `git diff --check` PASS. Linux amd64 artifacts: `netosd_linux` `34a59ac5c8228ffbf73c40bb4c6d3bf3d6afc31116aa624f4e3a1f8bf48ecf1f`; `vpnservers_tests_linux` `682a92b97db5186c3e37ca2f2fc6c4279810bb87064830124a1def2c1c1135b7`; `tlsutil_tests_linux` `4ec355e28ecf625733119f55392532d4a4b67f79f584e332d1719d602961e532`.
- Read-only QA probe в 07:39 MSK снова не дошёл до команд: SSH timeout во время protocol banner; HTTPS `/api/ping` не установил TCP за 8,02 с (`http=000`, connect/TLS 0). Удалённых мутаций не было.

## DEF-153 — uninstall мог объявить успех при работающем компоненте или неудалённом артефакте, 2026-09-01 07:42 MSK

- Статус: исправлено локально; реальный uninstall/reinstall и before/after snapshot остаются обязательным пунктом текущего гола.
- До исправления динамические `netos-*.service` останавливались через best-effort, ошибки `systemctl disable --now` терялись, а unit всё равно удалялся. Ошибки удаления большинства системных конфигов, основного unit, бинарника и CLI также игнорировались; команда могла вывести «netOS удалён» при оставшемся процессе/файле.
- `removeComponentUnits` теперь fail-closed: сначала подтверждённо останавливает и отключает каждый существующий unit, затем проверяемо удаляет его; при ошибке сохраняет unit, пытается вернуть `netosd` и прекращает uninstall.
- Удаление всех перечисленных managed system/network paths, основного unit, `netosd` и CLI теперь проверяет результат и допускает только фактическое отсутствие. Success message остаётся строго последней операцией после всех обязательных удалений.
- Негативные tests PASS: injected stop failure сохраняет unit и не печатает успех; non-empty managed path вызывает точную ошибку и также не печатает успех. Полный `go test -count=1 ./...` (27/27), `go vet ./...` и `git diff --check` PASS.
- Linux amd64 artifacts: `netosd_linux` `6e267744efa1dba65aa06829c3790445009190ec225b06ffc5cb5aade223fb1c`; `manage_tests_linux` `3f4e4e9fb532cfa57872d7b1503afb1963feb101db1c7761046251071d0770ed`.

## DEF-154 — reset мог продолжить удаление после неудачной остановки компонента или очистки firewall, 2026-09-01 07:55 MSK

- Статус: исправлено локально; реальный reset под мониторингом systemd/firewall ожидает Linux QA.
- `reset` игнорировал результат удаления динамических `netos-*.service`, а обе ветки `iptables-restore`/`ip6tables-restore` выполнялись best-effort. Поэтому команда могла удалить БД и объявить заводской сброс завершённым при работающем старом компоненте либо частично оставшемся firewall.
- Остановка/disable и удаление каждого component unit, IPv4 firewall restore и IPv6 firewall restore теперь обязательны. При любой ошибке reset прекращает дальнейшее удаление и пытается снова запустить прежний `netosd`, чтобы тот reconciled уже затронутое состояние.
- Удаление каждого managed system/network path в reset также стало проверяемым: неудаляемый файл или каталог больше не превращается в ложный успех.
- Regression matrix инъецирует отказ `iptables-restore`, `ip6tables-restore` и остановки компонента; во всех случаях БД сохраняется, сообщение об успехе отсутствует и выполняется попытка возврата daemon.

## DEF-155 — rollback установщика не покрывал чистую/раннюю установку и частично существующие каталоги, 2026-09-01 07:55 MSK

- Статус: исправлено локально; fault-injection установщика и реальный install/update/uninstall/reinstall остаются обязательной Linux QA-матрицей.
- Транзакция раньше вооружалась только после замены бинарника и сохраняла предыдущий executable лишь при upgrade. Ошибка после записи apt policy, установки зависимостей, создания каталогов, baseline capture или частичного первого daemon Apply оставляла изменения чистой установки на машине.
- EXIT-транзакция теперь начинается до первого принадлежащего netOS изменения. Она снимает бинарник, CLI, unit, completion, apt policy, полное содержимое и метаданные state/config/log/system-baseline каталогов, а также active/enabled состояния прежнего `netosd`.
- При неудачной чистой установке, успевшей запустить daemon, rollback сначала вызывает только штатную CLI-ссылку на текущий бинарник через `uninstall --keep-data --yes`, возвращая сохранённый firewall/routes/rules/sysctl/hostname/timezone и службы. Затем атомарно возвращаются исходные файлы/каталоги и прежнее systemd-состояние. Частично существовавшие каталоги теперь восстанавливаются целиком, а не ошибочно считаются неизменёнными.
- Статический contract проверяет наличие всех snapshots/restores и безопасный порядок transaction → apt policy → binary → baseline → daemon start → disarm. Git Bash `bash -n install.sh`, целевой `go test -count=1 ./internal/manage` и полный локальный шлюз PASS.
- После финального исправления: полный `go test -count=1 ./...` PASS, `go vet ./...` PASS, `bash -n install.sh` и `bash -n scripts/dev-push.sh` PASS, `git diff --check` PASS без whitespace-ошибок (только предупреждения о будущей CRLF-конверсии).
- Актуальные Linux amd64 artifacts: `netosd_linux` SHA-256 `230cc95e951e917c09c2ebe92565cc302d5a5745cdcc453ea11c9b6be4570bdf`; `manage_tests_linux` SHA-256 `83030879d330a8386ba9649faf21728214b8a3d44f30d20b033b5d5bef913142`.
- apt-зависимости не объявлены совпавшими: публичная семантика `netos uninstall` прямо оставляет установленные через apt компоненты. Реальный before/after обязан зафиксировать точный package delta отдельно; локальная файловая транзакция его не подменяет.

## DEF-156 — installer принимал ранний `systemd active` за завершённый Apply, 2026-09-01 08:02 MSK

- Статус: исправлено локально; реальный медленный Apply/ACME и rollback ожидают Linux QA.
- Unit использует `Type=simple`, поэтому `systemctl is-active` становится истинным сразу после запуска процесса — до применения конфигурации, запуска TLS listener и live HTTPS probe. Установщик требовал лишь 20 секунд непрерывного `active` и после этого снимал rollback-защиту; зависший Apply либо процесс в restart-loop мог быть объявлен успешной установкой.
- Перед restart теперь явно удаляется `/run/netosd.ready`. Успех допускается только когда unit active и свежий непустой marker существует; daemon пишет его после полного Apply, живого TLS listener и собственного `/api/ping`. Окно 360 секунд покрывает медленное устройство и ACME HTTP-01.
- Возврат предыдущей версии в EXIT rollback проверяется тем же marker-критерием и больше не печатает «работает» только по раннему active.
- Installer contract фиксирует порядок stale-marker removal → restart → ready wait → rollback disarm. `bash -n` и targeted manage tests PASS.

## DEF-157 — QA dev-push оставлял нерабочий бинарник и проверял службу фиксированной паузой, 2026-09-01 08:02 MSK

- Статус: исправлено локально; live success/failure deploy ожидает восстановления QA.
- Скрипт без snapshot заменял работающий бинарник, ждал три секунды и проверял только `systemctl is-active`. Ошибка после `mv`, поздний Apply failure, restart-loop или грязный post-Apply plan оставляли стенд на новой неисправной версии, и следующие тесты могли ошибочно исследовать уже повреждённое состояние.
- Перед заменой снимаются точные binary/CLI/completion. Новая версия считается принятой только после свежего ready marker и чистого `netos plan`; затем отдельно выводятся failed units и revision marker. При любом отказе печатаются последние 40 строк daemon journal, возвращаются прежние файлы, перезапускается старая версия и повторно проверяются ready marker и clean plan.
- CI теперь выполняет `bash -n` и `shellcheck --severity=warning` также для `scripts/dev-push.sh`. Локальный static regression проверяет обязательные snapshot/restart/wait/plan/restore шаги и CI contract; Git Bash syntax и targeted manage suite PASS. Локальный shellcheck отсутствует, поэтому его результат до CI/Linux не заявляется.
- Финальный полный локальный gate после DEF-156/157: `go test -count=1 ./...`, `go vet ./...`, `bash -n` для install/dev-deploy/dev-push и `git diff --check` PASS. Актуальные Linux amd64: `netosd_linux` SHA-256 `230cc95e951e917c09c2ebe92565cc302d5a5745cdcc453ea11c9b6be4570bdf`; `manage_tests_linux` SHA-256 `f862bba09a0e2d19c3f294fe6e7bb7300b3b923c0e2430d6bfa002689d12c2d8`.
- Read-only QA probe в 07:49:42 MSK: SSH timeout во время protocol banner; независимый HTTPS не установил TCP за 8,008878 с (`http=000`, connect/TLS 0). Ни одна удалённая команда не исполнилась, стенд не изменялся.

## DEF-158 — remote-source dev-deploy мог собрать stale-файлы и активировать непроверенный бинарник, 2026-09-01 08:08 MSK

- Статус: исправлено локально; обе ветки remote build с/без `--restart`, vet failure и activation rollback ожидают Linux QA.
- Старый скрипт распаковывал новое дерево поверх `/opt/netos`, поэтому удалённый локально `.go`-файл оставался на QA и продолжал входить в сборку. Pipeline `go mod tidy | grep ... || true` скрывал реальную ошибку tidy. Неизвестные аргументы принимались молча, binary заменялся до optional vet, а `--restart` снова проверял только active после трёх секунд без rollback.
- Upload теперь собирается в отдельном `/opt/netos.upload`, затем заменяет только принадлежащее скрипту source-tree с возвратом `/opt/netos.previous` при ошибке swap. Воспроизводимые coverage/Linux artifacts и output/dist не отправляются на QA. `set -euo pipefail`, точный parser аргументов и remote `set -o pipefail` не позволяют замаскировать tidy/build/vet failure.
- Remote build создаёт CGO-off `netosd.candidate` и не касается рабочего binary. Без `--restart` кандидат только собирается; с `--restart` он скачивается во временный локальный файл и передаётся `dev-push` через `NETOS_BINARY_FILE`, поэтому snapshot, fresh ready marker, clean plan, logs и automatic rollback едины для обеих доставок.
- Static regression фиксирует clean upload → tidy → возврат go.mod/go.sum → build → transactional activation. Git Bash syntax и targeted manage tests PASS; shellcheck остаётся CI/Linux gate и локально не заявлен.
- После DEF-158 полный `go test -count=1 ./...`, `go vet ./...`, синтаксис всех трёх shell-скриптов и `git diff --check` PASS. Актуальный `manage_tests_linux` SHA-256 `f8e3c9a2f016a74158874c5574637229b25d6e3602c8739f53297c15ed28815d`; `netosd_linux` остаётся `230cc95e951e917c09c2ebe92565cc302d5a5745cdcc453ea11c9b6be4570bdf` (Go production source после предыдущей сборки не менялся).
- Read-only availability monitor 07:57:59, 07:58:42, 07:59:24 и 08:00:06 MSK: каждый цикл получил SSH exit 255 и HTTPS curl exit 28 с `http=000`, TCP/TLS time 0. Ни одна remote command не начала исполнение. После четвёртого одинакового результата локальный monitor-процесс остановлен; live deploy/E2E не засчитаны, текущий гол остаётся активным.
- Недостающий локальный shellcheck gate закрыт официальным ShellCheck v0.11.0: release asset `shellcheck-v0.11.0.zip` перед распаковкой совпал с опубликованным SHA-256 `8a4e35ab0b331c85d73567b12f2a444df187f483e5079ceffa6bda1faa2e740e`; `--severity=warning install.sh scripts/dev-deploy.sh scripts/dev-push.sh` завершился exit 0 без diagnostics. Системная установка не выполнялась. Две cleanup-команды были отклонены execution policy до запуска; четыре точных временных файла остались в `C:\Users\NymVetamin\AppData\Local\Temp\netos-shellcheck-410da040fc6a4997b9996cf7f0d32657`, обход защиты не предпринимался.
- Read-only QA probe 08:02:17 MSK: SSH exit 255 во время protocol banner; HTTPS curl exit 28, `http=000`, TCP/TLS 0, total 8,009377 s. Remote command не исполнялась, состояние QA не менялось.
- Текущее состояние встроенного Browser перепроверено через обязательный browser runtime/diagnostics: подключение backend `iab` вернуло `Browser is not available`, однократный authoritative discovery — пустой список `[]`. UI E2E не засчитан; инструкция backend запрещает подменять отсутствующее встроенное окно несвязанным browser surface.
- Race gate локально по-прежнему не может стартовать: `gcc`, `clang`, `zig`, `cc` и MSVC `cl` отсутствуют, `CGO_ENABLED=0`; это проверено текущим PATH/`go env`, а не унаследовано из старого журнала. Race остаётся Linux QA/CI-пунктом, PASS не заявляется.

## DEF-159 — QA lifecycle verifier не доказывал точный before/after и SSH helper доверял неизвестному host key, 2026-09-01 08:10 MSK

- Статус: локальные verifier contracts исправлены и PASS; исполнение полного цикла ожидает восстановления QA.
- Старый capture не снимал IPv6 address/rule/route, manual package state, ipset, bridge/tc, stable listeners, hostname/timezone, полный фактический managed sysctl, состояния всех netOS/host units, system baseline и managed-конфиги вне `/etc/netos`. Comparator лишь печатал часть render/package/TLS отличий и мог завершиться успехом при `CHANGED`/`MISSING`.
- Capture теперь сохраняет стабильные и диагностические представления package/systemd/network/firewall/ipset/tc/resolver/sysctl/files/logs, оба IP family и manifest. Comparator fail-closed проверяет manifests, exact stable host state, все renders, backup-vs-live TLS/generated, clean `netos plan`, свежий ready marker и пустой `systemctl --failed`; каждое отличие увеличивает итоговый failure count и даёт non-zero exit.
- `qa-remote.py` больше не использует `AutoAddPolicy`: неизвестный или изменившийся SSH host key останавливает соединение до upload/command. Help/import path проверен с `python -B`; статический contract запрещает возврат AutoAddPolicy.
- Live API runner сопоставлен с фактическими 39 маршрутами `Server.Routes`. Добавлены password rejection, confirm/rollback без pending, неверные maintenance confirmations, invalid/missing revision, missing backup delete/download, все revision details, первые три backup range-download и сертификаты каждого enabled OpenConnect/IKEv2 server. Новые routes теперь ломают contract, пока не получат safe live marker либо явную destructive-классификацию; success apply/revision-restore/backup-create остаются в отдельном monitored lifecycle.
- Полный gate после изменений: все Go packages PASS, `go vet ./...` PASS, Git Bash syntax всех install/deploy/QA shell scripts PASS, ShellCheck v0.11.0 `--severity=warning` PASS, PowerShell parser PASS, Python helper load/help PASS, `git diff --check` PASS. Актуальный `manage_tests_linux` SHA-256 `7a571540c8324275857d7e35ac644b1ecb2c17909e62661658be919c369737ea`.
- Read-only QA probe 08:10:46 MSK: SSH снова завершился timeout во время protocol banner; HTTPS curl exit 28, `http=000`, TCP/TLS 0, total 8,010151 s. Ни одна remote command не исполнилась.

## DEF-160 — QA before/after пропускал 5 из 16 render-артефактов, daemon help показывал только 4, 2026-09-01 08:14 MSK

- Статус: исправлено локально; реальный снимок всех 16 артефактов ожидает QA.
- Capture hardcoded перечислял только `iptables`, WireGuard, DNS/DHCP, network/sysctl/config и не сохранял Xray client/server, hostapd, ocserv и strongSwan. Низкоуровневая справка `netosd -render` отдельно перечисляла только четыре значения, хотя backend-каталог уже содержал 16.
- Добавлен машинно-читаемый `netos render --list`, выдающий по одному ID из единого `render.IDs()` и не требующий root, поскольку не читает конфигурацию и не выполняет системных команд. Help `netos`, completion и daemon flag help используют тот же каталог.
- QA capture получает список только через `netos render --list`; ошибка list прерывает capture под `set -e`, новый renderer автоматически входит в snapshot. Static contract запрещает возврат hardcoded loop, CLI test требует точное совпадение порядка/набора, daemon test проверяет каждое имя в flag help.
- Полный Go suite, `go vet`, ShellCheck QA capture, bash syntax и `git diff --check` PASS. Актуальные Linux amd64: `netosd_linux` SHA-256 `b147b73b6b96760fccb715e062bf9a212db7c6ffd9abe7d536a879ae4cdf710f`; `manage_tests_linux` SHA-256 `68d4d21a34a97b85061711c677049bf2e8e5ec317445274940f978258e2746d0`.

## DEF-161 — destructive reset/uninstall/reinstall не имел единого fail-closed monitored runner, 2026-09-01 08:18 MSK

- Статус: orchestrator и contracts готовы локально; сам destructive цикл не запускался и ожидает QA SSH.
- Добавлен `qa-destructive-cycle.sh`: он отказывается работать вне transient systemd unit (`INVOCATION_ID`), принимает только root-owned non-writable regular assets из `/var/backups/netos/qa-assets-*`, проверяет amd64 и независимый SHA-256 бинарника, создаёт новый non-overwrite evidence directory с umask 077.
- Фоновый двухсекундный monitor сохраняет timestamp, Load/Active/SubState/Result/NRestarts, ready revision, failed-unit count и SSH/HTTP/panel listeners на всём цикле, включая отсутствие netosd во время uninstall. Каждая стадия отдельно сохраняет полный state и свежий journal.
- Порядок зафиксирован contract-тестом: clean preflight → backup+gzip validation → reset без скрытого backup → ready/clean/capture → restore+exact compare → uninstall+проверка отсутствия binary/CLI/unit → clean install из локального verified artifact → restore исходного backup → exact host/render/TLS/generated compare → новая backup → per-table SQLite compare → final ready/plan/failed-units gate.
- ERR/EXIT recovery до выхода отключает рекурсивные traps, при отсутствии CLI заново ставит тот же проверенный кандидат, восстанавливает исходный backup, ждёт ready, печатает status/journal и снимает failure-recovery state. Запуск через systemd сохраняет транзакцию при разрыве SSH.
- Bash syntax, ShellCheck v0.11.0 warning gate, static content/order/recovery contract, полный Go suite, vet и diff-check PASS. `netosd_linux` остаётся SHA-256 `b147b73b6b96760fccb715e062bf9a212db7c6ffd9abe7d536a879ae4cdf710f`; актуальный `manage_tests_linux` SHA-256 `214927cecc0d81dd180ba815871ef0d200b4a5a2241b4b8a7885020042dde182`.
- Read-only QA probe 08:18:52 MSK: SSH timeout during banner (exit 255); HTTPS curl exit 28, `http=000`, TCP/TLS 0, total 8,016325 s. Ни одна remote command не исполнилась; destructive orchestrator не запускался.
- Third-turn blocked audit, 08:20:27 MSK: обязательный Browser runtime снова не выбрал `iab`, authoritative discovery вернул `[]`; SSH завершился timeout during banner (exit 255); HTTPS curl exit 28, `http=000`, TCP/TLS 0, total 8,007768 s. Это тот же внешний блокер третий последовательный goal-turn. Completion не заявлен: live deploy, Linux integrations/fault injection/race, browser field-by-field E2E и destructive before/after остаются невыполненными. После исчерпания локальных verifier/runner/gate работ текущий гол переводится в `blocked` до восстановления QA или появления browser window.

## DEF-162 — QA state capture падал при отсутствии необязательного managed-каталога, 2026-09-01 09:44 MSK

- Статус: исправлено локально и проверено на QA; предвыкладочный снимок завершён с валидным manifest.
- QA после перезагрузки снова доступен: SSH и HTTPS `/api/ping` работают; `netosd` active/running, `Result=success`, `NRestarts=0`, ready revision 96, `systemctl --failed` пуст, текущий `netos plan` чист. Установленный до выкладки binary имеет SHA-256 `0d1bdaf2dcacdba29389a6863fa135761ce87258914db28ad40cd545816759ec`.
- Verified asset bundle создан в root-only `/var/backups/netos/qa-assets-20260901-0639`: загруженный `netosd-linux-amd64` байт-в-байт совпал с локальным SHA-256 `b147b73b6b96760fccb715e062bf9a212db7c6ffd9abe7d536a879ae4cdf710f`; checksum проверен. Два первых незавершённых снимка и один xtrace-снимок сохранены как evidence, не перезаписывались.
- Причина отказа: hash pipeline вызывал один `find` для всех четырёх roots, а затем вариант с `[[ -e "$root" ]] && find ...` оставлял status 1 на последнем отсутствующем `/var/lib/netos-system-baseline`; при `set -euo pipefail` capture прерывался до managed files/renders/manifest. Цикл заменён явным `if`, поэтому допустимо отсутствующие roots не маскируют реальные ошибки существующих roots.
- Git Bash `bash -n` и официальный ShellCheck v0.11.0 warning gate для исправленного capture PASS. Полный снимок `/var/backups/netos/qa-predeploy-20260901-0649` содержит 61 файл, все 16 динамически перечисленных render-артефактов и `render-sha256.txt`; `sha256sum -c manifest.sha256` PASS. После снимка сервис и revision не изменились, failed units отсутствуют.

## DEF-163 — новая ownership-защита ломала upgrade legacy-компонентов, а dev-push скрывал ручной rollback, 2026-09-01 09:48 MSK

- Статус: оба дефекта исправлены и live-проверены; migration Xray прошла, fail-fast rollback сработал на следующем независимом firewall-дефекте.
- Первая live-выкладка кандидата `b147b73b6b96760fccb715e062bf9a212db7c6ffd9abe7d536a879ae4cdf710f` обнаружила несовместимость: Xray 26.7.28 был установлен старым netOS до появления `/usr/local/bin/xray.netos-owned`, поэтому новый `components.Apply` ошибочно объявлял существующий target чужим. `netosd` вошёл в crash-loop; внешний монитор зафиксировал отсутствие ready/HTTPS и до ручного восстановления systemd успел выполнить 24 рестарта.
- Transaction snapshot `/tmp/tmp.SFE1TUwMgA/binary` перед восстановлением независимо совпал с исходным SHA-256 `0d1bdaf2dcacdba29389a6863fa135761ce87258914db28ad40cd545816759ec`. Из него атомарно восстановлены binary/CLI/completion, затем сервис успешно применил revision 96. Итог после recovery: old hash точный, active/running, `Result=success`, `NRestarts=0`, ready 96, чистый plan, failed units 0, HTTPS 200.
- Реализована однократная migration ownership: только при отсутствии sentinel и только для внешнего компонента, уже выбранного в активном config, обычного target, который исполняется и точно сообщает закреплённую версию. Marker создаётся 0600, затем атомарный sentinel `/var/lib/netos/external-ownership-v1`; при ошибке sentinel все созданные markers откатываются. После sentinel любой unmarked target, включая точную текущую версию, остаётся чужим и не перезаписывается/не удаляется. Первый live-кандидат ошибочно разместил sentinel в generated-подкаталоге; до успешной выкладки путь исправлен на долговечный parent state directory.
- Ownership и migration markers теперь требуют точное содержимое, обычный файл без symlink и mode 0600 на Unix. Tests покрывают legacy adoption+removal, запрет повторной adoption, rollback при невозможности записать sentinel, symlink marker/sentinel и слишком широкие права.
- `dev-push` теперь передаёт независимо вычисленный 64-hex SHA-256 кандидата, проверяет активный binary до restart и после ready, сбрасывает старое failed-состояние и завершает ожидание при первом `Result=exit-code|signal|core-dump` либо `NRestarts>0`. Это исключает шестиминутный crash-loop и ложное сообщение «работает», если в transaction вручную/внешне вернулся предыдущий binary.
- После исправлений полный `go test -count=1 ./...` (27/27 packages), `go vet ./...`, targeted migration/security tests, manage contracts, Git Bash syntax, ShellCheck v0.11.0 warning gate и `git diff --check` PASS; diff-check вывел только существующие CRLF conversion warnings.

## DEF-164 — firewall Health сравнивал семантически равный nft/iptables-save как drift, 2026-09-01 10:04 MSK

- Статус: исправлено локально и подтверждено live; текущая сборка `9929aa1c85f6a0d10a161a7a1531344c96c3863f172b80c6b744a187f33507b0` работает на QA.
- После успешной legacy Xray migration кандидат `6c75302f5e10356b71ee5cfe296a330aa9387142d3f4acb76db01837e0261853` применил все подсистемы, но post-Apply Health отверг IPv4 ruleset. Новый dev-push зафиксировал `Result=exit-code`, не допустил ни одного automatic restart и автоматически восстановил `0d1bdaf…`; old daemon вернулся к ready 96, clean plan и HTTPS 200.
- Exact evidence сохранён в `/var/backups/netos/qa-assets-20260901-0657/{expected-after-def163.iptables,live-after-def163.iptables}`. nft-backed `iptables-save` без изменения семантики: переставляет таблицы; сортирует chain declarations; группирует правила по chain вместо interleaved renderer order; добавляет избыточные `-m tcp`/`-m udp`; канонизирует `RELATED,ESTABLISHED`; добавляет counters/timestamps. Старый comparator нормализовал только counters/comments/table order и поэтому неизбежно давал false FAIL после каждого restore.
- Comparator теперь строит canonical table: chain declarations сортируются, правила группируются по chain, но порядок правил внутри каждой chain строго сохраняется; redundant protocol match удаляется, state-list сортируется. Таким образом форматирование nft игнорируется, а реальная перестановка ACCEPT/DROP внутри одной chain остаётся Health FAIL.
- Regression test покрывает table/chain grouping, counters, comments, redundant protocol modules, state order и отдельно доказывает обнаружение изменения порядка внутри chain. Targeted firewall/main/components suites PASS.
- Третья monitored deployment кандидата `9929aa1…` завершилась PASS: fresh ready 96, exact installed hash, `netos plan` clean, active/running, `Result=success`, `NRestarts=0`, failed units 0, HTTPS 200. Внешний monitor видел только штатное окно restart с `NO_READY`; после 07:03:49 UTC все последовательные пробы оставались 200 без рестартов.
- Однократная ownership migration создала root-only `/usr/local/bin/xray.netos-owned` и долговечный `/var/lib/netos/external-ownership-v1`; Xray hash `64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d` не менялся и не скачивался. Ошибочный generated sentinel от предыдущего неуспешного кандидата перед удалением был сверён `cmp` с долговечным sentinel и затем удалён как QA residue; он невосстановим, но не содержал уникальных данных.

## DEF-165 — у root не было безопасного восстановления забытого panel password, 2026-09-01 10:20 MSK

- Статус: исправлено и live-проверено; исходный password hash после QA восстановлен из backup.
- Защищённый API sweep повторно упёрся в ранее известный 401: локальный `dev_server_creds.txt` содержал уже несуществующее имя длиной 4, тогда как единственная живая учётная запись — `admin`; действующий пароль неизвестен. CLI не имел password recovery, поэтому root мог только сбросить весь продукт либо править SQLite в обход транзакций/аудита.
- Добавлена root-only команда `netos password-reset [user] --stdin`. Пароль никогда не передаётся argv и не печатается, строго ограничен 10–1024 байт и NUL запрещён; username проверяется. Если username опущен, CLI выбирает его только при ровно одной учётной записи и отказывается угадывать при нескольких.
- Store одной SQLite-транзакцией обновляет Argon2id hash, отзывает все сессии и пишет audit `password_reset`; injected audit trigger доказывает rollback password и sessions. Tests также покрывают missing/multiple user, non-root, отсутствие `--stdin`, control username, short/NUL/oversize password и отсутствие утечки нового пароля в output.
- Перед live reset создан и проверен backup `/var/backups/netos/netos-backup-20260901-071141.tar.gz`, SHA-256 `a3d260eba1e54b32c9bf79514223b4312c7e90514976fba3e3111d04963ac1cd`, gzip/tar PASS, mode 0600. Implicit single-user reset выбрал `admin`, отозвал сессии и позволил выполнить sweep. После него `netos restore ... --yes` создал дополнительный before-restore backup `7e22c8061b9aedf1a024fd361ea94cab369e2b2aaff6d44e15d605a4cbc32783` и восстановил исходную БД; временный QA password снова даёт 401.
- Restore monitor зафиксировал только штатное окно `NO_READY`; итог: installed binary `fdfec72ac99780f76d9c03050b00198b0ea575f7b682b3d8dd3ab804162e4934`, active/running, `Result=success`, `NRestarts=0`, ready 96, clean plan, failed units 0, оба ownership markers 0600.

## DEF-166 — live API verifier разбирал backup range как config JSON, 2026-09-01 10:20 MSK

- Статус: исправлено; полный safe live sweep PASS 113/113.
- После успешного login verifier сохранил config в `$configResponse`, но затем много раз переиспользовал `$response`; после трёх range-download последний response содержал gzip archive. В JavaScript round-trip ошибочно передавались его bytes (`1f 8b`), поэтому проверка падала с `Unexpected token` и никогда не доходила до validate/idempotent-save/render/logout.
- Raw config envelope теперь фиксируется непосредственно при каждом успешном `GET /api/config` и не зависит от последующих responses. Добавлен безопасный `UsernameOverride`, валидируемый узким allowlist, чтобы не менять сохранённый secret-файл.
- Итоговая матрица: public/unauth/auth/session/CSRF/password negatives/maintenance confirmations/missing resources, 17 базовых GET-вариантов, WireGuard/Reality generate+derive+invalid, config, revision details 47–96, три настоящих backup Range 206, validate, idempotent save, stale version 409, clean plan, список и все 9 применимых render-артефактов, logout/session rejection — 113 checks PASS. Конфигурация осталась чистой и revision 96 не изменилась.

## DEF-167 — factory reset падал на Health пустого списка VPN-серверов, 2026-09-01 10:31 MSK

- Статус: исправлено и дважды подтверждено live.
- Apply пустой factory-конфигурации записывал `owned-vpn-servers.json` как JSON `null`; Health строил пустой, но non-nil slice и сравнивал через `reflect.DeepEqual`, где `nil != []`. После фактического удаления всех компонентов daemon завершался с `список принадлежащих netOS VPN-серверов расходится с конфигурацией`.
- Сравнение заменено на поэлементное с одинаковой семантикой для nil/empty. Добавлен regression `TestApplyHealthWithNoVPNServers` для полного Apply→Health пустой конфигурации.
- Первый destructive unit `netos-qa-cycle-20260901-0729` корректно остановился и автоматически восстановил revision 96. Последующие factory reset в циклах `0743`, `0755` и финальном `0807` прошли ready revision 1 и clean plan.

## DEF-168 — lifecycle comparator считал timestamps/counters iptables изменением правил, 2026-09-01 10:42 MSK

- Статус: исправлено и подтверждено финальным live lifecycle.
- После reset→restore правила IPv4/IPv6 были идентичны, но `iptables-save` меняет строки Generated/Completed и накопительные `[packets:bytes]` базовых chains. Raw `cmp` дал два ложных FAIL.
- Comparator теперь игнорирует только эти динамические поля; таблицы, policies, chains и порядок/содержание каждого правила остаются строгими. Сохранённые evidence после нормализации PASS, финальный цикл также PASS.

## DEF-169 — clean reinstall менял права installer-файлов и auto/manual статус APT, 2026-09-01 10:53 MSK

- Статус: исправлено и подтверждено полным повторным uninstall/reinstall.
- QA runner использует `umask 077`; installer наследовал его и создавал `/etc/apt/apt.conf.d/99netos`, `/etc/bash_completion.d/netos` и `/etc/systemd/system/netosd.service` с mode 0600 вместо 0644. Явный `apt-get install systemd-timesyncd` также превращал уже установленный auto-пакет в manual.
- Installer теперь явно задаёт 0644 всем трём публичным конфигурационным файлам, запоминает уже установленные auto-зависимости и возвращает их через `apt-mark auto`. Contract-test фиксирует эти гарантии; `bash -n`, ShellCheck warning и manage suite PASS.
- Финальный цикл сохранил `packages-manual.txt`, все managed system files и mode 0644 без изменений. Существующий unit без новой `NETOS_INITIAL_PORT` строки был однократно мигрирован текущим installer; следующий полный цикл доказал идемпотентность канонического unit.

## DEF-170 — SQLite verifier считал повторный applied_at потерей состояния, 2026-09-01 11:04 MSK

- Статус: исправлено; точные базы и финальный автономный цикл PASS.
- Restore сохранял все строки и поля, но daemon закономерно обновлял только `revisions[96].applied_at` при повторном применении активной ревизии. Verifier ошибочно требовал равенства runtime timestamp.
- Нормализуется только `revisions.applied_at`; audit, devices, revision config/metadata, schema_version, sessions и users сравниваются строго. На финальных базах все 6 таблиц SAME.

## Полный destructive lifecycle PASS, 2026-09-01 11:14 MSK

- Автономный unit `netos-qa-cycle-20260901-0807.service`, evidence `/var/backups/netos/qa-cycle-20260901-0807-6bd36bc4`, candidate SHA-256 `6bd36bc419ead6c25d5ccef5a9413e128cef3ae369c0b28991b53c4b91ed4736`.
- PASS: preflight/backup; factory reset revision 1; restore revision 96; exact host/render/TLS/generated/package comparison; uninstall с отсутствием binary/CLI/unit; clean install из `file://` с обязательным SHA; новая factory account/TLS; финальный restore; повторный exact comparison; SQLite SAME; final backup/ready/clean plan; failed units 0 и `NRestarts=0`.
- Финальное состояние QA: active/running, `Result=success`, ready 96, clean plan, binary SHA совпадает, три installer-файла 0644, `systemd-timesyncd` остался auto.
- Production web build PASS (`app.js` 386.99 kB, gzip 106.04 kB), `go vet ./...`, targeted изменённые пакеты и последовательный проход всех Go packages PASS; один Windows `t.TempDir RemoveAll: directory is not empty` cleanup-only сбой в services не повторился в 10 последовательных запусках того же теста.
- Встроенный Browser после обязательного bootstrap/troubleshooting вернул пустой список `[]`; UI field-by-field не засчитан и остаётся единственным внешним блокером полного текущего гола.

## DEF-171 — root Linux CLI-тесты обращались к живой машине, 2026-09-01 12:14 MSK

- Статус: исправлено; Linux race-проверка `cmd/netosd` PASS.
- CLI subprocess и in-process dry-run использовали настоящий `system.Exec`, а bootstrap определял реальные интерфейсы QA. Тесты теперь получают детерминированный detector и изолированный runner; гарантированная ошибка открытия SQLite создаётся одинаково на Windows/Linux через каталог вместо файла.

## DEF-172 — QoS fault-test не доходил до проверяемого отказа на Linux, 2026-09-01 12:14 MSK

- Статус: исправлено; QoS race-suite PASS.
- Путь через regular-file parent на Linux возвращал `ENOTDIR` уже при чтении ownership, поэтому runtime-очередь не создавалась и cleanup не тестировался. Запись ownership теперь инъецируется через точный writer seam после создания объекта; WAN и client cleanup проверяются платформенно одинаково.

## DEF-173 — ACME renewal test мог повторно увидеть старое TLS-соединение, 2026-09-01 12:14 MSK

- Статус: исправлено; API race-suite PASS.
- Однократный запрос сразу после `CloseIdleConnections` гонялся с переходом соединения в idle и иногда обслуживался старой TLS-сессией. Проверка обновления использует новые transport/connection с ограниченным polling; реальная динамическая выдача нового сертификата и renewal-log по-прежнему обязательны.

## DEF-174 — services tests изменяли живые DNS-файлы root-хоста, 2026-09-01 12:46 MSK

- Статус: исправлено и подтверждено повторным полным race-gate.
- Gate `0922` доказал утечку: после PASS всех Go-тестов исчез `/var/lib/netos/generated/dnsmasq.conf`, а `/etc/resolv.conf` сменил SHA-256. Evidence сохранён в `/var/backups/netos/qa-race-20260901-0922-29891cd0`; trap признал gate failed и восстановил live state перезапуском daemon.
- Package-wide `TestMain` направляет все service configs, leases, systemd units, blocklists и resolver root во временный sandbox. Production defaults сохранены; provider render contracts используют актуальные path variables.

## Полный Linux race gate PASS, 2026-09-01 12:48 MSK

- Unit `netos-qa-race-20260901-0940.service`, evidence `/var/backups/netos/qa-race-20260901-0940-bc0dbe03`, source SHA-256 `bc0dbe031524aa48ccd72ff98a831671a306f628649690bcbbf71d763a75e5fe`.
- `CGO_ENABLED=1 go test -race -p 1 -count=1 ./...`: все 27 пакетов PASS, `WARNING: DATA RACE` отсутствует. ShellCheck gate PASS.
- Временные gcc/libc headers/ShellCheck (ровно 26 пакетов) удалены; package versions и manual set идентичны до/после. Временный 1 GiB swap отключён и удалён.
- `dnsmasq.conf` и `/etc/resolv.conf` идентичны по type/mode/owner/hash; netosd state и ready идентичны. Monitor: 270 последовательных проб без `NO_READY`, все `success 0 active running 96`. Финал: active/running, `Result=success`, `NRestarts=0`, ready 96, clean plan.

## Полный production UI/browser sweep PASS, 2026-09-01 14:06 MSK

- Восстановлен встроенный Browser runtime: в закреплённый bundled plugin возвращены совместимый `browser-client.mjs`, 274 отсутствовавших dependency-файла и capability/API references. Существующие файлы plugin не перезаписывались. Это изменение выполнено в пользовательском cache Codex, не в репозитории netOS.
- Исходный self-signed URL закономерно блокировался браузером с `ERR_CERT_AUTHORITY_INVALID`. Через штатный API/UI включён ACME для `45-38-170-119.sslip.io`: Let's Encrypt успешно выдал сертификат, ревизия 97 стала ready, панель открылась во встроенном браузере без TLS bypass. Во время операции `NRestarts=0`, failed units 0, clean plan.
- Перед UI-сценариями создана и проверена контрольная копия `/var/backups/netos/netos-backup-20260901-103609.tar.gz`, mode 0600, SHA-256 `d11045ffea9e6e5a8b9e638f6545582897a11ac74e097deeb43a8a6af788f8fd`; gzip и tar listing PASS.
- Все 14 разделов панели открыты реальной навигацией: Сводка, Устройства, Сеть, Маршрутизация, Интернет-каналы, VPN-доступ, Wi-Fi, Скорость и QoS, Защита сети, Адреса и DNS, Компоненты, Система, История, Диагностика.
- Базовый field sweep: 104/104 полей покрыты. 103 редактируемых поля приняли boundary/invalid/select/checkbox действия и корректно показали browser/product validation; оставшееся поле `Имя пользователя` отдельно подтверждено как намеренно readonly и не редактируемое. После каждого раздела черновик отменён/восстановлен.
- Динамические формы: 270/270 взаимодействий PASS. Routing 11, Wi-Fi 6, QoS 6, DHCP/DNS 37, Network 34, Channels 58, VPN 62, Firewall 56. Проверены все доступные Add-сценарии, зависимые поля, альтернативные select и ожидаемые ограничения отсутствующих компонентов/конфликтов.
- Компоненты: все 16 видимых переключателей реально нажаты, каждое значение инвертировалось, затем `Отменить` вернул точный исходный набор. История: все 49 кнопок `Загрузить` успешно загрузили соответствующие ревизии в черновик; финальный черновик сброшен.
- Диагностика: все 11 вкладок открыты. Полные результаты получены для iptables, Xray client/server, dnsmasq, unbound, resolver, network, sysctl, netOS config, routes и neighbor table; промежуточное `Загрузка…` не засчитано как результат. Copy сверено с отображаемым текстом, включая повторную точную проверку Xray; таблица соседей показала live gateway `45.38.170.1`/`eth0`/`REACHABLE`.
- System UI: подтверждения `RESTART`, `UPDATE`, `RESTORE` отвергают неполное значение и включают действие только при точном токене. Через UI создан backup `netos-backup-20260901-105655.tar.gz`, download event получен, затем удаление подтверждено и файл исчез с сервера. Смена admin password выполнена реально: короткий/несовпадающий пароль блокируется; корректный новый пароль принят, старый отвергнут, новый разрешил вход. Явные logout/login PASS.
- Темы: `системная → тёмная → светлая → системная` PASS. Responsive 390×844: появилась кнопка мобильного меню, меню открылось, навигация в Систему сработала, меню закрылось/вернулось в компактный режим; viewport override сброшен. Console warnings/errors самой страницы: 0.
- Непрерывный внешний монитор сопровождал UI/ACME/backup/password/restore: active service, failed units 0, warning count 0, `NRestarts=0`. Дважды наблюдалось только штатное короткое отсутствие ready-marker во время отдельной maintenance-операции создания backup и финального restore; service оставался active, marker вернулся сначала к 97, затем к 96.
- Финальное восстановление выполнено через встроенный UI из точной контрольной копии. Итог: ready 96, active/running, `Result=success`, `NRestarts=0`, failed units 0, clean plan, `system.panel.tls.mode=selfsigned`, порт 80 больше не слушается, представлен исходный сертификат `92:9B:14:31:E2:25:51:AC:86:4D:3F:0D:3D:E6:C3:AE:BA:F3:02:5E:47:92:F9:F8:3E:D0:C8:A2:DC:89:7F:3B`. Оба временных QA-пароля после restore дают HTTP 401. Journal warning..alert за окно UI-теста пуст.
- Новых дефектов продукта в полном UI sweep не обнаружено. Общий текущий gate: safe live API 113/113 PASS, destructive lifecycle PASS, Linux race 27/27 packages PASS без DATA RACE, production UI/browser sweep PASS с точным возвратом исходного состояния.

## Аудит истории с 630d707 включительно, 2026-09-01

- Просмотрены все 23 коммита диапазона `630d707e995585bc507de55fc5c150647e4f33d8^..HEAD`, их полные patch/name-status и итоговое состояние каждого затронутого поведения. Диапазон меняет 108 файлов (`4859` добавлений, `692` удаления); отдельно просмотрен текущий незакоммиченный diff по 111 tracked-файлам (`9647` добавлений, `1312` удалений) и перечень untracked QA/test-артефактов.
- Stable patch-id каждого из 23 коммитов уникален. Коммитов с `revert`/`rollback`/`restore` в subject нет. Файлово-зависимый анализ добавленных и удалённых строк не нашёл цепочек, где разные коммиты многократно перекидывают одну и ту же строку туда-обратно. Наибольшее пересечение (`Services.tsx` — 5 коммитов; `netiface/subsys.go`, `config/validate.go`, `Firewall.tsx`, `Network.tsx`, `api/handlers.go` — по 4) соответствует последовательному расширению поведения, а не циклической правке.
- `630d707`: production hardening, runtime/UI-аудит и его security-регрессии сохранены. Единственный заменённый тест — `TestLatestUpdatePinsInstallerToResolvedReleaseTag`; это связано с отдельно проверенной осознанной сменой update-стратегии в `91173d5`, а не случайным откатом.
- `3461cba`: Unbound по-прежнему фильтрует AAAA через respip для loopback и локальных сетей; capability UI сейчас также объявляет `filterAAAA: true`.
- `5019389`: повторный Apply сохраняет интерфейсы каналов и VPN; `TestRepeatedApplyPreservesChannelAndVPNLinks` существует и PASS.
- `6b80d04`: Xray lifecycle integration использует доступный Linux test path, не private Windows temp; соответствующий Linux gate ранее PASS.
- `9bed3ac`: актуальный внешний компонент не переустанавливается; поздняя переработка сохранила `externalCurrent`, ownership и pinned-version проверки. Три целевые регрессии PASS.
- `3d9ad53`: активные TUN-интерфейсы распознаются как поднятые; поведение сохранено в runtime collector и покрыто текущими тестами.
- `fbbf752`: WAN-соседи не попадают в управляемых клиентов. Поздний API refactor по-прежнему вызывает collector с `localClientInterfaces(cfg)`, сформированными только из включённых локальных сетей.
- `0f57738`: Reality/VLESS flow не теряется при import/export и отображается фактическим значением; текущий UI содержит условный `flow`, selector `XTLS Vision/Без flow`, а production dynamic sweep каналов PASS.
- `4b453e4`: firewall VPN-zone по-прежнему включает активные channel/server interfaces; backend и UI используют согласованные имена WireGuard/L2TP/IKEv2/Xray/OpenConnect, firewall regressions и UI sweep PASS.
- `36da15d`: block-mode сохраняет device route рядом с низкоприоритетным blackhole, поэтому probe может увидеть восстановление без утечки в main WAN; TCP probe проверяет handshake, а не application data. Целевые monitor/probe тесты PASS.
- `32059de`: capability Unbound AAAA согласована между renderer и UI (`filterAAAA: true`); более позднее расширение DNS не отменило исправление.
- `bb5e4c9`: неподдерживаемый AdGuard Home не предлагается как рабочий DNS provider; текущий provider catalog/UI и полный component/services sweep это сохраняют.
- `e93d940`: PPPoE concentrator остаётся доступной функциональной опцией, а поздняя валидация дополнительно ограничивает производные `ppp-<id>` Linux IFNAMSIZ. Network dynamic sweep PASS.
- `f55f0aa`: реальный OpenConnect/ocserv lifecycle test сохранён и прошёл в предыдущем Linux integration gate.
- `7ec5b2e`: Kea unit по-прежнему создаёт Debian runtime directory; `TestKeaUnitCreatesRequiredRuntimeDirectory` PASS.
- `a641105`: пустой bridge получает carrier через управляемую veth-пару, коллизии имени валидируются; обе целевые регрессии PASS.
- `1a7cee6`: Diagnostics сбрасывает result/error синхронно при смене вкладки и не показывает stale content; все 11 production-вкладок были проверены с ожиданием полного результата.
- `e0a7655`: SPA fallback допускает только безопасные read methods; `TestSPARejectsNonReadMethods` PASS.
- `e47c724`: interrupted atomic-write temp-файлы очищаются на старте; regression test сохранился и общий backend gate PASS.
- `86a853c`: IPv4 prefixes разбираются без narrowing conversion; целевая malformed-address regression PASS.
- `77d629b`: backup archive/path операции остаются ограничены backup root, traversal и links отвергаются; targeted backup regressions PASS.
- `8303e80`: redesign не потерял доступность полей или WireGuard client generation. Production browser дал 104/104 базовых полей, 270/270 dynamic interactions и успешные WireGuard UI-сценарии. Старый clone-label helper удалён вместе со старой разметкой, не как функциональный откат.
- `91173d5`: hardening apply/validation сохранён. Update намеренно использует текущий `master/install.sh`, но передаёт выбранную версию бинарника через `NETOS_VERSION`; так новый rollback-safe installer обслуживает старый release. Замещающие `TestUpdateUsesCurrentInstallerForRequestedTag` и `TestLatestUpdatePinsBinaryVersionButUsesCurrentInstaller` PASS.
- Все test functions, добавленные этими 23 коммитами, присутствуют в текущем дереве, кроме ровно одного заменённого update-теста выше. Удаления прежних запретов `custom`/`acme` TLS и DNS blocklists не являются ослаблением: обе возможности реализованы, валидируются, покрыты новыми тестами и прошли live/UI сценарии.
- Текущая проверка: целевой cross-package regression gate PASS; отдельно TCP probe/subnet parsing PASS; `npm run build` PASS; `git diff --check` PASS. Первый `go test ./...` получил один Windows cleanup race `t.TempDir RemoveAll: directory is not empty`; 20 повторов названного теста PASS, package `internal/api -count=5` показал тот же cleanup-шум уже на другом несвязанном TempDir, а повторный полный `go test ./...` PASS по всем пакетам. Это не связано с продуктовым lifecycle и не маскируется изменением кода.
- Итог аудита: признаков того, что агенты циклически отменяют и повторно вносят одни и те же исправления, не найдено. Одна семантическая смена решения подтверждена как намеренная и лучше защищённая тестами. Подтверждённых новых дефектов продукта, требующих исправления в этом аудите, нет; существующий dirty worktree и untracked evidence сохранены без удаления или перезаписи.
