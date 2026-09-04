# Отчёт о live-валидации netOS

| Поле | Значение |
|---|---|
| Дата прогона | 2026-09-04 |
| Стенд | предавторизованный непроизводственный роутер `45.38.170.119` |
| Кандидат | `079df615bb184befcf974fe64605c7225f93c6f5` (`dev-079df61`) |
| Последний релиз на момент выбора | `v0.06`, commit `b9a775b…`; релиз является предком кандидата |
| Итог | **FAIL — кандидат не сертифицирован** |
| Состояние отчёта | ретроспективно восстановлен по наблюдениям текущего прогона |

## Важное замечание о полноте записи

Во время прогона не вёлся постоянный файл-журнал. Этот документ восстановлен сразу после тестирования по сохранённым результатам браузерных действий, SSH-наблюдений, сетевых проверок и lifecycle-операций. Поэтому здесь приведены проверенные факты и порядок событий, но не выдуманы отсутствующие точные timestamps для каждого клика и команды. Все секреты, пароли, private keys, session cookies и полные client profiles намеренно исключены.

Это был широкий live-регрессионный прогон, но не полный certification run: часть обязательной матрицы не была доведена до реального data plane. Непроверенные возможности явно перечислены ниже и не считаются пройденными.

## Кандидат, установка и доверенный endpoint

- Локальный `HEAD`: `079df615bb184befcf974fe64605c7225f93c6f5`, дата commit `2026-09-04 10:37:58 +03:00`, сообщение `chore: replace router QA harness`.
- Выбран текущий кандидат, поскольку опубликованный `v0.06` от 2026-08-19 (`b9a775b…`) отставал и являлся предком `HEAD`.
- Готовый бинарник взят из root-only cache `/var/lib/netos-test-infra/netosd-079df615`.
- SHA-256 кандидата и установленного бинарника: `5de16f4d829f776e17f6d28f7f7fcf0d35ac5c3c7b70beb91b909e54da03229f`.
- SHA-256 использованного `install.sh`: `3fb59e1cb7f30a3cbbcd9819854e3a18c357b29592281dfb58586ea735c22433`; он совпал с локальным скриптом выбранного commit.
- Перед установкой штатный полный uninstall завершился успешно. Его recovery-backup: `netos-uninstall-20260904-133423.tar.gz` (удалён при финальной уборке).
- Чистая установка завершилась успешно; активная версия после установки — `netOS dev-079df61`.
- Первый вход выполнен свежими initial credentials. Plaintext-файл credentials после входа был удалён штатным механизмом. Значения credentials нигде в отчёте не сохранены.
- Восстановлен инфраструктурный ACME baseline из `/var/lib/netos-test-infra/acme-baseline`.
- Рабочий endpoint: `https://45-38-170-119.sslip.io:8443`.
- Сертификат: Let’s Encrypt `YE1`, CN/SAN `45-38-170-119.sslip.io`, срок `2026-09-04` — `2026-12-03`.
- Leaf SHA-256 fingerprint: `79:75:C8:5E:B5:7A:C9:D3:DE:F2:5D:DD:F5:BE:16:A1:69:4A:52:00:54:F0:CB:0B:00:CC:9B:1C:99:1F:2E:53`.

## Три поверхности проверки

### 1. Реальный браузер

Основной прогон выполнялся через встроенный интерактивный браузер по доверенному ACME endpoint. Через UI выполнены навигация по всем страницам, изменение конфигурации, Plan/Apply/Confirm/Rollback, установка компонентов, настройка сети, DNS/DHCP, Wi-Fi, WireGuard, QoS, диагностика, backup/restore и другие описанные ниже сценарии.

На основном браузерном сеансе ошибок в console не зафиксировано: `[]`.

### 2. Наблюдение роутера

Во время функциональных окон контролировались `netosd`, управляемые службы, restart count, journal, интерфейсы, namespaces, маршруты/rules, iptables, `tc`, WireGuard, процессы и ресурсы. До lifecycle-сбоя `netosd` оставался active с `NRestarts=0`; нагрузка была низкой, доступная память около 967 MiB. Установка компонентов кратковременно повышала load, но необъяснимого устойчивого роста не обнаружено.

### 3. Изолированные сетевые условия

Созданы namespaces `v904lan`, `v904cli1`, `v904cli2`, `v904isp`, `v904is2`; links `v904l0`, `v904w0`, `v904w1`; подсети `192.0.2.0/24`, `198.18.40.0/24` и `198.18.41.0/24`. Использовались реальные DHCP DORA, DNS-запросы, ICMP/маршрутизация, NAT/FORWARD counters, Wi-Fi association и WireGuard handshake/traffic.

## Discovery поверхности

Механический audit выбранного commit не обнаружил drift относительно контрольного каталога:

| Категория | Найдено |
|---|---:|
| Страницы | 14 |
| Статические control tokens | 621 |
| `Card` | 46 |
| `Field` | 199 |
| `aria-label` | 77 |
| `ariaLabel` | 10 |
| `option` | 150 |
| `button` | 88 |
| `Switch` | 51 |
| Уникальные JSON tags | 198 |
| Browser API routes | 39 |
| Catalog components | 16 |
| Render artifacts | 16 |
| Публичные CLI-команды | 17 |
| Drift | отсутствует |
| Несопоставленные элементы | `unmapped=0` |

Все 14 навигационных страниц были открыты. Это подтверждает discovery поверхности, но само по себе не означает прохождение всех вариантов каждой формы.

## Хронология выполненного

1. Проверен доступ к стенду, выбран самый свежий кандидат, зафиксированы хэши и ACME baseline.
2. Выполнены штатный uninstall прежней установки и чистая установка кандидата.
3. Получены свежие credentials, выполнен первый браузерный вход, восстановлен доверенный ACME endpoint.
4. Выполнен source/UI discovery и сверка контрольного fingerprint.
5. Проверены навигация, темы, mobile menu, login/logout, независимость двух сессий, History/Audit и транзакции Plan/Apply/Confirm/Rollback.
6. Через UI менялись и возвращались hostname, timezone и NTP.
7. Подняты изолированные network fixtures, bridge/LAN и реальный клиентский трафик.
8. Установлены все 16 компонентов; отдельные подсистемы проверялись в работе.
9. Проверены DHCP/DNS с dnsmasq, Unbound и dnsproxy, включая локальную A-запись.
10. Проверены Wi-Fi AP/client через `mac80211_hwsim`, WireGuard server/client и QoS/CAKE.
11. Проверены диагностические вкладки и CLI render artifacts.
12. Созданы backup через UI и CLI, затем выполнен restore.
13. После restore обнаружены осиротевшие runtime-артефакты при ложном «чистом» плане.
14. `netos reset --no-backup --yes` привёл к потере management-доступа и restart loop. Доступ восстановлен пользователем перезагрузкой стенда.
15. После восстановления выполнена точечная финальная уборка и проверено чистое стабильное состояние.

## Результаты по проверенным областям

Статусы `PARTIAL` и `NOT RUN` используются намеренно: этот документ не объявляет прогон полным. Они не эквивалентны `PASS`.

| Область / ID | Статус | Фактический результат |
|---|---|---|
| Выбор кандидата, clean uninstall/install | PASS | Согласованная пара `install.sh` + binary, совпавшие SHA-256, свежая установка и версия доказаны. |
| `UI-01` login/logout | PARTIAL | Первый вход, неверный пароль, повторный вход и logout проверены; полный password lifecycle не проверен. |
| `UI-03` два сеанса | PARTIAL | Второй browser login и независимость logout подтверждены; полный stale-draft conflict не завершён. |
| `UI-04` навигация/viewport | PARTIAL | Все страницы и mobile menu пройдены; полный набор back/forward/reconnect не завершён. |
| `UI-05` транзакции | PARTIAL с дефектами подсистем | Plan, Apply, Confirm и timeout rollback наблюдались; отдельные Apply выявили дефекты ниже. Полная проверка manual rollback/repeated Apply не подтверждена журналом. |
| `UI-07` History/Audit | PASS | Видны состояния revisions и audit-события login/apply/confirm/rollback. |
| `UI-08` темы | PASS | system/dark/light сохранялись после переключения/reload. |
| `OBS-05..07` диагностика/render | PARTIAL | UI: iptables, network, sysctl, redacted config, routes, neighbors; Copy работает. CLI перечислил/отрендерил 16 artifacts. Не все условные UI-artifacts проверены во всех состояниях. |
| `NET-02` bridge | PASS с timing-risk | `v904b0`, LAN `192.0.2.1/24`, реальный трафик после STP convergence. Два ранних Apply откатились до forwarding; см. BUG-06. |
| `NET-04` bond | FAIL | Backend capability есть, создать bond из UI нельзя. |
| `WAN-06/08/09` Multi-WAN | FAIL/BLOCKED | Fresh-install management WAN получает stable index `0`, UI не позволяет исправить; валидная Multi-WAN конфигурация недостижима без удаления management WAN. |
| `DHCP-01` | PARTIAL | Реальный DORA доказан для dnsmasq; ISC и Kea как DHCP data plane не проверены. |
| `DNS-01` | PARTIAL | dnsmasq, Unbound и dnsproxy отвечали на реальные запросы клиента/роутера; полный TCP/cache/error matrix не завершён. |
| `DNS-05` force-local | FAIL | Включение перенаправления DNS клиентов стабильно ломает post-apply firewall check и откатывается. |
| `DNS-06` records | PARTIAL | A-record `v904host.lan -> 192.0.2.10` проверен; CNAME/TXT/SRV/MX не проверены. |
| `ROUTE-07` | FAIL | `RouteRule.interface` поддерживается backend, но поле отсутствует в UI. |
| `VPN-WG-01` | PARTIAL | Один сервер/peer: profile, реальный handshake, ping `10.9.0.1`, рост transfer counters. Два peer/reissue/revoke не завершены. |
| `WIFI-01/02` | PARTIAL | `mac80211_hwsim` с двумя radios; AP на wlan0, реальная association wlan1, DHCP; WPA2 и open проверены. WPA3/mixed/hidden/isolation/full matrix не завершены. |
| `QOS-01/02` | PARTIAL | CAKE 2/2 Mbit на uplink, qdisc на eth0 и `ifb-netos-0`, counters росли; все modes/multi-WAN/teardown matrix не завершены до restore. |
| `COMP-01/05` | PARTIAL | Все 16 toggles применены, пакеты/binaries появились, external dnsproxy `0.84.0` и Xray `26.7.28`; функциональный data plane каждой компоненты не доказан. |
| `SYS-01` | PASS | Hostname/timezone/NTP применялись, live-state проверялся, затем baseline восстановлен. |
| `LIFE-01` backup | PARTIAL | Backup через UI и CLI создан; UI restore modal validation проверена. Полный download/content/redaction/delete matrix не завершён. |
| `LIFE-02` restore | FAIL | Config восстановлен, но runtime Wi-Fi/WireGuard/QoS не очищен, а `netos plan` сообщил совпадение. |
| `LIFE-06` reset | FAIL | Reset при оставшемся hwsim wlan0 вызвал crash/restart loop и потерю управления. |
| `LIFE-07` uninstall/install | PARTIAL | Начальный clean uninstall/install прошёл; полный финальный reinstall после lifecycle-окна не выполнялся. |
| `LIFE-08` финальная уборка | PASS | Fixtures, test backups, listeners и runtime leftovers удалены; ACME и стабильный daemon восстановлены, lock свободен. |
| `LIFE-09` CLI | PARTIAL | status/version/help/plan/render/completion и invalid command проверены; backup/restore/reset реально выполнены. update/reinstall/dev-push и весь validation matrix не завершены. |

## Дефекты

### BUG-01 — CRITICAL — reset создаёт постоянный restart loop при обнаруженном `mac80211_hwsim` radio

**Контекст:** после Wi-Fi теста виртуальный `wlan0` ещё существовал. Был запущен `netos reset --no-backup --yes` в конце lifecycle-окна.

**Шаги воспроизведения:** создать AP-capable radio через `mac80211_hwsim`; дать netOS управлять им; выполнить factory reset без backup; наблюдать `netosd` и journal.

**Ожидалось:** reset завершает очистку, создаёт валидную factory configuration или безопасно пропускает несовместимый интерфейс; daemon остаётся работоспособным, management-доступ восстанавливается.

**Фактически:** factory revision 1 не содержала WAN и пыталась выполнить `ip link set wlan0 master br-lan`. Kernel вернул `Device does not allow enslaving to a bridge`. `netosd` падал и перезапускался; restart counter достиг 99. Management-доступ вернулся только после перезагрузки, удалившей hwsim fixture.

**Риск:** удалённый reset может сделать устройство недоступным до out-of-band reboot. Даже при тестовом radio daemon не должен входить в бесконечный crash loop.

### BUG-02 — HIGH — restore оставляет runtime-артефакты, отсутствующие в восстановленной конфигурации

**Контекст:** восстановлен UI-backup `netos-backup-20260904-135716.tar.gz` после включения WireGuard server, Wi-Fi AP и QoS.

**Ожидалось:** live-состояние полностью приводится к восстановленной конфигурации; удалённые функции останавливаются и очищают interfaces, listeners, units/processes и qdisc.

**Фактически:** восстановленная config не содержала WireGuard/Wi-Fi/QoS, а `netos plan` сообщил, что live-state совпадает с config. При этом остались:

- `wg-srv1` и listener UDP/51820;
- hostapd service/process;
- CAKE qdisc на `eth0`;
- `ifb-netos-0`.

**Риск:** ложный clean plan скрывает активные сетевые сервисы и правила после restore; поведение и поверхность атаки не соответствуют конфигурации.

### BUG-03 — HIGH — DNS force-local не применяется из-за несовпадения firewall health check

**Контекст:** работали LAN bridge, dnsmasq/dnsproxy и реальный клиент.

**Шаги:** в «Адреса и DNS» включить «Заворачивать запросы клиентов на роутер», выполнить Plan/Apply; повторить с toggle как единственным изменением.

**Ожидалось:** создаются правила перенаправления UDP/TCP 53, post-apply проверка проходит, запрос клиента к внешнему resolver обслуживается локальным DNS.

**Фактически:** Apply завершался автоматическим rollback с сообщением `проверка после применения не прошла: подсистема firewall: живые правила iptables не соответствуют конфигурации`. Дефект воспроизведён как в составе DNS-настройки, так и изолированным toggle.

### BUG-04 — HIGH — Multi-WAN нельзя валидно включить после clean install через UI

**Контекст:** существующий management WAN, созданный fresh install/bootstrap, имел stable index `0`.

**Шаги:** добавить второй uplink через UI и включить Multi-WAN.

**Ожидалось:** UI позволяет назначить каждому uplink уникальный валидный stable index и включить Multi-WAN без ручного редактирования внутренних данных.

**Фактически:** validation сообщает `для Multi-WAN нужен стабильный индекс аплинка`; существующий WAN из UI исправить нельзя. Обход требовал бы удаления/recreation management WAN, что небезопасно для удалённого стенда.

**Затронуто:** `WAN-06`, вследствие этого `WAN-08` и `WAN-09` недостижимы.

### BUG-05 — MEDIUM — поле `RouteRule.interface` отсутствует в UI

**Контекст:** backend применяет поле как `ip rule iif`.

**Шаги:** открыть редактор policy routing rule и попытаться задать входной интерфейс.

**Ожидалось:** поле доступно, сохраняется и отображается после reload.

**Фактически:** форма содержит priority/name/from/to/fwmark/table, но не interface. Через достижимые поля создано правило `20100: from all lookup netos-t1`, после проверки оно откатилось; проверить `iif` пользовательским путём невозможно.

### BUG-06 — MEDIUM — safe-confirm timeout совпадает с временем STP convergence

**Контекст:** bridge `v904b0` использовал стандартный forward delay 15 секунд на состояние, около 30 секунд до forwarding. Safe-confirm timeout также составлял около 30 секунд.

**Фактически:** первые два корректных bridge Apply автоматически откатились до появления data plane. На третьей попытке конфигурация была подтверждена через UI до convergence; после завершения STP клиентский ping прошёл.

**Риск:** корректная bridge-конфигурация может ложно считаться нерабочей или откатываться ровно перед восстановлением трафика. Нужен запас timeout либо readiness, учитывающий STP state.

### BUG-07 — MEDIUM — backend bond capability недостижима из UI

`Interface.type=bond` поддерживается validation/runtime, но текущая панель предлагает только bridge и VLAN. На выбранном commit это подтверждено discovery; `NET-04` — FAIL.

## Непроверенные или недостаточно доказанные области

Следующее нельзя считать пройденным по факту установки компонента или появления формы:

- PPPoE и L2TP с реальными concentrator и трафиком;
- OpenConnect client и ocserv server;
- IKEv2/XFRM server/client;
- Xray/Reality с реальным совместимым peer и прикладным трафиком;
- Multi-WAN failover/failback/balance после устранения BUG-04;
- VLAN и bond data plane, переключение network backend и reboot persistence;
- полная firewall/NAT/port-forward matrix, расписания и client blocking;
- политики направления трафика, fail modes и полный reference graph каналов;
- DNS DoT/DoH/DoQ, DNSSEC, split-DNS, blocklists, все record types;
- ISC DHCP и Kea data plane;
- DDNS providers и IPv6 passthrough;
- WPA3/mixed/hidden/client isolation и негативные Wi-Fi сценарии;
- password change/expiry/CSRF/concurrent stale draft;
- update, reinstall и `dev-push` текущего кандидата.

## Отклонение тестовой среды

Прямой terminal Playwright к hostname перехватывался Kaspersky и получал HTTP 499. Контроль через SSH tunnel на `127.0.0.1` с проверенным fingerprint и отдельным headed Chromium обходил локальный перехват. Основной встроенный браузер после восстановления доверенного ACME работал штатно. Это классифицировано как дефект/ограничение среды оператора, а не netOS.

## Backup/restore артефакты прогона

В ходе теста создавались:

- `netos-uninstall-20260904-133423.tar.gz`;
- `netos-backup-20260904-135716.tar.gz`;
- `netos-backup-20260904-142328.tar.gz`;
- `netos-before-restore-20260904-142341.tar.gz`.

Все четыре файла удалены при финальной уборке. Ещё 30 существовавших до прогона backup-файлов не изменялись.

## Финальное состояние стенда

После пользовательского reboot и последующей уборки подтверждено:

- `netOS dev-079df61`, `netosd` active, текущий `MainPID=1101`, `NRestarts=0` в текущем boot;
- `netos plan`: live-state соответствует текущей config;
- default `br-lan` с `192.168.10.1/24` присутствует и down; management `eth0` сохраняет `45.38.170.119/24` и default route через `45.38.170.1`;
- отсутствуют test namespaces, `v904*`, `wg-srv1`, `ifb-netos-0`, `/run/v904`, listeners на 19090 и 51820;
- component services неактивны, `mac80211_hwsim` не загружен;
- advisory lock свободен;
- в journal текущего boot нет новых warning/error, связанных с прогоном;
- доверенный ACME endpoint и прямой browser login работают;
- рабочее дерево репозитория до создания этого отчёта было чистым.

## Итоговый вердикт

**FAIL. Кандидат `079df615…` нельзя сертифицировать.** Блокирующие причины: reset способен оставить daemon в постоянном crash loop с потерей управления; restore не удаляет runtime-состояние и при этом выдаёт ложный чистый plan; DNS force-local не применяется; Multi-WAN недостижим через UI после fresh install. Дополнительно подтверждены UI/backend gaps и риск ложного rollback из-за STP/safe-confirm timing.

Точные агрегаты по всем scenario ID не восстанавливались задним числом: исходный live-ledger отсутствовал, а присваивать неподтверждённые статусы было бы недостоверно. В таблице выше отражены только области, для которых сохранились проверяемые результаты; оставшаяся матрица считается непокрытой.

Повторный прогон должен начаться после исправления минимум BUG-01—BUG-04, вести журнал в репозитории с начала работы и не объявляться полным, пока каждая строка обязательной матрицы не получит `PASS`, `FAIL` или конкретный `BLOCKED` с трёхслойными доказательствами.
