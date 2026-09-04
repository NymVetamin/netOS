# Проверка дефектов из router-validation-2026-09-04-079df61

| Поле | Значение |
|---|---|
| Run ID | `bugverify-20260904-175516-msk` |
| Начало / окончание / timezone | `2026-09-04 17:55:16 +03:00` / `2026-09-04 21:52:36 +03:00` |
| Стенд и подтверждённое назначение | Предавторизованный непроизводственный роутер `45.38.170.119` |
| Candidate commit/version/SHA-256 | `079df615bb184befcf974fe64605c7225f93c6f5` / `dev-079df61` / `5de16f4d829f776e17f6d28f7f7fcf0d35ac5c3c7b70beb91b909e54da03229f` |
| Latest release и решение о свежести | `v0.06`, `b9a775b3af2874d3de5c340fda8d6c7e12dc5090`; release — предок candidate, проверяется candidate |
| Операторские поверхности | встроенный browser / SSH observer / изолированные fixtures |
| Исправленный live-кандидат | `dev-bugfix-079df61`, SHA-256 `ddcd7d7256859d139f2464485f436e86ae5554c72c99fd3e408848bbcbc42f27` |
| Статус | COMPLETE — семь дефектов подтверждены на исходном кандидате и прошли focused retest после исправлений |

## Исходное состояние и recovery

- SSH-доступ подтверждён; recovery: root SSH и консоль провайдера.
- `netosd` active, `MainPID=1101`, `NRestarts=0`; load `0.00 0.01 0.05`, available RAM 743 MiB.
- Management: `eth0=45.38.170.119/24`, default route через `45.38.170.1`; `br-lan=192.168.10.1/24`, down.
- Advisory lock успешно получен отдельным долгоживущим SSH-процессом и удерживается.
- ACME bundle `/var/lib/netos-test-infra/acme-baseline` присутствует.
- Endpoint `https://45-38-170-119.sslip.io:8443` отдаёт Let’s Encrypt YE1 для SAN `45-38-170-119.sslip.io`, срок до `2026-12-03`; leaf SHA-256 `79:75:C8:5E:B5:7A:C9:D3:DE:F2:5D:DD:F5:BE:16:A1:69:4A:52:00:54:F0:CB:0B:00:CC:9B:1C:99:1F:2E:53`.

## Discovery

Текущий commit совпадает с кандидатом исходного отчёта. Для точечного прогона используются семь зафиксированных дефектов исходного отчёта; расширенная certification-матрица не заявляется.

## Fixtures

| Fixture ID | Объект | Назначение | Создано | Удалено |
|---|---|---|---|---|
| `BV-WAN` | netns `bvwanisp`, veth `bvwan0`/`bvwanp0`, `198.18.88.0/24` | Второй реальный uplink и Multi-WAN | 18:07 MSK | 21:48 MSK |
| `BV-STP` | netns `bvstpcli`, macvlan `bvstpc0` на peer `p-br1` | Реальный клиент за новым bridge для замера STP | 18:30 MSK | 21:48 MSK |
| `BV-WIFI` | `mac80211_hwsim`, два виртуальных radio `wlan0`/`wlan1` | Реальный mac80211/hostapd runtime для restore/reset | 18:56 MSK | 21:48 MSK |

## Ledger сценариев

| Scenario ID | Статус | Время/окно | Предусловия и UI-действия | UI | Router | Data plane | Bug/evidence |
|---|---|---|---|---|---|---|---|
| BUG-01 reset+hwsim | FAIL (подтверждён) | 18:49–18:54 MSK | При загруженном `mac80211_hwsim` выполнен штатный `netos reset --yes --no-backup` | Панель стала недоступна и не вернулась | Существующие SSH/tunnel/lock-сессии оборвались; новые TCP/22 соединения многократно не доходили до SSH banner, совпадая с повторной перестройкой management-сети | Management plane недоступен; out-of-band recovery необходим | BUG-01 воспроизведён повторно; bootstrap выбирает безадресный `wlan0` как LAN и пытается включить его в bridge |
| BUG-02 restore cleanup | FAIL (подтверждён) | 19:34–19:42 MSK | До runtime создана чистая backup; затем из UI включены и подтверждены Wi-Fi AP, WireGuard server и QoS, после чего чистая backup восстановлена через штатный UI | Restore завершён успешно; active config после него не содержит Wi-Fi/VPN/QoS, `netos plan` сообщает отсутствие изменений | Остались `hostapd` и `wlan0` AP, `wg-srv1` и UDP/51820, CAKE+ingress на `eth0`, `ifb-netos-0`; daemon запущен заново без crash-loop | Все три независимых runtime-класса продолжают работать вопреки восстановленной конфигурации | BUG-02 воспроизведён: restore стирает ownership до снятия текущего runtime |
| BUG-03 DNS force-local | FAIL (подтверждён) | 18:19–18:23 MSK | На работающем DNS-резолвере изолированно включён force-local и дважды нажат Apply | Оба раза точная ошибка: `подсистема firewall: живые правила iptables не соответствуют конфигурации`; draft остаётся неприменённым | В момент Apply правила DNAT реально появляются, затем транзакция откатывается; `MainPID=4135`, `NRestarts=0`, после отката `netos plan` чист | Клиент `bvdnscli` сохраняет связь с `192.0.2.1`; рабочая DNS-конфигурация не повреждена | BUG-03 воспроизведён; nft `iptables-save` переставляет `! -d` перед `-p`, а строгая health-проверка не канонизирует этот порядок |
| BUG-04 Multi-WAN stable index | FAIL (подтверждён) | 18:07–18:09 MSK | В чистой установке через UI добавлены VLAN, второй static uplink и включён Multi-WAN | Показана блокирующая ошибка `для Multi-WAN нужен стабильный индекс аплинка`; поля index нет | `netos render config`: management WAN имеет `index: 0`; daemon active, рестартов нет | Проверка второго uplink не начинается: draft невалиден до Apply | BUG-04 воспроизведён |
| BUG-05 RouteRule.interface UI | FAIL (подтверждён) | 18:09 MSK | Через UI добавлены routing table и policy rule | Форма содержит priority/name/from/to/fwmark/table/enabled, но не interface | Backend `RouteRule.Interface` используется routing subsystem как `iif`; live config не менялась | Недостижимо пользовательским путём | BUG-05 воспроизведён |
| BUG-06 STP safe-confirm timing | FAIL (подтверждён) | 18:30–18:32 MSK | Из UI создан новый пустой bridge `br1` и сегмент `192.0.2.1/24`; подтверждение намеренно ожидало восстановления клиентского пути | UI показал 30-секундный safe-confirm и затем `Изменения откачены: подтверждение не получено` | Carrier `d-br1` прошёл `listening` 8 с и `learning` 7 с; daemon не перезапускался, после отката `netos plan` чист | Реальный клиент `bvstpcli` за macvlan на peer `p-br1`: ping fail t=0…14, ok t=15…17, на t=18 bridge уже удалён откатом | BUG-06 воспроизведён: после STP остаётся лишь около 3 с на подтверждение |
| BUG-07 bond UI | FAIL (подтверждён) | 18:07 MSK | Открыта свежая страница «Сеть», просмотрены все controls интерфейсов | Доступны только `Добавить мост` и `Добавить VLAN`; bond control отсутствует | Backend config/validation/netiface/netconf содержит `type=bond` и runtime-реализацию | Создать bond для data plane из UI невозможно | BUG-07 воспроизведён |

## Дефекты

### BUG-01 — CRITICAL — reset с hwsim создаёт недоступную factory-конфигурацию

- Перед reset observer подтвердил active daemon без рестартов и загруженный `mac80211_hwsim`; выполнена точная штатная команда из исходного отчёта.
- Reset оборвал панель и все длительные SSH-контрольные соединения. Новые TCP/22 соединения устанавливались, но многократно обрывались до SSH banner на фоне повторного применения management-сети — доступ штатно не восстановился.
- Кодовая причина однозначна: `physicalInterfaces` включает mac80211 radio, а Detect добавляет безадресный `wlan0` в `LANCandidates`; BuildInitial затем делает его прямым member `br-lan`, хотя ядро возвращает `Device does not allow enslaving to a bridge`.
- Исправление исключает wireless netdev из автоматических LAN-кандидатов по sysfs-маркеру `wireless`, сохраняя radio в общем списке для штатной Wi-Fi-настройки; добавлен regression-тест с hwsim-подобным sysfs.

### BUG-02 — HIGH — restore оставляет runtime удалённой конфигурации

- Чистая backup создана до включения Wi-Fi AP, WireGuard server и QoS; каждый компонент сначала применён и подтверждён через UI, а его live runtime отдельно проверен observer-ом.
- После штатного UI restore active config вернулся к чистому состоянию: `vpn_servers: []`, Wi-Fi отсутствует, QoS выключен; `netos plan` ложно чист.
- Одновременно в ядре и процессах остались все удалённые сущности: `wg-srv1` с UDP/51820, hostapd с `wlan0` в AP mode, CAKE/ingress на `eth0` и `ifb-netos-0`.
- Причина в порядке restore: каталоги состояния вместе с ownership-журналами удаляются до запуска восстановленного daemon. Исправление снимает текущие netOS-owned units, firewall, policy/QoS и виртуальные interfaces до замены StateDir; аварийный rollback по страховочной backup сохранён.

### BUG-03 — HIGH — force-local откатывается из-за порядка аргументов nft iptables-save

- Изолированное включение force-local дважды воспроизвело исходную ошибку UI без рестарта daemon.
- Observer успел снять живой ruleset до отката: nft-backend сохранил правило как `-s 192.0.2.0/24 ! -d 192.0.2.1/32 -p udp ...`, тогда как генератор ожидал `-s ... -p udp ... ! -d 192.0.2.1`.
- Семантика правил одинакова, но строгая строковая health-проверка считает это drift. Исправление генерирует стабильный порядок и явный `/32`, которые возвращает `iptables-save`; покрыто unit-тестом firewall.
- Функциональная проверка выявила вторую часть того же пути: при force-local dnsmasq слушал только loopback. Теперь он дополнительно слушает интерфейсы включённых локальных сетей. Изолированный клиент успешно разрешил `example.com` как при запросе к `192.168.10.1`, так и при запросе к `1.1.1.1`, перехваченном DNAT.

### BUG-04 — HIGH — Multi-WAN блокируется нулевым stable index fresh-install WAN

- В чистой установке management WAN действительно сохранён с `index: 0`.
- UI не показывает и не позволяет изменить stable index ни существующего, ни нового uplink.
- После добавления второго валидно заполненного uplink и включения Multi-WAN draft немедленно блокируется точным сообщением из исходного отчёта.

### BUG-05 — MEDIUM — `RouteRule.interface` отсутствует в UI

- После создания дополнительной таблицы и policy rule UI показал все заявленные поля, кроме входного интерфейса.
- Backend-модель и routing runtime поддерживают `RouteRule.Interface`/`ip rule iif`; пользовательский путь отсутствует.

### BUG-06 — MEDIUM — safe-confirm почти полностью съедается STP

- На чистом создании пустого bridge клиентский путь оставался недоступен 15 секунд после появления carrier: 8 секунд `listening`, 7 секунд `learning`.
- После перехода в `forwarding` ping работал только три секунды, затем 30-секундный safe-confirm удалил bridge откатом.
- Исправление вводит минимальные 60 секунд подтверждения именно при изменении bridge-топологии, не растягивая обычные безопасные применения.

### BUG-07 — MEDIUM — backend bond capability отсутствует в UI

- Fresh UI предлагает только bridge и VLAN.
- Backend принимает, валидирует и применяет `Interface.type=bond`, поэтому это именно разрыв UI/backend, а не ошибочное ожидание отчёта.

## Нагрузка и стабильность

После последнего восстановления `netosd` active, `NRestarts=0`; активный бинарник имеет SHA-256 `ddcd7d7256859d139f2464485f436e86ae5554c72c99fd3e408848bbcbc42f27`. Непредусмотренных crash-loop, роста нагрузки или потери management plane на исправленном кандидате не наблюдалось.

## Focused retest исправленного кандидата

| Дефект | Результат | Проверка исправления |
|---|---|---|
| BUG-01 | PASS | `reset --yes --no-backup` при двух hwsim-radio не выбрал Wi-Fi как LAN-кандидат и не создал bridge из `wlan0`; `eth0`, SSH и панель оставались доступны, штатная пауза сервиса около 1 с, `NRestarts=0`. |
| BUG-02 | PASS | До restore одновременно подтверждены работающие hostapd/AP, `wg-srv1` и UDP/51820, CAKE+ingress и `ifb-netos-2`. После UI restore отсутствуют unit/process hostapd, WG interface/listener, IFB и QoS; `eth0` снова использует `fq_codel`. |
| BUG-03 | PASS | Force-local применился и подтвердился из UI; live DNAT содержит канонические `! -d 192.168.10.1/32`, health не откатил конфигурацию. dnsmasq слушает LAN, реальный netns-клиент получил ответы и напрямую, и через перехват внешнего DNS-адреса. |
| BUG-04 | PASS | При добавлении второго static uplink и включении Multi-WAN UI автоматически назначил уникальные положительные индексы `2` и `1`; Apply/confirm успешны, второй адрес и маршрут появились в data plane. |
| BUG-05 | PASS | В форме policy rule появился столбец и редактируемое поле «Входной интерфейс»; временный черновик затем отменён. |
| BUG-06 | PASS | При создании bridge `br1` UI дал 60-секундное окно; на восьмой секунде после Apply оставалось 52 с. Реальный клиент прошёл STP `listening`/`learning`, на t=15 получил ping и конфигурация была успешно подтверждена. |
| BUG-07 | PASS | На странице «Сеть» присутствует «Добавить агрегацию», bond отображается среди поддержанных объектов и может выбираться членом bridge. |

## Отклонения среды и инструмента

Встроенный browser отсутствовал. Playwright/Chromium использован как предусмотренный fallback. На self-signed bootstrap Kaspersky возвращал собственный HTTP 499 даже через SSH tunnel; предупреждение не обходилось. Первый вход и включение ACME выполнены в реальном Chromium через локальный loopback HTTP reverse-proxy к предварительно сверенной TLS-точке. После восстановления исходного ACME cache браузер перезапущен и продолжил работу по доверенному hostname через SSH tunnel. Секреты и cookies в отчёт/репозиторий не сохранялись.

Полный `go test ./...` прошёл во всех пакетах, кроме одной гонки Windows `TempDir RemoveAll cleanup` в неизменённом тесте channels; точный упавший тест немедленно повторён отдельно и прошёл. Затронутые firewall/services/bootstrap/apply/manage тесты проходят. `npm run build` проходит.

## Lifecycle и финальная уборка

- Контрольная конфигурация и доверенный ACME endpoint восстановлены; leaf SHA-256 снова `79:75:C8:5E:B5:7A:C9:D3:DE:F2:5D:DD:F5:BE:16:A1:69:4A:52:00:54:F0:CB:0B:00:CC:9B:1C:99:1F:2E:53`.
- Удалены созданные прогоном network namespaces, veth/macvlan, hwsim-radio, временный ACME cache, тестовые backup/safety-архивы и промежуточные rollback-копии бинарника.
- На роутере оставлен исправленный `netosd`; hostapd/WireGuard/QoS runtime после контрольного восстановления отсутствует.

## Итог

COMPLETE. Все семь дефектов исходного отчёта воспроизведены на candidate `079df615`, признаны реальными и исправлены. Все семь прошли focused live retest на исправленном кандидате. Это точечная перепроверка перечисленных дефектов, а не новый полный certification run.
