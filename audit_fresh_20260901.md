# Новый аудит netOS с чистого листа

Статус: завершён 2026-09-01. Старые результаты, QA-cycle и прежний `test_results.md` не использовались как доказательства.

Итог: lifecycle PASS с оговорками; найдено 5 воспроизводимых дефектов (2 high, 3 medium) и 1 low UI-наблюдение. Dev server финально очищен, `FINAL_RESULT=PASS`.

## Область и идентичность среды

- Цель: только `dev_server` из `dev_server_creds.txt`.
- Подтверждено до удаления: Debian 13, `x86_64`, root SSH, hostname `netos`, public IPv4 совпал с credential-файлом, SHA-256 machine-id начинается с `e4c0e747159c4ad0`.
- Локальная рабочая копия и другие хосты разрушительными действиями не затрагивались.

## Чистый baseline

- Штатно выполнен `netos uninstall --yes`, затем по точному whitelist удалены прежние `/var/backups/netos` и `/opt/netos*`.
- После удаления отсутствовали binaries/CLI, unit, completion, `/var/lib/netos`, `/etc/netos`, `/var/log/netos`, system baseline, ready-marker, backups, dev build trees, процессы, `tun-ch1` и бывшие listeners 443/8443/5354.
- Поиск managed-файлов netOS в `/etc` и `/usr/local/bin` вернул `NONE`; failed units 0; SSH остался active.
- Диск изменился с 79% (2,0 ГБ свободно) до 53% (4,2 ГБ свободно) после удаления прежних QA-данных.
- Новый snapshot: `/var/backups/netos/qa-fresh-before-install`, manifest PASS.

## Сборка и установка

- Исходное дерево: commit `b69e46b27d9286cea85e0b318f0c27a260aae50d`.
- Production frontend: `tsc --noEmit` и `vite build` PASS.
- Свежий source archive: SHA-256 `2715c909b5cfb3d8597b019cb3bef71b17bc513b41ecf5ee4d84c62064fca850`.
- Свежий статический Linux ELF: SHA-256 `0ef4f3165bfde040a839cb7e1045169cbb1e792590b6c5b6d778f27b1f03c342`.
- Негативная попытка без соседнего `.sha256` корректно отказала до запуска бинарника и полностью откатила созданные пути. Это ошибка первоначальной QA-оснастки, не дефект продукта.
- Повтор с корректной checksum прошёл: `netOS fresh-b69e46b2`, ready `1`, active/running, `Result=success`, `NRestarts=0`, failed units 0, clean plan.
- Install monitor: 49 секунд, crash/restart/failed unit не было. Snapshot `/var/backups/netos/qa-fresh-after-install`, manifest PASS.

## API с чистой revision 1

- 56/56 live API checks PASS: public/auth/session/logout, CSRF, literal confirmations, negative/missing cases, status/list endpoints, revision detail, WireGuard и Reality key generation/derivation, validation, idempotent save, stale draft conflict, clean plan и все render artifacts.
- Первый успешный login удалил `/var/lib/netos/initial-credentials`.
- API monitor: 53 последовательных core-state проб active/running, ready 1, failed 0; `NRestarts=0`, final plan clean.

## UI с чистой revision 1

- Реальный Chromium через SSH tunnel к `127.0.0.1:8443`; прямой public URL локально подменялся Kaspersky страницей HTTP 499 и не засчитан как поведение netOS.
- Успешно открыты и проверены: Сводка, Устройства, Сеть, Маршрутизация, Интернет-каналы, VPN-доступ, Wi-Fi, Скорость и QoS, Защита сети, Адреса и DNS, Компоненты.
- Проверены conditional формы WAN static/DHCP/PPPoE, route types/table/rule, WireGuard/OpenConnect/Xray channels, четыре VPN server types, Wi-Fi radio/SSID/security/bands, QoS, три DDNS provider, firewall rule/schedule/NAT/port-forward.
- Все черновые формы возвращались через `Отменить`; после выдержки draft исчезал, active revision не менялась.
- OBS-FRESH-001 (low): при включении пустого DDNS draft UI показывает `ошибка обновления` и даты `01.01, 02:30` до первой реальной попытки. В рамках цикла наблюдалось один раз; provider API без реальных внешних токенов не вызывался, поэтому это оставлено наблюдением, а не подтверждённым дефектом интеграции.

### DEF-FRESH-001 — скрытый невалидный DNSSEC draft

- Severity: medium. Обнаружено на чистой revision 2 после установки компонентов.
- Preconditions: DNS выключен, `dns.provider` в конфигурации пуст, но HTML select визуально показывает первый вариант `dnsmasq`.
- Воспроизведение: открыть «Адреса и DNS» → включить видимый «Проверять DNSSEC» → включить «Резолвер включён».
- Фактический результат: переключатель DNSSEC исчезает, select продолжает показывать `dnsmasq`, sticky-bar сообщает одну ошибку, а «Показать план» и «Применить» заблокированы. Исправляющий контрол больше не виден; остаётся только отменить весь draft.
- Сетевое доказательство: первый PUT сохранил `dnssec=true` при пустом provider; следующий PUT с автоподстановкой `dnsmasq` получил HTTP 422 на `dns.dnssec`: DNSSEC для dnsmasq не реализован, нужно выбрать unbound или dnsproxy.
- Ожидание: визуальное значение select должно совпадать с моделью с первого render; при выборе/автоподстановке dnsmasq несовместимый `dnssec` должен сбрасываться, либо UI обязан оставить ошибочный контрол видимым для исправления.

## Реальная установка компонентов через UI

- Выбраны все 16 компонентов. UI plan показал 15 операций create; QoS уже был обеспечен базовым `iproute2`.
- Установка завершилась примерно за 1 мин 45 с. Apt и закреплённые external downloads dnsproxy/Xray прошли; все 20 ожидаемых commands найдены в PATH.
- Active config содержит ровно 16 component IDs, draft clean, pending confirmation false. Revisions: 2 active, 1 superseded.
- За первые 845 UI-monitor samples: 0 core-state отклонений, всегда active/running, ready-marker 1, failed 0, `NRestarts=0`.
- После компонентов: clean plan, failed units 0; snapshot `/var/backups/netos/qa-fresh-after-components`, manifest PASS.

## Система, история, диагностика

- Проверены все три network-backend варианта, оба IPv6-режима, self-signed/custom/ACME TLS и их условные поля; опасные изменения порта/TLS не стартуют без буквального `RESTART`.
- Через UI создана резервная копия, открыта защищённая форма восстановления, подтверждение без буквального `RESTORE` заблокировано. Реальное восстановление той же копии создало страховочный `netos-before-restore-*`, перезапустило службу и вернуло clean config/plan.
- После backup и restore служба каждый раз штатно stop/start; `Result=success`, `NRestarts=0`, failed units 0. За 1626 мониторных проб отклонений core-state не поймано; SSH/tunnel не потеряны.
- История показала revisions 2/1; «Загрузить» revision 1 создал только draft, «Отменить» вернул clean state.
- Все шесть диагностических вкладок загрузили непустые данные: iptables, network config, sysctl, netOS config, routes, neighbours.
- Цикл тем auto/dark/light и mobile viewport 390×844 проверены; мобильное меню открывается и закрывается по Escape.
- Console: JavaScript exceptions нет. Накопленные browser errors — HTTP 401 до login и HTTP 422 от намеренно невалидных draft-форм.

### DEF-FRESH-002 — восстановление исчезает из журнала действий

- Severity: high для аудита/трассируемости.
- Воспроизведение: создать backup через UI → восстановить его с буквальным `RESTORE` → после завершения открыть «История».
- Фактический результат: restore реально выполнен (страховочная копия создана, netosd stop/start, конфигурация восстановлена), но в активном журнале действий записи о restore нет; последняя запись — только предшествующий `backup: операция запланирована`.
- Вероятная причина: база журнала заменяется содержимым backup, поэтому запись о восстановлении, сделанная до/в процессе операции, сама откатывается. Это вывод из наблюдаемого результата, требующий проверки реализации.
- Ожидание: restore и его исход должны фиксироваться в неоткатываемом журнале либо повторно дописываться после замены базы.

### DEF-FRESH-003 — stale UI после завершённого restore

- Severity: medium. Сразу после успешного restore UI продолжал показывать прежний optimistic draft TLS=`ACME`, открытую confirmation-форму и сообщение «Восстановление запланировано», тогда как `/api/config` уже отвечал `dirty=false`, TLS=`selfsigned`, backend=`netos`, IPv6=`off`.
- Обычный reload синхронизировал экран и сохранил авторизованную сессию.
- Ожидание: по завершении фоновой операции UI должен заново загрузить config/operation state или явно потребовать reload, не показывая устаревшие значения как текущие.

## CLI и транзакционное применение

- CLI PASS: `version`, `status`, `logs`, `plan`, `completion bash`, `render --list`, все 16 render-артефактов и `restore` list-mode на EOF. Все read-only команды exit 0; render-вывод непустой.
- `update fresh-b69e46b2` без force корректно распознал ту же версию и ничего не изменил.
- `stop` оставил службу inactive/dead и убрал listener; `start` и `restart` вернули active/running, `Result=success`, `NRestarts=0`, failed units 0, plan clean. Browser session после reload восстановилась.
- Отдельный panel-restart реально перевёл listener 8443→9443 и затем 9443→8443; literal `RESTART` обязателен, firewall/config следовали новому порту, связь через новый SSH tunnel работала.
- Неразрывный apply timezone показал точный plan и применил `Europe/Moscow`; `timedatectl` подтвердил live state.
- Connectivity apply на дополнительной routing-table показал countdown и после «Всё работает» зафиксировал revision 8 active. Следующий apply проверен и ручным rollback, и timeout rollback.

### DEF-FRESH-004 — rollback оставляет откатанную конфигурацию dirty-draft

- Severity: high. Воспроизводится и ручным «Откатить», и автоматическим timeout.
- Сценарий 1: подтвердить revision 8 с таблицей `netos-t1` → удалить таблицу → применить revision 9 → нажать «Откатить».
- Фактический результат: revision 9=`rolled_back`, revision 8=`active`, engine/live plan clean, но `/api/config` возвращает `dirty=true` и draft без таблицы — то есть ровно откатанное содержимое revision 9. UI сообщает об успешном откате, одновременно показывает «Дополнительных таблиц нет» и предлагает снова применить удаление. Только отдельное «Отменить» возвращает draft к revision 8.
- Сценарий 2: изменить comment таблицы → применить revision 10 → не подтверждать. После deadline revision 10=`rolled_back`, revision 8 остаётся active, но `/api/config` снова `dirty=true` и содержит `comment=timeout-rollback-probe` из откатанной revision.
- Риск: администратор может сразу повторно применить опасную конфигурацию, которую механизм безопасности только что откатил; UI и active/live state расходятся.
- Ожидание: успешный manual/timeout rollback должен атомарно заменить/очистить draft до восстановленной active revision и вернуть `dirty=false`.

## Reset, reinstall и аварийное восстановление

- `SIGKILL` живого netosd: systemd поднял новый PID, `NRestarts` 0→1; через несколько секунд listener 8443, clean plan и browser session восстановились, failed units 0.
- `netos reinstall fresh-b69e46b2` корректно отказал до мутаций, потому что для локального dev-version нет готового GitHub release. Реальный reinstall тем же свежим `install.sh` и тем же checksum-проверенным ELF выполнен отдельно: версия сохранена, служба active/running, plan clean, result PASS.
- `netos reset --backup --yes` создал `netos-reset-*`, отозвал старую сессию, вернул revision 1/factory config, создал новые initial credentials; пароль сразу безопасно заменён credential-файлом, а первый login удалил initial-credentials.
- Reset удалил все 20 component-команд и 21 пакет относительно исходного clean baseline (включая шесть пакетов, уже помеченных manual до свежей установки: dnsmasq, isc-dhcp-server, ocserv, unbound, unbound-anchor, wireguard-tools). Это оставило сервер чище исходного baseline.

## Финальное удаление

- `netos uninstall --yes` завершился штатно, создал последнюю страховочную копию и удалил CLI/daemon/unit/config/data/logs/listeners/processes.
- Затем по проверенному whitelist удалены все созданные аудитом backups, snapshots, build trees, archives, monitor logs и temp scripts. Системные `/var/tmp/cloud-init` и `systemd-private-*` не затронуты.
- Финальный proof: отсутствуют netos/netosd, completion, unit, `/var/lib/netos`, `/etc/netos`, `/var/log/netos`, baseline, `/var/backups/netos`, `/opt/netos*`, ready markers, dnsproxy/Xray, component commands, процессы, listeners 8443/9443/5354 и `tun-ch1`; поиск `*netos*` по managed roots пуст.
- `systemctl --failed`: 0; SSH active; tuned active; eth0 UP/LOWER_UP; default route сохранён; диск 54%, свободно 4,34 ГБ.
- После скачивания proof его временные файлы тоже удалены. В `/var/tmp` остались только `cloud-init` и три системных `systemd-private-*` каталога.

### DEF-FRESH-005 — uninstall оставляет Kea lease-файл с клиентскими данными

- Severity: medium (остаточные данные/приватность).
- После штатного reset, reinstall и `netos uninstall --yes` основной product footprint отсутствовал, но поиск managed names нашёл `/var/lib/kea/netos-leases4.csv`.
- Файл root:root 0640, 181 байт, содержал заголовок Kea CSV и тестовую аренду `192.0.2.50` / `client.qa.lan`; SHA-256 `9ddc3fcd746df68ee03bcdc7318131547faa85afcb5e4c2cb0194aabc4cf7a31`.
- Файл удалён вручную точным whitelist, после чего финальный поиск прошёл PASS.
- Ожидание: full uninstall должен удалять netOS-managed lease backend либо явно предлагать/preserve его только с `--keep-data`.

## Ограничения среды

- На сервере один физический NIC и нет Wi-Fi radio/второго провайдера/внешних VPN peers. Поэтому hardware/third-party handshake проверялись через validation, render, component lifecycle и формы, но не через реальный радиоклиент, второй WAN или внешние коммерческие аккаунты.
- Прямой public browser path блокировался локальным Kaspersky HTTP 499; продукт тестировался реальным Chromium через SSH loopback tunnel. SSH/API/daemon path на сервере работал штатно.

## Evidence

- Pre-reset archive: `output/netos-fresh-evidence-20260901.tar.gz`, SHA-256 `a52cdbd929e4b69a447403ef0d47fdd2f34198f52c6ee2660d7bcca3f219cd32`.
- Post-reset/reinstall archive: `output/netos-fresh-postreset-evidence-20260901.tar.gz`, SHA-256 `6f199921f1cd381949c7e96c74156af15a25f0af8f3b9f200734724c1fd4e216`.
- Final clean proof: `output/final-clean-proof.txt`, заканчивается `FINAL_RESULT=PASS`.
- Пользовательский `test_results.md` не изменялся этим аудитом и не использовался как доказательство.
