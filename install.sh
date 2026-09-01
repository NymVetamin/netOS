#!/bin/bash
#
# Установщик netOS.
#
#   curl -fsSL https://raw.githubusercontent.com/NymVetamin/netOS/master/install.sh | sudo bash
#
# Скрипт ставит зависимости, разворачивает демон, определяет сетевые
# интерфейсы и печатает адрес панели с учётными данными.
#
# Переменные окружения:
#   NETOS_VERSION      версия релиза (по умолчанию latest)
#   NETOS_BINARY_URL   прямая ссылка на бинарник вместо GitHub Releases
#   NETOS_FROM_SOURCE  1 — собрать из исходников вместо загрузки релиза
#   NETOS_PORT         порт веб-панели (по умолчанию 8443)
#
# Повторный запуск обновляет netOS и сохраняет конфигурацию. После первой
# установки для этого используется публичная команда: sudo netos update.

set -euo pipefail

REPO="NymVetamin/netOS"
VERSION="${NETOS_VERSION:-latest}"
PORT="${NETOS_PORT:-8443}"

case "$PORT" in
    ''|*[!0-9]*) echo "Некорректный порт панели: $PORT" >&2; exit 1 ;;
esac
[ "${#PORT}" -le 5 ] || { echo "Некорректный порт панели: $PORT" >&2; exit 1; }
PORT=$((10#$PORT))
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
    || { echo "Некорректный порт панели: $PORT" >&2; exit 1; }
[ "$PORT" -ne 53 ] \
    || { echo "Порт панели 53 занят системной службой DNS" >&2; exit 1; }

BIN_PATH="/usr/local/bin/netosd"
CLI_PATH="/usr/local/bin/netos"
STATE_DIR="/var/lib/netos"
CONF_DIR="/etc/netos"
LOG_DIR="/var/log/netos"
BASELINE_DIR="/var/lib/netos-system-baseline"

case "$VERSION" in
    *[!A-Za-z0-9._+-]*) echo "Некорректная версия: $VERSION" >&2; exit 1 ;;
esac

# --- вывод -------------------------------------------------------------------

if [ -t 1 ]; then
    B=$(printf '\033[1m'); D=$(printf '\033[2m'); R=$(printf '\033[0m')
    GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); YELLOW=$(printf '\033[33m')
else
    B=""; D=""; R=""; GREEN=""; RED=""; YELLOW=""
fi

step()  { echo "${B}==>${R} $*"; }
info()  { echo "    $*"; }
ok()    { echo "    ${GREEN}✓${R} $*"; }
warn()  { echo "    ${YELLOW}!${R} $*"; }
die()   { echo "${RED}Ошибка:${R} $*" >&2; exit 1; }

SRC=""
TMP=""
INSTALL_TXN=""
ROLLBACK_ARMED=0
PREVIOUS_ACTIVE=0
PREVIOUS_ENABLED=0

snapshot_path() {
    source_path=$1
    label=$2
    if [ -e "$source_path" ] || [ -L "$source_path" ]; then
        cp -a -- "$source_path" "$INSTALL_TXN/$label"
    else
        : > "$INSTALL_TXN/$label.absent"
    fi
}

restore_path() {
    target_path=$1
    label=$2
    rm -rf -- "$target_path"
    if [ ! -f "$INSTALL_TXN/$label.absent" ]; then
        cp -a -- "$INSTALL_TXN/$label" "$target_path"
    fi
}

wait_netosd_ready() {
    wait_limit=$1
    wait_count=0
    while [ "$wait_count" -lt "$wait_limit" ]; do
        if systemctl is-active --quiet netosd && [ -s /run/netosd.ready ]; then
            return 0
        fi
        wait_count=$((wait_count + 1))
        sleep 1
    done
    return 1
}

rollback_and_cleanup() {
    status=$?
    trap - EXIT
    set +e
    if [ -n "$SRC" ] && [ "$SRC" != "/" ]; then rm -rf -- "$SRC"; fi
    if [ -n "$TMP" ]; then rm -f -- "$TMP" "$TMP.sha256"; fi
    if [ "$status" -ne 0 ] && [ "$ROLLBACK_ARMED" = "1" ]; then
        warn "установка оборвалась — возвращаю исходные файлы и состояние службы"
        # На чистой установке демон мог успеть применить firewall, маршруты и
        # sysctl до отказа readiness. Файлового rollback недостаточно: сначала
        # штатный uninstall возвращает сохранённый системный baseline. Данные
        # пока сохраняются, чтобы rollback ниже сам удалил только новые dirs.
        if [ "$UPGRADE" = "0" ] && [ -x "$BIN_PATH" ] && [ "$(readlink -f "$CLI_PATH" 2>/dev/null)" = "$BIN_PATH" ]; then
            if "$CLI_PATH" uninstall --keep-data --yes >/dev/null 2>&1; then
                warn "исходное состояние сети и служб восстановлено"
            else
                warn "автоматический возврат системного baseline не удался; проверьте журнал и состояние сети"
            fi
        fi
        systemctl stop netosd >/dev/null 2>&1
        restore_path "$BIN_PATH" binary
        restore_path "$CLI_PATH" cli
        restore_path /etc/systemd/system/netosd.service unit
        restore_path /etc/bash_completion.d/netos completion
        restore_path /etc/apt/apt.conf.d/99netos aptconf
        restore_path "$STATE_DIR" state-dir
        restore_path "$CONF_DIR" conf-dir
        restore_path "$LOG_DIR" log-dir
        restore_path "$BASELINE_DIR" baseline-dir
        systemctl daemon-reload >/dev/null 2>&1
        if [ "$PREVIOUS_ENABLED" = "1" ]; then
            systemctl enable netosd >/dev/null 2>&1
        else
            systemctl disable netosd >/dev/null 2>&1
        fi
        rm -f /run/netosd.ready
        if [ "$PREVIOUS_ACTIVE" = "1" ] && systemctl start netosd >/dev/null 2>&1 && wait_netosd_ready 360; then
            warn "предыдущая версия netOS восстановлена и работает"
        elif [ "$PREVIOUS_ACTIVE" = "1" ]; then
            warn "предыдущие файлы восстановлены, но netosd не запустился; проверьте journalctl -u netosd"
        fi
    fi
    if [ -n "$INSTALL_TXN" ] && [ "$INSTALL_TXN" != "/" ]; then rm -rf -- "$INSTALL_TXN"; fi
    exit "$status"
}
trap rollback_and_cleanup EXIT

# --- проверки ----------------------------------------------------------------

step "Проверяю систему"

[ "$(id -u)" -eq 0 ] || die "нужны права root — запустите через sudo"

command -v systemctl >/dev/null 2>&1 || die "требуется systemd"

# os-release читается в подоболочке: файл объявляет собственные VERSION и
# NAME, и обычный `. /etc/os-release` затёр бы VERSION установщика — тогда
# ссылка на релиз собирается из версии дистрибутива ("13 (trixie)") и загрузка
# падает. Наружу выносятся только те значения, которые нам нужны.
if [ -r /etc/os-release ]; then
    OS_FAMILY=$( . /etc/os-release; printf '%s' "${ID:-}${ID_LIKE:-}" )
    OS_NAME=$( . /etc/os-release; printf '%s' "${PRETTY_NAME:-неизвестна}" )
    case "$OS_FAMILY" in
        *debian*|*ubuntu*) : ;;
        *) warn "система ${OS_NAME}, netOS рассчитан на Debian — продолжаю на свой страх" ;;
    esac
    info "Система: ${OS_NAME}"
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    *) die "архитектура $ARCH не поддерживается (нужна x86_64 или aarch64)" ;;
esac
info "Архитектура: $ARCH"

# Роутер без второго интерфейса работать будет, но локальную сеть обслуживать
# не сможет — предупреждаем сразу, а не после установки.
NIC_COUNT=$(find /sys/class/net -mindepth 1 -maxdepth 1 ! -name lo -exec test -e {}/device \; -print | wc -l)
info "Сетевых карт: $NIC_COUNT"
if [ "$NIC_COUNT" -lt 2 ]; then
    warn "меньше двух сетевых карт: локальный сегмент будет создан на виртуальном интерфейсе"
fi

if [ -x "$BIN_PATH" ] || [ -s "$STATE_DIR/netos.db" ]; then
    warn "netOS уже установлен — будет обновлён, конфигурация сохранится"
    UPGRADE=1
else
    UPGRADE=0
fi

# Транзакция начинается до первого принадлежащего netOS изменения (apt policy
# ниже). Поэтому и чистая установка, и ранний отказ обновления возвращают
# исходные файлы, состояние службы и только что созданные каталоги.
INSTALL_TXN=$(mktemp -d)
snapshot_path "$BIN_PATH" binary
snapshot_path "$CLI_PATH" cli
snapshot_path /etc/systemd/system/netosd.service unit
snapshot_path /etc/bash_completion.d/netos completion
snapshot_path /etc/apt/apt.conf.d/99netos aptconf
snapshot_path "$STATE_DIR" state-dir
snapshot_path "$CONF_DIR" conf-dir
snapshot_path "$LOG_DIR" log-dir
snapshot_path "$BASELINE_DIR" baseline-dir
systemctl is-active --quiet netosd && PREVIOUS_ACTIVE=1 || true
systemctl is-enabled --quiet netosd && PREVIOUS_ENABLED=1 || true
ROLLBACK_ARMED=1

# --- зависимости -------------------------------------------------------------

step "Устанавливаю зависимости"

export DEBIAN_FRONTEND=noninteractive

# AAAA-записи есть у большинства зеркал, а связности по IPv6 у роутера может не
# быть — заставляем apt работать по IPv4, иначе установка молча зависает.
cat > /etc/apt/apt.conf.d/99netos <<'EOF'
Acquire::ForceIPv4 "true";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF
chmod 0644 /etc/apt/apt.conf.d/99netos

# Базовая установка ставит только то, без чего не поднимется сам роутер и
# панель. DHCP-сервер, резолверы, VPN и точка доступа — это компоненты,
# которые администратор выбирает в панели уже после установки.
# procps и kmod на облачных образах есть всегда, а на минимальной установке
# Debian их нет. Сам netOS без них обходится — параметры ядра он пишет прямо в
# /proc/sys, — но администратор, пришедший на роутер руками, ожидает найти
# sysctl и modprobe на месте.
PACKAGES="iptables iproute2 ca-certificates curl busybox procps kmod bash-completion systemd-timesyncd"
if [ "${NETOS_FROM_SOURCE:-0}" = "1" ]; then
    PACKAGES="$PACKAGES git nodejs npm"
fi

# Preserve the auto/manual status of dependencies that were already installed.
# An explicit apt-get install otherwise turns existing auto packages into manual ones.
AUTO_PACKAGES=""
for package in $PACKAGES; do
    if dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii ' \
        && apt-mark showauto 2>/dev/null | grep -Fxq "$package"
    then
        AUTO_PACKAGES="$AUTO_PACKAGES $package"
    fi
done

apt-get update -qq 2>/dev/null || warn "не удалось обновить списки пакетов, пробую продолжить"
if apt-get install -y -qq $PACKAGES >/dev/null 2>&1; then
    if [ -n "$AUTO_PACKAGES" ]; then
        # shellcheck disable=SC2086 # fixed package names collected from PACKAGES above
        apt-mark auto $AUTO_PACKAGES >/dev/null
    fi
    ok "пакеты установлены"
else
    die "не удалось установить пакеты: $PACKAGES"
fi

# --- бинарник ----------------------------------------------------------------

step "Разворачиваю netOS"

install -d -m 0700 "$STATE_DIR"
install -d -m 0755 "$STATE_DIR/generated" "$CONF_DIR" "$LOG_DIR"
install -d -m 0700 "$CONF_DIR/tls"
if [ "$UPGRADE" = "0" ]; then
    install -d -m 0700 "$BASELINE_DIR"
    : > "$BASELINE_DIR/.capture-required"
    chmod 0600 "$BASELINE_DIR/.capture-required"
fi

if [ "${NETOS_FROM_SOURCE:-0}" = "1" ]; then
    info "сборка из исходников"
    command -v git >/dev/null 2>&1 || die "для сборки из исходников нужен git"

    # Сборка компилирует встроенный SQLite — самую тяжёлую зависимость
    # проекта. На роутере с гигабайтом памяти и без подкачки машина уходит в
    # OOM и перестаёт отвечать даже по SSH: со стороны это выглядит зависанием,
    # а не отказом сборки. Считаем память вместе с подкачкой и отказываемся
    # заранее, объяснив, что делать.
    MEM_KB=$(awk '/^MemTotal:/ {m=$2} /^SwapTotal:/ {s=$2} END {print m + s}' /proc/meminfo)
    if [ "${MEM_KB:-0}" -lt 2000000 ]; then
        die "для сборки из исходников нужно около 2 ГБ памяти вместе с подкачкой, доступно $((MEM_KB / 1024)) МБ.
    Добавьте файл подкачки или поставьте готовый релиз, убрав NETOS_FROM_SOURCE."
    fi

    SRC=$(mktemp -d)
    GO_VERSION="1.27.0"
    GO_ARCHIVE="$SRC/go.tar.gz"
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    info "загружаю Go $GO_VERSION"
    curl -4 -fsSL --retry 3 -o "$GO_ARCHIVE" "$GO_URL" \
        || die "не удалось загрузить Go $GO_VERSION"
    curl -4 -fsSL --retry 3 -o "$GO_ARCHIVE.sha256" "$GO_URL.sha256" \
        || die "не удалось загрузить контрольную сумму Go $GO_VERSION"
    EXPECTED=$(tr -d '[:space:]' < "$GO_ARCHIVE.sha256")
    ACTUAL=$(sha256sum "$GO_ARCHIVE" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || die "контрольная сумма Go не совпадает"
    tar -C "$SRC" -xzf "$GO_ARCHIVE" || die "не удалось распаковать Go"

    if [ "$VERSION" = "latest" ]; then
        git clone --depth 1 "https://github.com/$REPO.git" "$SRC/netos" >/dev/null 2>&1 \
            || die "не удалось получить исходники"
    else
        git clone --depth 1 --branch "$VERSION" "https://github.com/$REPO.git" "$SRC/netos" >/dev/null 2>&1 \
            || die "не удалось получить исходники версии $VERSION"
    fi
    BUILD_VERSION="$VERSION"
    if [ "$BUILD_VERSION" = "latest" ]; then
        BUILD_VERSION=$(git -C "$SRC/netos" describe --tags --always --dirty 2>/dev/null || echo dev)
    fi
    CANDIDATE="$SRC/netosd"
    (
        cd "$SRC/netos/web"
        npm ci
        npm run build
        cd ../backend
        # Пакеты собираются по одному: параллельная сборка встроенного
        # SQLite съедает память кратно числу ядер и на роутере валит
        # машину раньше, чем успевает закончиться.
        #
        # Запасное зеркало модулей — отдельной попыткой, а не списком через
        # запятую: по списку Go идёт дальше только на 404 и 410, а
        # заблокированное зеркало отвечает 403 — и сборка падала бы, имея
        # рабочий запасной адрес.
        GOFLAGS="-p=1" GOMAXPROCS=1 GOPROXY="https://proxy.golang.org,direct" \
            "$SRC/go/bin/go" build -trimpath -ldflags "-s -w -X main.version=$BUILD_VERSION" -o "$CANDIDATE" ./cmd/netosd \
        || GOFLAGS="-p=1" GOMAXPROCS=1 GOPROXY="https://goproxy.io,direct" \
            "$SRC/go/bin/go" build -trimpath -ldflags "-s -w -X main.version=$BUILD_VERSION" -o "$CANDIDATE" ./cmd/netosd
    ) || die "сборка не удалась"
    ok "собрано из исходников"
else
    if [ -n "${NETOS_BINARY_URL:-}" ]; then
        URL="$NETOS_BINARY_URL"
    elif [ "$VERSION" = "latest" ]; then
        URL="https://github.com/$REPO/releases/latest/download/netosd-linux-$GOARCH"
    else
        URL="https://github.com/$REPO/releases/download/$VERSION/netosd-linux-$GOARCH"
    fi

    info "загружаю $URL"
    TMP=$(mktemp)
    if ! curl -4 -fsSL --retry 3 --retry-delay 2 -o "$TMP" "$URL"; then
        die "не удалось загрузить бинарник. Соберите из исходников: NETOS_FROM_SOURCE=1 $0"
    fi

    # Непроверенный root-бинарник запускать нельзя. Release workflow всегда
    # публикует сумму рядом с артефактом; её отсутствие означает неполный или
    # недоверенный релиз, а не повод ослабить проверку.
    curl -4 -fsSL --retry 2 -o "$TMP.sha256" "$URL.sha256" \
        || die "контрольная сумма бинарника недоступна — установка отменена"
    EXPECTED=$(awk 'NR == 1 && $1 ~ /^[0-9a-fA-F]{64}$/ {print tolower($1)}' "$TMP.sha256")
    [ -n "$EXPECTED" ] || die "файл контрольной суммы имеет неверный формат"
    ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || die "контрольная сумма не совпадает — загрузка повреждена"
    ok "контрольная сумма проверена"

    CANDIDATE="$TMP"
fi

# Нельзя перезаписывать исполняемый файл на месте: при обновлении ядро может
# вернуть ETXTBSY. Новый файл кладётся рядом и атомарно переименовывается.
install -m 0755 "$CANDIDATE" "$BIN_PATH.new"
mv -f "$BIN_PATH.new" "$BIN_PATH"
ln -sfn "$BIN_PATH" "$CLI_PATH"
ok "бинарник и команда netos установлены"

# Первый запуск netOS переписывает firewall, маршруты и параметры ядра. До него
# сохраняем точное исходное состояние вне рабочего StateDir: reset не должен
# стереть память о том, какой была машина до установки. На обновлении снимок не
# создаём заново, иначе уже применённое состояние netOS стало бы «исходным».
if [ "$UPGRADE" = "0" ] || [ -f "$BASELINE_DIR/.capture-required" ]; then
    "$BIN_PATH" -capture-system-baseline \
        || die "не удалось сохранить состояние системы до первого применения"
    rm -f "$BASELINE_DIR/.capture-required"
    ok "исходное состояние системы сохранено для безопасного удаления"
fi

# Дополнение команд генерирует сам netos: список команд задан в его коде, и
# отдельный файл в репозитории разошёлся бы с ним при первой же новой команде.
if "$CLI_PATH" completion bash > /etc/bash_completion.d/netos 2>/dev/null; then
    chmod 0644 /etc/bash_completion.d/netos
    ok "дополнение команд установлено (заработает в новой сессии)"
else
    rm -f /etc/bash_completion.d/netos
    warn "не удалось установить дополнение команд"
fi

# --- служба ------------------------------------------------------------------

step "Настраиваю службу"

cat > /etc/systemd/system/netosd.service <<EOF
[Unit]
Description=netOS — маршрутизатор и веб-панель управления
Documentation=https://github.com/$REPO
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=simple
ExecStart=$BIN_PATH
Environment=NETOS_INITIAL_PORT=$PORT
Restart=always
RestartSec=3
# Демон управляет сетевым стеком и запускает вспомогательные службы,
# поэтому изоляция ограничена тем, что не мешает работе.
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
LockPersonality=true
ProtectClock=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictRealtime=true
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/netosd.service

systemctl daemon-reload
# Enable меняет зависимости target-а на диске. На чистой установке systemd
# обязан перечитать их до первого restart, иначе честно предупреждает, что unit
# изменился после daemon-reload. Обычный enable делает нужный reload сам.
systemctl enable netosd >/dev/null 2>&1
ok "служба netosd зарегистрирована"

# --- запуск ------------------------------------------------------------------

step "Запускаю netOS"

START_OK=1
rm -f /run/netosd.ready
if ! systemctl restart netosd; then
    START_OK=0
fi

# `Type=simple` становится active до стартового Apply. Готовность подтверждает
# только свежий marker: daemon пишет его после Apply, запуска TLS listener и
# собственного HTTPS probe. 360 секунд также покрывают медленный ACME HTTP-01.
if ! wait_netosd_ready 360; then
    START_OK=0
fi
if [ "$START_OK" = "0" ]; then
    echo
    journalctl -u netosd --no-pager -n 30
    die "служба не запустилась, журнал выше"
fi
ROLLBACK_ARMED=0
ok "служба работает"

# Печатать нужно фактически сохранённый порт, а не значение окружения текущего
# запуска: при update конфигурация пользователя намеренно не перезаписывается.
PANEL_PORT=$("$BIN_PATH" -panel-port 2>/dev/null || true)
case "$PANEL_PORT" in
    ''|*[!0-9]*) PANEL_PORT="$PORT" ;;
esac

# --- итог --------------------------------------------------------------------

# Учётные данные первого запуска демон кладёт в файл — разбирать журнал
# ненадёжно, там остаются записи от прошлых установок.
#
# Файл появляется не сразу: сначала демон применяет всю конфигурацию (сеть,
# файрволл, службы), и только потом заводит учётную запись. Поэтому ждём его
# появления, а не спим фиксированное время.
CREDS_FILE="$STATE_DIR/initial-credentials"
if [ "$UPGRADE" = "0" ]; then
    for _ in $(seq 1 40); do
        [ -s "$CREDS_FILE" ] && break
        sleep 1
    done
fi

echo
echo "${B}============================================================${R}"
if [ "$UPGRADE" = "1" ]; then
    echo "  ${GREEN}netOS обновлён${R}"
    echo
    echo "  Конфигурация и учётные записи сохранены."
    # Глобального адреса может не быть вовсе: аплинк ещё не поднялся, машина
    # стоит за NAT без внешнего адреса. Печатать "https://:8443" нельзя — по
    # такой ссылке никуда не попадёшь, а выглядит она как поломка установки.
    PANEL_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$PANEL_IP" ] || PANEL_IP=$(hostname)
    echo "  Панель: ${B}https://${PANEL_IP}:${PANEL_PORT}${R}"
else
    echo "  ${GREEN}netOS установлен${R}"
    echo
    if [ -r "$CREDS_FILE" ]; then
        sed 's/^/  /' "$CREDS_FILE"
    else
        warn "файл с учётными данными не найден"
        info "посмотрите их командой: journalctl -u netosd | grep -A6 netOS"
    fi
    echo
    echo "  ${D}Сертификат самоподписанный — браузер предупредит об этом.${R}"
    echo
    echo "  ${D}Установлены только панель и доступ по SSH. DHCP, DNS, VPN и${R}"
    echo "  ${D}остальное включаются в панели, в разделе «Компоненты».${R}"
fi
echo "${B}============================================================${R}"
echo
info "Управление:   netos help (дополнение по Tab — в новой сессии)"
info "Обновление:   sudo netos update"
info "Состояние:    netos status"
info "Журнал:       netos logs -f"
echo
