#!/bin/bash
#
# Установщик netOS.
#
#   curl -fsSL https://raw.githubusercontent.com/NymVetamin/netOS/master/install.sh | sudo bash && source /etc/bash_completion.d/netos
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

fetch_release_source() {
    local dest=$1 prefix="https://github.com/$REPO/releases/tag/" url
    if [ "$VERSION" = latest ]; then
        url=$(curl -4 -fsSLI --retry 2 -o /dev/null -w '%{url_effective}' \
            "https://github.com/$REPO/releases/latest") || die "не удалось определить последний релиз"
        BUILD_VERSION=${url#"$prefix"}
        [ "$url" != "$BUILD_VERSION" ] || die "неожиданный адрес последнего релиза"
        case "$BUILD_VERSION" in
            ''|*[!A-Za-z0-9._+-]*) die "не удалось определить тег последнего релиза" ;;
        esac
    else
        BUILD_VERSION=$VERSION
    fi
    git init -q "$dest" &&
        git -C "$dest" fetch -q --depth 1 "https://github.com/$REPO.git" "refs/tags/$BUILD_VERSION" &&
        git -C "$dest" checkout -q --detach FETCH_HEAD ||
        die "не удалось получить исходники релиза $BUILD_VERSION"
}

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
    if rm -rf -- "$target_path" && { [ -f "$INSTALL_TXN/$label.absent" ] || cp -a -- "$INSTALL_TXN/$label" "$target_path"; }; then
        return 0
    fi
    restore_failed=1
    warn "не удалось восстановить $target_path"
}

wait_netosd_ready() {
    wait_limit=$1
    wait_count=0
    wait_deadline=$((SECONDS + wait_limit))
    initial_restarts=$(systemctl show netosd --property=NRestarts --value)
    legacy_port=""
    # Released v0.06 starts HTTPS only after the synchronous startup Apply,
    # but predates the readiness marker and -panel-port. Keep the marker
    # mandatory for newer binaries; an unhealthy modern daemon must not fall
    # back to a weaker compatibility check.
    if ! "$BIN_PATH" -h 2>&1 | grep -- '-panel-port' >/dev/null; then
        case "$("$BIN_PATH" -version 2>/dev/null)" in
            'netOS v0.06')
                legacy_port=$("$BIN_PATH" -render config 2>/dev/null | awk '
                    /^[[:space:]]*"panel":[[:space:]]*\{/ { panel=1; next }
                    panel && !found && /^[[:space:]]*"port":[[:space:]]*[0-9]+/ {
                        gsub(/[^0-9]/, ""); port=$0; found=1
                    }
                    END { if (found) print port }') || return 1
                case "$legacy_port" in ''|*[!0-9]*) return 1 ;; esac
                [ "$legacy_port" -ge 1 ] && [ "$legacy_port" -le 65535 ] || return 1
                ;;
            *) return 1 ;;
        esac
    fi
    while [ "$wait_count" -lt "$wait_limit" ] && [ "$SECONDS" -lt "$wait_deadline" ]; do
        # A slow initial Apply can need time (notably ACME). A crashed daemon
        # cannot establish readiness: return to the transaction's rollback
        # instead of letting Restart=always repeat a failed upgrade for minutes.
        current_restarts=$(systemctl show netosd --property=NRestarts --value)
        case "$initial_restarts:$current_restarts" in
            *[!0-9:]*|:*|*:) : ;;
            *) [ "$current_restarts" -le "$initial_restarts" ] || return 1 ;;
        esac
        if systemctl is-active --quiet netosd; then
            if [ -z "$legacy_port" ]; then
                [ -s /run/netosd.ready ] && return 0
            else
                legacy_pid=$(systemctl show netosd --property=MainPID --value)
                case "$legacy_pid" in ''|0|*[!0-9]*) legacy_pid=invalid ;; esac
                # A different process on the configured port cannot vouch for
                # netosd. Only probe a listener owned by its current MainPID.
                if ss -H -ltnp "sport = :$legacy_port" | grep -F "pid=$legacy_pid," >/dev/null; then
                    legacy_ping=$(curl --noproxy '*' -kfsS --connect-timeout 1 --max-time 2 "https://127.0.0.1:$legacy_port/api/ping" 2>/dev/null) || legacy_ping=""
                    [ "$legacy_ping" = '{"ok":true,"service":"netos"}' ] && return 0
                fi
            fi
        fi
        wait_count=$((wait_count + 1))
        sleep 1
    done
    return 1
}

rollback_and_cleanup() {
    status=$?
    restore_failed=0
    keep_live_baseline=0
    trap - EXIT
    set +e
    if [ -n "$SRC" ] && [ "$SRC" != "/" ]; then rm -rf -- "$SRC"; fi
    if [ -n "$TMP" ]; then rm -f -- "$TMP" "$TMP.sha256"; fi
    if [ "$status" -ne 0 ] && { [ "$ROLLBACK_ARMED" = apt ] || [ "$ROLLBACK_ARMED" = stopping ]; }; then
        restore_path /etc/apt/apt.conf.d/99netos aptconf
    elif [ "$status" -ne 0 ] && [ "$ROLLBACK_ARMED" = "1" ]; then
        warn "установка оборвалась — возвращаю исходные файлы и состояние службы"
        # На чистой установке демон мог успеть применить firewall, маршруты и
        # sysctl до отказа readiness. Файлового rollback недостаточно: сначала
        # штатный uninstall возвращает сохранённый системный baseline. Данные
        # пока сохраняются, чтобы rollback ниже сам удалил только новые dirs.
        if [ "$UPGRADE" = "0" ] && [ -x "$BIN_PATH" ] && [ "$(readlink -f "$CLI_PATH" 2>/dev/null)" = "$BIN_PATH" ]; then
            # uninstall can consume the captured baseline before a later step
            # fails. The pre-install snapshot may only contain an absent marker.
            if [ -d "$BASELINE_DIR" ] && ! cp -a -- "$BASELINE_DIR" "$INSTALL_TXN/captured-baseline"; then
                keep_live_baseline=1
                warn "не удалось скопировать $BASELINE_DIR; выполняю штатный возврат сети и служб"
            fi
            if "$CLI_PATH" uninstall --keep-data --yes >/dev/null 2>&1; then
                keep_live_baseline=0
                warn "исходное состояние сети и служб восстановлено"
            else
                restore_failed=1
                warn "автоматический возврат системного baseline не удался; проверьте журнал и состояние сети"
                if [ "$keep_live_baseline" = "1" ]; then
                    warn "проверьте оставшиеся данные в $BASELINE_DIR"
                elif [ -d "$INSTALL_TXN/captured-baseline" ]; then
                    warn "исходные настройки системы сохранены в $INSTALL_TXN/captured-baseline"
                fi
            fi
        fi
        if ! systemctl stop netosd >/dev/null 2>&1; then
            case "$(systemctl show netosd --property=ActiveState --value)" in
                inactive|failed) ;;
                *) warn "остановка netosd не подтверждена; снимок для восстановления сохранён в $INSTALL_TXN"; exit "$status" ;;
            esac
        fi
        restore_path "$BIN_PATH" binary
        restore_path "$CLI_PATH" cli
        restore_path /etc/systemd/system/netosd.service unit
        restore_path /etc/bash_completion.d/netos completion
        restore_path /usr/share/bash-completion/completions/netos completion-lazy
        restore_path /etc/apt/apt.conf.d/99netos aptconf
        restore_path "$STATE_DIR" state-dir
        restore_path "$CONF_DIR" conf-dir
        restore_path "$LOG_DIR" log-dir
        if [ "$keep_live_baseline" = "0" ]; then
            restore_path "$BASELINE_DIR" baseline-dir
        fi
        systemctl daemon-reload >/dev/null 2>&1
        if [ "$PREVIOUS_ENABLED" = "1" ]; then
            systemctl enable netosd >/dev/null 2>&1
        else
            systemctl disable netosd >/dev/null 2>&1
        fi
        rm -f /run/netosd.ready
    fi
    if [ "$status" -ne 0 ] && { [ "$ROLLBACK_ARMED" = stopping ] || [ "$ROLLBACK_ARMED" = 1 ]; }; then
        if [ "$ROLLBACK_ARMED" = stopping ] && [ "$PREVIOUS_ACTIVE" = 1 ] && ! systemctl is-active --quiet netosd; then
            rm -f /run/netosd.ready
        fi
        if [ "$PREVIOUS_ACTIVE" = "1" ] && systemctl start netosd >/dev/null 2>&1 && wait_netosd_ready 360; then
            warn "служба netosd запущена и готова"
        elif [ "$PREVIOUS_ACTIVE" = "1" ]; then
            restore_failed=1
            warn "готовность netosd не подтверждена; проверьте journalctl -u netosd"
        fi
    fi
    if [ "$restore_failed" = "1" ]; then
        warn "восстановление не завершено; снимок сохранён в $INSTALL_TXN"
    elif [ -n "$INSTALL_TXN" ] && [ "$INSTALL_TXN" != "/" ]; then
        rm -rf -- "$INSTALL_TXN"
    fi
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
    warn "для автоматической настройки локального сегмента нужен свободный проводной интерфейс"
fi

check_bootstrap_wan() {
    local default_route wan_devs wan_dev member
    # A fresh bootstrap can only configure the WAN directly. Check before apt,
    # snapshots or systemd changes, while the administrator still has access.
    if command -v ip >/dev/null 2>&1; then
        default_route=$(ip -4 -o route show default) || die "не удалось определить маршрут по умолчанию"
        wan_devs=$(awk '{
            for (i=1; i<NF; i++) if ($i=="dev") {print $(i+1); found=1}
            if (found) exit
        }' <<< "$default_route")
    else
        # iproute2 is installed later on minimal systems. The kernel table
        # exposes destination/mask in hex and metric in decimal.
        wan_devs=$(awk '$2=="00000000" && $8=="00000000" && (!found || $7+0<metric) {
            dev=$1; metric=$7+0; found=1
        } END {print dev}' /proc/net/route) || die "не удалось прочитать таблицу маршрутов"
    fi
    while IFS= read -r wan_dev; do
        [[ -n $wan_dev && -d /sys/class/net/$wan_dev/bridge ]] || continue
        if command -v ip >/dev/null 2>&1; then
            printf '%s\n' "$default_route" >&2
            ip -4 -o addr show dev "$wan_dev" >&2 || warn "не удалось прочитать адрес моста $wan_dev"
        fi
        for member in "/sys/class/net/$wan_dev/brif/"*; do
            [ ! -e "$member" ] || printf 'Порт моста: %s\n' "${member##*/}" >&2
        done
        die "маршрут по умолчанию проходит через мост $wan_dev. Подготовьте отдельный доступ к машине, перенесите аплинк с моста и повторите установку. Затем воссоздайте мост в netOS."
    done <<< "$wan_devs"
}

recheck_bootstrap_wan=0
if [ ! -s "$STATE_DIR/netos.db" ]; then
    command -v ip >/dev/null 2>&1 || recheck_bootstrap_wan=1
    check_bootstrap_wan
fi

# Пока готовится бинарник, из файлов для отката меняется только политика apt.
# Работающий демон в это время продолжает принимать настройки.
INSTALL_TXN=$(mktemp -d)
exec 9>/run/netos-install.lock
flock -n 9 || die "другая установка netOS уже выполняется"
# Bash keeps the original descriptor until this group finishes. Descendants
# (including package scripts) cannot retain the lock after the installer exits.
{
if [ -x "$BIN_PATH" ] || [ -s "$STATE_DIR/netos.db" ]; then
    warn "netOS уже установлен — будет обновлён, конфигурация сохранится"
    UPGRADE=1
else
    UPGRADE=0
fi
snapshot_path /etc/apt/apt.conf.d/99netos aptconf
ROLLBACK_ARMED=apt

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
PACKAGES="ethtool iptables iproute2 conntrack ca-certificates curl busybox procps kmod bash-completion systemd-timesyncd"
if [ "${NETOS_FROM_SOURCE:-0}" = "1" ]; then
    PACKAGES="$PACKAGES git nodejs npm"
fi

# Preserve the auto/manual status of dependencies that were already installed.
# An explicit apt-get install otherwise turns existing auto packages into manual ones.
AUTO_PACKAGES=""
unset auto_marks
for package in $PACKAGES; do
    if ! dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^[ih]i '; then
        continue
    fi
    if [[ ! -v auto_marks ]]; then
        # Keep only installer dependencies, even when showauto lists thousands of packages.
        if ! auto_marks=$(apt-mark showauto 2>/dev/null | awk -v packages="$PACKAGES" '
            BEGIN { n = split(packages, names, " "); for (i = 1; i <= n; i++) wanted[names[i]] = 1 }
            $0 in wanted { printf "%s ", $0 }
        '); then
            unset auto_marks
            continue
        fi
    fi
    if [[ " $auto_marks" == *" $package "* ]]; then
        AUTO_PACKAGES="$AUTO_PACKAGES $package"
    fi
done

# Keep package ownership outside installer rollback: an apt transaction remains
# installed even when a later installation step fails. Never overwrite the
# original package set on upgrade or on a retry.
PACKAGE_STATE=/var/lib/netos-package-state
install -d -m 0700 "$PACKAGE_STATE"
package_inventory() {
    dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\n' > "$PACKAGE_STATE/inventory.tmp" || return 1
    awk '$2 != "un" && $2 != "pn" {print $1}' "$PACKAGE_STATE/inventory.tmp" | LC_ALL=C sort -u
}
[ ! -e "$PACKAGE_STATE/pending" ] || die "предыдущий учёт пакетов не завершён: $PACKAGE_STATE/pending"
package_inventory > "$PACKAGE_STATE/before.txt" || die "не удалось снять список пакетов"
if [ ! -f "$PACKAGE_STATE/initial.txt" ]; then
    cp "$PACKAGE_STATE/before.txt" "$PACKAGE_STATE/initial.txt"
    # Only fresh installations can record true pre-netOS component state.
    # Never adopt already modified component files on an upgrade.
    if [ "$UPGRADE" = 0 ]; then
        : > "$PACKAGE_STATE/restore-components"
        chmod 0600 "$PACKAGE_STATE/restore-components"
    fi
fi
[ -f "$PACKAGE_STATE/owned.txt" ] || : > "$PACKAGE_STATE/owned.txt"
: > "$PACKAGE_STATE/pending"
chmod 0600 "$PACKAGE_STATE/"*.txt "$PACKAGE_STATE/pending"
finish_package_capture() {
    package_inventory > "$PACKAGE_STATE/after.txt" || return 1
    LC_ALL=C comm -13 "$PACKAGE_STATE/before.txt" "$PACKAGE_STATE/after.txt" > "$PACKAGE_STATE/added.txt" || return 1
    LC_ALL=C comm -23 "$PACKAGE_STATE/added.txt" "$PACKAGE_STATE/initial.txt" > "$PACKAGE_STATE/new.txt" || return 1
    cat "$PACKAGE_STATE/owned.txt" "$PACKAGE_STATE/new.txt" | LC_ALL=C sort -u > "$PACKAGE_STATE/owned.tmp" || return 1
    chmod 0600 "$PACKAGE_STATE/owned.tmp"
    mv "$PACKAGE_STATE/owned.tmp" "$PACKAGE_STATE/owned.txt" || return 1
    rm -f "$PACKAGE_STATE/pending" "$PACKAGE_STATE/inventory.tmp" "$PACKAGE_STATE/before.txt" "$PACKAGE_STATE/after.txt" "$PACKAGE_STATE/added.txt" "$PACKAGE_STATE/new.txt"
}

apt-get update -qq 2>/dev/null || warn "не удалось обновить списки пакетов, пробую продолжить"
if apt-get install -y -qq $PACKAGES >/dev/null 2>&1; then
    finish_package_capture || die "не удалось сохранить учёт пакетов"
    if [ -n "$AUTO_PACKAGES" ]; then
        # shellcheck disable=SC2086 # fixed package names collected from PACKAGES above
        apt-mark auto $AUTO_PACKAGES >/dev/null
    fi
    ok "пакеты установлены"
else
    finish_package_capture || die "не удалось сохранить учёт частично установленных пакетов"
    die "не удалось установить пакеты: $PACKAGES"
fi

# --- бинарник ----------------------------------------------------------------

# /proc/net/route can expose just one leg of a multipath default.
if [ "$recheck_bootstrap_wan" = 1 ]; then
    check_bootstrap_wan
fi

step "Разворачиваю netOS"

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

    # /tmp is commonly a small tmpfs on routers. Keeping the downloaded Go
    # toolchain, module cache and compiler work tree there can exhaust it even
    # when the persistent filesystem has several gigabytes free. Source builds
    # are sizeable and non-secret, so use the disk-backed /var/tmp and point
    # Go/npm temporary files into the same transaction-owned directory.
    SRC=$(mktemp -d /var/tmp/netos-source.XXXXXX)
    install -d -m 0700 "$SRC/tmp"
    fetch_release_source "$SRC/netos"
    GO_VERSION="1.27.0"
    GO_ARCHIVE="$SRC/go.tar.gz"
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    info "загружаю Go $GO_VERSION"
    curl -4 -fsSL --retry 3 -o "$GO_ARCHIVE" "$GO_URL" \
        || die "не удалось загрузить Go $GO_VERSION"
    # go.dev publishes checksums in its signed release catalog, not beside
    # archives as <archive>.sha256 (that URL is an HTML page). Node is already
    # a source-build dependency, so parse the official JSON without adding jq.
    EXPECTED=$(curl -4 -fsSL --retry 3 'https://go.dev/dl/?mode=json&include=all' | \
        node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const n=process.argv[1];for(const r of JSON.parse(s))for(const f of r.files||[])if(f.filename===n){process.stdout.write(f.sha256||"");return}})' \
        "go${GO_VERSION}.linux-${GOARCH}.tar.gz") \
        || die "не удалось получить контрольную сумму Go $GO_VERSION"
    printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-fA-F]{64}$' \
        || die "контрольная сумма Go $GO_VERSION отсутствует в каталоге go.dev"
    ACTUAL=$(sha256sum "$GO_ARCHIVE" | awk '{print $1}')
    [ "$(printf '%s' "$EXPECTED" | tr '[:upper:]' '[:lower:]')" = "$ACTUAL" ] \
        || die "контрольная сумма Go не совпадает"
    tar -C "$SRC" -xzf "$GO_ARCHIVE" || die "не удалось распаковать Go"

    CANDIDATE="$SRC/netosd"
    (
        export TMPDIR="$SRC/tmp"
        # Transient systemd maintenance jobs may have no HOME. Keep build
        # and module caches in this transaction's private directory so Go
        # and npm work without a login environment and cleanup removes them.
        export GOPATH="$SRC/gopath"
        export GOMODCACHE="$SRC/gopath/pkg/mod"
        export GOCACHE="$SRC/go-cache"
        export npm_config_cache="$SRC/npm-cache"
        cd "$SRC/netos/web" || exit 1
        npm ci || exit 1
        npm run build || exit 1
        cd ../backend || exit 1
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
    EXPECTED=$(awk 'NR == 1 && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ {print tolower($1)}' "$TMP.sha256")
    [ -n "$EXPECTED" ] || die "файл контрольной суммы имеет неверный формат"
    ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || die "контрольная сумма не совпадает — загрузка повреждена"
    ok "контрольная сумма проверена"

    CANDIDATE="$TMP"
fi

snapshot_path "$BIN_PATH" binary
snapshot_path "$CLI_PATH" cli
snapshot_path /etc/systemd/system/netosd.service unit
snapshot_path /etc/bash_completion.d/netos completion
snapshot_path /usr/share/bash-completion/completions/netos completion-lazy
systemctl is-enabled --quiet netosd && PREVIOUS_ENABLED=1 || true
if [ "$UPGRADE" = 1 ]; then
    active_state=$(systemctl show netosd --property=ActiveState --value) || die "не удалось определить состояние netosd"
    case "$active_state" in
        active|activating|reloading|refreshing) PREVIOUS_ACTIVE=1 ;;
        inactive|failed|deactivating) ;;
        *) die "неизвестное состояние netosd: $active_state" ;;
    esac
    if [ "$PREVIOUS_ACTIVE" = 1 ] || [ "$active_state" = deactivating ]; then
        ROLLBACK_ARMED=stopping
        systemctl stop netosd || die "не удалось остановить netosd перед копированием состояния"
    fi
else
    systemctl is-active --quiet netosd && PREVIOUS_ACTIVE=1 || true
fi
snapshot_path "$STATE_DIR" state-dir
snapshot_path "$CONF_DIR" conf-dir
snapshot_path "$LOG_DIR" log-dir
snapshot_path "$BASELINE_DIR" baseline-dir
ROLLBACK_ARMED=1

install -d -m 0700 "$STATE_DIR"
install -d -m 0755 "$STATE_DIR/generated" "$CONF_DIR" "$LOG_DIR"
install -d -m 0700 "$CONF_DIR/tls"
if [ "$UPGRADE" = "0" ]; then
    install -d -m 0700 "$BASELINE_DIR"
    : > "$BASELINE_DIR/.capture-required"
    chmod 0600 "$BASELINE_DIR/.capture-required"
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
install -d -m 0755 /etc/bash_completion.d /usr/share/bash-completion/completions
if "$CLI_PATH" completion bash > /etc/bash_completion.d/netos 2>/dev/null; then
    chmod 0644 /etc/bash_completion.d/netos
    # bash-completion ищет этот файл при первом Tab даже в уже открытой
    # оболочке. compatdir выше перечитывается лишь при загрузке framework.
    install -m 0644 /etc/bash_completion.d/netos /usr/share/bash-completion/completions/netos
    ok "дополнение команд установлено для загрузки по Tab"
else
    rm -f /etc/bash_completion.d/netos
    rm -f /usr/share/bash-completion/completions/netos
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
# свежий marker: daemon пишет его после Apply, запуска TLS listener и
# собственного HTTPS probe. Для v0.06 выше проверяется принадлежащий netosd
# HTTPS listener после синхронного Apply. 360 секунд покрывают ACME HTTP-01.
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
    PANEL_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk 'NR == 1 {split($4, addr, "/"); print addr[1]}')
    [ -n "$PANEL_IP" ] || PANEL_IP=$(hostname)
    echo "  Панель: ${B}https://${PANEL_IP}:${PANEL_PORT}${R}"
else
    echo "  ${GREEN}netOS установлен${R}"
    echo
    if [ -r "$CREDS_FILE" ]; then
        sed 's/^/  /' "$CREDS_FILE"
    else
        warn "файл с учётными данными не найден"
        info "проверьте ошибки запуска командой: journalctl -u netosd"
    fi
    echo
    echo "  ${D}Сертификат самоподписанный — браузер предупредит об этом.${R}"
    echo
    echo "  ${D}Установлены только панель и доступ по SSH. DHCP, DNS, VPN и${R}"
    echo "  ${D}остальное включаются в панели, в разделе «Компоненты».${R}"
fi
echo "${B}============================================================${R}"
echo
info "Управление:   netos help; список команд — netos <пробел><Tab><Tab>"
info "Если Tab в текущем Bash ещё не работает, выполните:"
info "  source /etc/bash_completion.d/netos"
info "Обновление:   sudo netos update"
info "Состояние:    netos status"
info "Журнал:       netos logs -f"
echo
} 9>&-
