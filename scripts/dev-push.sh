#!/bin/bash
# Доставить на стенд готовый бинарник текущей ревизии, не выпуская релиз.
#
#   ./scripts/dev-push.sh              собрать и залить
#   ./scripts/dev-push.sh --logs       и показать журнал после запуска
#
# Исходники и инструменты сборки на стенд не передаются. Фронтенд и netosd
# собираются на машине разработчика либо в CI; роутер получает только бинарник.
#
# Откуда берётся бинарник, решается по обстановке:
#
#   1. Есть локальный Go — кросс-сборка под linux/amd64 прямо здесь. Самый
#      быстрый круг: секунды на сборку, секунды на заливку.
#   2. Go нет — берётся артефакт последней сборки CI для текущей ветки.
#      Компилятор при этом не нужен нигде, но ждать приходится саму CI.
#
# Переменные окружения:
#   NETOS_HOST   имя хоста из ~/.ssh/config (по умолчанию netos)
#   NETOS_ARCH   архитектура машины: amd64 (по умолчанию) или arm64
#   NETOS_BINARY_FILE готовый Linux-бинарник; локальная сборка тогда пропускается

set -euo pipefail

HOST="${NETOS_HOST:-netos}"
ARCH="${NETOS_ARCH:-amd64}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHOW_LOGS=0
for arg in "$@"; do
    case "$arg" in
        --logs) SHOW_LOGS=1 ;;
        *) echo "неизвестный параметр: $arg" >&2; exit 1 ;;
    esac
done

cd "$REPO"

# Фронтенд собирается всегда и первым: vite кладёт результат в
# backend/internal/api/webdist, откуда его встраивает go:embed. Без этого шага
# на машину уезжает панель от прошлой сборки, а правки в web/src молча теряются.
if [ "${NETOS_SKIP_WEB:-0}" != "1" ]; then
    echo "→ собираю фронтенд"
    ( cd web && npm run build >/dev/null ) || { echo "   СБОРКА ФРОНТЕНДА НЕ УДАЛАСЬ"; exit 1; }
fi

BINARY="$(mktemp -t netosd.XXXXXX)"
trap 'rm -f "$BINARY"' EXIT

if [ -n "${NETOS_BINARY_FILE:-}" ]; then
    [ -f "$NETOS_BINARY_FILE" ] || {
        echo "   готовый бинарник не найден: $NETOS_BINARY_FILE" >&2; exit 1; }
    cp "$NETOS_BINARY_FILE" "$BINARY"
elif command -v go >/dev/null 2>&1; then
    echo "→ собираю netosd под linux/$ARCH"
    # CGO выключён: sqlite взят в чистой реализации на Go, поэтому бинарник
    # получается статическим и кросс-сборка с любой системы работает как есть.
    ( cd backend && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        go build -trimpath -ldflags "-X main.version=dev" -o "$BINARY" ./cmd/netosd )
else
    echo "→ локального Go нет, беру бинарник из сборки CI"
    command -v gh >/dev/null 2>&1 || {
        echo "   нужен либо Go, либо gh для загрузки артефакта CI" >&2; exit 1; }

    BRANCH="$(git rev-parse --abbrev-ref HEAD)"
    RUN=$(gh run list --workflow=ci.yml --branch "$BRANCH" --limit 1 \
        --json databaseId,status,conclusion,headSha \
        -q '.[0] | select(.status=="completed" and .conclusion=="success") | .databaseId')
    [ -n "${RUN:-}" ] || {
        echo "   нет успешной сборки CI для ветки $BRANCH — запушьте изменения и дождитесь её" >&2
        exit 1; }

    TMPDIR_ART="$(mktemp -d)"
    trap 'rm -f "$BINARY"; rm -rf "$TMPDIR_ART"' EXIT
    gh run download "$RUN" --name "netosd-linux-$ARCH" --dir "$TMPDIR_ART" >/dev/null || {
        echo "   в сборке $RUN нет артефакта netosd-linux-$ARCH" >&2; exit 1; }
    cp "$TMPDIR_ART/netosd-linux-$ARCH" "$BINARY"
fi

CANDIDATE_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
if ! printf '%s\n' "$CANDIDATE_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "   не удалось вычислить SHA-256 кандидата" >&2
    exit 1
fi

echo "→ заливаю на $HOST"
# Исполняемый файл нельзя перезаписывать на месте: ядро вернёт ETXTBSY на
# работающем демоне. Кладём рядом и переименовываем.
scp -q "$BINARY" "$HOST:/usr/local/bin/netosd.new"
echo "→ проверяю службу"
ssh "$HOST" "NETOS_EXPECTED_SHA=$CANDIDATE_SHA bash -s" <<'REMOTE_DEPLOY'
set -u

BIN_PATH=/usr/local/bin/netosd
CLI_PATH=/usr/local/bin/netos
COMPLETION_PATH=/etc/bash_completion.d/netos
READY_PATH=/run/netosd.ready
EXPECTED_SHA=${NETOS_EXPECTED_SHA:?candidate SHA-256 is required}
TXN=$(mktemp -d) || { echo "не удалось создать deploy transaction" >&2; exit 1; }
DEPLOY_OK=0

cleanup() {
    rm -f -- "$BIN_PATH.new"
    rm -rf -- "$TXN"
}
trap cleanup EXIT

snapshot_path() {
    snapshot_source=$1
    snapshot_label=$2
    if [ -e "$snapshot_source" ] || [ -L "$snapshot_source" ]; then
        cp -a -- "$snapshot_source" "$TXN/$snapshot_label"
    else
        : > "$TXN/$snapshot_label.absent"
    fi
}

restore_path() {
    restore_target=$1
    restore_label=$2
    rm -rf -- "$restore_target"
    if [ ! -f "$TXN/$restore_label.absent" ]; then
        cp -a -- "$TXN/$restore_label" "$restore_target"
    fi
}

wait_ready() {
    ready_count=0
    while [ "$ready_count" -lt 360 ]; do
        if systemctl is-active --quiet netosd && [ -s "$READY_PATH" ]; then
            return 0
        fi
        unit_result=$(systemctl show netosd -p Result --value 2>/dev/null || true)
        unit_restarts=$(systemctl show netosd -p NRestarts --value 2>/dev/null || true)
        case "$unit_restarts" in ''|*[!0-9]*) unit_restarts=0 ;; esac
        if [ "$unit_result" = "exit-code" ] || [ "$unit_result" = "signal" ] \
            || [ "$unit_result" = "core-dump" ] || [ "$unit_restarts" -gt 0 ]; then
            echo "netosd завершился до готовности: Result=$unit_result NRestarts=$unit_restarts" >&2
            return 1
        fi
        ready_count=$((ready_count + 1))
        sleep 1
    done
    return 1
}

verify_binary() {
    actual_sha=$(sha256sum "$BIN_PATH" 2>/dev/null | awk '{print $1}')
    if [ "$actual_sha" != "$EXPECTED_SHA" ]; then
        echo "SHA-256 активного binary не совпал: ожидался $EXPECTED_SHA, получен ${actual_sha:-отсутствует}" >&2
        return 1
    fi
}

verify_plan() {
    plan_output=$("$CLI_PATH" plan 2>&1) || {
        printf '%s\n' "$plan_output" >&2
        return 1
    }
    printf '%s\n' "$plan_output"
    printf '%s\n' "$plan_output" | grep -Fq 'Живая система соответствует конфигурации: применять нечего.'
}

if ! snapshot_path "$BIN_PATH" binary \
    || ! snapshot_path "$CLI_PATH" cli \
    || ! snapshot_path "$COMPLETION_PATH" completion
then
    echo "не удалось сохранить предыдущие deploy-файлы" >&2
    exit 1
fi

chmod 0755 "$BIN_PATH.new" \
    && mv -f "$BIN_PATH.new" "$BIN_PATH" \
    && ln -sfn "$BIN_PATH" "$CLI_PATH" \
    && "$CLI_PATH" completion bash > "$COMPLETION_PATH.new" \
    && chmod 0644 "$COMPLETION_PATH.new" \
    && mv -f "$COMPLETION_PATH.new" "$COMPLETION_PATH" \
    && rm -f "$READY_PATH" \
    && verify_binary \
    && systemctl reset-failed netosd \
    && systemctl restart netosd \
    && wait_ready \
    && verify_binary \
    && verify_plan \
    && DEPLOY_OK=1

if [ "$DEPLOY_OK" = "1" ]; then
    echo "   работает: $($CLI_PATH version)"
    exit 0
fi

echo "   НОВАЯ ВЕРСИЯ НЕ ПОДТВЕРДИЛА ГОТОВНОСТЬ" >&2
journalctl -u netosd --no-pager -n 40 >&2
systemctl stop netosd >/dev/null 2>&1 || true
RESTORE_OK=1
restore_path "$BIN_PATH" binary || RESTORE_OK=0
restore_path "$CLI_PATH" cli || RESTORE_OK=0
restore_path "$COMPLETION_PATH" completion || RESTORE_OK=0
rm -f "$COMPLETION_PATH.new" "$READY_PATH"
systemctl reset-failed netosd >/dev/null 2>&1 || true
if [ "$RESTORE_OK" = "1" ] && systemctl restart netosd >/dev/null 2>&1 && wait_ready && verify_plan; then
    echo "   предыдущая версия восстановлена: $($CLI_PATH version)" >&2
else
    echo "   предыдущие файлы восстановлены, но готовность службы не подтверждена" >&2
    journalctl -u netosd --no-pager -n 40 >&2
fi
exit 1
REMOTE_DEPLOY

ssh "$HOST" 'systemctl --failed --no-legend --plain; echo "   ready revision: $(cat /run/netosd.ready)"'

if [ "$SHOW_LOGS" = "1" ]; then
    ssh "$HOST" 'journalctl -u netosd --no-pager -n 40'
fi
