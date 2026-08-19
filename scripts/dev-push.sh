#!/bin/bash
# Залить текущее дерево на тестовую машину, не выпуская релиз.
#
#   ./scripts/dev-push.sh              собрать и залить
#   ./scripts/dev-push.sh --logs       и показать журнал после запуска
#
# Отличие от dev-deploy.sh: тот заливает исходники и собирает их на самой
# машине, а значит требует установленного там Go. Роутеру компилятор не нужен,
# и на минимальной установке его нет — этот скрипт кладёт готовый бинарник.
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

if command -v go >/dev/null 2>&1; then
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

echo "→ заливаю на $HOST"
# Исполняемый файл нельзя перезаписывать на месте: ядро вернёт ETXTBSY на
# работающем демоне. Кладём рядом и переименовываем.
scp -q "$BINARY" "$HOST:/usr/local/bin/netosd.new"
ssh "$HOST" 'chmod 755 /usr/local/bin/netosd.new \
    && mv -f /usr/local/bin/netosd.new /usr/local/bin/netosd \
    && ln -sfn /usr/local/bin/netosd /usr/local/bin/netos \
    && netos completion bash > /etc/bash_completion.d/netos \
    && systemctl restart netosd'

# Служба поднимается не мгновенно: сначала применяется вся конфигурация.
# Проверяем, что она осталась живой, а не упала через секунду после старта.
echo "→ проверяю службу"
if ssh "$HOST" 'sleep 3; systemctl is-active --quiet netosd'; then
    ssh "$HOST" 'echo "   работает: $(netos version)"'
else
    echo "   СЛУЖБА НЕ ПОДНЯЛАСЬ"
    ssh "$HOST" 'journalctl -u netosd --no-pager -n 30'
    exit 1
fi

if [ "$SHOW_LOGS" = "1" ]; then
    ssh "$HOST" 'journalctl -u netosd --no-pager -n 40'
fi
