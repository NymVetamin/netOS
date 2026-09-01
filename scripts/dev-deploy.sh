#!/bin/bash
# Разработческий цикл: залить исходники на тестовую машину, собрать, вернуть
# обновлённые go.mod и go.sum обратно в репозиторий.
#
# Возврат файлов модулей обязателен: зависимости добавляются командой go get на
# машине сборки, и без обратной синхронизации следующая заливка затрёт их
# старой версией из репозитория.
set -euo pipefail

HOST="${NETOS_HOST:-netos}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESTART=0
RUN_VET=0
for arg in "$@"; do
    case "$arg" in
        --restart) RESTART=1 ;;
        --vet) RUN_VET=1 ;;
        *) echo "неизвестный параметр: $arg" >&2; exit 1 ;;
    esac
done

cd "$REPO"

# Фронтенд собирается до заливки: vite кладёт результат в backend/internal/api/webdist,
# откуда его встраивает go:embed. Без этого шага на машину уезжает
# панель от прошлой сборки, а правки в web/src молча теряются.
if [ "${NETOS_SKIP_WEB:-0}" != "1" ]; then
    echo "→ собираю фронтенд"
    ( cd web && npm run build >/dev/null ) || { echo "   СБОРКА ФРОНТЕНДА НЕ УДАЛАСЬ"; exit 1; }
fi

echo "→ заливаю исходники на $HOST"
ssh "$HOST" 'rm -rf -- /opt/netos.upload && install -d -m 0755 /opt/netos.upload'
tar czf - --exclude='.git' --exclude='node_modules' --exclude='web/dist' \
    --exclude='output' --exclude='dist' --exclude='*.cov' --exclude='coverage*' \
    --exclude='*_cov' --exclude='*_coverage' --exclude='*_tests_linux' \
    --exclude='netosd_linux' . \
    | ssh "$HOST" 'tar xzf - -C /opt/netos.upload'
ssh "$HOST" 'rm -rf -- /opt/netos.previous; if [ -d /opt/netos ]; then mv /opt/netos /opt/netos.previous; fi; if mv /opt/netos.upload /opt/netos; then rm -rf -- /opt/netos.previous; else [ ! -d /opt/netos.previous ] || mv /opt/netos.previous /opt/netos; exit 1; fi'

echo "→ разрешаю зависимости"
ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && set -o pipefail && go mod tidy 2>&1 | sed "/^go: downloading/d"'

echo "→ возвращаю go.mod и go.sum"
ssh "$HOST" 'cat /opt/netos/backend/go.mod' > backend/go.mod
ssh "$HOST" 'cat /opt/netos/backend/go.sum' > backend/go.sum

echo "→ сборка"
if ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=dev" -o /opt/netos/netosd.candidate ./cmd/netosd'; then
    ssh "$HOST" 'echo "   собран кандидат: $(ls -lh /opt/netos/netosd.candidate | awk "{print \$5}")"'
else
    echo "   СБОРКА НЕ УДАЛАСЬ"
    exit 1
fi

if [ "$RUN_VET" = "1" ]; then
    echo "→ go vet"
    ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && go vet ./...' && echo "   чисто"
fi

if [ "$RESTART" = "1" ]; then
    CANDIDATE=$(mktemp -t netosd.remote.XXXXXX)
    trap 'rm -f "$CANDIDATE"' EXIT
    scp -q "$HOST:/opt/netos/netosd.candidate" "$CANDIDATE"
    echo "→ транзакционно активирую и проверяю netosd"
    NETOS_HOST="$HOST" NETOS_SKIP_WEB=1 NETOS_BINARY_FILE="$CANDIDATE" \
        "$REPO/scripts/dev-push.sh"
else
    echo "→ кандидат проверен сборкой, но не активирован; для deploy нужен --restart"
fi
