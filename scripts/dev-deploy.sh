#!/bin/bash
# Разработческий цикл: залить исходники на тестовую машину, собрать, вернуть
# обновлённые go.mod и go.sum обратно в репозиторий.
#
# Возврат файлов модулей обязателен: зависимости добавляются командой go get на
# машине сборки, и без обратной синхронизации следующая заливка затрёт их
# старой версией из репозитория.
set -e

HOST="${NETOS_HOST:-netos}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO"

# Фронтенд собирается до заливки: vite кладёт результат в backend/internal/api/webdist,
# откуда его встраивает go:embed. Без этого шага на машину уезжает
# панель от прошлой сборки, а правки в web/src молча теряются.
if [ "${NETOS_SKIP_WEB:-0}" != "1" ]; then
    echo "→ собираю фронтенд"
    ( cd web && npm run build >/dev/null ) || { echo "   СБОРКА ФРОНТЕНДА НЕ УДАЛАСЬ"; exit 1; }
fi

echo "→ заливаю исходники на $HOST"
tar czf - --exclude='.git' --exclude='node_modules' --exclude='web/dist' . \
    | ssh "$HOST" 'mkdir -p /opt/netos && tar xzf - -C /opt/netos'

echo "→ разрешаю зависимости"
ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && go mod tidy 2>&1 | grep -v "^go: downloading" || true'

echo "→ возвращаю go.mod и go.sum"
ssh "$HOST" 'cat /opt/netos/backend/go.mod' > backend/go.mod
ssh "$HOST" 'cat /opt/netos/backend/go.sum' > backend/go.sum

echo "→ сборка"
if ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && go build -ldflags "-X main.version=dev" -o /usr/local/bin/netosd.new ./cmd/netosd && mv -f /usr/local/bin/netosd.new /usr/local/bin/netosd && ln -sfn /usr/local/bin/netosd /usr/local/bin/netos'; then
    ssh "$HOST" 'echo "   собран netosd: $(ls -lh /usr/local/bin/netosd | awk "{print \$5}")"'
else
    echo "   СБОРКА НЕ УДАЛАСЬ"
    exit 1
fi

if [[ " $* " == *" --restart "* ]]; then
    echo "→ перезапуск netosd"
    ssh "$HOST" 'systemctl restart netosd && sleep 3 && systemctl is-active netosd'
fi

if [[ " $* " == *" --vet "* ]]; then
    echo "→ go vet"
    ssh "$HOST" 'export PATH="/usr/local/go/bin:$PATH"; cd /opt/netos/backend && go vet ./...' && echo "   чисто"
fi
