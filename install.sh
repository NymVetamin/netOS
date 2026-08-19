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

BIN_PATH="/usr/local/bin/netosd"
CLI_PATH="/usr/local/bin/netos"
STATE_DIR="/var/lib/netos"
CONF_DIR="/etc/netos"
LOG_DIR="/var/log/netos"

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

# Базовая установка ставит только то, без чего не поднимется сам роутер и
# панель. DHCP-сервер, резолверы, VPN и точка доступа — это компоненты,
# которые администратор выбирает в панели уже после установки.
PACKAGES="iptables iproute2 ca-certificates curl busybox"
if [ "${NETOS_FROM_SOURCE:-0}" = "1" ]; then
    PACKAGES="$PACKAGES git nodejs npm"
fi

apt-get update -qq 2>/dev/null || warn "не удалось обновить списки пакетов, пробую продолжить"
if apt-get install -y -qq $PACKAGES >/dev/null 2>&1; then
    ok "пакеты установлены"
else
    die "не удалось установить пакеты: $PACKAGES"
fi

# --- бинарник ----------------------------------------------------------------

step "Разворачиваю netOS"

install -d -m 0700 "$STATE_DIR"
install -d -m 0755 "$STATE_DIR/generated" "$CONF_DIR" "$LOG_DIR"
install -d -m 0700 "$CONF_DIR/tls"

if [ "${NETOS_FROM_SOURCE:-0}" = "1" ]; then
    info "сборка из исходников"
    command -v git >/dev/null 2>&1 || die "для сборки из исходников нужен git"

    SRC=$(mktemp -d)
    trap 'rm -rf "$SRC"' EXIT
    GO_VERSION="1.25.0"
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
        cd "$SRC/netos/backend"
        # Основное зеркало модулей Go доступно не из всех сетей, поэтому
        # заранее указываем запасное.
        cd ../web
        npm ci
        npm run build
        cd ../backend
        GOPROXY="https://proxy.golang.org,https://goproxy.io,direct" \
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
    trap 'rm -f "$TMP"' EXIT
    if ! curl -4 -fsSL --retry 3 --retry-delay 2 -o "$TMP" "$URL"; then
        die "не удалось загрузить бинарник. Соберите из исходников: NETOS_FROM_SOURCE=1 $0"
    fi

    # Контрольная сумма публикуется рядом с бинарником. Её отсутствие не
    # блокирует установку, но о непроверенной загрузке предупреждаем.
    if curl -4 -fsSL --retry 2 -o "$TMP.sha256" "$URL.sha256" 2>/dev/null; then
        EXPECTED=$(awk '{print $1}' "$TMP.sha256")
        ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
        [ "$EXPECTED" = "$ACTUAL" ] || die "контрольная сумма не совпадает — загрузка повреждена"
        ok "контрольная сумма проверена"
    else
        warn "контрольная сумма недоступна, пропускаю проверку"
    fi

    CANDIDATE="$TMP"
fi

# Нельзя перезаписывать исполняемый файл на месте: при обновлении ядро может
# вернуть ETXTBSY. Новый файл кладётся рядом и атомарно переименовывается.
if [ "$UPGRADE" = "1" ] && [ -x "$BIN_PATH" ]; then
    cp -p "$BIN_PATH" "$STATE_DIR/netosd.previous"
fi
install -m 0755 "$CANDIDATE" "$BIN_PATH.new"
mv -f "$BIN_PATH.new" "$BIN_PATH"
ln -sfn "$BIN_PATH" "$CLI_PATH"
ok "бинарник и команда netos установлены"

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
Restart=always
RestartSec=3
# Демон управляет сетевым стеком и запускает вспомогательные службы,
# поэтому изоляция ограничена тем, что не мешает работе.
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netosd >/dev/null 2>&1
ok "служба netosd зарегистрирована"

# --- запуск ------------------------------------------------------------------

step "Запускаю netOS"

START_OK=1
if ! systemctl restart netosd; then
    START_OK=0
fi

STABLE=0
for _ in $(seq 1 30); do
    if systemctl is-active --quiet netosd; then
        STABLE=$((STABLE + 1))
        [ "$STABLE" -ge 5 ] && break
    else
        STABLE=0
    fi
    sleep 1
done

if ! systemctl is-active --quiet netosd || [ "$STABLE" -lt 5 ]; then
    START_OK=0
fi
if [ "$START_OK" = "0" ]; then
    echo
    journalctl -u netosd --no-pager -n 30
    if [ -x "$STATE_DIR/netosd.previous" ]; then
        warn "новая версия не запустилась — возвращаю предыдущий бинарник"
        install -m 0755 "$STATE_DIR/netosd.previous" "$BIN_PATH.new"
        mv -f "$BIN_PATH.new" "$BIN_PATH"
        systemctl restart netosd || true
    fi
    die "служба не запустилась, журнал выше"
fi
rm -f "$STATE_DIR/netosd.previous"
ok "служба работает"

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
    PANEL_IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
    echo "  Панель: ${B}https://${PANEL_IP}:${PORT}${R}"
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
    echo "  ${D}Пароль нужно сменить при первом входе.${R}"
    echo "  ${D}Сертификат самоподписанный — браузер предупредит об этом.${R}"
    echo
    echo "  ${D}Установлены только панель и доступ по SSH. DHCP, DNS, VPN и${R}"
    echo "  ${D}остальное включаются в панели, в разделе «Компоненты».${R}"
fi
echo "${B}============================================================${R}"
echo
info "Управление:   netos help"
info "Обновление:   sudo netos update"
info "Состояние:    netos status"
info "Журнал:       netos logs -f"
echo
