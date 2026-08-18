#!/bin/bash
#
# Установщик netOS.
#
#   curl -fsSL https://raw.githubusercontent.com/netos-router/netos/main/install.sh | sudo bash
#
# Скрипт ставит зависимости, разворачивает демон, определяет сетевые
# интерфейсы и печатает адрес панели с учётными данными.
#
# Переменные окружения:
#   NETOS_VERSION      версия релиза (по умолчанию latest)
#   NETOS_BINARY_URL   прямая ссылка на бинарник вместо GitHub Releases
#   NETOS_FROM_SOURCE  1 — собрать из исходников вместо загрузки релиза
#   NETOS_PORT         порт веб-панели (по умолчанию 8443)

set -euo pipefail

REPO="netos-router/netos"
VERSION="${NETOS_VERSION:-latest}"
PORT="${NETOS_PORT:-8443}"

BIN_PATH="/usr/local/bin/netosd"
STATE_DIR="/var/lib/netos"
CONF_DIR="/etc/netos"
LOG_DIR="/var/log/netos"

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

if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}${ID_LIKE:-}" in
        *debian*|*ubuntu*) : ;;
        *) warn "система ${PRETTY_NAME:-неизвестна}, netOS рассчитан на Debian — продолжаю на свой страх" ;;
    esac
    info "Система: ${PRETTY_NAME:-неизвестна}"
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

if systemctl is-active --quiet netosd 2>/dev/null; then
    warn "netOS уже запущен — будет обновлён, конфигурация сохранится"
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

    git clone --depth 1 "https://github.com/$REPO.git" "$SRC/netos" >/dev/null 2>&1 \
        || die "не удалось получить исходники"
    (
        cd "$SRC/netos/backend"
        # Основное зеркало модулей Go доступно не из всех сетей, поэтому
        # заранее указываем запасное.
        cd ../web
        npm ci
        npm run build
        cd ../backend
        GOPROXY="https://proxy.golang.org,https://goproxy.io,direct" \
            "$SRC/go/bin/go" build -trimpath -ldflags "-s -w" -o "$BIN_PATH" ./cmd/netosd
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

    install -m 0755 "$TMP" "$BIN_PATH"
    ok "бинарник установлен"
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

systemctl restart netosd

for _ in $(seq 1 30); do
    if systemctl is-active --quiet netosd; then break; fi
    sleep 1
done

systemctl is-active --quiet netosd || {
    echo
    journalctl -u netosd --no-pager -n 30
    die "служба не запустилась, журнал выше"
}
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
info "Журнал:      journalctl -u netosd -f"
info "Состояние:   systemctl status netosd"
info "Диагностика: netosd -plan"
echo
