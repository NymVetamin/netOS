package channels

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// tcpConfirmWindow — сколько ждать после установленного соединения, прежде чем
// признать его рабочим.
//
// Окно намеренно короткое: молчащая исправная служба ничего не пришлёт никогда,
// и ждать её нечего. Ловим здесь другое — соединение, закрытое сразу после
// установки.
const tcpConfirmWindow = 200 * time.Millisecond

// confirmTCPHandshake отличает установленное соединение от установленного и тут
// же разорванного.
//
// Через TUN канала (Xray) трёхстороннее рукопожатие завершает локальный стек:
// он принимает SYN до того, как узнает, доступна ли удалённая сторона. Успешный
// connect поэтому не доказывал ничего, и остановленная удалённая цель не
// переводила канал в down — проверка живости молча считала его исправным.
// Обрыв удалённой стороны такой стек отражает закрытием локального соединения,
// и вот его мы и ждём.
//
// Полной проверки удалённой доступности это не даёт: цель, которая приняла
// соединение и молчит, неотличима от цели, до которой соединение только
// строится. Для таких случаев в настройках канала есть проверки ICMP и HTTP.
func confirmTCPHandshake(conn net.Conn, timeout time.Duration) error {
	defer conn.Close()

	window := tcpConfirmWindow
	if timeout > 0 && timeout < window {
		window = timeout
	}
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		return nil // дедлайн не поставить — довольствуемся фактом соединения
	}
	var buf [1]byte
	_, err := conn.Read(buf[:])
	switch {
	case err == nil:
		return nil // удалённая сторона ответила сама — она точно жива
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil // молчит, но соединение держит: так ведёт себя исправная служба
	case errors.Is(err, io.EOF):
		return fmt.Errorf("соединение с %s закрыто сразу после установки: удалённая сторона недоступна", conn.RemoteAddr())
	default:
		return fmt.Errorf("соединение с %s разорвано сразу после установки: %w", conn.RemoteAddr(), err)
	}
}
