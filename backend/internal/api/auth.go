package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Параметры Argon2id. Подобраны так, чтобы проверка пароля занимала заметное
// время даже на слабом процессоре роутера, но не мешала входу.
const (
	argonTime        = 2
	argonMemory      = 64 * 1024 // 64 МБ
	argonThreads     = 2
	argonKeyLen      = 32
	saltLen          = 16
	maxPasswordBytes = 1024
	maxArgonMemory   = 128 * 1024

	sessionTTL    = 12 * time.Hour
	sessionCookie = "netos_session"
	csrfHeader    = "X-NetOS-CSRF"
)

// HashPassword возвращает строку вида
// $argon2id$v=19$m=65536,t=2,p=2$<соль>$<хэш>, самодостаточную для проверки:
// параметры хранятся вместе с хэшем, поэтому их можно менять без миграции.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword сравнивает пароль с сохранённым хэшем за постоянное время.
func VerifyPassword(password, encoded string) bool {
	if len(password) > maxPasswordBytes {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}

	var memory uint32
	var timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false
	}
	// The parameters are stored in the database. Treat a restored or corrupted
	// database as untrusted: otherwise one login could request gigabytes of RAM.
	if memory < 8*1024 || memory > maxArgonMemory || timeCost < 1 || timeCost > 10 || threads < 1 || threads > 16 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateToken возвращает криптостойкий случайный токен для сессии или CSRF.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GeneratePassword создаёт пароль для учётной записи администратора при
// установке. Алфавит без символов, которые легко перепутать при чтении с
// экрана консоли: ноль и O, единица, l и I.
func GeneratePassword(length int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out), nil
}
