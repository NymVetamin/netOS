package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

// resolvRunner изображает systemctl и запоминает, что ему велели сделать.
type resolvRunner struct {
	commands []string
	// active и enabled — состояние systemd-resolved до вмешательства netOS.
	active  bool
	enabled bool
}

func (r *resolvRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	command := name + " " + strings.Join(args, " ")
	switch {
	case strings.HasPrefix(command, "systemctl is-active systemd-resolved"):
		if r.active {
			return "active\n", nil
		}
		return "inactive\n", nil
	case strings.HasPrefix(command, "systemctl is-enabled systemd-resolved"):
		if r.enabled {
			return "enabled\n", nil
		}
		return "disabled\n", nil
	}
	r.commands = append(r.commands, command)
	switch {
	case strings.HasPrefix(command, "systemctl stop"):
		r.active = false
	case strings.HasPrefix(command, "systemctl disable"):
		r.enabled = false
	case strings.HasPrefix(command, "systemctl enable --now"):
		r.active, r.enabled = true, true
	}
	return "", nil
}

func (r *resolvRunner) RunInput(ctx context.Context, _ string, name string, args ...string) (string, error) {
	return r.Run(ctx, name, args...)
}

func (r *resolvRunner) did(prefix string) bool {
	for _, c := range r.commands {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// resolvFixture готовит корень с симлинком на systemd-resolved — ровно то, что
// netOS застаёт на облачном образе Debian.
func resolvFixture(t *testing.T, r *resolvRunner) (*SystemResolver, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib/netos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../run/systemd/resolve/stub-resolv.conf", filepath.Join(root, "etc/resolv.conf")); err != nil {
		t.Skipf("симлинки в этой среде недоступны: %v", err)
	}
	u := NewSystemResolver(r)
	u.Root = root
	return u, root
}

func resolvConfig() *config.Config {
	cfg := config.Default()
	cfg.DNS.Enabled, cfg.DNS.Provider, cfg.DNS.Port = true, "unbound", 53
	return cfg
}

// Роутер обязан спрашивать имена у резолвера, который выбран в панели. Пока
// /etc/resolv.conf указывает на systemd-resolved, машина ходит наружу мимо
// шифрования, фильтров и локальной зоны.
func TestSystemResolverTakesOverResolvConf(t *testing.T) {
	r := &resolvRunner{active: true, enabled: true}
	u, root := resolvFixture(t, r)

	if err := u.Apply(context.Background(), resolvConfig()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(root, "etc/resolv.conf")
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("resolv.conf остался симлинком на systemd-resolved")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "nameserver 127.0.0.1") {
		t.Fatalf("роутер не отправлен к своему резолверу:\n%s", content)
	}
	if !r.did("systemctl stop systemd-resolved.service") {
		t.Fatalf("systemd-resolved остался работать: %v", r.commands)
	}
}

// Повторное применение не должно ни переписывать файл, ни трогать systemd:
// применение конфигурации идёт при каждом изменении любой её части.
func TestSystemResolverIsIdempotent(t *testing.T) {
	r := &resolvRunner{active: true, enabled: true}
	u, root := resolvFixture(t, r)
	cfg := resolvConfig()

	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "etc/resolv.conf")
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	r.commands = nil
	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	second, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Error("файл переписан, хотя не менялся")
	}
	if r.did("systemctl disable") || r.did("systemctl stop") {
		t.Errorf("погашенный systemd-resolved гасили повторно: %v", r.commands)
	}
}

// Выключенный в панели резолвер означает, что netOS больше не владеет именами
// машины: файл и systemd-resolved возвращаются в исходное состояние.
func TestSystemResolverGivesResolvConfBack(t *testing.T) {
	r := &resolvRunner{active: true, enabled: true}
	u, root := resolvFixture(t, r)

	if err := u.Apply(context.Background(), resolvConfig()); err != nil {
		t.Fatal(err)
	}
	off := resolvConfig()
	off.DNS.Enabled = false
	if err := u.Apply(context.Background(), off); err != nil {
		t.Fatal(err)
	}

	target, err := os.Readlink(filepath.Join(root, "etc/resolv.conf"))
	if err != nil {
		t.Fatalf("симлинк не восстановлен: %v", err)
	}
	if target != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("восстановлена не та цель: %s", target)
	}
	if !r.did("systemctl enable --now systemd-resolved.service") {
		t.Errorf("systemd-resolved не возвращён системе: %v", r.commands)
	}
	if _, err := os.Stat(filepath.Join(root, resolvStatePath)); !os.IsNotExist(err) {
		t.Error("память об исходном состоянии осталась на диске")
	}
}

// Выключенный до netOS systemd-resolved включать обратно нельзя: удаление
// обязано вернуть машину такой, какой она была, а не такой, как принято.
func TestSystemResolverDoesNotReviveDisabledResolved(t *testing.T) {
	r := &resolvRunner{active: false, enabled: false}
	u, _ := resolvFixture(t, r)

	if err := u.Apply(context.Background(), resolvConfig()); err != nil {
		t.Fatal(err)
	}
	off := resolvConfig()
	off.DNS.Enabled = false
	if err := u.Apply(context.Background(), off); err != nil {
		t.Fatal(err)
	}
	if r.did("systemctl enable --now systemd-resolved.service") {
		t.Errorf("включили то, что не работало и до netOS: %v", r.commands)
	}
}

// Порт, отличный от 53, в /etc/resolv.conf выразить нечем. Забирать файл в
// этом случае — оставить машину без имён: указать там можно только адрес.
func TestSystemResolverLeavesResolvConfOnNonStandardPort(t *testing.T) {
	r := &resolvRunner{active: true, enabled: true}
	u, root := resolvFixture(t, r)

	cfg := resolvConfig()
	cfg.DNS.Port = 5353
	if err := u.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(filepath.Join(root, "etc/resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("файл забрали, хотя резолвер недоступен на 53")
	}
	if r.did("systemctl stop systemd-resolved.service") {
		t.Errorf("остановили единственный работающий резолвер машины: %v", r.commands)
	}
}
