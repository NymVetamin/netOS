package samba

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"golang.org/x/crypto/md4"
)

type Subsystem struct {
	Runner            system.Runner
	StateDir, UnitDir string
	mu                sync.Mutex
	nextVPNRepair     time.Time
}

func New(r system.Runner, dir string) *Subsystem {
	return &Subsystem{Runner: r, StateDir: dir, UnitDir: "/etc/systemd/system"}
}
func (s *Subsystem) Name() string { return "samba" }
func (s *Subsystem) stamp(c *config.Config) []byte {
	host := ""
	if c.Samba.Enabled && c.Samba.Discovery && len(c.Samba.Networks) > 0 {
		host = c.System.Hostname
	}
	data, _ := json.Marshal(struct {
		Samba  config.Samba
		Access []Access
		Host   string
	}{c.Samba, Accesses(c), host})
	h := sha256.Sum256(data)
	return []byte(hex.EncodeToString(h[:]))
}
func (s *Subsystem) Plan(old, next *config.Config) ([]apply.Action, error) {
	return s.PlanContext(context.Background(), old, next)
}
func (s *Subsystem) PlanContext(ctx context.Context, old, next *config.Config) ([]apply.Action, error) {
	if !next.Samba.Enabled && len(next.Samba.Volumes) == 0 && (old == nil || (!old.Samba.Enabled && len(old.Samba.Volumes) == 0)) {
		if _, err := os.Stat(filepath.Join(s.StateDir, "samba")); os.IsNotExist(err) {
			return nil, nil
		}
	}
	if system.FileChanged(filepath.Join(s.StateDir, "samba", "applied"), s.stamp(next)) || s.Health(ctx, next) != nil {
		return []apply.Action{{Kind: "update", Target: "Диски и Samba", Detail: "тома, сетевые папки, пользователи и обнаружение", Disruptive: true}}, nil
	}
	return nil, nil
}
func (s *Subsystem) owned() ([]config.StorageVolume, error) {
	data, err := os.ReadFile(filepath.Join(s.StateDir, "samba", "volumes.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var v []config.StorageVolume
	err = json.Unmarshal(data, &v)
	return v, err
}
func (s *Subsystem) write(name string, data []byte, mode os.FileMode) (bool, error) {
	return system.WriteFileAtomicIfChanged(filepath.Join(s.StateDir, name), data, mode)
}
func (s *Subsystem) account(ctx context.Context, name string) (string, error) {
	// Never take ownership of an unrelated pre-existing Unix identity.
	out, err := s.Runner.Run(ctx, "getent", "passwd", name)
	if err != nil || strings.TrimSpace(out) == "" {
		if _, err = s.Runner.Run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", "netOS Samba", name); err != nil {
			return "", err
		}
		out, err = s.Runner.Run(ctx, "getent", "passwd", name)
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if err != nil || len(fields) != 7 || fields[0] != name || fields[4] != "netOS Samba" || fields[5] != "/nonexistent" || fields[6] != "/usr/sbin/nologin" {
		return "", fmt.Errorf("Unix account %s is not owned by netOS", name)
	}
	if _, err := strconv.ParseUint(fields[2], 10, 32); err != nil {
		return "", err
	}
	return fields[2], nil
}
func ntHash(password string) string {
	chars := utf16.Encode([]rune(password))
	raw := make([]byte, len(chars)*2)
	for i, v := range chars {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	h := md4.New()
	_, _ = h.Write(raw)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func (s *Subsystem) Apply(ctx context.Context, c *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.owned()
	if err != nil {
		return err
	}
	if !c.Samba.Enabled && len(c.Samba.Volumes) == 0 && len(old) == 0 {
		if _, err := os.Stat(filepath.Join(s.StateDir, "samba")); os.IsNotExist(err) {
			return nil
		}
	}
	sd := system.NewSystemd(s.Runner)
	var wanted []config.StorageVolume
	for _, v := range c.Samba.Volumes {
		if v.Enabled {
			wanted = append(wanted, v)
		}
	}
	for _, v := range wanted {
		known := false
		for _, o := range old {
			if o.ID == v.ID {
				known = true
			}
		}
		for _, ext := range []string{".mount", ".automount"} {
			p := filepath.Join(s.UnitDir, strings.TrimSuffix(mountUnit(v), ".mount")+ext)
			if info, e := os.Lstat(p); e == nil && (!known || !info.Mode().IsRegular()) {
				return fmt.Errorf("чужой артефакт накопителя: %s", p)
			} else if e != nil && !os.IsNotExist(e) {
				return e
			}
		}
		for _, p := range []string{"/srv", "/srv/netos", MountPath(v)} {
			if info, e := os.Lstat(p); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
				return fmt.Errorf("небезопасный каталог накопителя: %s", p)
			}
		}
	}
	if len(wanted) > 0 {
		devices, e := Devices(ctx, s.Runner)
		if e != nil {
			return e
		}
		for _, v := range wanted {
			for _, d := range devices {
				for _, m := range d.Mountpoints {
					if m == MountPath(v) && !strings.EqualFold(d.UUID, v.UUID) {
						return fmt.Errorf("в каталоге %s подключён другой том %s", m, d.UUID)
					}
				}
				if strings.EqualFold(d.UUID, v.UUID) {
					if !d.Available || d.Filesystem != v.Filesystem {
						return fmt.Errorf("том %s: %s (файловая система %s)", v.UUID, d.Reason, d.Filesystem)
					}
					for _, m := range d.Mountpoints {
						if m != "" && m != MountPath(v) {
							return fmt.Errorf("том %s уже подключён в %s", v.UUID, m)
						}
					}
				}
			}
		}
	}
	// Validate the new configuration before stopping the currently working
	// daemon or publishing its replacement. A failed testparm must leave the
	// active listener and configuration untouched.
	validatedConf := ""
	if c.Samba.Enabled {
		validatedConf, err = Render(c, s.StateDir)
		if err != nil {
			return err
		}
		// testparm resolves state/cache paths while validating the candidate.
		// They must exist on the first enable, before the daemon is touched.
		if err := os.MkdirAll(filepath.Join(s.StateDir, "samba"), 0700); err != nil {
			return err
		}
		if system.FileChanged(filepath.Join(s.StateDir, "samba.conf"), []byte(validatedConf)) {
			if err := os.MkdirAll(s.StateDir, 0700); err != nil {
				return err
			}
			pending, err := os.CreateTemp(s.StateDir, ".samba-validate-*")
			if err != nil {
				return err
			}
			defer os.Remove(pending.Name())
			if _, err = pending.WriteString(validatedConf); err != nil {
				_ = pending.Close()
				return err
			}
			if err = pending.Close(); err != nil {
				return err
			}
			if _, err = s.Runner.Run(ctx, "testparm", "--suppress-prompt", pending.Name()); err != nil {
				return fmt.Errorf("Samba config: %w", err)
			}
		}
	}
	changed := system.FileChanged(filepath.Join(s.StateDir, "samba", "applied"), s.stamp(c))
	if !reflect.DeepEqual(old, wanted) || !c.Samba.Enabled || changed {
		for _, u := range []string{"netos-wsdd.service", "netos-samba.service"} {
			if err := sd.Disable(ctx, u); err != nil {
				return err
			}
		}
	}
	for _, v := range old {
		keep := false
		for _, n := range wanted {
			if n == v {
				keep = true
			}
		}
		if !keep {
			if err := s.removeVolume(ctx, v); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(s.StateDir, "samba"), 0700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(s.StateDir, "samba"), 0700); err != nil {
		return err
	}
	uid := ""
	gid := ""
	if c.Samba.Enabled || len(wanted) > 0 {
		uid, err = s.account(ctx, "netos-storage")
		if err != nil {
			return err
		}
		group, e := s.Runner.Run(ctx, "id", "-g", "netos-storage")
		if e != nil {
			return e
		}
		gid = strings.TrimSpace(group)
		if _, e = strconv.ParseUint(gid, 10, 32); e != nil {
			return e
		}
	}
	// Record ownership before creating units so rollback can clean partial work.
	data, _ := json.Marshal(wanted)
	if _, err = s.write("samba/volumes.json", data, 0600); err != nil {
		return err
	}
	for _, v := range wanted {
		for ext, text := range map[string]string{".mount": mountText(v, uid, gid), ".automount": automountText(v)} {
			name := strings.TrimSuffix(mountUnit(v), ".mount") + ext
			if _, err = system.WriteFileAtomicIfChanged(filepath.Join(s.UnitDir, name), []byte(text), 0644); err != nil {
				return err
			}
		}
	}
	if len(old) > 0 || len(wanted) > 0 {
		if err := sd.DaemonReload(ctx); err != nil {
			return err
		}
	}
	for _, v := range wanted {
		auto := strings.TrimSuffix(mountUnit(v), ".mount") + ".automount"
		if err := sd.Enable(ctx, auto); err != nil {
			return err
		}
		if !sd.IsActive(ctx, auto) {
			if err := sd.Start(ctx, auto); err != nil {
				return err
			}
		}
	}
	data, _ = json.Marshal(wanted)
	if _, err = s.write("samba/volumes.json", data, 0600); err != nil {
		return err
	}
	if c.Samba.Enabled {
		var passwords, mapping strings.Builder
		previousPasswords, _ := os.ReadFile(filepath.Join(s.StateDir, "samba", "smbpasswd"))
		lastChanges := map[string][]string{}
		for _, line := range strings.Split(string(previousPasswords), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) == 7 {
				lastChanges[fields[0]] = fields
			}
		}
		for _, u := range c.Samba.Users {
			name := account(u.ID)
			id, err := s.account(ctx, name)
			if err != nil {
				return err
			}
			hash := ntHash(u.Password)
			lastChange := fmt.Sprintf("LCT-%08X", time.Now().Unix())
			if previous := lastChanges[name]; len(previous) == 7 && previous[3] == hash && validLastChange(previous[5]) {
				lastChange = previous[5]
			}
			fmt.Fprintf(&passwords, "%s:%s:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:%s:[UX         ]:%s:\n", name, id, hash, lastChange)
			fmt.Fprintf(&mapping, "%s = %s\n", name, u.Name)
		}
		for name, text := range map[string]string{"samba/smbpasswd": passwords.String(), "samba/users.map": mapping.String()} {
			ch, e := s.write(name, []byte(text), 0600)
			if e != nil {
				return e
			}
			changed = changed || ch
		}
		if _, err = s.write("samba/check-volume", []byte(mountGuard), 0700); err != nil {
			return err
		}
		ch, e := s.write("samba.conf", []byte(validatedConf), 0600)
		if e != nil {
			return e
		}
		changed = changed || ch
		// An enabled unit can start before netOS assigns the LAN addresses at
		// boot. An active smbd listening only on loopback must be repaired.
		// Discovery also caches interface addresses at startup. Repair both
		// services when the LAN was not ready for their initial start.
		changed = changed || s.lanListeners(ctx, c) != nil
		if err = s.startUnit(ctx, "netos-samba.service", sambaUnit(s.StateDir), changed); err != nil {
			return err
		}
		for attempt := 0; ; attempt++ {
			if err = s.lanListeners(ctx, c); err == nil {
				break
			}
			if attempt == 49 {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if c.Samba.Discovery && len(c.Samba.Networks) > 0 {
			if err = s.startUnit(ctx, "netos-wsdd.service", discoveryUnit(c), changed); err != nil {
				return err
			}
		} else {
			if err = sd.Disable(ctx, "netos-wsdd.service"); err != nil {
				return err
			}
		}
	} else {
		for _, name := range []string{"samba.conf", "samba/smbpasswd", "samba/users.map"} {
			if err := os.Remove(filepath.Join(s.StateDir, name)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	_, err = s.write("samba/applied", s.stamp(c), 0600)
	return err
}

func (s *Subsystem) startUnit(ctx context.Context, name, text string, changed bool) error {
	ch, err := system.WriteFileAtomicIfChanged(filepath.Join(s.UnitDir, name), []byte(text), 0644)
	if err != nil {
		return err
	}
	sd := system.NewSystemd(s.Runner)
	if ch {
		if err = sd.DaemonReload(ctx); err != nil {
			return err
		}
	}
	if err = sd.Enable(ctx, name); err != nil {
		return err
	}
	if ch || changed || !sd.IsActive(ctx, name) {
		return sd.Restart(ctx, name)
	}
	return nil
}
func (s *Subsystem) removeVolume(ctx context.Context, v config.StorageVolume) error {
	sd := system.NewSystemd(s.Runner)
	if err := unmountVolume(ctx, s.Runner.Run, v); err != nil {
		return err
	}
	for _, ext := range []string{".automount", ".mount"} {
		name := strings.TrimSuffix(mountUnit(v), ".mount") + ext
		if err := sd.Disable(ctx, name); err != nil {
			return fmt.Errorf("извлечение %s: %w", v.UUID, err)
		}
		if err := os.Remove(filepath.Join(s.UnitDir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
func (s *Subsystem) Health(ctx context.Context, c *config.Config) error {
	sd := system.NewSystemd(s.Runner)
	if !c.Samba.Enabled && sd.IsActive(ctx, "netos-samba.service") {
		return fmt.Errorf("Samba продолжает работать после отключения")
	}
	if (!c.Samba.Enabled || !c.Samba.Discovery || len(c.Samba.Networks) == 0) && sd.IsActive(ctx, "netos-wsdd.service") {
		return fmt.Errorf("обнаружение продолжает работать после отключения")
	}
	if c.Samba.Enabled {
		if !sd.IsActive(ctx, "netos-samba.service") {
			return fmt.Errorf("Samba не работает")
		}
		if err := s.lanListeners(ctx, c); err != nil {
			return err
		}
		conf, err := Render(c, s.StateDir)
		if err != nil {
			return err
		}
		if system.FileChanged(filepath.Join(s.StateDir, "samba.conf"), []byte(conf)) {
			return fmt.Errorf("настройки Samba изменены вне netOS")
		}
		if system.FileChanged(filepath.Join(s.UnitDir, "netos-samba.service"), []byte(sambaUnit(s.StateDir))) || system.FileChanged(filepath.Join(s.StateDir, "samba", "check-volume"), []byte(mountGuard)) {
			return fmt.Errorf("артефакты Samba изменены вне netOS")
		}
		data, err := os.ReadFile(filepath.Join(s.StateDir, "samba", "smbpasswd"))
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(c.Samba.Users) == 0 && strings.TrimSpace(string(data)) == "" {
			lines = nil
		}
		if len(lines) != len(c.Samba.Users) {
			return fmt.Errorf("состав пользователей Samba изменён вне netOS")
		}
		var mapping strings.Builder
		for i, u := range c.Samba.Users {
			fields := strings.Split(lines[i], ":")
			if len(fields) != 7 || fields[0] != account(u.ID) || fields[3] != ntHash(u.Password) || fields[4] != "[UX         ]" || !validLastChange(fields[5]) {
				return fmt.Errorf("учётные данные Samba изменены вне netOS")
			}
			fmt.Fprintf(&mapping, "%s = %s\n", account(u.ID), u.Name)
		}
		if system.FileChanged(filepath.Join(s.StateDir, "samba", "users.map"), []byte(mapping.String())) {
			return fmt.Errorf("имена пользователей Samba изменены вне netOS")
		}
		if c.Samba.Discovery && len(c.Samba.Networks) > 0 && !sd.IsActive(ctx, "netos-wsdd.service") {
			return fmt.Errorf("обнаружение Samba не работает")
		}
		if c.Samba.Discovery && len(c.Samba.Networks) > 0 && system.FileChanged(filepath.Join(s.UnitDir, "netos-wsdd.service"), []byte(discoveryUnit(c))) {
			return fmt.Errorf("настройки обнаружения Samba изменены вне netOS")
		}
	}
	for _, v := range c.Samba.Volumes {
		if v.Enabled && !sd.IsActive(ctx, strings.TrimSuffix(mountUnit(v), ".mount")+".automount") {
			return fmt.Errorf("автоподключение тома %s не работает", v.UUID)
		}
		if v.Enabled {
			out, err := s.Runner.Run(ctx, "getent", "passwd", "netos-storage")
			if err != nil {
				return err
			}
			fields := strings.Split(strings.TrimSpace(out), ":")
			if len(fields) != 7 {
				return fmt.Errorf("учётная запись накопителей отсутствует")
			}
			if system.FileChanged(filepath.Join(s.UnitDir, mountUnit(v)), []byte(mountText(v, fields[2], fields[3]))) || system.FileChanged(filepath.Join(s.UnitDir, strings.TrimSuffix(mountUnit(v), ".mount")+".automount"), []byte(automountText(v))) {
				return fmt.Errorf("настройки тома %s изменены вне netOS", v.UUID)
			}
		}
	}
	return nil
}

func (s *Subsystem) lanListeners(ctx context.Context, c *config.Config) error {
	wanted := map[string]bool{}
	for _, n := range c.Networks {
		if n.Enabled && selected(c.Samba.Networks, n.ID) {
			prefix, err := netip.ParsePrefix(n.RouterAddress)
			if err != nil {
				return err
			}
			wanted[netip.AddrPortFrom(prefix.Addr(), 445).String()] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}
	out, err := s.Runner.Run(ctx, "ss", "-H", "-lnt")
	if err != nil {
		return fmt.Errorf("проверка слушателей Samba: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			delete(wanted, fields[3])
		}
	}
	for address := range wanted {
		return fmt.Errorf("Samba не слушает выбранную LAN: %s", address)
	}
	return nil
}

func validLastChange(value string) bool {
	if !strings.HasPrefix(value, "LCT-") {
		return false
	}
	timestamp, err := strconv.ParseUint(strings.TrimPrefix(value, "LCT-"), 16, 64)
	return err == nil && timestamp > 0
}

// OwnedMountUnits returns only identities from the persisted registry. A unit
// with a similar prefix is not sufficient proof of ownership.
func OwnedMountUnits(stateDir string) ([]string, error) {
	volumes, err := New(nil, stateDir).owned()
	if err != nil {
		return nil, err
	}
	var units []string
	for _, ext := range []string{".automount", ".mount"} {
		for _, v := range volumes {
			if v.ID == "" {
				return nil, fmt.Errorf("пустой ID в реестре накопителей")
			}
			units = append(units, strings.TrimSuffix(mountUnit(v), ".mount")+ext)
		}
	}
	return units, nil
}

// UnmountOwnedVolumes rejects busy filesystems before lifecycle operations
// stop any automount or remove the persisted ownership needed for recovery.
func UnmountOwnedVolumes(ctx context.Context, stateDir string, run func(context.Context, string, ...string) (string, error)) error {
	volumes, err := New(nil, stateDir).owned()
	if err != nil {
		return err
	}
	for _, v := range volumes {
		if err := unmountVolume(ctx, run, v); err != nil {
			return err
		}
	}
	return nil
}
func unmountVolume(ctx context.Context, run func(context.Context, string, ...string) (string, error), v config.StorageVolume) error {
	// Never force/lazy-unmount: busy files must surface as an apply error.
	// Stopping an automount first detaches its mount tree, including a busy
	// filesystem. Ask the kernel to unmount the real filesystem before that.
	// netosd has PrivateTmp and therefore a private mount namespace. Unmount
	// in PID 1's namespace, where the systemd mount and clients actually live.
	mounts, err := run(ctx, "nsenter", "--target", "1", "--mount", "--", "findmnt", "-rn", "-o", "TARGET,FSTYPE")
	if err != nil {
		return fmt.Errorf("проверка тома %s: %w", v.UUID, err)
	}
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == MountPath(v) && fields[1] != "autofs" {
			if _, err := run(ctx, "nsenter", "--target", "1", "--mount", "--", "umount", "--", MountPath(v)); err != nil {
				return fmt.Errorf("извлечение %s: %w", v.UUID, err)
			}
			break
		}
	}
	return nil
}
