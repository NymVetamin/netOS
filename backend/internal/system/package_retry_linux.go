package system

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type interruptedPackage struct {
	Name    string
	Arch    string
	Version string
}

func anonymousPackageLog(label string) (*os.File, error) {
	fd, err := unix.MemfdCreate(label, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), label), nil
}

// Apt supplies the version and architecture, while only dpkg can attest
// that an action actually started. Either stream alone is insufficient.
func packageParticipants(plan, events io.Reader, targets []string) ([]interruptedPackage, error) {
	requested := make(map[string]bool, len(targets))
	for _, target := range targets {
		name, _, _ := strings.Cut(target, "=")
		requested[name] = true
	}
	byID := map[string]interruptedPackage{}
	alias := map[string]string{}
	var unpackOrder, configureOrder []string
	sc := bufio.NewScanner(plan)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 {
			return nil, fmt.Errorf("некорректный план apt")
		}
		id := f[0] + ":" + f[2]
		if !packageNamePattern.MatchString(id) {
			return nil, fmt.Errorf("некорректный пакет в плане apt: %q", id)
		}
		entry := interruptedPackage{f[0], f[2], f[1]}
		if prev, ok := byID[id]; ok && prev != entry {
			return nil, fmt.Errorf("несколько версий %s в плане apt", id)
		} else if !ok {
			unpackOrder = append(unpackOrder, id)
		}
		if f[3] == "configure" {
			configureOrder = append(configureOrder, id)
		}
		byID[id] = entry
		if prev, ok := alias[f[0]]; ok && prev != id {
			alias[f[0]] = ""
		} else {
			alias[f[0]] = id
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	touched := map[string]bool{}
	sc = bufio.NewScanner(events)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		line, processing := strings.CutPrefix(sc.Text(), "processing: ")
		if !processing {
			continue
		}
		action, name, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		id := name
		if !strings.Contains(id, ":") {
			id = alias[id]
		}
		p, ok := byID[id]
		if ok && (action == "install" || action == "upgrade" || action == "configure" && (requested[id] || requested[p.Name] && alias[p.Name] == id)) {
			touched[id] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var result []interruptedPackage
	// Apt may unpack in a different order from dependency configuration.
	for _, id := range append(configureOrder, unpackOrder...) {
		if touched[id] {
			result = append(result, byID[id])
			delete(touched, id)
		}
	}
	return result, nil
}

func (p *Packages) changePackages(ctx context.Context, path string, targets, args []string) error {
	if path == "" {
		return runPackageApt(ctx, p.R, args)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	// Serialize readers and writers across CLI and daemon processes. Closing
	// the directory fd also releases the lock after a caller crashes.
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("другая пакетная операция netOS: %w", err)
	}
	data, err := os.ReadFile(path)
	if err == nil {
		var items []interruptedPackage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		if err := p.resumePackages(ctx, items, targets); err != nil {
			return err
		}
		return os.Remove(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(args) == 0 {
		// Another process may have completed recovery since the first stat.
		// Never issue a bare apt-get install with a stale missing list.
		for _, name := range targets {
			if !p.Installed(ctx, name) {
				return fmt.Errorf("состояние прерванной установки %s изменилось; повторите установку", name)
			}
		}
		return nil
	}
	actions, err := anonymousPackageLog("dpkg-actions")
	if err != nil {
		return err
	}
	defer actions.Close()
	plan, err := anonymousPackageLog("apt-participants")
	if err != nil {
		return err
	}
	defer plan.Close()
	awk, err := os.Open("/usr/bin/awk")
	if err != nil {
		return err
	}
	defer awk.Close()
	opts := packageCommandOptions{name: "apt-get", prepare: func(args []string, files []*os.File) ([]string, []*os.File) {
		first := 3 + len(files)
		tool := "/proc/self/fd/" + strconv.Itoa(first+1)
		hook := fmt.Sprintf(`%s 'NR == 1 && $0 != "VERSION 3" {exit 1} body && NF >= 9 && $6 != "-" && $9 != "**REMOVE**" {print $1,$6,$7,($9 == "**CONFIGURE**" ? "configure" : "unpack")} /^$/ {body=1}' >&%d`, tool, first+2)
		options := []string{"-o", "DPkg::Pre-Install-Pkgs::=" + hook, "-o", "DPkg::Tools::options::" + tool + "::Version=3", "-o", "DPkg::Options::=--status-fd=" + strconv.Itoa(first)}
		for fd := first; fd < first+3; fd++ {
			options = append(options, "-o", "APT::Keep-Fds::="+strconv.Itoa(fd))
		}
		return append(options, args...), append(files, actions, awk, plan)
	}}
	err = runPackageApt(context.WithValue(ctx, packageCommandOptionsKey{}, &opts), p.R, args)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return err
	}
	// Independent read offsets also work if a completed maintainer script
	// left an inherited descriptor in a long-running process.
	items, readErr := packageParticipants(io.NewSectionReader(plan, 0, 1<<63-1), io.NewSectionReader(actions, 0, 1<<63-1), targets)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	if len(items) > 0 {
		raw, marshalErr := json.Marshal(items)
		if marshalErr != nil {
			return errors.Join(err, marshalErr)
		}
		return errors.Join(err, WriteFileAtomic(path, raw, 0600))
	}
	return err
}

func (p *Packages) resumePackages(ctx context.Context, items []interruptedPackage, targets []string) error {
	adm := os.Getenv("DPKG_ADMINDIR")
	if adm == "" {
		adm = filepath.Join(os.Getenv("DPKG_ROOT"), "/var/lib/dpkg")
	}
	lock, err := os.OpenFile(filepath.Join(adm, "lock-frontend"), os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = unix.FcntlFlock(lock.Fd(), unix.F_OFD_SETLK, &unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart}); err != nil {
		return fmt.Errorf("блокировка dpkg: %w", err)
	}
	// A successfully configured package may leave a helper alive with an
	// inherited fd. Its lifetime must not extend the completed transaction.
	defer unix.FcntlFlock(lock.Fd(), unix.F_OFD_SETLK, &unix.Flock_t{Type: unix.F_UNLCK, Whence: io.SeekStart})
	opts := packageCommandOptions{name: "dpkg", env: []string{"DPKG_FRONTEND_LOCKED=1"}, prepare: func(args []string, files []*os.File) ([]string, []*os.File) { return args, append(files, lock) }}
	ctx = context.WithValue(ctx, packageCommandOptionsKey{}, &opts)
	// Each postinst may enqueue a handler. Refresh only after a mutation,
	// sharing that inventory across verification and the next decision.
	live, awaited, err := p.retryInventory(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		id := item.Name + ":" + item.Arch
		if !packageNamePattern.MatchString(id) || item.Version == "" || live[id].version != item.Version {
			return fmt.Errorf("пакет %s изменился после прерывания", id)
		}
	}
	for _, item := range items {
		id := item.Name + ":" + item.Arch
		current := live[id]
		if current.version != item.Version {
			return fmt.Errorf("изменилась версия %s", id)
		}
		switch current.status {
		case "install ok installed", "hold ok installed":
			continue
		case "install ok unpacked", "install ok half-configured":
		default:
			return fmt.Errorf("состояние %s требует проверки: %s", id, current.status)
		}
		if awaited != "" {
			return fmt.Errorf("dpkg ожидает обработчик %s", awaited)
		}
		if _, err := p.R.Run(ctx, "dpkg", "--no-triggers", "--configure", id); err != nil {
			return err
		}
		live, awaited, err = p.retryInventory(ctx)
		if err != nil {
			return err
		}
		if live[id].status != "install ok installed" || live[id].version != item.Version {
			return fmt.Errorf("пакет %s остался в состоянии %s, версия %s", id, live[id].status, live[id].version)
		}
	}
	for _, target := range targets {
		name, version, pinned := strings.Cut(target, "=")
		current := live[name]
		if (current.status != "install ok installed" && current.status != "hold ok installed") || pinned && current.version != version {
			return fmt.Errorf("пакет %s ещё не установлен в запрошенной версии", target)
		}
	}
	return nil
}

type retryPackageState struct{ version, status string }

func (p *Packages) retryInventory(ctx context.Context) (map[string]retryPackageState, string, error) {
	const format = "-f=${Package}\t${Architecture}\t${Version}\t${Status}\t${Triggers-Awaited}\n"
	out, err := p.R.Run(ctx, "dpkg-query", "-W", format)
	if err != nil {
		return nil, "", err
	}
	live := map[string]retryPackageState{}
	var awaited string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return nil, "", fmt.Errorf("некорректная строка dpkg-query")
		}
		state := retryPackageState{f[2], f[3]}
		live[f[0]+":"+f[1]] = state
		// An unqualified multiarch target cannot prove which instance the
		// administrator selected. Require an exact architecture in that case.
		if _, exists := live[f[0]]; exists {
			live[f[0]] = retryPackageState{}
		} else {
			live[f[0]] = state
		}
		if awaited == "" {
			awaited = strings.TrimSpace(f[4])
		}
	}
	return live, awaited, nil
}
