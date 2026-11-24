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
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func anonymousPackageLog(label string) (*os.File, error) {
	fd, err := unix.MemfdCreate(label, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), label), nil
}

// Apt supplies the version and architecture, while only dpkg can attest
// that an action actually started. Either stream alone is insufficient.
func packageParticipants(plan, events io.Reader, targets []string) (packageReceipt, error) {
	requested := make(map[string]bool, len(targets))
	for _, target := range targets {
		name, _, _ := strings.Cut(target, "=")
		requested[name] = true
	}
	byID := map[string]interruptedPackage{}
	alias := map[string]string{}
	archives := map[string]string{}
	unpackAt, configureAt := map[string]int{}, map[string]int{}
	step := 0
	var unpackOrder, configureOrder []string
	sc := bufio.NewScanner(plan)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 5 {
			return packageReceipt{}, fmt.Errorf("некорректный план apt")
		}
		id := f[0] + ":" + f[2]
		if !packageNamePattern.MatchString(id) {
			return packageReceipt{}, fmt.Errorf("некорректный пакет в плане apt: %q", id)
		}
		entry := interruptedPackage{f[0], f[2], f[1]}
		if prev, ok := byID[id]; ok && prev != entry {
			return packageReceipt{}, fmt.Errorf("несколько версий %s в плане apt", id)
		} else if !ok {
			unpackOrder = append(unpackOrder, id)
		}
		if f[3] == "unpack" {
			archives[id] = f[4]
			unpackAt[id] = step
		}
		if f[3] == "configure" {
			configureOrder = append(configureOrder, id)
			configureAt[id] = step
		}
		step++
		byID[id] = entry
		if prev, ok := alias[f[0]]; ok && prev != id {
			alias[f[0]] = ""
		} else {
			alias[f[0]] = id
		}
	}
	if err := sc.Err(); err != nil {
		return packageReceipt{}, err
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
		return packageReceipt{}, err
	}
	result := packageReceipt{Targets: targets}
	// Apt may unpack in a different order from dependency configuration.
	for _, id := range append(configureOrder, unpackOrder...) {
		if touched[id] {
			result.Started = append(result.Started, byID[id])
			delete(archives, id)
			delete(touched, id)
		} else if before, ok := archives[id]; ok {
			result.Remaining = append(result.Remaining, remainingArchive{byID[id], before, unpackAt[id]})
			delete(archives, id)
		}
	}
	if len(result.Remaining) > 0 {
		result.ConfigureAt = make(map[string]int, len(result.Started)+len(result.Remaining))
		saveOrder := func(item interruptedPackage) {
			id := item.Name + ":" + item.Arch
			if rank, ok := configureAt[id]; ok {
				result.ConfigureAt[id] = rank
			}
		}
		for _, item := range result.Started {
			saveOrder(item)
		}
		for _, a := range result.Remaining {
			saveOrder(a.interruptedPackage)
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
	rec, err := readPackageReceipt(path)
	if expected, check := ctx.Value(upgradeReceiptKey{}).(string); check {
		if err == nil && rec.fingerprint() != expected || os.IsNotExist(err) && expected != "" {
			return fmt.Errorf("состояние обновления изменилось; проверьте обновления ещё раз")
		}
	}
	if err == nil {
		if len(rec.Targets) > 0 && !sameTargets(rec.Targets, targets) {
			return fmt.Errorf("изменился состав прерванной операции")
		}
		if err := p.finishReceipt(ctx, path, &rec, targets); err != nil {
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
	observed, runErr := p.observeApt(ctx, targets, args, nil)
	if len(observed.Started) > 0 || len(observed.Remaining) > 0 {
		return errors.Join(runErr, saveReceipt(path, observed))
	}
	return runErr
}

func saveReceipt(path string, rec packageReceipt) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, b, 0600)
}

// Filter before writing anything from protocol v3: its header also contains
// the machine's apt configuration. Only the package-action rows belong here.
const captureAptPlan = `%s '
NR == 1 && $0 != "VERSION 3" {exit 1}
body && NF >= 9 && $6 != "-" && $9 != "**REMOVE**" {
	print $1, $6, $7, ($9 == "**CONFIGURE**" ? "configure" : "unpack"), $2
}
/^$/ {body=1}' >&%d`

const checkRemainingArchives = `%s '
BEGIN {
	while ((getline < "/proc/self/fd/%s") > 0) permitted[$1,$2,$3,$4]=1
	cmd="dpkg --get-selections"
	while ((cmd | getline) > 0) if ($2 != "install") blocked[$1]=1
	if (close(cmd) != 0) exit 1
}
NR == 1 && $0 != "VERSION 3" {exit 1}
body && NF >= 9 && $9 != "**CONFIGURE**" {
	if ($9 == "**REMOVE**" || !(($1,$7,$6,$2) in permitted) || blocked[$1] || blocked[$1 ":" $7]) {
		print "netOS: changed package plan or selection for " $1 > "/dev/stderr"
		exit 1
	}
}
/^$/ {body=1}'`

func (p *Packages) observeApt(ctx context.Context, targets, args []string, allowed []remainingArchive) (packageReceipt, error) {
	actions, err := anonymousPackageLog("dpkg-actions")
	if err != nil {
		return packageReceipt{}, err
	}
	defer actions.Close()
	plan, err := anonymousPackageLog("apt-participants")
	if err != nil {
		return packageReceipt{}, err
	}
	defer plan.Close()
	awk, err := os.Open("/usr/bin/awk")
	if err != nil {
		return packageReceipt{}, err
	}
	defer awk.Close()
	var manifest *os.File
	if len(allowed) > 0 {
		manifest, err = anonymousPackageLog("allowed-archives")
		if err != nil {
			return packageReceipt{}, err
		}
		defer manifest.Close()
		for _, a := range allowed {
			if _, err = fmt.Fprintln(manifest, a.Name, a.Arch, a.Version, a.Before); err != nil {
				return packageReceipt{}, err
			}
		}
	}
	opts := packageCommandOptions{name: "apt-get", prepare: func(args []string, files []*os.File) ([]string, []*os.File) {
		first := 3 + len(files)
		tool := "/proc/self/fd/" + strconv.Itoa(first+1)
		hook := fmt.Sprintf(captureAptPlan, tool, first+2)
		options := []string{"-o", "DPkg::Pre-Install-Pkgs::=" + hook, "-o", "DPkg::Tools::options::" + tool + "::Version=3", "-o", "DPkg::Options::=--status-fd=" + strconv.Itoa(first)}
		for fd := first; fd < first+3; fd++ {
			options = append(options, "-o", "APT::Keep-Fds::="+strconv.Itoa(fd))
		}
		files = append(files, actions, awk, plan)
		if manifest != nil {
			fd := strconv.Itoa(first + 3)
			// Apt holds its frontend lock while running protocol-v3 hooks. Recheck
			// the actual solver plan and administrative selections before unpack.
			guard := fmt.Sprintf(checkRemainingArchives, tool, fd)
			const deferConfigure = `DPkg::Options::=--pre-invoke=case "$DPKG_HOOK_ACTION" in unpack) exit 0;; configure) echo netos-deferred-configure;; esac; exit 1`
			options = append(options, "-o", "APT::Keep-Fds::="+fd, "-o", "DPkg::Pre-Install-Pkgs::="+guard, "-o", "DPkg::ConfigurePending=false", "-o", "DPkg::Options::=--no-triggers", "-o", deferConfigure)
			files = append(files, manifest)
		}
		return append(options, args...), files
	}}
	output, err := p.R.Run(context.WithValue(ctx, packageCommandOptionsKey{}, &opts), "apt-get", args...)
	if manifest == nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return packageReceipt{}, err
	}
	// Independent read offsets also work if a completed maintainer script
	// left an inherited descriptor in a long-running process.
	observed, readErr := packageParticipants(io.NewSectionReader(plan, 0, 1<<63-1), io.NewSectionReader(actions, 0, 1<<63-1), targets)
	if err != nil && manifest != nil {
		observed.deferredConfigure = strings.Contains(output, "\nnetos-deferred-configure\n") || strings.Contains(output, "\nnetos-deferred-configure\r\n")
	}
	return observed, errors.Join(err, readErr)
}

func (p *Packages) finishReceipt(ctx context.Context, path string, rec *packageReceipt, targets []string) error {
	if len(rec.Remaining) == 0 {
		return p.resumePackages(ctx, rec.Started, targets)
	}
	// The participant set and its approved ordering do not change between
	// rounds. Only membership in the started subset changes.
	ordered := append([]interruptedPackage(nil), rec.Started...)
	started := make(map[interruptedPackage]bool, len(ordered))
	for _, item := range ordered {
		started[item] = true
	}
	for _, a := range rec.Remaining {
		ordered = append(ordered, a.interruptedPackage)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		return rec.ConfigureAt[a.Name+":"+a.Arch] < rec.ConfigureAt[b.Name+":"+b.Arch]
	})
	args := []string{"-o", "DPkg::Lock::Timeout=60", "--no-remove", "--no-install-recommends", "-y", "install"}
	// Keep dependencies automatic. Only the original direct targets may
	// become command-line requests, even when several archives remain.
	pins := map[string]string{}
	addPin := func(p interruptedPackage) {
		id := p.Name + ":" + p.Arch
		pins[id] = id + "=" + p.Version
		if prior, exists := pins[p.Name]; exists && prior != pins[id] {
			pins[p.Name] = ""
		} else {
			pins[p.Name] = pins[id]
		}
	}
	for _, item := range ordered {
		addPin(item)
	}
	var direct []string
	for _, target := range targets {
		name, _, _ := strings.Cut(target, "=")
		if pin := pins[name]; pin != "" {
			direct = append(direct, pin)
		}
	}
	if len(direct) == 0 {
		return fmt.Errorf("нет однозначной версии запрошенного пакета для продолжения установки")
	}
	args = append(args, direct...)
	for len(rec.Remaining) > 0 {
		first := rec.Remaining[0].UnpackAt
		for _, a := range rec.Remaining {
			first = min(first, a.UnpackAt)
		}
		var prerequisites []interruptedPackage
		for _, item := range rec.Started {
			if i, ok := rec.ConfigureAt[item.Name+":"+item.Arch]; ok && i < first {
				prerequisites = append(prerequisites, item)
			}
		}
		if err := p.configureRecorded(ctx, rec.Started, prerequisites, nil, rec.Remaining); err != nil {
			return err
		}
		observed, runErr := p.observeApt(ctx, targets, args, rec.Remaining)
		done := map[interruptedPackage]bool{}
		for _, item := range observed.Started {
			done[item] = true
		}
		remaining := rec.Remaining[:0]
		for _, a := range rec.Remaining {
			if done[a.interruptedPackage] {
				started[a.interruptedPackage] = true
			} else {
				remaining = append(remaining, a)
			}
		}
		if len(remaining) == len(rec.Remaining) {
			return errors.Join(fmt.Errorf("apt не распаковал ожидаемые версии пакетов"), runErr)
		}
		rec.Remaining = remaining
		rec.Started = rec.Started[:0]
		for _, item := range ordered {
			if started[item] {
				rec.Started = append(rec.Started, item)
			}
		}
		if err := saveReceipt(path, *rec); err != nil {
			return errors.Join(runErr, err)
		}
		if runErr != nil && (!observed.deferredConfigure || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)) {
			return runErr
		}
	}
	return p.resumePackages(ctx, rec.Started, targets)
}

func (p *Packages) resumePackages(ctx context.Context, items []interruptedPackage, targets []string) error {
	return p.configureRecorded(ctx, items, items, targets, nil)
}

func (p *Packages) configureRecorded(ctx context.Context, items, eligible []interruptedPackage, targets []string, remaining []remainingArchive) error {
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
	versions := make(map[string]string, len(items))
	for _, item := range items {
		id := item.Name + ":" + item.Arch
		if !packageNamePattern.MatchString(id) || item.Version == "" {
			return fmt.Errorf("некорректная запись о пакете %s", id)
		}
		versions[id] = item.Version
	}
	configured, triggered := map[string]bool{}, map[string]bool{}
	var live map[string]retryPackageState
	for {
		var waits []packageTriggerWait
		live, waits, err = p.retryInventory(ctx)
		if err != nil {
			return err
		}
		for _, a := range remaining {
			id := a.Name + ":" + a.Arch
			s := live[id]
			if !packageNamePattern.MatchString(id) || a.Version == "" || (a.Before == "-" && s.id != "" && s.status != "install ok not-installed") ||
				(a.Before != "-" && (a.Before != s.version || s.status != "install ok installed")) {
				return fmt.Errorf("изменилась исходная версия или выбор пакета %s", id)
			}
		}
		if _, upgrade := ctx.Value(upgradeReceiptKey{}).(string); upgrade {
			for id := range versions {
				if !strings.HasPrefix(live[id].status, "install ok ") {
					return fmt.Errorf("изменился выбор пакета %s", id)
				}
			}
		}
		action, id, err := nextPackageAction(live, waits, eligible, versions)
		if err != nil {
			return err
		}
		if action == "" {
			break
		}
		if action == "--configure" {
			if configured[id] {
				return fmt.Errorf("dpkg не завершил настройку %s", id)
			}
			configured[id] = true
			clear(triggered) // The next postinst may legitimately enqueue the same handler.
		} else {
			if triggered[id] {
				return fmt.Errorf("dpkg повторно ожидает обработчик %s", id)
			}
			triggered[id] = true
		}
		if _, err = p.R.Run(ctx, "dpkg", "--no-triggers", action, id); err != nil {
			return err
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

type retryPackageState struct{ id, version, status string }
type packageTriggerWait struct{ waiter, handler string }

// Dpkg can invoke a dependency's awaited trigger even for an explicitly
// named --configure with --no-triggers. Resolve the proven handler first.
func nextPackageAction(live map[string]retryPackageState, waits []packageTriggerWait, items []interruptedPackage, versions map[string]string) (action, id string, err error) {
	for key, version := range versions {
		s := live[key]
		if s.version != version {
			return "", "", fmt.Errorf("пакет %s изменился после прерывания", key)
		}
		switch s.status {
		case "install ok installed", "hold ok installed":
			continue
		case "install ok unpacked", "install ok half-configured", "install ok triggers-awaited", "install ok triggers-pending":
		default:
			return "", "", fmt.Errorf("состояние %s требует проверки: %s", key, s.status)
		}
	}
	for _, item := range items {
		key := item.Name + ":" + item.Arch
		if status := live[key].status; status != "install ok installed" && status != "hold ok installed" {
			id = key
			break
		}
	}
	if id == "" {
		return "", "", nil
	}
	var handler string
	for _, wait := range waits {
		s := live[wait.handler]
		if versions[wait.waiter] == "" || versions[s.id] == "" || versions[s.id] != s.version || s.status != "install ok triggers-pending" {
			return "", "", fmt.Errorf("%s ожидает обработчик %s; адресное восстановление остановлено", wait.waiter, wait.handler)
		}
		if handler == "" {
			handler = s.id
		}
	}
	if handler != "" {
		return "--triggers-only", handler, nil
	}
	switch live[id].status {
	case "install ok triggers-pending":
		return "--triggers-only", id, nil
	case "install ok triggers-awaited":
		return "", "", fmt.Errorf("неизвестен ожидаемый обработчик %s", id)
	default:
		return "--configure", id, nil
	}
}

func (p *Packages) retryInventory(ctx context.Context) (map[string]retryPackageState, []packageTriggerWait, error) {
	const format = "-f=${Package}\t${Architecture}\t${Version}\t${Status}\t${Triggers-Awaited}\n"
	out, err := p.R.Run(ctx, "dpkg-query", "-W", format)
	if err != nil {
		return nil, nil, err
	}
	live := map[string]retryPackageState{}
	var waits []packageTriggerWait
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			return nil, nil, fmt.Errorf("некорректная строка dpkg-query")
		}
		id := f[0] + ":" + f[1]
		state := retryPackageState{id, f[2], f[3]}
		live[id] = state
		// An unqualified multiarch target cannot prove which instance the
		// administrator selected. Require an exact architecture in that case.
		if _, exists := live[f[0]]; exists {
			live[f[0]] = retryPackageState{}
		} else {
			live[f[0]] = state
		}
		for _, handler := range strings.Fields(f[4]) {
			waits = append(waits, packageTriggerWait{id, handler})
		}
	}
	return live, waits, nil
}
