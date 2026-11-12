package components

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
)

// AmneziaWG — единственный компонент из стороннего apt-репозитория и
// единственный, чей модуль ядра собирается на роутере (DKMS). Отсюда две
// особенности: netOS сам подключает репозиторий Amnezia, а установка возможна
// только тогда, когда для работающего ядра есть заголовки.
const amneziaWGID = "amneziawg"

var (
	amneziaListPath   = "/etc/apt/sources.list.d/netos-amnezia.list"
	amneziaKeyPath    = "/etc/apt/keyrings/netos-amnezia.asc"
	kernelReleasePath = "/proc/sys/kernel/osrelease"
)

// The PPA publishes builds for Ubuntu 20.04; the DKMS source and the tools
// install on Debian 12/13 as well. The key is pinned here instead of being
// fetched from a keyserver: fingerprint 75C9DD72C799870E310542E24166F2C257290828
// ("Launchpad PPA for Iurii Egorov"), the key that signs the PPA's InRelease.
const amneziaList = "deb [signed-by=/etc/apt/keyrings/netos-amnezia.asc] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main\n"

const amneziaKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Hostname: 
Version: Hockeypuck 2.2

xsFNBGV0UhsBEAC33rMndHSN/k+u7gcZbh9/FjgYfGltQAtVe2QDxzn7UV+k/ChX
OrYRw6Izw/DrhaapkNCThK2jwJE64e0NjboLH7UrrmSJLXMfOlDFbyGJVRA+1sTB
lo7kKHY0xiZ1CHDzjKNV3czbesu80A9nuTZYyWHEn9ax6wsqKG3N8SvzQkUrIOVD
2wZjh0p273CCEGkBnax1ghAV3MF8OrsPU6FRJ+ZakzKbu54g68xoV+2813YECme0
JKsWfUUe/1uEJOXCvuACURSxnYr0sihJd8QI/jHSGlfeq72e5MflFEOrnu5xaDSJ
r2W5lvUetG7EGSxtNKd7Jm/KhUV04g7arA0qydRjRToW3QqyzG7VB2nXKz3AOBYN
earWAuBcTkfPvRVchxbjiYonKZA5tIlVrpawMZsdxKvYwl6LVnpBcccFWPhpudfy
4TpCqCxRoAanOCvSirI3/y7TcZMBw643SaxXi1ifGeg6eyMzrLtP3CeonKBHGzrt
1eeKGtEw/PFN4RmwpBePxi+uj0CoTD6zjCQa3c8EeB4Qz7tt6PnpibxdtZE8sBdd
51wSA/fPGi2tFph8IVAsws7oxcQxZYl8CyncKDLcoR4dxVHYdFEDDf1GjRjoQ3Ai
nD7fxD5qYzExe50DBVpuUbWcAiGICNxfvzQtUSRRtMoSHDcvzsy03KC6VwARAQAB
zR5MYXVuY2hwYWQgUFBBIGZvciBJdXJpaSBFZ29yb3bCwY4EEwEKADgWIQR1yd1y
x5mHDjEFQuJBZvLCVykIKAUCZXRSGwIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIX
gAAKCRBBZvLCVykIKBu5D/9akmHCHlUqm2RTTBeTMbLNGc0l6YugpPaCM6vz0O9k
BFP5PfRaNSRzyF7wHFHNY3JUHcor28my1fD8AE4+C3PwXz8tVYLh57UUsp4wjqHY
+MTl/1ngDViPGD3PRjB8ZlO+19yerfplZv1Jaw7FZZv2BZOAXb+ddqUG4EmlzOnC
EhcSDdFrzEBB3RGthjIb3QkKWKGbELDiMfogmsO9BE139Raiw23blagDrbnWsG4j
ReZeu3atjG6AW8eL7m+i7bKKshD2CYVMznI5cYGLMKo9w7sb33uylPj1Vx9O7joP
2GFf2rTpCY8wgzk7i1RqsipJ80u1/DY91Xdizv3f2BBe6UY7qHKoK00O11J0y8yU
is2Asycy33Wy51pf6rCFUBLQu+c1fEypHF6jqANmQwaH7pPBliy4gGWvrVggzV4m
xv7SnRiMi4PFyVwjKWm8dmuMxi/B9s++VG/ed+5aYgJYL58MohG3MUI/L58eitSC
DDcQ1iAnBmawnGMKPqzMgRFB3OU3wDwfh7LNVvQqWpQ4q7pr4Cq1CvZvGoggXWDo
1/vylPsRmiiuNetfsoVYmrkgtj1om07m5Xp1v4SyXJH11c3dc/xfMmn/4RlMWIpq
86IsOjpr3avsw3FVUNCgD5Wf5+rHG+7gNmM6Cm/F8MDfAnnRmsw4h6hgvcJNQT5D
ig==
=OY2W
-----END PGP PUBLIC KEY BLOCK-----
`

// writeIfChanged keeps the apt source idempotent: rewriting identical files
// would only bump mtimes and make every Apply look like a change.
func writeIfChanged(path, content string, mode os.FileMode) error {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, []byte(content)) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return system.WriteFileAtomic(path, []byte(content), mode)
}

func ensureAmneziaRepo() error {
	if err := writeIfChanged(amneziaKeyPath, amneziaKey, 0o644); err != nil {
		return fmt.Errorf("ключ репозитория Amnezia: %w", err)
	}
	if err := writeIfChanged(amneziaListPath, amneziaList, 0o644); err != nil {
		return fmt.Errorf("репозиторий Amnezia: %w", err)
	}
	return nil
}

// removeAmneziaRepo убирает подключённый netOS репозиторий, когда компонент
// не выбран. netos uninstall удаляет те же файлы своим списком.
func removeAmneziaRepo() error {
	var errs []error
	for _, path := range []string{amneziaListPath, amneziaKeyPath} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func kernelRelease() string {
	data, err := os.ReadFile(kernelReleasePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func kernelHeadersPackage() string {
	if release := kernelRelease(); release != "" {
		return "linux-headers-" + release
	}
	return ""
}

// amneziaKernelProblem отвечает, можно ли собрать модуль под работающее ядро.
// DKMS нужны заголовки именно этой версии. Когда Debian выпускает новое ядро,
// заголовки прежнего из репозитория пропадают, и роутер, не перезагруженный в
// новое ядро, модуль собрать не может. Ответ берётся из текущих списков apt;
// установка обновляет их и спрашивает заново.
func (s *Subsystem) amneziaKernelProblem(ctx context.Context) string {
	release := kernelRelease()
	if release == "" {
		return "Невозможно установить AmneziaWG: не удалось определить версию ядра Linux."
	}
	headers := "linux-headers-" + release
	if s.Packages.Installed(ctx, headers) {
		return ""
	}
	out, err := s.Runner.Run(ctx, "apt-cache", "policy", headers)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			if candidate, ok := strings.CutPrefix(strings.TrimSpace(line), "Candidate:"); ok {
				if candidate = strings.TrimSpace(candidate); candidate != "" && candidate != "(none)" {
					return ""
				}
			}
		}
	}
	return fmt.Sprintf("Невозможно установить AmneziaWG: требуется обновление ядра Linux. "+
		"Работает ядро %s, а заголовков для него в репозиториях нет. "+
		"Обновите систему и перезагрузите роутер, затем установите компонент.", release)
}

// Unavailable сообщает панели, какие из неустановленных компонентов поставить
// сейчас нельзя и почему, чтобы это было видно до нажатия «Применить»: ошибка
// установки откатила бы всю конфигурацию.
func (s *Subsystem) Unavailable(ctx context.Context, installed map[string]bool) map[string]string {
	out := map[string]string{}
	if !installed[amneziaWGID] {
		if problem := s.amneziaKernelProblem(ctx); problem != "" {
			out[amneziaWGID] = problem
		}
	}
	return out
}

// The module brings kernel headers and a compiler. Two apt rules keep them
// after the component is purged: the running kernel's headers are never
// autoremoved, and the compiler stays while anything merely suggests it
// (libdpkg-perl suggests a C compiler). netOS records what this installation
// brought and removes exactly that, never packages it found on the machine.
func (s *Subsystem) amneziaRecord() string {
	return filepath.Join(s.StateDir, "amneziawg-packages")
}

func (s *Subsystem) readAmneziaRecord() []string {
	data, err := os.ReadFile(s.amneziaRecord())
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

// Include interrupted installations and residual configs: neither is absent,
// and both must be excluded from new ownership and remain eligible for purge.
func (s *Subsystem) installedPackageNames(ctx context.Context) (map[string]bool, error) {
	out, err := s.Runner.Run(ctx, "dpkg-query", "-W", "-f=${Package}\t${Status}\n")
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if name, status, ok := strings.Cut(line, "\t"); ok {
			fields := strings.Fields(status)
			if len(fields) == 3 {
				switch fields[2] {
				case "installed", "unpacked", "half-installed", "half-configured", "triggers-awaited", "triggers-pending", "config-files":
					names[name] = true
				}
			}
		}
	}
	return names, nil
}

// removeAmneziaLeftovers purges recorded packages that apt itself considers
// unneeded once suggestions are ignored. Simulation first: a package that
// something still depends on or recommends is not touched.
func (s *Subsystem) removeAmneziaLeftovers(ctx context.Context, recorded []string, keep, installed map[string]bool) error {
	if len(recorded) == 0 {
		return nil
	}
	if installed == nil {
		var err error
		installed, err = s.installedPackageNames(ctx)
		if err != nil {
			return err
		}
	}
	left := map[string]bool{}
	for _, name := range recorded {
		if installed[name] && !keep[name] {
			left[name] = true
		}
	}
	if len(left) == 0 {
		return nil
	}
	out, err := s.Runner.Run(ctx, "apt-get", "-s", "-o", "APT::AutoRemove::SuggestsImportant=false", "autoremove")
	if err != nil {
		return err
	}
	var purge []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "Remv" && left[fields[1]] {
			purge = append(purge, fields[1])
		}
	}
	if len(purge) == 0 {
		return nil
	}
	_, err = s.Runner.Run(ctx, "apt-get", append([]string{"-o", "DPkg::Lock::Timeout=60", "purge", "-y"}, purge...)...)
	return err
}

func (s *Subsystem) installAmneziaWG(ctx context.Context, info config.ComponentInfo, refresh func() error) error {
	if err := s.finishAmneziaCapture(); err != nil {
		return fmt.Errorf("учёт предыдущей установки AmneziaWG: %w", err)
	}
	// The repository was written before any refresh of this Apply, so the
	// shared refresh sees it. Refresh first: the kernel check reads apt lists.
	if err := ensureAmneziaRepo(); err != nil {
		return err
	}
	if err := refresh(); err != nil {
		return err
	}
	if problem := s.amneziaKernelProblem(ctx); problem != "" {
		// The apply error appends its own sentence after this one.
		return errors.New(strings.TrimSuffix(problem, "."))
	}
	before, err := s.installedPackageNames(ctx)
	if err != nil {
		return err
	}
	_, err = system.ReadPackageNames(s.amneziaRecord())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("чтение установленных пакетов: %w", err)
	}
	captureRunner, err := s.beginAmneziaCapture(before)
	if err != nil {
		return fmt.Errorf("начало учёта пакетов AmneziaWG: %w", err)
	}
	packages := *s.Packages
	packages.R = captureRunner
	installed, installErr := packages.EnsureWithRefresh(ctx, refresh, append([]string{kernelHeadersPackage()}, info.Packages...)...)
	// Native events survive an apt error, cancellation and a failed record write.
	if err := s.finishAmneziaCapture(); err != nil {
		return errors.Join(installErr, fmt.Errorf("учёт установленных пакетов: %w", err))
	}
	if installErr != nil {
		return installErr
	}
	if len(installed) > 0 {
		s.Logger.Infof("установлен компонент %s (%s)", info.Title, strings.Join(installed, ", "))
	}
	// A package that installed is not yet a working module: DKMS can fail to
	// build it for this kernel. Say so instead of reporting success.
	if _, err := s.Runner.Run(ctx, "modprobe", "amneziawg"); err != nil {
		return fmt.Errorf("модуль ядра AmneziaWG не загрузился: %w", err)
	}
	return nil
}
