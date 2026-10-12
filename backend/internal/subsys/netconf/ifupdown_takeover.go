package netconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/netos-router/netos/internal/system"
)

var ifupdownBackupPath = "/var/lib/netos-system-baseline/ifupdown.json"

type ifupdownFile struct {
	Original []byte      `json:"original"`
	Applied  []byte      `json:"applied"`
	Mode     os.FileMode `json:"mode"`
	Exists   bool        `json:"exists"`
}

type ifupdownBackup map[string]ifupdownFile

func readIfupdownBackup(path string) (ifupdownBackup, error) {
	b := ifupdownBackup{}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("пустой журнал исходной конфигурации networking")
	}
	return b, nil
}

// RestoreIfupdown restores the input saved before taking ownership. Used by
// backend changes and uninstall, before deleting the system baseline directory.
func RestoreIfupdown(root string) error {
	path := ifupdownBackupPath
	if root != "" {
		path = filepath.Join(root, path)
	}
	b, err := readIfupdownBackup(path)
	if err != nil {
		return err
	}
	// Check every file first: never overwrite an administrator's later edits.
	for name, f := range b {
		target := name
		if root != "" {
			target = filepath.Join(root, name)
		}
		info, err := os.Lstat(target)
		if os.IsNotExist(err) && !f.Exists {
			continue
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("тип файла networking изменён после переноса: %s", name)
		}
		data, err := os.ReadFile(target)
		if os.IsNotExist(err) && !f.Exists {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(data, f.Applied) && !bytes.Equal(data, f.Original) {
			return fmt.Errorf("исходная конфигурация networking изменена после переноса: %s; сохранённая копия оставлена без изменений", name)
		}
	}
	for name, f := range b {
		if root != "" {
			name = filepath.Join(root, name)
		}
		if f.Exists {
			if err := system.WriteFileAtomic(name, f.Original, f.Mode); err != nil {
				return err
			}
		} else if err := removeFile(name); err != nil {
			return err
		}
	}
	return removeFile(path)
}

var sourceDirectoryName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Keep original bytes for untouched lines, while parsing continued directives.
func ifupdownLines(data []byte) []string {
	var lines []string
	var pending string
	for _, line := range strings.SplitAfter(string(data), "\n") {
		pending += line
		if strings.HasSuffix(strings.TrimRight(line, "\r\n"), "\\") {
			continue
		}
		lines = append(lines, pending)
		pending = ""
	}
	if pending != "" {
		lines = append(lines, pending)
	}
	return lines
}

func ifupdownFields(raw string) []string {
	logical := strings.ReplaceAll(strings.ReplaceAll(raw, "\\\r\n", " "), "\\\n", " ")
	logical, _, _ = strings.Cut(logical, "#")
	return strings.Fields(logical)
}

// Read the actual include graph, including source-directory and nested sources.
// The generated file is intentionally excluded from the foreign input.
func ifupdownInputs(read func(string) ([]byte, error)) (map[string][]byte, bool, error) {
	files := map[string][]byte{}
	included := false
	var visit func(string) error
	visit = func(path string) error {
		path = filepath.Clean(path)
		if path == filepath.Clean(ifupdownPath) {
			included = true
			return nil
		}
		if _, ok := files[path]; ok {
			return nil
		}
		if len(files) >= 256 {
			return fmt.Errorf("слишком много включений в конфигурации networking")
		}
		data, err := read(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		files[path] = data
		for _, line := range ifupdownLines(data) {
			fields := ifupdownFields(line)
			if len(fields) < 2 || (fields[0] != "source" && fields[0] != "source-directory") {
				continue
			}
			for _, pattern := range fields[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(path), pattern)
				}
				if fields[0] == "source" {
					match, err := filepath.Match(pattern, ifupdownPath)
					if err != nil {
						return err
					}
					included = included || match
				}
				matches, err := filepath.Glob(pattern)
				if err != nil {
					return err
				}
				for _, match := range matches {
					if fields[0] == "source-directory" {
						entries, err := os.ReadDir(match)
						if err != nil {
							return err
						}
						for _, entry := range entries {
							if !entry.IsDir() && sourceDirectoryName.MatchString(entry.Name()) {
								if err := visit(filepath.Join(match, entry.Name())); err != nil {
									return err
								}
							}
						}
					} else if err := visit(match); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	err := visit(ifupdownMain)
	return files, included, err
}

// Remove only managed iface stanzas (both inet and inet6) and their activation
// names. Preserve unrelated stanzas, hooks, comments and include directives.
func withoutManagedIfupdown(data []byte, names []string) ([]byte, error) {
	managed := map[string]bool{}
	for _, name := range names {
		managed[name] = true
	}
	var out strings.Builder
	drop := false
	for _, raw := range ifupdownLines(data) {
		fields := ifupdownFields(raw)
		if len(fields) == 0 {
			out.WriteString(raw)
			continue
		}
		key := fields[0]
		top := key == "iface" || key == "mapping" || key == "source" || key == "source-directory" || key == "auto" || key == "no-auto-down" || key == "no-scripts" || strings.HasPrefix(key, "allow-")
		if top {
			drop = false
		}
		if key == "iface" && len(fields) >= 2 {
			drop = managed[fields[1]]
		}
		if key == "mapping" {
			for _, pattern := range fields[1:] {
				for name := range managed {
					if match, _ := filepath.Match(pattern, name); match {
						return nil, fmt.Errorf("не удалось автоматически перенести mapping для %s; исходные настройки networking сохранены", name)
					}
				}
			}
		}
		if drop {
			continue
		}
		if key == "auto" || strings.HasPrefix(key, "allow-") {
			kept := []string{key}
			for _, name := range fields[1:] {
				if !managed[name] {
					kept = append(kept, name)
				}
			}
			if len(kept) != len(fields) {
				if len(kept) > 1 {
					out.WriteString(strings.Join(kept, " ") + "\n")
				}
				continue
			}
		}
		out.WriteString(raw)
	}
	return []byte(out.String()), nil
}

// Persist originals before the first mutation. A failed Apply restores the
// exact pre-call files and journal; a later rollback uses RestoreIfupdown.
func takeOverIfupdown(names []string) (func() error, error) {
	previous, err := os.ReadFile(ifupdownBackupPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	b, err := readIfupdownBackup(ifupdownBackupPath)
	if err != nil {
		return nil, err
	}
	read := func(name string) ([]byte, error) {
		if f, ok := b[name]; ok {
			current, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(current, f.Applied) && !bytes.Equal(current, f.Original) {
				return nil, fmt.Errorf("конфигурация networking изменена после переноса: %s", name)
			}
			return f.Original, nil
		}
		return os.ReadFile(name)
	}
	files, included, err := ifupdownInputs(read)
	if err != nil {
		return nil, err
	}
	if _, ok := files[ifupdownMain]; !ok {
		files[ifupdownMain] = nil
	}
	// Previously changed files may no longer be included; restore them too.
	for name := range b {
		if _, ok := files[name]; !ok {
			data, err := read(name)
			if err != nil {
				return nil, err
			}
			files[name] = data
		}
	}
	before := ifupdownBackup{}
	for name, data := range files {
		filtered, err := withoutManagedIfupdown(data, names)
		if err != nil {
			return nil, err
		}
		if name == ifupdownMain && !included {
			filtered = append(filtered, []byte("\n# netOS: управляемые интерфейсы\nsource "+ifupdownPath+"\n")...)
		}
		current, err := os.ReadFile(name)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if bytes.Equal(current, filtered) {
			continue
		}
		info, err := os.Lstat(name)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		f := ifupdownFile{Original: current, Applied: filtered, Mode: 0644, Exists: err == nil}
		if info != nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("не удалось безопасно перенести networking: %s не является обычным файлом", name)
			}
			f.Mode = info.Mode().Perm()
		}
		before[name] = f
		if original, ok := b[name]; ok {
			original.Applied = filtered
			b[name] = original
		} else {
			b[name] = f
		}
	}
	noop := func() error { return nil }
	if len(before) == 0 {
		return noop, nil
	}
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if err := system.WriteFileAtomic(ifupdownBackupPath, data, 0600); err != nil {
		return nil, err
	}
	undo := func() error {
		var result error
		for name, f := range before {
			if f.Exists {
				result = errors.Join(result, system.WriteFileAtomic(name, f.Original, f.Mode))
			} else {
				result = errors.Join(result, removeFile(name))
			}
		}
		if result != nil {
			return result
		}
		if previous == nil {
			return removeFile(ifupdownBackupPath)
		}
		return system.WriteFileAtomic(ifupdownBackupPath, previous, 0600)
	}
	paths := make([]string, 0, len(before))
	for name := range before {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		f := before[name]
		if err := system.WriteFileAtomic(name, f.Applied, f.Mode); err != nil {
			return nil, errors.Join(err, undo())
		}
	}
	return undo, nil
}
