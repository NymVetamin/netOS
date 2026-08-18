package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

// externalRelease описывает закреплённый релиз компонента, которого нет в
// репозиториях Debian.
//
// Версия и контрольная сумма закреплены в коде намеренно. У dnsproxy в релизах
// нет файла с суммами, а «скачать последнее и запустить» — это установка
// произвольного бинарника с правами root по чужому решению. Обновление версии
// становится осознанной правкой с новой суммой, а не тем, что случается само.
type externalRelease struct {
	// Version — тег релиза на GitHub.
	Version string
	// URL строит ссылку на архив для архитектуры Go (amd64, arm64).
	URL func(version, goarch string) string
	// SHA256 — сумма архива для каждой поддерживаемой архитектуры.
	SHA256 map[string]string
	// FileInArchive — базовое имя нужного файла внутри архива.
	FileInArchive string
	// Target — куда положить исполняемый файл.
	Target string
}

var externalReleases = map[string]externalRelease{
	"dnsproxy": {
		Version: "v0.84.0",
		URL: func(version, goarch string) string {
			return fmt.Sprintf(
				"https://github.com/AdguardTeam/dnsproxy/releases/download/%s/dnsproxy-linux-%s-%s.tar.gz",
				version, goarch, version)
		},
		SHA256: map[string]string{
			"amd64": "5137f6fd0e965692889e8e94cc7ff8be512a6bbee07d988a4935f9d8f24a2102",
			"arm64": "5180311ad9f16cfe16f354fdc66db6a67fe45193b35bf7f70df5ac275f48d098",
		},
		FileInArchive: "dnsproxy",
		Target:        "/usr/local/bin/dnsproxy",
	},
}

// fetch скачивает файл. Вынесено в переменную, чтобы тесты не ходили в сеть.
var fetch = func(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	// Ограничение спасает от бесконечного тела: релизный архив на два порядка
	// меньше, а качаем мы под root.
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// installRelease скачивает, проверяет и раскладывает внешний компонент.
func (s *Subsystem) installRelease(ctx context.Context, id string, rel externalRelease) error {
	want, ok := rel.SHA256[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("%s не собирается под архитектуру %s", id, runtime.GOARCH)
	}
	url := rel.URL(rel.Version, runtime.GOARCH)

	s.Logger.Infof("загружаю %s %s", id, rel.Version)
	archive, err := fetch(ctx, url)
	if err != nil {
		return fmt.Errorf("загрузка %s: %w", id, err)
	}

	sum := sha256.Sum256(archive)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf(
			"контрольная сумма %s не совпадает: ожидалась %s, получена %s", id, want, got)
	}

	binary, err := extractFile(archive, rel.FileInArchive)
	if err != nil {
		return fmt.Errorf("распаковка %s: %w", id, err)
	}

	// Пишем рядом и переименовываем: перезапись работающего файла на месте
	// даёт ETXTBSY, а половина файла — неработающий компонент.
	if err := os.MkdirAll(filepath.Dir(rel.Target), 0o755); err != nil {
		return err
	}
	tmp := rel.Target + ".new"
	if err := os.WriteFile(tmp, binary, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, rel.Target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	s.Logger.Infof("установлен %s %s в %s", id, rel.Version, rel.Target)
	return nil
}

// extractFile достаёт один файл из tar.gz по базовому имени. Пути внутри
// архива не используются как есть: архив пришёл извне, и «../» в имени не
// должен приводить к записи мимо цели.
func extractFile(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("файл %s в архиве не найден", name)
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag != tar.TypeReg || path.Base(header.Name) != name {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, 256<<20))
	}
}

// externalInstalled сообщает, лежит ли исполняемый файл компонента на месте.
func externalInstalled(id string) bool {
	rel, ok := externalReleases[id]
	if !ok {
		return false
	}
	info, err := os.Stat(rel.Target)
	return err == nil && !info.IsDir()
}
