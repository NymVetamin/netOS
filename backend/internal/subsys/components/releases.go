package components

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/netos-router/netos/internal/releaseversion"
)

var releaseHTTPClient = &http.Client{Timeout: 30 * time.Second}
var releaseAPIBase = "https://api.github.com/repos/"

// Resolve metadata once per install/check, never on the catalog/status path.
// The asset digest comes from GitHub over HTTPS; it is not an author signature.
func latestRelease(ctx context.Context, rel externalRelease) (externalRelease, error) {
	return latestReleaseForArch(ctx, rel, runtime.GOARCH)
}

func latestReleaseForArch(ctx context.Context, rel externalRelease, arch string) (externalRelease, error) {
	if rel.Repository == "" {
		return rel, nil
	}
	if arch != "amd64" && arch != "arm64" {
		return rel, fmt.Errorf("неподдерживаемая архитектура %s", arch)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", releaseAPIBase+rel.Repository+"/releases/latest", nil)
	if err != nil {
		return rel, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "netOS-component-updates")
	resp, err := releaseHTTPClient.Do(req)
	if err != nil {
		return rel, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rel, fmt.Errorf("проверка %s: HTTP %d", rel.Repository, resp.StatusCode)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&release); err != nil {
		return rel, err
	}
	if _, valid := releaseversion.Compare(release.Tag, release.Tag); !valid || release.Draft || release.Prerelease {
		return rel, fmt.Errorf("источник не вернул стабильный релиз")
	}
	wantURL := rel.URL(release.Tag, arch)
	for _, asset := range release.Assets {
		if asset.Name != path.Base(wantURL) {
			continue
		}
		if asset.URL != wantURL {
			return rel, fmt.Errorf("неожиданный адрес архива %s", asset.Name)
		}
		digest := strings.TrimPrefix(asset.Digest, "sha256:")
		sum, err := hex.DecodeString(digest)
		if !strings.HasPrefix(asset.Digest, "sha256:") || err != nil || len(sum) != 32 {
			return rel, fmt.Errorf("для %s отсутствует корректная SHA256", asset.Name)
		}
		rel.Version = release.Tag
		rel.SHA256 = map[string]string{arch: strings.ToLower(digest)}
		return rel, nil
	}
	return rel, fmt.Errorf("нет архива для %s", arch)
}

var externalVersionPattern = regexp.MustCompile(`(?i)\b(?:xray|dnsproxy)(?:\s+version)?\s+v?([0-9]+(?:\.[0-9]+){1,3})(?:\s|$)`)

func (s *Subsystem) installedExternalVersion(ctx context.Context, rel externalRelease) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, externalVersionTimeout)
	defer cancel()
	out, err := s.Runner.Run(ctx, rel.Target, rel.VersionArgs...)
	if err != nil {
		return "", err
	}
	m := externalVersionPattern.FindStringSubmatch(out)
	if len(m) != 2 {
		return "", fmt.Errorf("не удалось определить версию %s", path.Base(rel.Target))
	}
	return "v" + m[1], nil
}

func (s *Subsystem) legacyExternalCurrent(ctx context.Context, rel externalRelease) bool {
	if rel.Version != "" {
		return s.externalCurrent(ctx, rel)
	}
	v, err := s.installedExternalVersion(ctx, rel)
	if err != nil {
		return false
	}
	for _, old := range rel.LegacyVersions {
		if v == old {
			return true
		}
	}
	return false
}
