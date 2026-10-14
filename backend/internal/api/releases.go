package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

type releaseInfo struct {
	Tag        string    `json:"tag_name"`
	Name       string    `json:"name"`
	Body       string    `json:"body"`
	Published  time.Time `json:"published_at"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
}

func fetchReleases(ctx context.Context, client *http.Client, endpoint string) ([]releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "netOS-release-check")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось связаться с GitHub; проверьте доступ в интернет и повторите проверку")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return nil, fmt.Errorf("GitHub временно ограничил запросы; повторите проверку позже")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub не вернул список релизов (HTTP %d)", resp.StatusCode)
	}
	var all []releaseInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&all); err != nil {
		return nil, fmt.Errorf("не удалось прочитать список релизов GitHub")
	}
	releases := []releaseInfo{}
	for _, release := range all {
		if !release.Draft && !release.Prerelease && release.Tag != "latest" && versionPattern.MatchString(release.Tag) {
			releases = append(releases, release)
		}
	}
	sort.SliceStable(releases, func(i, j int) bool { return releases[i].Published.After(releases[j].Published) })
	if len(releases) > 10 {
		releases = releases[:10]
	}
	if len(releases) == 0 {
		return nil, fmt.Errorf("опубликованных стабильных релизов не найдено")
	}
	return releases, nil
}

func (s *Server) handleReleases(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	releases, err := fetchReleases(ctx, &http.Client{Timeout: 20 * time.Second}, "https://api.github.com/repos/NymVetamin/netOS/releases?per_page=100")
	if err != nil {
		writeError(w, http.StatusBadGateway, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"current": s.Version, "releases": releases})
}
