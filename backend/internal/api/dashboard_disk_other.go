//go:build !linux

package api

func filesystemUsage(path string) (total, used *uint64) {
	return nil, nil
}
