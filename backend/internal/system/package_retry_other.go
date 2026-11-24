//go:build !linux

package system

import "context"

func (p *Packages) changePackages(ctx context.Context, path string, targets, args []string) error {
	return runPackageApt(ctx, p.R, args)
}
