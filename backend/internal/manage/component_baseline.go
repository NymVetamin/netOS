package manage

import "context"

// Keep the manager's injected runner and Root in uninstall tests.
type componentRestoreRunner struct{ m *Manager }

func (r componentRestoreRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return r.m.Output(ctx, name, args...)
}

func (r componentRestoreRunner) RunInput(ctx context.Context, input, name string, args ...string) (string, error) {
	return "", r.m.Run(ctx, command{name: name, args: args, stdin: input, feedStdin: true})
}
