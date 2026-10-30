package components

import (
	"context"
	"io"
	"sync"
	"time"
)

type Operation struct {
	Active    bool      `json:"active"`
	Kind      string    `json:"kind,omitempty"`
	Component string    `json:"component,omitempty"`
	Stage     string    `json:"stage,omitempty"`
	Error     string    `json:"error,omitempty"`
	Bytes     int64     `json:"bytes,omitempty"`
	Total     int64     `json:"total,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
}
type Progress struct {
	mu    sync.Mutex
	state Operation
}

func (p *Progress) Snapshot() Operation {
	if p == nil {
		return Operation{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}
func (p *Progress) Start(kind, id string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = Operation{Active: true, Kind: kind, Component: id, UpdatedAt: time.Now(), StartedAt: time.Now()}
}
func (p *Progress) Stage(id, stage string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.Component = id
	p.state.Stage = stage
	p.state.Bytes = 0
	p.state.Total = 0
	p.state.UpdatedAt = time.Now()
}
func (p *Progress) Finish(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state.Active = false
	p.state.UpdatedAt = time.Now()
	if err != nil {
		p.state.Error = err.Error()
	}
}

type progressContextKey struct{}
type progressReader struct {
	io.Reader
	progress    *Progress
	total, read int64
	last        time.Time
}

func (r *progressReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	r.read += int64(n)
	if time.Since(r.last) >= 200*time.Millisecond || e != nil || r.read == r.total {
		r.last = time.Now()
		r.progress.mu.Lock()
		r.progress.state.Bytes = r.read
		r.progress.state.Total = r.total
		r.progress.state.UpdatedAt = r.last
		r.progress.mu.Unlock()
	}
	return n, e
}
func downloadProgress(ctx context.Context, body io.Reader, total int64) io.Reader {
	if p, ok := ctx.Value(progressContextKey{}).(*Progress); ok {
		return &progressReader{Reader: body, progress: p, total: total}
	}
	return body
}
