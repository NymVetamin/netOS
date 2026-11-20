package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/netos-router/netos/internal/certificates"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/system"
	"github.com/netos-router/netos/internal/tlsutil"
)

func TestManagedPanelHandshakeDuringBundleRotation(t *testing.T) {
	cfg := config.Default()
	cfg.System.Panel.Port = freeTCPPort(t)
	dir := t.TempDir()
	manager := certificates.New(dir, nil)
	manager.HTTPAddress = "127.0.0.1:0"
	defer manager.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	path, err := manager.Panel(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secondManager := certificates.New(t.TempDir(), nil)
	defer secondManager.Close()
	secondPath, err := secondManager.Panel(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	s := New(nil, nil, nil, &lifecycleLogger{})
	s.Certificates = manager
	ready, done := make(chan struct{}), make(chan error, 1)
	s.Ready = func() error { close(ready); return nil }
	go func() { done <- s.Start(ctx, cfg, dir) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("panel startup: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer func() { cancel(); <-done }()

	dial := func() (string, error) {
		d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- compare the exact loopback certificate below
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.System.Panel.Port)))
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return tlsutil.Fingerprint(conn.(*tls.Conn).ConnectionState().PeerCertificates[0]), nil
	}
	original, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	// A FIFO holds the first open in progress while rename publishes a
	// different complete pair. Any second open will see the new key.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	type result struct {
		fingerprint string
		err         error
	}
	inFlight := make(chan result, 1)
	go func() { fp, err := dial(); inFlight <- result{fp, err} }()
	var writer *os.File
	for {
		writer, err = os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if !errors.Is(err, syscall.ENXIO) || ctx.Err() != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := system.WriteFileAtomic(path, second, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(first); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	r := <-inFlight
	if r.err != nil || r.fingerprint != original {
		t.Fatalf("in-flight handshake: certificate %q, error %v", r.fingerprint, r.err)
	}
	if err := system.WriteFileAtomic(path, []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	if err := system.WriteFileAtomic(path, second, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := certificates.ParsePair(second, second, "")
	if err != nil {
		t.Fatal(err)
	}
	if fp, err := dial(); err != nil || fp == original || fp != tlsutil.Fingerprint(pair.Leaf) {
		t.Fatalf("next handshake: certificate %q, error %v", fp, err)
	}
}
