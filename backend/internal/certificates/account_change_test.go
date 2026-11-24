package certificates

import (
	"context"
	"testing"
)

func TestEmailChangeUsesNewAccount(t *testing.T) {
	issuer := makeIssuer(t, "vpn.example.test")
	var caches, emails []string
	m := New(t.TempDir(), func(cache, _, email string) (ACME, error) {
		caches, emails = append(caches, cache), append(emails, email)
		return issuer, nil
	})
	m.HTTPAddress = "127.0.0.1:0"
	defer m.Close()
	for _, email := range []string{"old@example.test", "old@example.test", "new@example.test", "new@example.test", "old@example.test"} {
		if _, err := m.acme(context.Background(), "vpn.example.test", email); err != nil {
			t.Fatal(err)
		}
	}
	// One issuer per change of email; an unchanged email reuses it.
	want := []string{"old@example.test", "new@example.test", "old@example.test"}
	if len(emails) != len(want) || emails[0] != want[0] || emails[1] != want[1] || emails[2] != want[2] {
		t.Fatalf("issuers created for %v, want %v", emails, want)
	}
	if caches[0] == caches[1] || caches[0] != caches[2] {
		t.Fatalf("account caches %v must follow the email", caches)
	}
}
