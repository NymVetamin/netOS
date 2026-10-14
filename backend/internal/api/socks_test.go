package api

import (
	"github.com/netos-router/netos/internal/config"
	"testing"
)

func TestSocksSecretsRoundTrip(t *testing.T) {
	c := config.Default()
	c.Socks.Password = "secret-fixture"
	visible, err := redactAdminConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if visible.Socks.Password != "" || !visible.Socks.SecretsSet["password"] {
		t.Fatal("secret leaked or presence lost")
	}
	mergeRedactedSecrets(visible, c)
	if visible.Socks.Password != c.Socks.Password || visible.Socks.SecretsSet != nil {
		t.Fatal("secret lost during edit")
	}
	viewer, _ := redactConfig(c)
	if viewer.Socks.Password != "" {
		t.Fatal("viewer leak")
	}
	diagnostic, _ := diagnosticConfig(c)
	if diagnostic.Socks.Password == c.Socks.Password {
		t.Fatal("diagnostic leak")
	}
}
