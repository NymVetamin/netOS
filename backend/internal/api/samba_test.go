package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSambaPasswordsRedactedAndMergedByStableID(t *testing.T) {
	c := config.Default()
	c.Samba.Users = []config.SambaUser{{ID: "a", Name: "alice", Password: "AliceSecret"}, {ID: "b", Name: "bob", Password: "BobSecret"}}
	for _, redact := range []func(*config.Config) (*config.Config, error){redactAdminConfig, redactConfig} {
		visible, err := redact(c)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(visible)
		if strings.Contains(string(data), "Secret") {
			t.Fatal("API leaks Samba credentials")
		}
		visible.Samba.Users[0], visible.Samba.Users[1] = visible.Samba.Users[1], visible.Samba.Users[0]
		visible.Samba.Users[1].Name = "renamed"
		mergeRedactedSecrets(visible, c)
		if visible.Samba.Users[0].Password != "BobSecret" || visible.Samba.Users[1].Password != "AliceSecret" {
			t.Fatal("reorder/rename lost secrets")
		}
		visible.Samba.Users[0].Password = "NewSecret"
		mergeRedactedSecrets(visible, c)
		if visible.Samba.Users[0].Password != "NewSecret" {
			t.Fatal("password rotation ignored")
		}
	}
}
