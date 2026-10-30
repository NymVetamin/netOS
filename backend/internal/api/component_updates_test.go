package api

import "testing"

func TestComponentUpdatePermissions(t *testing.T) {
	for _, section := range []string{"components", "system", "channels"} {
		for _, level := range []string{"view", "manage", "none"} {
			for _, method := range []string{"GET", "POST"} {
				r := limitedRequest(map[string]string{section: level})
				r.URL.Path = "/api/components/updates"
				r.Method = method
				want := section == "components" && (level == "manage" || method == "GET" && level == "view")
				if limitedEndpoint(r) != want {
					t.Fatalf("%s %s %s", section, level, method)
				}
			}
		}
	}
}
