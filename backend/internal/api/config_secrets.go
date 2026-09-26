package api

import (
	"encoding/json"
	"strings"

	"github.com/netos-router/netos/internal/config"
)

// Administrators may edit the configuration, but reading it must not return
// stored credentials to browser memory or password inputs.
func redactAdminConfig(cfg *config.Config) (*config.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	for i := range out.WANs {
		out.WANs[i].Password = ""
	}
	for i := range out.WiFi {
		for j := range out.WiFi[i].SSIDs {
			out.WiFi[i].SSIDs[j].Password = ""
		}
	}
	for i := range out.Channels {
		redactSecretValues(out.Channels[i].Config)
	}
	for i := range out.VPNServers {
		redactSecretValues(out.VPNServers[i].Config)
		for j := range out.VPNServers[i].Peers {
			for key := range out.VPNServers[i].Peers[j].Credentials {
				if secretField(key) {
					out.VPNServers[i].Peers[j].Credentials[key] = ""
				}
			}
		}
	}
	out.DDNS.Token = ""
	out.DDNS.Password = ""
	return &out, nil
}

func secretField(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", " ", "_").Replace(key))
	if normalized == "uuid" || normalized == "shortid" || normalized == "short_id" {
		return true
	}
	return strings.Contains(normalized, "password") || strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "private_key") || strings.Contains(normalized, "preshared_key") ||
		strings.Contains(normalized, "token")
}

// Empty secret fields in an edited, redacted tree mean "keep the current
// value". New nonempty credentials always replace the old ones.
func mergeRedactedSecrets(next, previous *config.Config) {
	if next == nil || previous == nil {
		return
	}
	oldWANs := map[string]config.WAN{}
	for _, value := range previous.WANs {
		oldWANs[value.ID] = value
	}
	for i := range next.WANs {
		if next.WANs[i].Password == "" {
			next.WANs[i].Password = oldWANs[next.WANs[i].ID].Password
		}
	}
	oldRadios := map[string]config.WiFiRadio{}
	for _, value := range previous.WiFi {
		oldRadios[value.ID] = value
	}
	for i := range next.WiFi {
		oldSSIDs := map[string]config.WiFiSSID{}
		for _, value := range oldRadios[next.WiFi[i].ID].SSIDs {
			oldSSIDs[value.ID] = value
		}
		for j := range next.WiFi[i].SSIDs {
			if next.WiFi[i].SSIDs[j].Password == "" {
				next.WiFi[i].SSIDs[j].Password = oldSSIDs[next.WiFi[i].SSIDs[j].ID].Password
			}
		}
	}
	oldChannels := map[string]config.Channel{}
	for _, value := range previous.Channels {
		oldChannels[value.ID] = value
	}
	for i := range next.Channels {
		mergeSecretMap(next.Channels[i].Config, oldChannels[next.Channels[i].ID].Config)
	}
	oldServers := map[string]config.VPNServer{}
	for _, value := range previous.VPNServers {
		oldServers[value.ID] = value
	}
	for i := range next.VPNServers {
		old := oldServers[next.VPNServers[i].ID]
		mergeSecretMap(next.VPNServers[i].Config, old.Config)
		oldPeers := map[string]config.VPNPeer{}
		for _, value := range old.Peers {
			oldPeers[value.ID] = value
		}
		for j := range next.VPNServers[i].Peers {
			credentials := next.VPNServers[i].Peers[j].Credentials
			previousCredentials := oldPeers[next.VPNServers[i].Peers[j].ID].Credentials
			for key, value := range credentials {
				if secretField(key) && value == "" {
					credentials[key] = previousCredentials[key]
				}
			}
		}
	}
	if next.DDNS.Token == "" {
		next.DDNS.Token = previous.DDNS.Token
	}
	if next.DDNS.Password == "" {
		next.DDNS.Password = previous.DDNS.Password
	}
}

func mergeSecretMap(next, previous map[string]any) {
	for key, value := range next {
		old, ok := previous[key]
		if !ok {
			continue
		}
		if secretField(key) {
			if value == "" {
				next[key] = old
			}
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if oldMap, ok := old.(map[string]any); ok {
				mergeSecretMap(typed, oldMap)
			}
		case []any:
			if oldList, ok := old.([]any); ok {
				for i, child := range typed {
					if childMap, ok := child.(map[string]any); ok {
						if oldMap := correspondingSecretMap(childMap, oldList, i); oldMap != nil {
							mergeSecretMap(childMap, oldMap)
						}
					}
				}
			}
		}
	}
}

func correspondingSecretMap(child map[string]any, oldList []any, index int) map[string]any {
	for _, field := range []string{"id", "name"} {
		identity, ok := child[field].(string)
		if !ok || identity == "" {
			continue
		}
		for _, previous := range oldList {
			oldMap, ok := previous.(map[string]any)
			if ok && oldMap[field] == identity {
				return oldMap
			}
		}
		return nil
	}
	if index < len(oldList) {
		oldMap, _ := oldList[index].(map[string]any)
		return oldMap
	}
	return nil
}
