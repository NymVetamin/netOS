package api

import (
	"encoding/json"
	"strconv"
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
		out.WANs[i].SecretsSet = secretPresence(map[string]any{"password": out.WANs[i].Password})
		out.WANs[i].Password = ""
	}
	for i := range out.WiFi {
		for j := range out.WiFi[i].SSIDs {
			out.WiFi[i].SSIDs[j].SecretsSet = secretPresence(map[string]any{"password": out.WiFi[i].SSIDs[j].Password})
			out.WiFi[i].SSIDs[j].Password = ""
		}
	}
	for i := range out.Channels {
		out.Channels[i].SecretsSet = secretPresence(out.Channels[i].Config)
		redactSecretValues(out.Channels[i].Config)
	}
	for i := range out.VPNServers {
		key, _ := cfg.VPNServers[i].Config["private_key"].(string)
		out.VPNServers[i].RealityKeySet = cfg.VPNServers[i].Type == "xray" && key != ""
		out.VPNServers[i].SecretsSet = secretPresence(out.VPNServers[i].Config)
		redactSecretValues(out.VPNServers[i].Config)
		for j := range out.VPNServers[i].Peers {
			out.VPNServers[i].Peers[j].SecretsSet = map[string]bool{}
			for key, value := range out.VPNServers[i].Peers[j].Credentials {
				if secretField(key) {
					if value != "" {
						out.VPNServers[i].Peers[j].SecretsSet[key] = true
					}
					out.VPNServers[i].Peers[j].Credentials[key] = ""
				}
			}
		}
	}
	out.DDNS.SecretsSet = secretPresence(map[string]any{"token": out.DDNS.Token, "password": out.DDNS.Password})
	out.DDNS.Token = ""
	out.DDNS.Password = ""
	for i := range out.Samba.Users {
		out.Samba.Users[i].SecretsSet = secretPresence(map[string]any{"password": out.Samba.Users[i].Password})
		out.Samba.Users[i].Password = ""
	}
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

// Xray uses generic names for credentials inside outbound settings. Keep
// those aliases scoped: an id elsewhere identifies an editable object.
func secretConfigField(path, key string) bool {
	if secretField(key) {
		return true
	}
	if !strings.HasPrefix(path, "outbound.") {
		return false
	}
	if key == "id" {
		return path == "outbound.settings" || strings.HasSuffix(path, ".users")
	}
	return key == "pass" || key == "auth"
}

// Empty secret fields in an edited, redacted tree mean "keep the current
// value". New nonempty credentials always replace the old ones.
func mergeRedactedSecrets(next, previous *config.Config) {
	if next == nil {
		return
	}
	next.DDNS.SecretsSet = nil
	for i := range next.WANs {
		next.WANs[i].SecretsSet = nil
	}
	for i := range next.WiFi {
		for j := range next.WiFi[i].SSIDs {
			next.WiFi[i].SSIDs[j].SecretsSet = nil
		}
	}
	for i := range next.Samba.Users {
		next.Samba.Users[i].SecretsSet = nil
	}
	for i := range next.Channels {
		next.Channels[i].SecretsSet = nil
	}
	for i := range next.VPNServers {
		next.VPNServers[i].SecretsSet = nil
		next.VPNServers[i].RealityKeySet = false
		for j := range next.VPNServers[i].Peers {
			next.VPNServers[i].Peers[j].SecretsSet = nil
		}
	}
	if previous == nil {
		return
	}
	for i := range next.Samba.Users {
		if next.Samba.Users[i].Password == "" {
			for _, u := range previous.Samba.Users {
				if u.ID == next.Samba.Users[i].ID {
					next.Samba.Users[i].Password = u.Password
					break
				}
			}
		}
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
			// A manually replaced public key invalidates a retained client key.
			// Do not merge the old private key into a different identity.
			if next.VPNServers[i].Type == "wireguard" && credentials["public_key"] != previousCredentials["public_key"] && credentials["private_key"] == "" {
				delete(credentials, "private_key")
			}
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
	mergeSecretMapAt(next, previous, "")
}

func mergeSecretMapAt(next, previous map[string]any, path string) {
	for key, value := range next {
		old, ok := previous[key]
		if !ok {
			continue
		}
		if secretConfigField(path, key) {
			if value == "" {
				next[key] = old
			}
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if oldMap, ok := old.(map[string]any); ok {
				mergeSecretMapAt(typed, oldMap, configChildPath(path, key))
			}
		case []any:
			if oldList, ok := old.([]any); ok {
				for i, child := range typed {
					if childMap, ok := child.(map[string]any); ok {
						identity := childMap
						childPath := configChildPath(path, key)
						if secretConfigField(childPath, "id") {
							identity = map[string]any{"name": childMap["name"], "email": childMap["email"]}
						}
						if oldMap := correspondingSecretMap(identity, oldList, i); oldMap != nil {
							mergeSecretMapAt(childMap, oldMap, childPath)
						}
					}
				}
			}
		}
	}
}

func configChildPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func correspondingSecretMap(child map[string]any, oldList []any, index int) map[string]any {
	for _, field := range []string{"id", "name", "email"} {
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

// Presence follows exactly the same field classification as redaction. Array
// indices are only used inside an opaque outbound, never as entity identities.
func secretPresence(values map[string]any) map[string]bool {
	result := map[string]bool{}
	var walk func(map[string]any, string, string)
	walk = func(values map[string]any, schemaPath, displayPath string) {
		for key, value := range values {
			field := configChildPath(displayPath, key)
			if secretConfigField(schemaPath, key) {
				if text, ok := value.(string); ok && text != "" {
					result[field] = true
				}
				continue
			}
			childPath := configChildPath(schemaPath, key)
			switch v := value.(type) {
			case map[string]any:
				walk(v, childPath, field)
			case []any:
				for i, item := range v {
					if m, ok := item.(map[string]any); ok {
						walk(m, childPath, field+"["+strconv.Itoa(i)+"]")
					}
				}
			}
		}
	}
	walk(values, "", "")
	return result
}
