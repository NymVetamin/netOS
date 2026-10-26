package api

import (
	"github.com/netos-router/netos/internal/config"
	"reflect"
	"strconv"
	"strings"
)

var planChannelSchemas = map[string]reflect.Type{
	"wireguard": reflect.TypeOf(config.WireGuardChannelConfig{}), "openconnect": reflect.TypeOf(config.OpenConnectChannelConfig{}),
	"l2tp": reflect.TypeOf(config.L2TPChannelConfig{}), "ikev2": reflect.TypeOf(config.IKEv2ChannelConfig{}), "xray": reflect.TypeOf(config.XrayChannelConfig{}),
}
var planServerSchemas = map[string]reflect.Type{
	"wireguard": reflect.TypeOf(config.WireGuardServerConfig{}), "ocserv": reflect.TypeOf(config.OcservServerConfig{}),
	"l2tp": reflect.TypeOf(config.L2TPServerConfig{}), "ikev2": reflect.TypeOf(config.IKEv2ServerConfig{}), "xray": reflect.TypeOf(config.XrayServerConfig{}),
}

type planField struct {
	Label, Key, Format, Reference, Identity string
	Sensitive, Ignored                      bool
}

func indirectPlanType(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

func planIdentity(t reflect.Type) string {
	t = indirectPlanType(t)
	if t == nil || t.Kind() != reflect.Slice {
		return ""
	}
	t = indirectPlanType(t.Elem())
	if t.Kind() != reflect.Struct {
		return ""
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Tag.Get("identity") == "true" {
			return strings.Split(f.Tag.Get("json"), ",")[0]
		}
	}
	return ""
}

func planFieldByJSON(t reflect.Type, key string) (reflect.StructField, bool) {
	t = indirectPlanType(t)
	if t == nil || t.Kind() != reflect.Struct {
		return reflect.StructField{}, false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		jsonName := strings.Split(f.Tag.Get("json"), ",")[0]
		if jsonName == "" {
			jsonName = f.Name
		}
		if jsonName == key {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

func planArrayItem(raw any, key, id string) any {
	list, _ := raw.([]any)
	if key != "" {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok && m[key] == id {
				return item
			}
		}
		return nil
	}
	index, err := strconv.Atoi(id)
	if err == nil && index >= 0 && index < len(list) {
		return list[index]
	}
	return nil
}

// Resolve display metadata from schema tags. Values are used only to identify
// typed objects and select provider schemas. Opaque JSON never supplies IDs.
func resolvePlanField(after, before any, path []string) planField {
	typ := reflect.TypeOf(config.Config{})
	a, b := after, before
	out := planField{}
	providerPath := ""
	inProvider := false
	secretParent := false
	for _, part := range path {
		typ = indirectPlanType(typ)
		if typ != nil && typ.Kind() == reflect.Slice {
			identity := planIdentity(typ)
			a = planArrayItem(a, identity, part)
			b = planArrayItem(b, identity, part)
			name := part
			for _, value := range []any{a, b} {
				m, _ := value.(map[string]any)
				for _, key := range []string{"name", "hostname", "ssid", "label", "mac", "address"} {
					if text, ok := m[key].(string); ok && text != "" {
						name = text
						break
					}
				}
				if name != part {
					break
				}
			}
			if typ.Elem() == reflect.TypeOf(config.Component{}) {
				if c, ok := config.ComponentByID(part); ok {
					name = c.Title
				}
			}
			out.Label += " «" + name + "»"
			typ = typ.Elem()
			continue
		}
		// Arrays inside provider JSON are positional, including UUID-bearing users.
		_, aa := a.([]any)
		_, ba := b.([]any)
		if aa || ba {
			a = planArrayItem(a, "", part)
			b = planArrayItem(b, "", part)
			number := part
			if n, err := strconv.Atoi(part); err == nil {
				number = strconv.Itoa(n + 1)
			}
			out.Label += " · Запись " + number
			typ = nil
			continue
		}
		am, _ := a.(map[string]any)
		bm, _ := b.(map[string]any)
		f, known := planFieldByJSON(typ, part)
		label := part
		out.Key = part
		out.Format = ""
		out.Reference = ""
		out.Sensitive = true
		if known {
			if title := f.Tag.Get("plan"); title != "" {
				label = title
			}
			out.Ignored = out.Ignored || label == "-"
			out.Sensitive = secretParent || f.Tag.Get("sensitivity") != "public"
			secretParent = out.Sensitive
			out.Format = f.Tag.Get("format")
			out.Reference = f.Tag.Get("reference")
		} else if secretParent || secretConfigField(providerPath, part) {
			secretParent = true
		}
		if out.Label != "" {
			out.Label += " · "
		}
		out.Label += label
		nextType := reflect.Type(nil)
		if known {
			nextType = f.Type
		}
		if known && part == "config" {
			provider, _ := am["type"].(string)
			if provider == "" {
				provider, _ = bm["type"].(string)
			}
			if typ == reflect.TypeOf(config.Channel{}) {
				if t := planChannelSchemas[provider]; t != nil {
					nextType = t
				}
			}
			if typ == reflect.TypeOf(config.VPNServer{}) {
				if t := planServerSchemas[provider]; t != nil {
					nextType = t
				}
			}
			providerPath = ""
			inProvider = true
		} else if inProvider {
			providerPath = configChildPath(providerPath, part)
		}
		a, b = am[part], bm[part]
		typ = nextType
	}
	out.Identity = planIdentity(typ)
	return out
}
