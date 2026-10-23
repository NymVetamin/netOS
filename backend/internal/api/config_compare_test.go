package api

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/netos-router/netos/internal/config"
)

func TestSameConfigAllTypedLists(t *testing.T) {
	a, b := &config.Config{}, &config.Config{}
	count := 0
	var visit func(reflect.Value, reflect.Value, string)
	visit = func(x, y reflect.Value, path string) {
		switch x.Kind() {
		case reflect.Struct:
			for i := 0; i < x.NumField(); i++ {
				if x.Type().Field(i).IsExported() {
					visit(x.Field(i), y.Field(i), path+"."+x.Type().Field(i).Name)
				}
			}
		case reflect.Pointer:
			x.Set(reflect.New(x.Type().Elem()))
			y.Set(reflect.New(y.Type().Elem()))
			visit(x.Elem(), y.Elem(), path)
		case reflect.Slice:
			if x.Type().Elem().Kind() == reflect.Uint8 {
				return
			}
			count++
			x.Set(reflect.Zero(x.Type()))
			y.Set(reflect.MakeSlice(y.Type(), 0, 0))
			t.Run(path, func(t *testing.T) {
				beforeA, _ := json.Marshal(a)
				beforeB, _ := json.Marshal(b)
				if !sameConfig(a, b) || !sameConfig(b, a) {
					t.Fatal("empty list differs from nil")
				}
				afterA, _ := json.Marshal(a)
				afterB, _ := json.Marshal(b)
				if string(beforeA) != string(afterA) || string(beforeB) != string(afterB) {
					t.Fatal("comparison mutated configuration")
				}
			})
			x.Set(reflect.MakeSlice(x.Type(), 1, 1))
			y.Set(reflect.MakeSlice(y.Type(), 1, 1))
			visit(x.Index(0), y.Index(0), path+"[0]")
		}
	}
	visit(reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem(), "Config")
	if count < 30 {
		t.Fatalf("unexpectedly incomplete schema coverage: %d", count)
	}
	t.Logf("checked %d typed lists including nested configuration", count)
}

func TestSameConfigPreservesMeaningfulDifferences(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*config.Config)
	}{
		{"order", func(c *config.Config) { c.DNS.Bootstrap = []string{"8.8.8.8", "1.1.1.1"} }},
		{"value", func(c *config.Config) { c.DNS.Bootstrap[0] = "9.9.9.9" }},
		{"pointer", func(c *config.Config) { c.Policies[0].Schedule = &config.Schedule{} }},
		{"opaque-null-array", func(c *config.Config) { c.Channels[0].Config["items"] = []any{} }},
		{"opaque-missing-key", func(c *config.Config) { delete(c.Channels[0].Config, "items") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			makeConfig := func() *config.Config {
				c := config.Default()
				c.DNS.Bootstrap = []string{"1.1.1.1", "8.8.8.8"}
				c.Policies = []config.Policy{{}}
				c.Channels = []config.Channel{{Config: map[string]any{"items": nil}}}
				return c
			}
			a, b := makeConfig(), makeConfig()
			test.change(b)
			if sameConfig(a, b) {
				t.Fatal("meaningful change ignored")
			}
		})
	}
}
