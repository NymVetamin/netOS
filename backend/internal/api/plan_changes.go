package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	"github.com/netos-router/netos/internal/apply"
	"github.com/netos-router/netos/internal/config"
	"github.com/netos-router/netos/internal/configdiff"
)

type planChange struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Kind   string `json:"kind"`
	Before string `json:"before"`
	After  string `json:"after"`
}

type planResponse struct {
	Actions      []apply.Action `json:"actions"`
	Changes      []planChange   `json:"changes"`
	NeedsConfirm bool           `json:"needs_confirm"`
	DraftVersion uint64         `json:"draft_version"`
}

func describePlan(r *http.Request, old, next *config.Config, actions []apply.Action, version uint64) (planResponse, error) {
	before, after := old, next
	var err error
	if roleOf(r) != "" { // Unix/root callers have no panel projection.
		if old != nil {
			before, err = projectConfig(r, old)
			if err != nil {
				return planResponse{}, err
			}
		}
		after, err = projectConfig(r, next)
		if err != nil {
			return planResponse{}, err
		}
	}
	return planResponse{actions, configurationChanges(before, after), old != nil && apply.NeedsConfirmation(actions), version}, nil
}

func configurationChanges(old, next *config.Config) []planChange {
	object := func(c *config.Config) any {
		if c == nil {
			return nil
		}
		raw, _ := json.Marshal(comparisonValue(reflect.ValueOf(c)).Interface())
		var value any
		_ = json.Unmarshal(raw, &value)
		return value
	}
	a, b := object(old), object(next)
	changes := configdiff.Diff(a, b, func(path []string) string { return resolvePlanField(b, a, path).Identity })
	result := []planChange{}
	for _, change := range changes {
		field := resolvePlanField(b, a, change.Path)
		if field.Ignored {
			continue
		}
		path := []string{}
		for _, part := range change.Path {
			path = append(path, strings.NewReplacer("~", "~0", "/", "~1").Replace(part))
		}
		label := field.Label
		if change.Kind == "reorder" {
			label += " · Порядок"
			path = append(path, "@order")
			// Display named objects, including insertion/removal positions.
			names := func(value configdiff.Value, root, other any) configdiff.Value {
				ids, _ := value.Data.([]any)
				result := []any{}
				for _, id := range ids {
					part, _ := id.(string)
					p := append(append([]string{}, change.Path...), part)
					result = append(result, resolvePlanField(root, other, p).Label)
				}
				return configdiff.Value{Present: value.Present, Data: result}
			}
			change.Before = names(change.Before, a, b)
			change.After = names(change.After, b, a)
		}
		result = append(result, planChange{"/" + strings.Join(path, "/"), label, change.Kind, formatPlanValue(change.Before, field, old), formatPlanValue(change.After, field, next)})
	}
	return result
}
