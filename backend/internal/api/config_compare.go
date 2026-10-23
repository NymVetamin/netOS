package api

import (
	"encoding/json"
	"reflect"
)

// comparisonValue copies the typed configuration tree, making empty lists
// equivalent to nil. Maps/interfaces contain opaque provider configuration:
// null, [] and missing keys there may have different meanings and stay intact.
// This affects comparison only, never the stored or applied configuration.
func comparisonValue(v reflect.Value) reflect.Value {
	if v.Type().Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) {
		return v
	}
	switch v.Kind() {
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(comparisonValue(v.Field(i)))
			}
		}
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(comparisonValue(v.Elem()))
		return out
	case reflect.Slice:
		// Byte slices serialize as data, not JSON arrays.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		if v.Len() == 0 {
			return reflect.Zero(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(comparisonValue(v.Index(i)))
		}
		return out
	default:
		return v
	}
}
