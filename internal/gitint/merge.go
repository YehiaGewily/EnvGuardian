package gitint

import (
	"sort"

	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

type mergeValue struct {
	value   string
	present bool
}

func valueFor(file *dotenv.File, key string) mergeValue {
	if file == nil {
		return mergeValue{}
	}
	value, present := file.Get(key)
	return mergeValue{value: value, present: present}
}

func sameMergeValue(a, b mergeValue) bool {
	return a.present == b.present && (!a.present || a.value == b.value)
}

// MergeDotenv applies the accepted three-way decision table. Values are used
// only in memory. A conflict result contains sorted key names and leaves ours
// untouched; a successful result retains ours formatting where possible.
func MergeDotenv(base, ours, theirs *dotenv.File) (*dotenv.File, []string) {
	keySet := make(map[string]struct{})
	for _, file := range []*dotenv.File{base, ours, theirs} {
		if file == nil {
			continue
		}
		for _, key := range file.Keys() {
			keySet[key] = struct{}{}
		}
	}
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	resolved := make(map[string]mergeValue, len(keys))
	var conflicts []string
	for _, key := range keys {
		baseValue := valueFor(base, key)
		oursValue := valueFor(ours, key)
		theirsValue := valueFor(theirs, key)
		switch {
		case sameMergeValue(oursValue, theirsValue):
			resolved[key] = oursValue
		case sameMergeValue(oursValue, baseValue):
			resolved[key] = theirsValue
		case sameMergeValue(theirsValue, baseValue):
			resolved[key] = oursValue
		default:
			conflicts = append(conflicts, key)
		}
	}
	if len(conflicts) > 0 {
		return nil, conflicts
	}
	if ours == nil {
		ours = dotenv.New()
	}
	for _, key := range keys {
		choice := resolved[key]
		if !choice.present {
			ours.Delete(key)
			continue
		}
		current, present := ours.Get(key)
		if !present || current != choice.value {
			ours.Set(key, choice.value)
		}
	}
	return ours, nil
}
