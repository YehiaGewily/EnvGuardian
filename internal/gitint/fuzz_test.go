package gitint

import (
	"sort"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

// FuzzMergeDotenv asserts properties of the semantic three-way merge on
// arbitrary dotenv inputs: it never panics; swapping ours and theirs yields
// the same conflict set; conflicts name only keys that exist in an input and
// never contain a value; and a clean merge follows the decision table.
func FuzzMergeDotenv(f *testing.F) {
	f.Add("A=1\nB=2\n", "A=1\nB=3\n", "A=4\nB=2\n")
	f.Add("A=1\n", "A=2\n", "A=3\n")
	f.Add("", "A=sentinel-ours\n", "A=sentinel-theirs\n")
	f.Add("A=1\n# comment\n", "", "A=1\nC=5\n")
	f.Fuzz(func(t *testing.T, baseText, oursText, theirsText string) {
		parse := func(text string) *dotenv.File {
			file, err := dotenv.Parse(strings.NewReader(text))
			if err != nil {
				return nil
			}
			return file
		}
		base, ours, theirs := parse(baseText), parse(oursText), parse(theirsText)
		if base == nil || ours == nil || theirs == nil {
			return
		}
		inputs := []*dotenv.File{parse(baseText), parse(oursText), parse(theirsText)}

		merged, conflicts := MergeDotenv(base, ours, theirs)
		_, swapped := MergeDotenv(parse(baseText), parse(theirsText), parse(oursText))
		sort.Strings(conflicts)
		sort.Strings(swapped)
		if strings.Join(conflicts, "\x00") != strings.Join(swapped, "\x00") {
			t.Fatal("conflict set depends on which side is ours")
		}
		for _, key := range conflicts {
			known := false
			for _, file := range inputs {
				if _, ok := file.Get(key); ok {
					known = true
				}
			}
			if !known {
				t.Fatal("conflict names a key that is in no input")
			}
		}
		if len(conflicts) > 0 {
			if merged != nil {
				t.Fatal("conflicting merge returned a result")
			}
			return
		}
		for _, key := range mergedKeys(inputs) {
			baseValue, inBase := inputs[0].Get(key)
			oursValue, inOurs := inputs[1].Get(key)
			theirsValue, inTheirs := inputs[2].Get(key)
			want, wantPresent := oursValue, inOurs
			if inOurs == inBase && (!inOurs || oursValue == baseValue) {
				want, wantPresent = theirsValue, inTheirs
			}
			got, present := merged.Get(key)
			if present != wantPresent || (present && got != want) {
				t.Fatalf("clean merge of key %q does not follow the decision table", key)
			}
		}
	})
}

func mergedKeys(files []*dotenv.File) []string {
	set := make(map[string]struct{})
	for _, file := range files {
		for _, key := range file.Keys() {
			set[key] = struct{}{}
		}
	}
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
