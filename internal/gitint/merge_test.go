package gitint

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/YehiaGewily/envguardian/internal/dotenv"
)

func mergeFile(t *testing.T, text string) *dotenv.File {
	t.Helper()
	file, err := dotenv.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestMergeDotenvDecisionTable(t *testing.T) {
	tests := []struct {
		name, base, ours, theirs string
		want                     map[string]string
		conflict                 bool
	}{
		{name: "add add equal", ours: "K=same\n", theirs: "K=same\n", want: map[string]string{"K": "same"}},
		{name: "add add conflict", ours: "K=ours\n", theirs: "K=theirs\n", conflict: true},
		{name: "theirs adds", theirs: "K=theirs\n", want: map[string]string{"K": "theirs"}},
		{name: "ours modifies", base: "K=base\n", ours: "K=ours\n", theirs: "K=base\n", want: map[string]string{"K": "ours"}},
		{name: "theirs modifies", base: "K=base\n", ours: "K=base\n", theirs: "K=theirs\n", want: map[string]string{"K": "theirs"}},
		{name: "same modification", base: "K=base\n", ours: "K=next\n", theirs: "K=next\n", want: map[string]string{"K": "next"}},
		{name: "modify conflict", base: "K=base\n", ours: "K=ours\n", theirs: "K=theirs\n", conflict: true},
		{name: "ours deletes", base: "K=base\n", theirs: "K=base\n", want: map[string]string{}},
		{name: "theirs deletes", base: "K=base\n", ours: "K=base\n", want: map[string]string{}},
		{name: "delete modify conflict", base: "K=base\n", theirs: "K=theirs\n", conflict: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := mergeFile(t, tt.base)
			ours := mergeFile(t, tt.ours)
			theirs := mergeFile(t, tt.theirs)
			merged, conflicts := MergeDotenv(base, ours, theirs)
			if tt.conflict {
				if !reflect.DeepEqual(conflicts, []string{"K"}) {
					t.Fatalf("conflicts = %v", conflicts)
				}
				return
			}
			if len(conflicts) != 0 {
				t.Fatalf("conflicts = %v", conflicts)
			}
			if len(merged.Keys()) != len(tt.want) {
				t.Fatalf("keys = %v, want %v", merged.Keys(), tt.want)
			}
			for key, want := range tt.want {
				if got, ok := merged.Get(key); !ok || got != want {
					t.Fatalf("%s = %q, %v", key, got, ok)
				}
			}
		})
	}
}

func TestMergeDotenvIgnoresReorderingAndComments(t *testing.T) {
	base := mergeFile(t, "A=1\nB=2\n")
	oursText := "# ours comment\nB=2\nA=1\n"
	ours := mergeFile(t, oursText)
	theirs := mergeFile(t, "A=1\n# theirs comment\nB=2\n")
	merged, conflicts := MergeDotenv(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %v", conflicts)
	}
	var out bytes.Buffer
	if _, err := merged.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != oursText {
		t.Fatalf("format changed:\n%s", out.String())
	}
}

func TestMergeDotenvBuildsFileWhenOursIsAbsent(t *testing.T) {
	theirs := mergeFile(t, "A=1\n")
	merged, conflicts := MergeDotenv(nil, nil, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("conflicts = %v", conflicts)
	}
	if value, ok := merged.Get("A"); !ok || value != "1" {
		t.Fatalf("A = %q, %v", value, ok)
	}
}
