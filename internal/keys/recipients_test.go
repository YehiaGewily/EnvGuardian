package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	gossh "golang.org/x/crypto/ssh"
)

func ageKey(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

func sshKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshPub)))
}

func TestParseRecipient(t *testing.T) {
	if _, err := ParseRecipient(ageKey(t)); err != nil {
		t.Errorf("age key: %v", err)
	}
	if _, err := ParseRecipient(sshKey(t)); err != nil {
		t.Errorf("ssh key: %v", err)
	}
	if _, err := ParseRecipient("ssh-ed25519 not-base64"); err == nil {
		t.Error("malformed ssh key accepted")
	}
	if _, err := ParseRecipient("age1garbage"); err == nil {
		t.Error("malformed age key accepted")
	}
	_, err := ParseRecipient("ecdsa-sha2-nistp256 AAAA")
	if err == nil || !strings.Contains(err.Error(), "unrecognized key") {
		t.Errorf("unsupported key type: got %v", err)
	}
}

func TestValidate(t *testing.T) {
	k1, k2 := ageKey(t), sshKey(t)

	tests := []struct {
		name    string
		file    RecipientsFile
		wantSub string // "" means valid
	}{
		{
			name: "valid",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: k1}, {Name: "bob", Key: k2},
			}},
		},
		{
			name:    "empty",
			file:    RecipientsFile{},
			wantSub: "no recipients",
		},
		{
			name: "duplicate name",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: k1}, {Name: "alice", Key: k2},
			}},
			wantSub: "duplicate recipient name",
		},
		{
			name: "duplicate key",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: k1}, {Name: "bob", Key: k1},
			}},
			wantSub: "share the same key",
		},
		{
			name: "duplicate key with different comment",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: k2}, {Name: "bob", Key: k2 + " alice@laptop"},
			}},
			wantSub: "share the same key",
		},
		{
			name: "no name",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "", Key: k1},
			}},
			wantSub: "has no name",
		},
		{
			name: "no key",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: ""},
			}},
			wantSub: "has no key",
		},
		{
			name: "malformed key",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: "not-a-key"},
			}},
			wantSub: "invalid key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.Validate()
			if tt.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recipients.toml")
	orig := &RecipientsFile{Recipients: []Recipient{
		{Name: "alice", Key: ageKey(t), Source: "manual", AddedAt: "2026-07-24", AddedBy: "alice"},
		{Name: "bob", Key: sshKey(t), Source: "github:bob", AddedAt: "2026-07-24", AddedBy: "alice"},
	}}

	if err := orig.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadRecipients(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if strings.Join(loaded.Names(), ",") != "alice,bob" {
		t.Errorf("names = %v, want [alice bob]", loaded.Names())
	}
	if len(loaded.Recipients) != 2 || loaded.Recipients[0].Source != "manual" {
		t.Errorf("round-trip lost metadata: %+v", loaded.Recipients)
	}

	recs, err := loaded.AgeRecipients()
	if err != nil {
		t.Fatalf("age recipients: %v", err)
	}
	if len(recs) != 2 {
		t.Errorf("got %d age recipients, want 2", len(recs))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := LoadRecipients(filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil || !strings.Contains(err.Error(), "init") {
		t.Errorf("missing file error = %v, want a hint to run init", err)
	}
}
