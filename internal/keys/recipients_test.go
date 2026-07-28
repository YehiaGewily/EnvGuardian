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
			wantSub: "duplicates a key",
		},
		{
			name: "duplicate key with different comment",
			file: RecipientsFile{Recipients: []Recipient{
				{Name: "alice", Key: k2}, {Name: "bob", Key: k2 + " alice@laptop"},
			}},
			wantSub: "duplicates a key",
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
			wantSub: "is invalid",
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

func TestMultiKeySchemaFlattensAndFingerprintsEveryKey(t *testing.T) {
	legacy := ageKey(t)
	laptop := sshKey(t)
	workstation := sshKey(t)
	file := &RecipientsFile{Recipients: []Recipient{
		{Name: "legacy", Key: legacy},
		{Name: "alice", Keys: []string{laptop, workstation}},
	}}
	if err := file.Validate(); err != nil {
		t.Fatalf("multi-key schema rejected: %v", err)
	}
	recipients, err := file.AgeRecipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 3 {
		t.Fatalf("flattened recipients = %d, want 3", len(recipients))
	}
	before := file.Fingerprint()
	file.Recipients[1].Keys[1] = sshKey(t)
	if after := file.Fingerprint(); after == before {
		t.Fatal("changing a secondary key did not change the recipient fingerprint")
	}
}

func TestMultiKeySchemaRejectsDuplicatesWithinOnePerson(t *testing.T) {
	key := sshKey(t)
	file := &RecipientsFile{Recipients: []Recipient{{Name: "alice", Keys: []string{key, key + " laptop"}}}}
	if err := file.Validate(); err == nil || !strings.Contains(err.Error(), "duplicates a key") {
		t.Fatalf("error = %v, want duplicate-key rejection", err)
	}
}

func TestRecipientSchemaReadsLegacyKeyAndWritesKeysArray(t *testing.T) {
	legacyKey := ageKey(t)
	legacyTOML := "[[recipient]]\nname = \"legacy\"\nkey = \"" + legacyKey + "\"\nsource = \"manual\"\nadded_at = \"2026-07-24\"\nadded_by = \"alice\"\n"
	legacy, err := ParseRecipients([]byte(legacyTOML))
	if err != nil {
		t.Fatalf("legacy key = rejected: %v", err)
	}
	if len(legacy.Recipients[0].PublicKeys()) != 1 {
		t.Fatalf("legacy key did not flatten: %+v", legacy.Recipients[0])
	}

	modern := &RecipientsFile{Recipients: []Recipient{{
		Name: "alice", Keys: []string{ageKey(t)}, Source: "manual", AddedAt: "2026-07-24", AddedBy: "alice",
	}}}
	encoded, err := modern.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "keys = [") || strings.Contains(string(encoded), "\nkey =") {
		t.Fatalf("modern schema encoding =\n%s", encoded)
	}
	if _, err := ParseRecipients(encoded); err != nil {
		t.Fatalf("modern schema did not round-trip: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := LoadRecipients(filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil || !strings.Contains(err.Error(), "init") {
		t.Errorf("missing file error = %v, want a hint to run init", err)
	}
}

func TestRecipientNameForSigningKey(t *testing.T) {
	sshRecipient := sshKey(t)
	pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(sshRecipient))
	if err != nil {
		t.Fatal(err)
	}
	file := &RecipientsFile{Recipients: []Recipient{
		{Name: "age-only", Key: ageKey(t)},
		{Name: "alice", Key: sshRecipient},
	}}
	if name, ok := file.RecipientNameForSigningKey(gossh.FingerprintSHA256(pub)); !ok || name != "alice" {
		t.Fatalf("SHA256 fingerprint matched %q, %v; want alice, true", name, ok)
	}
	if _, ok := file.RecipientNameForSigningKey("SHA256:not-a-recipient"); ok {
		t.Fatal("non-recipient signing fingerprint matched")
	}
}
