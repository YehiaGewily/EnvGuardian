package crypt

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestInspectStates(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")
	alice := newParty(t)
	bob := newParty(t)

	status, err := Inspect([]age.Identity{alice.id}, cipherPath, plainPath)
	if err != nil || status != (Status{}) {
		t.Fatalf("missing ciphertext status = %+v, err=%v", status, err)
	}

	ciphertext, err := encryptBytes([]byte("A=one\n"), []age.Recipient{alice.rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cipherPath, ciphertext, 0o644); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect([]age.Identity{alice.id}, cipherPath, plainPath)
	if err != nil || !status.CiphertextExists || !status.Decryptable || status.PlaintextExists || status.Matches {
		t.Fatalf("ciphertext-only status = %+v, err=%v", status, err)
	}

	if err := os.WriteFile(plainPath, []byte("A=one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect([]age.Identity{alice.id}, cipherPath, plainPath)
	if err != nil || !status.Matches {
		t.Fatalf("matching status = %+v, err=%v", status, err)
	}

	if err := os.WriteFile(plainPath, []byte("A=two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err = Inspect([]age.Identity{alice.id}, cipherPath, plainPath)
	if err != nil || status.Matches {
		t.Fatalf("changed status = %+v, err=%v", status, err)
	}

	status, err = Inspect([]age.Identity{bob.id}, cipherPath, plainPath)
	if err != nil || status.Decryptable {
		t.Fatalf("non-recipient status = %+v, err=%v", status, err)
	}

	status, err = Inspect(nil, cipherPath, plainPath)
	if err != nil || status.Decryptable {
		t.Fatalf("no-identity status = %+v, err=%v", status, err)
	}
}

func TestInspectAndDecryptToDotenvFailures(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, ".env.age")
	plainPath := filepath.Join(dir, ".env")
	alice := newParty(t)

	if err := os.WriteFile(cipherPath, []byte("not age"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect([]age.Identity{alice.id}, cipherPath, plainPath); err == nil {
		t.Fatal("Inspect accepted malformed ciphertext")
	}
	if _, err := DecryptToDotenv([]age.Identity{alice.id}, cipherPath); err == nil {
		t.Fatal("DecryptToDotenv accepted malformed ciphertext")
	}
	if _, err := DecryptToDotenv([]age.Identity{alice.id}, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("DecryptToDotenv accepted missing ciphertext")
	}

	if err := os.Remove(cipherPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cipherPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect([]age.Identity{alice.id}, cipherPath, plainPath); err == nil {
		t.Fatal("Inspect accepted unreadable ciphertext path")
	}
}

func TestDecryptToDotenvSuccess(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, ".env.age")
	alice := newParty(t)
	ciphertext, err := encryptBytes([]byte("A=one\n"), []age.Recipient{alice.rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cipherPath, ciphertext, 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := DecryptToDotenv([]age.Identity{alice.id}, cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := file.Get("A"); !ok || value != "one" {
		t.Fatal("decrypted dotenv did not contain expected key")
	}
}
