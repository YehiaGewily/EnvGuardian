package keys

import "testing"

// FuzzParseRecipients asserts that parsing repository-controlled
// recipients.toml never panics and that an accepted file survives a
// Marshal→Parse cycle with the same fingerprint and names.
func FuzzParseRecipients(f *testing.F) {
	for _, seed := range []string{
		"[[recipient]]\nname = \"alice\"\nkey = \"age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\"\n",
		"[[recipient]]\nname = \"bob\"\nkeys = [\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bob\"]\n",
		"[[recipient]]\nname = \"rsa\"\nkey = \"ssh-rsa AAAA\"\n",
		"[[recipient]]\nname = \"dup\"\nkey = \"x\"\n[[recipient]]\nname = \"dup\"\nkey = \"x\"\n",
		"",
		"recipient = 3\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		rf, err := ParseRecipients(data)
		if err != nil {
			return
		}
		encoded, err := rf.Marshal()
		if err != nil {
			t.Fatalf("Marshal accepted recipients: %v", err)
		}
		again, err := ParseRecipients(encoded)
		if err != nil {
			t.Fatalf("re-parse of marshaled recipients failed: %v", err)
		}
		if rf.Fingerprint() != again.Fingerprint() {
			t.Fatal("recipient fingerprint changed across Marshal→Parse")
		}
		names, againNames := rf.Names(), again.Names()
		if len(names) != len(againNames) {
			t.Fatalf("recipient names changed: %v then %v", names, againNames)
		}
		for i := range names {
			if names[i] != againNames[i] {
				t.Fatalf("recipient names changed: %v then %v", names, againNames)
			}
		}
	})
}
