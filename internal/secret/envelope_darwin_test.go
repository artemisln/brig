//go:build darwin

package secret

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// valuePath is where the store keeps the encrypted value for name, under the
// state directory testStore pointed BRIG_STATE_DIR at.
func valuePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(os.Getenv("BRIG_STATE_DIR"), "secrets", name)
}

// rawItem is the line security holds for name, exactly as stored.
func rawItem(t *testing.T, k *testKeychain, name string) string {
	t.Helper()
	out, err := exec.Command(securityBin, "find-generic-password",
		"-s", k.service, "-a", name, "-w").Output()
	if err != nil {
		t.Fatalf("find-generic-password: %v", err)
	}
	return strings.TrimRight(string(out), "\n")
}

// keyOf is the key an item holds, or a failed test.
func keyOf(t *testing.T, k *testKeychain, name string) []byte {
	t.Helper()
	raw := rawItem(t, k, name)
	rest, ok := strings.CutPrefix(raw, keyPrefix)
	if !ok {
		t.Fatalf("the item does not start with the key marker: %q", raw[:min(len(raw), 12)])
	}
	key, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		t.Fatalf("the key is not base64: %v", err)
	}
	return key
}

// A value far past the old command-line ceiling round-trips, because the
// value no longer rides the command line at all.
func TestLargeValueRoundTrips(t *testing.T) {
	k := testStore(t)
	value := bytes.Repeat([]byte("0123456789abcdef"), 1024) // 16 KB
	if err := k.Create("big", value); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := k.Read("big")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, value) {
		t.Errorf("read back %d bytes, want %d", len(got), len(value))
	}
}

// The keychain item holds a key, never the value: nothing about the value
// can be learned from the item alone, and the item is the same size for
// every secret.
func TestKeychainItemHoldsOnlyAKey(t *testing.T) {
	k := testStore(t)
	value := []byte("argv-and-keychain-canary")
	if err := k.Create("keyed", value); err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw := rawItem(t, k, "keyed")
	if strings.Contains(raw, string(value)) || strings.Contains(raw, base64.StdEncoding.EncodeToString(value)) {
		t.Fatal("the keychain item carries the value")
	}
	if got := len(keyOf(t, k, "keyed")); got != keyLen {
		t.Errorf("the item holds a %d-byte key, want %d", got, keyLen)
	}
}

// A brig from before the envelope reads an item as base64 of the value. The
// key item must not decode that way, or an older brig would hand a guest the
// key bytes as its credential. It refuses instead, with the error it already
// has for an item it did not write.
func TestKeyItemIsNotReadableAsAValueByAnOlderBrig(t *testing.T) {
	k := testStore(t)
	if err := k.Create("marked", []byte("v")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(rawItem(t, k, "marked")); err == nil {
		t.Error("the key item decodes as base64, so an older brig would read the key as the value")
	}
}

// The value on disk is ciphertext in a file only the user can read.
func TestValueFileIsEncryptedAndPrivate(t *testing.T) {
	k := testStore(t)
	value := []byte("on-disk-canary-value")
	if err := k.Create("filed", value); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := valuePath(t, "filed")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no value file at %s: %v", path, err)
	}
	if bytes.Contains(blob, value) {
		t.Fatal("the value file holds the plaintext")
	}
	if !bytes.HasPrefix(blob, []byte(fileMagic)) {
		t.Errorf("the value file does not start with the format marker")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("value file mode = %o, want 600", perm)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Errorf("secrets directory mode = %o, want 700", perm)
	}
}

// Delete takes the file with the item, and reports absence once for both.
func TestDeleteRemovesTheValueFile(t *testing.T) {
	k := testStore(t)
	if err := k.Create("gone", []byte("v")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := k.Delete("gone"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(valuePath(t, "gone")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the value file survived Delete: %v", err)
	}
	if err := k.Delete("gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
}

// A file left behind by an interrupted create is swept up by the next Delete
// of that name, and the caller still learns the secret is not there.
func TestDeleteSweepsAnOrphanedValueFile(t *testing.T) {
	k := testStore(t)
	path := valuePath(t, "orphan")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete("orphan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the orphaned file survived: %v", err)
	}
}

// An update rewrites the file under the same key and keeps reading back.
func TestUpdateReplacesTheValueFile(t *testing.T) {
	k := testStore(t)
	if err := k.Create("rot", []byte("first")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	key := keyOf(t, k, "rot")
	if err := k.Update("rot", []byte("second")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := k.Read("rot")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("read back %q, want %q", got, "second")
	}
	if !bytes.Equal(keyOf(t, k, "rot"), key) {
		t.Error("Update replaced the key, so the file and the key were changed in two steps rather than one")
	}
	if entries, _ := os.ReadDir(filepath.Dir(valuePath(t, "rot"))); len(entries) != 1 {
		t.Errorf("the secrets directory holds %d entries after an update, want 1", len(entries))
	}
}

// legacyItem stores value the way brig did before the envelope: the base64
// value itself in the keychain item, no file. Reads must keep working on a
// store that has these.
func legacyItem(t *testing.T, k *testKeychain, name string, value []byte) {
	t.Helper()
	k.cleanup(name)
	line := "add-generic-password -s " + k.service + " -a " + name +
		` -l "brig: ` + name + `" -D "brig secret" -w ` + base64.StdEncoding.EncodeToString(value) + "\n"
	cmd := exec.Command(securityBin, "-i")
	cmd.Stdin = strings.NewReader(line)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("planting a legacy item: %v\n%s", err, out)
	}
}

func TestReadsAnItemWrittenBeforeTheEnvelope(t *testing.T) {
	k := testStore(t)
	legacyItem(t, k, "old", []byte("legacy-value"))
	got, err := k.Read("old")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "legacy-value" {
		t.Errorf("read back %q", got)
	}
}

// Updating a pre-envelope item moves it to the envelope: after the update the
// item holds a key and the value is on disk.
func TestUpdateMovesAnOldItemIntoTheEnvelope(t *testing.T) {
	k := testStore(t)
	legacyItem(t, k, "moved", []byte("legacy-value"))
	if err := k.Update("moved", []byte("new-value")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !strings.HasPrefix(rawItem(t, k, "moved"), keyPrefix) {
		t.Error("the item still holds the value rather than a key")
	}
	if _, err := os.Stat(valuePath(t, "moved")); err != nil {
		t.Errorf("no value file after the update: %v", err)
	}
	got, err := k.Read("moved")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "new-value" {
		t.Errorf("read back %q", got)
	}
}

// A key without its file is a state brig has to explain rather than report
// as "no such secret": the secret exists, and something removed half of it.
func TestReadExplainsAMissingValueFile(t *testing.T) {
	k := testStore(t)
	if err := k.Create("half", []byte("v")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := valuePath(t, "half")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, err := k.Read("half")
	if err == nil {
		t.Fatal("Read succeeded with the value file gone")
	}
	if errors.Is(err, ErrNotFound) {
		t.Error("a missing file reported as ErrNotFound, which would let import overwrite the key")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error = %v, want it to name %s", err, path)
	}
}

// A file that does not decrypt with the stored key was replaced outside
// brig, and the error says so rather than reporting a decode failure.
func TestReadExplainsAFileThatDoesNotDecrypt(t *testing.T) {
	k := testStore(t)
	if err := k.Create("one", []byte("value-one")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := k.Create("two", []byte("value-two")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	other, err := os.ReadFile(valuePath(t, "two"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valuePath(t, "one"), other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = k.Read("one")
	if err == nil {
		t.Fatal("Read succeeded on a file encrypted for another secret")
	}
	if !strings.Contains(err.Error(), "outside brig") {
		t.Errorf("error = %v, want it to say the file was changed outside brig", err)
	}
}

// A create that cannot write its file leaves no key behind: a caller told
// the create failed expects nothing to be there.
func TestCreateRollsBackTheKeyWhenTheFileCannotBeWritten(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	k := testStore(t)
	dir := filepath.Dir(valuePath(t, "x"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := k.Create("nofile", []byte("v")); err == nil {
		t.Fatal("Create succeeded without writing a file")
	}
	if _, err := k.Read("nofile"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the failed create left a key behind: %v", err)
	}
}

// The key marker and the key are short by construction, so the command line
// no longer has a ceiling a value can reach: provenance at its longest and the
// key together stay well inside security's buffer.
func TestKeyLineNeverNearsTheBuffer(t *testing.T) {
	k := keychain{service: "sh.brig.test"}
	long := Provenance{V: ProvenanceVersion, From: strings.Repeat("x", maxFromLen), ExpiresAt: 1755436980000}
	prefix, err := k.writePrefix(strings.Repeat("n", maxName), true, long)
	if err != nil {
		t.Fatal(err)
	}
	line := len(prefix) + len(keyPrefix) + base64.StdEncoding.EncodedLen(keyLen)
	if line > maxLine/2 {
		t.Errorf("the longest key line is %d bytes, too close to the %d-byte buffer", line, maxLine)
	}
}

// Two writers of one secret must not share a temp file. A fixed
// `<name>.tmp` opened without O_EXCL let a second writer truncate the first
// one's bytes from under it, and the file renamed into place then held one
// writer's nonce over the other's ciphertext: a secret nothing could open.
// The write has to land in a file only it can name, so a file already at the
// fixed spelling, unreadable and unwritable, is no obstacle.
func TestWriteDoesNotShareATempFileWithAnotherWriter(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes through a 0000 file")
	}
	k := testStore(t)
	dir := filepath.Dir(valuePath(t, "shared"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shared.tmp"), []byte("someone else's"), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := k.Create("shared", []byte("mine")); err != nil {
		t.Fatalf("Create shared the fixed temp path with another writer: %v", err)
	}
	got, err := k.Read("shared")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "mine" {
		t.Errorf("read back %q", got)
	}
}

// Sixteen concurrent updates of one secret end with a secret that opens and
// holds one of the values written. Not a proof, but a write that shared a
// temp file fails it often, and one that does not never does. An individual
// update is allowed to fail: security's own -U reports a duplicate when two
// of them collide, and that is the keychain's behaviour, not this package's.
func TestConcurrentUpdatesLeaveAReadableSecret(t *testing.T) {
	k := testStore(t)
	if err := k.Create("busy", []byte("v0")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	const n = 16
	errs := make(chan error, n)
	for i := range n {
		go func() {
			errs <- k.keychain.Update("busy", bytes.Repeat([]byte{'a' + byte(i)}, 4096))
		}()
	}
	for range n {
		<-errs
	}
	got, err := k.Read("busy")
	if err != nil {
		t.Fatalf("after concurrent updates, Read: %v", err)
	}
	if len(got) != 4096 || strings.Trim(string(got), string(got[0])) != "" {
		t.Errorf("read back a value no writer wrote: %d bytes", len(got))
	}
}

// A temp file left by a write cut short is swept by Delete along with the
// value, so a failed write does not litter the directory for good.
func TestDeleteSweepsLeftoverTempFiles(t *testing.T) {
	k := testStore(t)
	if err := k.Create("littered", []byte("v")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	dir := filepath.Dir(valuePath(t, "littered"))
	for _, leftover := range []string{"littered.0badc0de.tmp", "littered.deadbeef.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, leftover), []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A neighbour's temp file is not this secret's to sweep.
	if err := os.WriteFile(filepath.Join(dir, "littered-two.0badc0de.tmp"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete("littered"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "littered-two.0badc0de.tmp" {
		t.Errorf("after Delete the directory holds %v, want only the neighbour's temp file", names)
	}
}

// A file that is not in brig's format at all is named as such, rather than
// reported as a value that was changed. The advice differs: nothing brig
// wrote is there to update.
func TestReadNamesAFileThatIsNotAValueFile(t *testing.T) {
	k := testStore(t)
	if err := k.Create("notours", []byte("v")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(valuePath(t, "notours"), []byte("just some file"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := k.Read("notours")
	if err == nil {
		t.Fatal("Read succeeded on a file that is not a value file")
	}
	if !strings.Contains(err.Error(), "not a brig value file") {
		t.Errorf("error = %v, want it to say the file is not a brig value file", err)
	}
}

// The secrets directory is reached through a root on the state directory, so
// a symlink planted at <state>/secrets is refused rather than followed.
func TestASymlinkAtTheSecretsDirectoryIsRefused(t *testing.T) {
	k := testStore(t)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(os.Getenv("BRIG_STATE_DIR"), "secrets")); err != nil {
		t.Fatal(err)
	}
	err := k.Create("planted", []byte("v"))
	if err == nil {
		t.Fatal("Create followed a symlink at the secrets directory")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("the write landed through the symlink: %d entries", len(entries))
	}
	if _, err := k.Read("planted"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused create left a key behind: %v", err)
	}
}
