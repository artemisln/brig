//go:build darwin

package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// testNative is a native store scoped to a service of its own, which removes
// every secret it created when the test ends. The removal is native too: the
// test binary created the items, so it is the application their ACL trusts,
// and no dialog is involved.
type testNative struct {
	*nativeKeychain
	t *testing.T
}

func testNativeStore(t *testing.T) *testNative {
	t.Helper()
	t.Setenv("BRIG_STATE_DIR", t.TempDir())
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	svc := fmt.Sprintf("%s%x-%s", testService, b, t.Name())
	n, err := openNative(svc, keychain{service: svc})
	if err != nil {
		t.Fatalf("openNative: %v", err)
	}
	return &testNative{nativeKeychain: n, t: t}
}

func (n *testNative) Create(name string, value []byte) error {
	n.cleanup(name)
	return n.nativeKeychain.Create(name, value)
}

func (n *testNative) Update(name string, value []byte) error {
	n.cleanup(name)
	return n.nativeKeychain.Update(name, value)
}

func (n *testNative) Write(name string, value []byte, p Provenance, update bool) error {
	n.cleanup(name)
	return n.nativeKeychain.Write(name, value, p, update)
}

func (n *testNative) cleanup(name string) {
	n.t.Cleanup(func() { _ = n.Delete(name) })
}

// The value goes into the item itself, whatever its shape or size: no
// command line, no encoding, no file.
func TestNativeCreateAndReadRoundTrip(t *testing.T) {
	n := testNativeStore(t)
	cases := map[string][]byte{
		"plain":   []byte("ghp_16C7e42F292c6912E7710c838347Ae178B4a"),
		"newline": []byte("-----BEGIN KEY-----\nabc\n-----END KEY-----\n"),
		"quotes":  []byte(`a "quoted" \ value`),
		"binary":  {0, 1, 2, 255, 254, 0},
		"large":   bytes.Repeat([]byte("0123456789abcdef"), 1024),
	}
	for name, value := range cases {
		if err := n.Create(name, value); err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
		got, err := n.Read(name)
		if err != nil {
			t.Fatalf("Read %s: %v", name, err)
		}
		if !bytes.Equal(got, value) {
			t.Errorf("%s: read back %q, want %q", name, got, value)
		}
	}
	if entries, _ := os.ReadDir(os.Getenv("BRIG_STATE_DIR")); len(entries) != 0 {
		t.Errorf("the native store wrote %d entries under the state directory, want none", len(entries))
	}
}

func TestNativeCreateRefusesACollision(t *testing.T) {
	n := testNativeStore(t)
	if err := n.Create("dup", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := n.Create("dup", []byte("second")); !errors.Is(err, ErrExists) {
		t.Fatalf("second Create = %v, want ErrExists", err)
	}
	got, _ := n.Read("dup")
	if string(got) != "first" {
		t.Errorf("the collision changed the value to %q", got)
	}
}

func TestNativeUpdateReplacesButNeverCreates(t *testing.T) {
	n := testNativeStore(t)
	if err := n.Update("absent", []byte("v")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update of an absent secret = %v, want ErrNotFound", err)
	}
	if _, err := n.Read("absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Update created the secret: %v", err)
	}
	if err := n.Create("rot", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := n.Update("rot", []byte("second")); err != nil {
		t.Fatal(err)
	}
	got, _ := n.Read("rot")
	if string(got) != "second" {
		t.Errorf("read back %q", got)
	}
}

func TestNativeReadAndDeleteReportAbsence(t *testing.T) {
	n := testNativeStore(t)
	if _, err := n.Read("nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read = %v, want ErrNotFound", err)
	}
	if err := n.Delete("nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete = %v, want ErrNotFound", err)
	}
	if err := n.Create("gone", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := n.Delete("gone"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Read("gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read after Delete = %v, want ErrNotFound", err)
	}
}

// List reads attributes only, and reports the provenance and the date the
// item carries, for this service and no other.
func TestNativeListReportsProvenanceAndStaysInItsNamespace(t *testing.T) {
	n := testNativeStore(t)
	p := Provenance{V: ProvenanceVersion, From: "keychain:Some App", ExpiresAt: 1755436980000}
	if err := n.Write("imported", []byte("v"), p, false); err != nil {
		t.Fatal(err)
	}
	if err := n.Create("plain", []byte("v")); err != nil {
		t.Fatal(err)
	}
	other := testNativeStore(t)
	if err := other.Create("elsewhere", []byte("v")); err != nil {
		t.Fatal(err)
	}
	list, err := n.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "imported" || list[1].Name != "plain" {
		t.Fatalf("List = %+v, want imported and plain", list)
	}
	if list[0].Provenance != p {
		t.Errorf("provenance = %+v, want %+v", list[0].Provenance, p)
	}
	if !list[1].Provenance.IsZero() {
		t.Errorf("a hand-created secret carries provenance %+v", list[1].Provenance)
	}
	for _, s := range list {
		if time.Since(s.Modified) > time.Hour || s.Modified.IsZero() {
			t.Errorf("%s: Modified = %v, want about now", s.Name, s.Modified)
		}
	}
}

// An update with no provenance clears the old one, the same rule the CLI
// store follows, so a renewed value never reports the previous expiry.
func TestNativeUpdateWithNoProvenanceClearsTheOldOne(t *testing.T) {
	n := testNativeStore(t)
	p := Provenance{V: ProvenanceVersion, From: "file:~/x", ExpiresAt: 1}
	if err := n.Write("renewed", []byte("old"), p, false); err != nil {
		t.Fatal(err)
	}
	if err := n.Update("renewed", []byte("new")); err != nil {
		t.Fatal(err)
	}
	list, err := n.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || !list[0].Provenance.IsZero() {
		t.Errorf("List = %+v, want one secret with no provenance", list)
	}
}

// An item security(1) wrote is not this binary's to decrypt, and the native
// store must neither hang on a dialog nor report it absent. It reads it the
// way it was written: through security.
func TestNativeReadsAnItemSecurityWroteWithoutADialog(t *testing.T) {
	n := testNativeStore(t)
	plant(t, n.service, "old", base64.StdEncoding.EncodeToString([]byte("legacy-value")))
	done := make(chan struct{})
	var got []byte
	var err error
	go func() {
		got, err = n.Read("old")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Read of an item security wrote did not return, so a dialog is up")
	}
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "legacy-value" {
		t.Errorf("read back %q", got)
	}
	if _, err := n.readNative("old"); err == nil {
		t.Error("the item security wrote opened natively, so this test is not testing the fallback")
	}
}

// Writing to an item security(1) wrote moves it to the native store: after
// the update the item opens natively, and the value is the new one.
func TestNativeUpdateMovesAnItemSecurityWrote(t *testing.T) {
	n := testNativeStore(t)
	plant(t, n.service, "moved", base64.StdEncoding.EncodeToString([]byte("legacy-value")))
	if err := n.Update("moved", []byte("new-value")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := n.readNative("moved")
	if err != nil {
		t.Fatalf("after Update the item does not open natively: %v", err)
	}
	if string(got) != "new-value" {
		t.Errorf("read back %q", got)
	}
}

// Delete of an item security(1) wrote goes through, whichever path has to
// remove it.
func TestNativeDeletesAnItemSecurityWrote(t *testing.T) {
	n := testNativeStore(t)
	plant(t, n.service, "stale", base64.StdEncoding.EncodeToString([]byte("v")))
	if err := n.Delete("stale"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := n.Read("stale"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Read after Delete = %v, want ErrNotFound", err)
	}
}

// The test binary is ad-hoc signed, which is what a plain `go build` is
// too. That is the build the native store must not be the default for.
func TestATestBinaryIsAdhocSigned(t *testing.T) {
	adhoc, err := adhocSigned()
	if err != nil {
		t.Fatalf("adhocSigned: %v", err)
	}
	if !adhoc {
		t.Error("the test binary reports a stable signature, so the default would be native and every rebuild a new application to the keychain")
	}
}

// BRIG_KEYCHAIN picks the backend by hand, and an unknown value is refused
// by name rather than silently picking one.
func TestBackendSelection(t *testing.T) {
	t.Setenv("BRIG_KEYCHAIN", "security")
	s, err := open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(keychain); !ok {
		t.Errorf("BRIG_KEYCHAIN=security opened %T", s)
	}
	t.Setenv("BRIG_KEYCHAIN", "native")
	s, err = open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*nativeKeychain); !ok {
		t.Errorf("BRIG_KEYCHAIN=native opened %T", s)
	}
	t.Setenv("BRIG_KEYCHAIN", "")
	s, err = open()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(keychain); !ok {
		t.Errorf("an ad-hoc signed binary with BRIG_KEYCHAIN unset opened %T, want the security fallback", s)
	}
	t.Setenv("BRIG_KEYCHAIN", "bogus")
	if _, err := open(); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Errorf("BRIG_KEYCHAIN=bogus: err = %v, want a refusal naming it", err)
	}
}

// The security store cannot decrypt an item the native store wrote: that
// item's ACL names brig's signed binary, not security(1), and asking
// security to read it puts a keychain dialog on screen, which headless is a
// hang. The security store has to tell such an item apart from its own by
// attributes alone, and refuse it with the reason, without ever asking for
// the value. Deleting one is different: security removes an item without
// decrypting it, measured, and a delete is what the user asked for.
func TestSecurityStoreRefusesToReadANativeItemWithoutADialog(t *testing.T) {
	n := testNativeStore(t)
	if err := n.Create("native-only", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// If the refusal is not there yet, security is sitting on a dialog;
	// take it down so the run can end.
	t.Cleanup(func() {
		_ = exec.Command("pkill", "-f", "find-generic-password -s "+n.service).Run()
	})
	cli := keychain{service: n.service}
	done := make(chan error, 1)
	go func() { _, err := cli.Read("native-only"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read through security succeeded on a native item")
		} else if !strings.Contains(err.Error(), "Security.framework") {
			t.Errorf("Read = %v, want a refusal naming the native store", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read through security did not return, so a keychain dialog is up")
	}
	if _, err := n.readNative("native-only"); err != nil {
		t.Errorf("the refused read damaged the native item: %v", err)
	}
	if err := cli.Delete("native-only"); err != nil {
		t.Errorf("Delete through security of a native item: %v", err)
	}
	if _, err := n.readNative("native-only"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Delete through security the native item is still there: %v", err)
	}
}

// The trusted list reaches the item's access: a path that is not there is
// refused by name before anything is written. That an included binary
// reads the item without a dialog cannot be shown here, because the test
// binary is ad-hoc signed and the keychain's partition list, a second gate
// on top of the ACL, admits only binaries of the writer's team; it is
// measured by hand with two binaries signed alike, see the pull request.
func TestNativeAddRefusesATrustedPathThatIsNotThere(t *testing.T) {
	n := testNativeStore(t)
	n.trust = []string{"/nonexistent/brigd"}
	err := n.Create("untrusting", []byte("v"))
	if err == nil {
		t.Fatal("Create succeeded with a trusted path that does not exist")
	}
	if !strings.Contains(err.Error(), "/nonexistent/brigd") {
		t.Errorf("err = %v, want it to name the path", err)
	}
	if _, err := n.Read("untrusting"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refused create left an item behind: %v", err)
	}
}

// A move that fails after the security item is removed puts it back as it
// was, provenance included, so the stale-credential warning that reads the
// provenance keeps working for it.
func TestFailedMoveRestoresTheProvenance(t *testing.T) {
	n := testNativeStore(t)
	p := Provenance{V: ProvenanceVersion, From: "keychain:Some App", ExpiresAt: 1755436980000}
	encoded, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plant(t, n.service, "kept", base64.StdEncoding.EncodeToString([]byte("old")), encoded)
	n.beforeAdd = func() error { return errors.New("injected: the native add failed") }
	if err := n.Update("kept", []byte("new")); err == nil {
		t.Fatal("Update succeeded although the native add was made to fail")
	}
	got, err := n.Read("kept")
	if err != nil {
		t.Fatalf("after the failed move the old item is gone: %v", err)
	}
	if string(got) != "old" {
		t.Errorf("read back %q, want the old value", got)
	}
	list, err := n.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Provenance != p {
		t.Errorf("List = %+v, want the old item with its provenance %+v", list, p)
	}
}

// bind reports a symbol it cannot resolve as an error, so open() falls back
// to the security store rather than crashing every command on a macOS that
// dropped one of the calls.
func TestBindReportsAMissingSymbolAsAnError(t *testing.T) {
	err := bindSymbols(func(lib uintptr, name string) (uintptr, error) {
		return 0, errors.New("dlsym: symbol not found: " + name)
	})
	if err == nil {
		t.Fatal("bind succeeded with no symbol resolvable")
	}
	if !strings.Contains(err.Error(), "symbol not found") {
		t.Errorf("err = %v, want the resolver's own reason", err)
	}
}
