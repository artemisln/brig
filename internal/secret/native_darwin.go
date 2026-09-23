//go:build darwin

package secret

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// nativeKeychain is the login keychain reached through Security.framework
// rather than through security(1).
//
// Two things change against the CLI backend. The value goes into the item as
// bytes, with no command line in the way, so there is no size ceiling and no
// encoding. And the item's ACL names brig: an item this store creates is
// readable by brig without a dialog, and by nothing else without one. That
// is the per-application ACL docs/security.md says the CLI backend cannot
// give, and it is what a code signature with a stable designated requirement
// buys.
//
// It is also what makes the CLI backend still necessary. An item security(1)
// wrote trusts security(1), not brig, so this store cannot decrypt it. Rather
// than raise a dialog, which brig never does, user interaction is disabled
// for the process, the read fails with a known code, and the fallback reads
// it the way it was written. A write to such an item moves it: the value is
// read through security, the item removed through security, and a native
// item put in its place. See docs/secrets.md.
type nativeKeychain struct {
	service  string
	fallback keychain
	// trust is every other binary an item this store writes must open for:
	// brigd when this is brig, since the daemon resolves a run's secrets,
	// and brig when this is brigd. Found beside this executable.
	trust []string
	// beforeAdd, when set, runs before every SecItemAdd. Tests use it to
	// make an add fail at the one point a move cannot roll back by itself.
	beforeAdd func() error
}

var _ Store = (*nativeKeychain)(nil)
var _ Annotator = (*nativeKeychain)(nil)

// nativeDescription is the kind attribute on an item this store writes. The
// CLI backend reads it, attributes only, before it would ask security for
// the value, because security cannot decrypt such an item and would put a
// keychain dialog up trying. The CLI backend's own items say "brig secret".
const nativeDescription = "brig secret (native)"

// openNative binds the frameworks and turns dialogs off for this process.
func openNative(service string, fallback keychain) (*nativeKeychain, error) {
	if err := bind(); err != nil {
		return nil, err
	}
	// Without this, a read of an item this binary is not trusted for puts a
	// keychain dialog on screen and blocks until it is answered. brig runs
	// headless as often as not, and a dialog nobody sees is a hang. With it,
	// the same read returns errSecInteractionNotAllowed, and the fallback
	// takes over.
	if err := osStatus("SecKeychainSetUserInteractionAllowed", cf.keychainSetInteractionAllowed(false)); err != nil {
		return nil, err
	}
	return &nativeKeychain{service: service, fallback: fallback, trust: siblingBinaries()}, nil
}

// siblingBinaries is the other half of brig found beside this executable:
// brigd next to brig, brig next to brigd. The daemon resolves secrets for
// every run it boots, so an item the CLI wrote has to open for it too. A
// sibling that is not there is not trusted, and an item written then does
// not open for a daemon installed later; a re-import fixes that.
func siblingBinaries() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	var sibling string
	switch filepath.Base(exe) {
	case "brig":
		sibling = "brigd"
	case "brigd":
		sibling = "brig"
	default:
		return nil
	}
	path := filepath.Join(filepath.Dir(exe), sibling)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return []string{path}
}

func (n *nativeKeychain) Kind() string { return "keychain (native)" }

// errNotOurs means the item exists and this binary is not on its ACL. The
// store answers it from a read with errSecInteractionNotAllowed when a
// dialog was the only way through and dialogs are off, and with
// errSecAuthFailed or errSecUserCanceled when one was refused. A delete or
// an update answers errSecInvalidOwnerEdit or errSecNoAccessForItem:
// measured, deleting an item security(1) created returns -25244. The list
// is deliberately a whitelist: any other failure, a locked keychain, a bad
// argument, is reported as itself rather than routed to the fallback.
var errNotOurs = errors.New("the item is not this application's to open")

// errKeychainLocked is a locked login keychain, which with dialogs off
// answers like an item that is not ours. Reported as itself, with the
// unlock as the fix, rather than sent down the fallback, where security(1)
// would put the unlock dialog up.
var errKeychainLocked = errors.New("the login keychain is locked. Unlock it: security unlock-keychain")

// osStatus turns an OSStatus into the error the rest of brig understands, or
// nil. Every framework call goes through it, so the mapping lives once.
func osStatus(call string, st int32) error {
	switch st {
	case errSecSuccess:
		return nil
	case errSecItemNotFound:
		return ErrNotFound
	case errSecDuplicateItem:
		return ErrExists
	case errSecInteractionNotAllowed:
		// Also what a locked keychain answers once dialogs are off, and
		// that one is not an ACL question.
		if locked, err := keychainLocked(); err == nil && locked {
			return fmt.Errorf("%s: %w", call, errKeychainLocked)
		}
		return fmt.Errorf("%s: %w", call, errNotOurs)
	case errSecAuthFailed, errSecUserCanceled, errSecInvalidOwnerEdit, errSecNoAccessForItem:
		return fmt.Errorf("%s: %w", call, errNotOurs)
	default:
		return fmt.Errorf("%s: OSStatus %d", call, st)
	}
}

// query is the dictionary that names one item.
func (n *nativeKeychain) query(name string) *dict {
	d := newDict()
	d.set(cf.kSecClass, cf.kSecClassGenericPassword)
	d.setString(cf.kSecAttrService, n.service)
	d.setString(cf.kSecAttrAccount, name)
	return d
}

func (n *nativeKeychain) Create(name string, value []byte) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return n.Write(name, value, Provenance{}, false)
}

func (n *nativeKeychain) Update(name string, value []byte) error {
	if err := ValidName(name); err != nil {
		return err
	}
	return n.Write(name, value, Provenance{}, true)
}

// Write stores value with its provenance, creating or updating.
//
// An update reads the item first, and the read is the probe: SecItemUpdate
// on an item security(1) wrote goes through, measured, so the ACL that
// keeps this binary from decrypting such an item does not keep it from
// overwriting one. An item the read answers errNotOurs for is moved rather
// than updated in place, so that it ends up as an item brig can read. The
// old value is read through security first and held, so that if the native
// add fails after the security delete, the item can be put back the way it
// was.
func (n *nativeKeychain) Write(name string, value []byte, p Provenance, update bool) error {
	comment := ""
	if !p.IsZero() {
		encoded, err := p.Encode()
		if err != nil {
			return err
		}
		comment = encoded
	}
	if !update {
		return n.add(name, value, comment)
	}
	_, err := n.readNative(name)
	if errors.Is(err, errNotOurs) {
		return n.move(name, value, comment)
	}
	if err != nil {
		return err
	}
	return n.update(name, value, comment)
}

// add creates the item. A duplicate is security's own answer, so no
// check-then-write window exists here.
func (n *nativeKeychain) add(name string, value []byte, comment string) error {
	if n.beforeAdd != nil {
		if err := n.beforeAdd(); err != nil {
			return err
		}
	}
	access, err := trustedAccess("brig: "+name, n.trust)
	if err != nil {
		return err
	}
	defer cf.release(access)
	attrs := n.query(name)
	defer attrs.close()
	attrs.setString(cf.kSecAttrLabel, "brig: "+name)
	attrs.setString(cf.kSecAttrDescription, nativeDescription)
	if comment != "" {
		attrs.setString(cf.kSecAttrComment, comment)
	}
	attrs.setData(cf.kSecValueData, value)
	attrs.set(cf.kSecAttrAccess, access)
	return osStatus("SecItemAdd", cf.itemAdd(attrs.ref, nil))
}

// update replaces the value and the comment of an item this binary trusts.
// An empty comment is written as empty rather than left alone, the rule the
// CLI backend follows: the provenance describes the value being replaced.
func (n *nativeKeychain) update(name string, value []byte, comment string) error {
	q := n.query(name)
	defer q.close()
	attrs := newDict()
	defer attrs.close()
	attrs.setData(cf.kSecValueData, value)
	attrs.setString(cf.kSecAttrComment, comment)
	return osStatus("SecItemUpdate", cf.itemUpdate(q.ref, attrs.ref))
}

// move replaces an item security(1) wrote with a native one holding value.
func (n *nativeKeychain) move(name string, value []byte, comment string) error {
	old, err := n.fallback.Read(name)
	if err != nil {
		return fmt.Errorf("%q was written by security and cannot be read back before replacing it: %w", name, err)
	}
	// The provenance too, so a restored item still drives the stale
	// warning the way it did.
	var oldProv Provenance
	if attrs, err := n.fallback.attributes(name); err == nil {
		oldProv, _ = DecodeProvenance(attr(attrs, "icmt"))
	}
	if err := n.fallback.Delete(name); err != nil {
		return fmt.Errorf("%q was written by security and cannot be removed before replacing it: %w", name, err)
	}
	if err := n.add(name, value, comment); err != nil {
		// Put the old one back through the path that wrote it, so a failed
		// move leaves what was there rather than nothing.
		if back := n.fallback.Write(name, old, oldProv, false); back != nil {
			return fmt.Errorf("%w; and the previous value could not be restored: %v", err, back)
		}
		return err
	}
	return nil
}

// readNative reads the item's value through the framework alone, and
// answers errNotOurs for an item this binary cannot open.
func (n *nativeKeychain) readNative(name string) ([]byte, error) {
	q := n.query(name)
	defer q.close()
	q.set(cf.kSecReturnData, cf.booleanTrue)
	var result cfRef
	if err := osStatus("SecItemCopyMatching", cf.itemCopyMatching(q.ref, &result)); err != nil {
		return nil, err
	}
	defer cf.release(result)
	return goBytes(result), nil
}

func (n *nativeKeychain) Read(name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	value, err := n.readNative(name)
	if errors.Is(err, errNotOurs) {
		// security(1) wrote it, so security(1) reads it.
		return n.fallback.Read(name)
	}
	return value, err
}

func (n *nativeKeychain) Delete(name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	q := n.query(name)
	defer q.close()
	err := osStatus("SecItemDelete", cf.itemDelete(q.ref))
	if errors.Is(err, errNotOurs) {
		// security(1) wrote it, and its value file, if the envelope left
		// one, goes with it on that path.
		return n.fallback.Delete(name)
	}
	return err
}

// List reads attributes only, for this service alone, so it raises no
// dialog and touches no other application's items on the way.
func (n *nativeKeychain) List() ([]Secret, error) {
	q := newDict()
	defer q.close()
	q.set(cf.kSecClass, cf.kSecClassGenericPassword)
	q.setString(cf.kSecAttrService, n.service)
	q.set(cf.kSecReturnAttributes, cf.booleanTrue)
	q.set(cf.kSecMatchLimit, cf.kSecMatchLimitAll)
	var result cfRef
	if err := osStatus("SecItemCopyMatching", cf.itemCopyMatching(q.ref, &result)); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	defer cf.release(result)
	count := cf.arrayGetCount(result)
	list := make([]Secret, 0, count)
	for i := range count {
		item := cf.arrayGetValueAtIndex(result, i)
		name := goString(cf.dictGetValue(item, cf.kSecAttrAccount))
		// A name outside brig's grammar is one brig did not write, and one
		// every other verb would refuse. Same rule as the CLI backend.
		if ValidName(name) != nil {
			continue
		}
		p, ok := DecodeProvenance(goString(cf.dictGetValue(item, cf.kSecAttrComment)))
		if !ok {
			p = Provenance{}
		}
		list = append(list, Secret{
			Name:       name,
			Modified:   goTime(cf.dictGetValue(item, cf.kSecAttrModificationDate)),
			Provenance: p,
		})
	}
	sortByName(list)
	return list, nil
}

// open picks the backend: BRIG_KEYCHAIN by hand, else the native store for
// a build whose signature survives a rebuild and the CLI backend for an
// ad-hoc one. adhocSigned says why, and docs/secrets.md says what each
// store means for the user.
func open() (Store, error) {
	cli := keychain{service: service}
	switch v := os.Getenv("BRIG_KEYCHAIN"); v {
	case "security":
		return cli, nil
	case "native":
		return openNative(service, cli)
	case "":
		adhoc, err := adhocSigned()
		if err != nil || adhoc {
			return cli, nil
		}
		return openNative(service, cli)
	default:
		return nil, fmt.Errorf("BRIG_KEYCHAIN %q is not a backend: use security or native, or leave it unset", v)
	}
}
