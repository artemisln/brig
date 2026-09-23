//go:build darwin

package secret

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// The CoreFoundation and Security calls the native keychain store makes, bound
// at first use through purego: dlopen of the two system frameworks and dlsym
// of each symbol. No cgo, so the binary stays static and cross-compiles from
// Linux; the frameworks are resolved at run time on the Mac that runs brig.
//
// purego supplies the call mechanics and nothing else. Every function and
// constant below is a symbol Apple exports, and the wrapping is brig's own.
// That makes this file the one place a wrong argument type or a missed
// CFRelease can live, which is why it is small and every wrapper is plain.

// cfRef is any CFTypeRef. Zero is NULL.
type cfRef = uintptr

const (
	securityPath = "/System/Library/Frameworks/Security.framework/Security"
	cfPath       = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	kCFStringEncodingUTF8 = 0x08000100
	kCFNumberSInt64Type   = 4

	// SecKeychainGetStatus bit: set while the keychain is unlocked.
	kSecUnlockStateStatus = 1

	// OSStatus values this store tells apart. Measured against the
	// SecBase.h names: errSecDuplicateItem, errSecItemNotFound,
	// errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled,
	// errSecNoAccessForItem, errSecInvalidOwnerEdit.
	errSecSuccess                = 0
	errSecDuplicateItem          = -25299
	errSecItemNotFound           = -25300
	errSecAuthFailed             = -25293
	errSecInteractionNotAllowed  = -25308
	errSecUserCanceled           = -128
	errSecNoAccessForItem        = -25243
	errSecInvalidOwnerEdit       = -25244
	kSecCodeSignatureAdhoc       = 0x0002
	kSecCSSigningInformationNone = 0

	// CFAbsoluteTime counts seconds from 2001-01-01 UTC.
	cfAbsoluteTimeEpoch = 978307200
)

// cf holds the bound functions and the constant keys, filled once.
var cf struct {
	once sync.Once
	err  error

	// CoreFoundation
	release              func(cfRef)
	stringCreate         func(alloc cfRef, cstr *byte, encoding uint32) cfRef
	stringGetCString     func(s cfRef, buf *byte, size int64, encoding uint32) bool
	stringGetLength      func(s cfRef) int64
	dataCreate           func(alloc cfRef, bytes *byte, length int64) cfRef
	dataGetLength        func(d cfRef) int64
	dataGetBytePtr       func(d cfRef) *byte
	dictCreateMutable    func(alloc cfRef, capacity int64, keyCB, valueCB cfRef) cfRef
	dictSetValue         func(dict, key, value cfRef)
	dictGetValue         func(dict, key cfRef) cfRef
	arrayGetCount        func(arr cfRef) int64
	arrayGetValueAtIndex func(arr cfRef, i int64) cfRef
	getTypeID            func(cfRef) uint64
	stringGetTypeID      func() uint64
	dataGetTypeID        func() uint64
	dateGetTypeID        func() uint64
	numberGetTypeID      func() uint64
	dateGetAbsoluteTime  func(d cfRef) float64
	numberGetValue       func(n cfRef, typ int64, out unsafe.Pointer) bool
	arrayCreate          func(alloc cfRef, values *cfRef, n int64, cb cfRef) cfRef

	// Security
	itemAdd                       func(attrs cfRef, result *cfRef) int32
	itemCopyMatching              func(query cfRef, result *cfRef) int32
	itemUpdate                    func(query, attrs cfRef) int32
	itemDelete                    func(query cfRef) int32
	keychainSetInteractionAllowed func(allowed bool) int32
	keychainGetStatus             func(keychain cfRef, out *uint32) int32
	codeCopySelf                  func(flags uint32, out *cfRef) int32
	codeCopySigningInformation    func(code cfRef, flags uint32, out *cfRef) int32
	accessCreate                  func(descriptor, trusted cfRef, out *cfRef) int32
	trustedAppCreate              func(path *byte, out *cfRef) int32

	// Constant CFStringRefs, read out of the framework's own globals so the
	// exact string Apple uses is the one on the wire.
	keyCB, valueCB, arrayCB cfRef
	booleanTrue             cfRef
	kSecClass, kSecClassGenericPassword, kSecAttrService, kSecAttrAccount,
	kSecAttrLabel, kSecAttrDescription, kSecAttrComment, kSecAttrModificationDate,
	kSecValueData, kSecReturnData, kSecReturnAttributes, kSecMatchLimit,
	kSecMatchLimitAll, kSecCodeInfoFlags, kSecAttrAccess cfRef
}

// bind loads the frameworks and resolves every symbol, once.
func bind() error {
	cf.once.Do(func() { cf.err = bindSymbols(purego.Dlsym) })
	return cf.err
}

// bindSymbols resolves every symbol through resolve and registers it. A
// symbol resolve cannot find is an error, never a panic: purego's own
// RegisterLibFunc panics on a missing symbol, and a panic inside the Once
// would leave every later call at a nil function. An error here makes
// open() take the security store instead, on a macOS that dropped a call.
func bindSymbols(resolve func(lib uintptr, name string) (uintptr, error)) error {
	sec, err := purego.Dlopen(securityPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("cannot load Security.framework: %w", err)
	}
	core, err := purego.Dlopen(cfPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("cannot load CoreFoundation.framework: %w", err)
	}
	funcs := []struct {
		lib  uintptr
		name string
		fptr any
	}{
		{core, "CFRelease", &cf.release},
		{core, "CFStringCreateWithCString", &cf.stringCreate},
		{core, "CFStringGetCString", &cf.stringGetCString},
		{core, "CFStringGetLength", &cf.stringGetLength},
		{core, "CFDataCreate", &cf.dataCreate},
		{core, "CFDataGetLength", &cf.dataGetLength},
		{core, "CFDataGetBytePtr", &cf.dataGetBytePtr},
		{core, "CFDictionaryCreateMutable", &cf.dictCreateMutable},
		{core, "CFDictionarySetValue", &cf.dictSetValue},
		{core, "CFDictionaryGetValue", &cf.dictGetValue},
		{core, "CFArrayGetCount", &cf.arrayGetCount},
		{core, "CFArrayGetValueAtIndex", &cf.arrayGetValueAtIndex},
		{core, "CFArrayCreate", &cf.arrayCreate},
		{core, "CFGetTypeID", &cf.getTypeID},
		{core, "CFStringGetTypeID", &cf.stringGetTypeID},
		{core, "CFDataGetTypeID", &cf.dataGetTypeID},
		{core, "CFDateGetTypeID", &cf.dateGetTypeID},
		{core, "CFNumberGetTypeID", &cf.numberGetTypeID},
		{core, "CFDateGetAbsoluteTime", &cf.dateGetAbsoluteTime},
		{core, "CFNumberGetValue", &cf.numberGetValue},
		{sec, "SecItemAdd", &cf.itemAdd},
		{sec, "SecItemCopyMatching", &cf.itemCopyMatching},
		{sec, "SecItemUpdate", &cf.itemUpdate},
		{sec, "SecItemDelete", &cf.itemDelete},
		{sec, "SecKeychainSetUserInteractionAllowed", &cf.keychainSetInteractionAllowed},
		{sec, "SecKeychainGetStatus", &cf.keychainGetStatus},
		{sec, "SecCodeCopySelf", &cf.codeCopySelf},
		{sec, "SecCodeCopySigningInformation", &cf.codeCopySigningInformation},
		{sec, "SecAccessCreate", &cf.accessCreate},
		{sec, "SecTrustedApplicationCreateFromPath", &cf.trustedAppCreate},
	}
	for _, f := range funcs {
		sym, err := resolve(f.lib, f.name)
		if err != nil {
			return fmt.Errorf("cannot resolve %s: %w", f.name, err)
		}
		purego.RegisterFunc(f.fptr, sym)
	}
	// The callbacks are structs the framework exports; the address of the
	// global is what the Create functions take.
	for _, c := range []struct {
		name string
		dst  *cfRef
	}{
		{"kCFTypeDictionaryKeyCallBacks", &cf.keyCB},
		{"kCFTypeDictionaryValueCallBacks", &cf.valueCB},
		{"kCFTypeArrayCallBacks", &cf.arrayCB},
	} {
		if *c.dst, err = resolve(core, c.name); err != nil {
			return fmt.Errorf("cannot resolve %s: %w", c.name, err)
		}
	}
	// The rest are globals holding a CFTypeRef, so the symbol's address is
	// dereferenced once to get the ref itself.
	globals := []struct {
		lib  uintptr
		name string
		dst  *cfRef
	}{
		{core, "kCFBooleanTrue", &cf.booleanTrue},
		{sec, "kSecClass", &cf.kSecClass},
		{sec, "kSecClassGenericPassword", &cf.kSecClassGenericPassword},
		{sec, "kSecAttrService", &cf.kSecAttrService},
		{sec, "kSecAttrAccount", &cf.kSecAttrAccount},
		{sec, "kSecAttrLabel", &cf.kSecAttrLabel},
		{sec, "kSecAttrDescription", &cf.kSecAttrDescription},
		{sec, "kSecAttrComment", &cf.kSecAttrComment},
		{sec, "kSecAttrModificationDate", &cf.kSecAttrModificationDate},
		{sec, "kSecValueData", &cf.kSecValueData},
		{sec, "kSecReturnData", &cf.kSecReturnData},
		{sec, "kSecReturnAttributes", &cf.kSecReturnAttributes},
		{sec, "kSecMatchLimit", &cf.kSecMatchLimit},
		{sec, "kSecMatchLimitAll", &cf.kSecMatchLimitAll},
		{sec, "kSecCodeInfoFlags", &cf.kSecCodeInfoFlags},
		{sec, "kSecAttrAccess", &cf.kSecAttrAccess},
	}
	for _, g := range globals {
		addr, err := resolve(g.lib, g.name)
		if err != nil {
			return fmt.Errorf("cannot resolve %s: %w", g.name, err)
		}
		// The address is the framework's own data, not Go memory, so this
		// is the one place a raw address becomes a pointer.
		*g.dst = *(*cfRef)(unsafe.Add(unsafe.Pointer(nil), addr))
	}
	return nil
}

// cstr is a NUL-terminated copy of s for a call that takes a C string.
func cstr(s string) *byte {
	b := append([]byte(s), 0)
	return &b[0]
}

// keychainLocked reports whether the default keychain is locked. With
// dialogs off, a locked keychain answers a read with the same status an
// item not on the ACL does, and the two need different advice.
func keychainLocked() (bool, error) {
	var st uint32
	if err := osStatus("SecKeychainGetStatus", cf.keychainGetStatus(0, &st)); err != nil {
		return false, err
	}
	return st&kSecUnlockStateStatus == 0, nil
}

// trustedAccess builds the access an item is created with: the calling
// binary and every path in trust may read it without a dialog, and nothing
// else can. NULL as a path is the calling application. The caller releases
// the result.
func trustedAccess(label string, trust []string) (cfRef, error) {
	apps := make([]cfRef, 0, len(trust)+1)
	release := func() {
		for _, a := range apps {
			cf.release(a)
		}
	}
	var self cfRef
	if err := osStatus("SecTrustedApplicationCreateFromPath", cf.trustedAppCreate(nil, &self)); err != nil {
		return 0, err
	}
	apps = append(apps, self)
	for _, path := range trust {
		var app cfRef
		if err := osStatus("SecTrustedApplicationCreateFromPath", cf.trustedAppCreate(cstr(path), &app)); err != nil {
			release()
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		apps = append(apps, app)
	}
	defer release()
	list := cf.arrayCreate(0, &apps[0], int64(len(apps)), cf.arrayCB)
	defer cf.release(list)
	desc := cfString(label)
	defer cf.release(desc)
	var access cfRef
	if err := osStatus("SecAccessCreate", cf.accessCreate(desc, list, &access)); err != nil {
		return 0, err
	}
	return access, nil
}

// cfString makes a CFString the caller releases.
func cfString(s string) cfRef {
	return cf.stringCreate(0, cstr(s), kCFStringEncodingUTF8)
}

// cfData makes a CFData holding a copy of b, which the caller releases.
func cfData(b []byte) cfRef {
	if len(b) == 0 {
		return cf.dataCreate(0, nil, 0)
	}
	return cf.dataCreate(0, &b[0], int64(len(b)))
}

// goString reads a CFString, or "" for anything that is not one.
func goString(s cfRef) string {
	if s == 0 || cf.getTypeID(s) != cf.stringGetTypeID() {
		return ""
	}
	// Four bytes per UTF-16 unit is the most UTF-8 needs, plus the NUL.
	size := cf.stringGetLength(s)*4 + 1
	buf := make([]byte, size)
	if !cf.stringGetCString(s, &buf[0], size, kCFStringEncodingUTF8) {
		return ""
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

// goBytes copies a CFData out, or returns nil for anything that is not one.
func goBytes(d cfRef) []byte {
	if d == 0 || cf.getTypeID(d) != cf.dataGetTypeID() {
		return nil
	}
	n := cf.dataGetLength(d)
	if n == 0 {
		return []byte{}
	}
	return append([]byte(nil), unsafe.Slice(cf.dataGetBytePtr(d), n)...)
}

// goTime reads a CFDate, or the zero time for anything that is not one.
func goTime(d cfRef) time.Time {
	if d == 0 || cf.getTypeID(d) != cf.dateGetTypeID() {
		return time.Time{}
	}
	secs := cf.dateGetAbsoluteTime(d)
	whole := int64(secs)
	return time.Unix(whole+cfAbsoluteTimeEpoch, int64((secs-float64(whole))*1e9)).UTC()
}

// goInt64 reads a CFNumber, or false for anything that is not one.
func goInt64(n cfRef) (int64, bool) {
	if n == 0 || cf.getTypeID(n) != cf.numberGetTypeID() {
		return 0, false
	}
	var v int64
	if !cf.numberGetValue(n, kCFNumberSInt64Type, unsafe.Pointer(&v)) {
		return 0, false
	}
	return v, true
}

// dict is a mutable CFDictionary under construction, with the refs it owns.
type dict struct {
	ref   cfRef
	owned []cfRef
}

func newDict() *dict {
	return &dict{ref: cf.dictCreateMutable(0, 0, cf.keyCB, cf.valueCB)}
}

// set puts a value the dictionary retains. The value stays the caller's:
// a framework constant such as kSecClassGenericPassword is never released.
func (d *dict) set(key, value cfRef) {
	cf.dictSetValue(d.ref, key, value)
}

// own puts a value the dict created, and releases at close.
func (d *dict) own(key, value cfRef) {
	d.set(key, value)
	d.owned = append(d.owned, value)
}

func (d *dict) setString(key cfRef, s string) { d.own(key, cfString(s)) }
func (d *dict) setData(key cfRef, b []byte)   { d.own(key, cfData(b)) }

// close releases what the dict created and the dict itself.
func (d *dict) close() {
	for _, r := range d.owned {
		cf.release(r)
	}
	cf.release(d.ref)
}

// adhocSigned reports whether this binary carries an ad-hoc signature, which
// is what `go build` produces on macOS. An ad-hoc signature's designated
// requirement is the binary's own hash, so to the keychain every rebuild is
// a different application: an item one build created prompts the next. A
// Developer ID or self-signed identity gives a requirement that survives a
// rebuild, and that is the build the native store is for.
func adhocSigned() (bool, error) {
	adhoc.once.Do(func() { adhoc.result, adhoc.err = adhocSignedNow() })
	return adhoc.result, adhoc.err
}

// The answer cannot change for the life of the process, and open() is
// called more than once per command.
var adhoc struct {
	once   sync.Once
	result bool
	err    error
}

func adhocSignedNow() (bool, error) {
	if err := bind(); err != nil {
		return false, err
	}
	var code cfRef
	if err := osStatus("SecCodeCopySelf", cf.codeCopySelf(0, &code)); err != nil {
		return false, err
	}
	defer cf.release(code)
	var info cfRef
	if err := osStatus("SecCodeCopySigningInformation",
		cf.codeCopySigningInformation(code, kSecCSSigningInformationNone, &info)); err != nil {
		return false, err
	}
	defer cf.release(info)
	flags, ok := goInt64(cf.dictGetValue(info, cf.kSecCodeInfoFlags))
	if !ok {
		// No flags at all means no signature at all, which the keychain
		// treats the same way it treats a fresh hash.
		return true, nil
	}
	return flags&kSecCodeSignatureAdhoc != 0, nil
}
