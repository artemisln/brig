//go:build darwin

package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The envelope: the keychain item holds a key, and the value lives on disk
// encrypted under it.
//
// security(1) reads one interactive command into a 4096-byte buffer and
// truncates a longer line without saying so. With the value on that line the
// ceiling was about 3 KB of raw value, less for a long name or a long
// provenance, and two shipped agents' credential documents did not fit
// (#189, #313). A key is 32 bytes for every secret, so the line the keychain
// sees is the same size whatever the value is, and the value has no ceiling
// of its own.
//
// What this does and does not change about the security of a stored secret
// is laid out in docs/security.md. The short form: a process that could read
// the item before can read the key and the file now, and a copy of the disk
// without the login keychain holds ciphertext it cannot open. Neither is a
// change. What is new is that a copy of ~/.brig carries the ciphertext, and a
// copy of the keychain carries the key, and the two can end up in different
// places.

// keyPrefix marks a keychain item as holding a key rather than a value.
//
// It sits outside the base64, not inside it, for the brig that came before
// the envelope. That brig reads every item as base64 of the value, and a key
// item that decoded cleanly would reach a guest as a 32-byte credential. A
// colon is not a base64 character, so the older read fails instead, with the
// refusal it already has for an item brig did not write.
//
// An item written before the envelope existed holds the value itself, base64
// and no prefix, and Read returns it as it always did.
const keyPrefix = "brigkey1:"

// keyLen is AES-256.
const keyLen = 32

// fileMagic opens the value file, so a file that is not one is named as such
// rather than failing inside the cipher.
const fileMagic = "BRIGSEC1"

// nonceLen is AES-GCM's standard nonce. A fresh random nonce per write is
// safe for far more writes than any secret will ever see.
const nonceLen = 12

// secretsDirName is the directory under the state directory. Values live
// there as one file per secret, named for the secret. ValidName has already
// refused anything that is not letters, digits, - and _, so a name cannot
// be a path.
const secretsDirName = "secrets"

// stateDir mirrors internal/wrap's stateDir: BRIG_STATE_DIR, else ~/.brig.
// Duplicated rather than imported because this package sits below wrap, and
// eight lines are cheaper than a dependency in the wrong direction.
func stateDir() (string, error) {
	if dir := os.Getenv("BRIG_STATE_DIR"); dir != "" {
		return dir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory to keep brig's secrets in: %w", err)
	}
	return filepath.Join(home, ".brig"), nil
}

// secretsDir is the directory the value files live in, created 0700 on
// first use.
func secretsDir() (string, error) {
	base, err := stateDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, secretsDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}
	return dir, nil
}

// openSecretsRoot opens the directory as an os.Root, so every file operation
// below is confined to it. The names are already safe; the root is what
// makes a symlink planted at one of them a refusal rather than a write
// somewhere else.
func openSecretsRoot() (*os.Root, string, error) {
	dir, err := secretsDir()
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", fmt.Errorf("cannot open %s: %w", dir, err)
	}
	return root, dir, nil
}

// newKey draws a fresh key from the system's random source.
func newKey() ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("cannot draw a key: %w", err)
	}
	return key, nil
}

// keyItem is the line the keychain item holds for an enveloped secret.
func keyItem(key []byte) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(key)
}

// keyFromItem reads the key out of an item line, or reports that the line
// is a pre-envelope value. A marked line that does not hold a key of the
// right size was written by something other than brig.
func keyFromItem(line string) (key []byte, enveloped bool, err error) {
	rest, ok := strings.CutPrefix(line, keyPrefix)
	if !ok {
		return nil, false, nil
	}
	key, err = base64.StdEncoding.DecodeString(rest)
	if err != nil || len(key) != keyLen {
		return nil, true, fmt.Errorf("the keychain item is marked as a key and does not hold one, so brig did not write it")
	}
	return key, true, nil
}

// seal encrypts value for name under key: magic, nonce, then the ciphertext
// with its tag. The name is the additional data, so a file cannot be moved
// under another secret's name and still open.
func seal(name string, key, value []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot draw a nonce: %w", err)
	}
	out := make([]byte, 0, len(fileMagic)+nonceLen+len(value)+gcm.Overhead())
	out = append(out, fileMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, value, []byte(name)), nil
}

// errNotSealed means the file is not in the envelope's format at all.
var errNotSealed = errors.New("not a brig value file")

// unseal reverses seal. A file that does not open with this key was written
// under another key, or changed since, and the cipher's own error says
// neither; the caller names what happened.
func unseal(name string, key, blob []byte) ([]byte, error) {
	rest, ok := bytes.CutPrefix(blob, []byte(fileMagic))
	if !ok || len(rest) < nonceLen {
		return nil, errNotSealed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, rest[:nonceLen], rest[nonceLen:], []byte(name))
}

// writeValueFile puts blob at name inside the secrets directory, through a
// temp file and a rename, so a crash mid-write leaves the old value whole
// and never a half-written new one. The file is 0600 from the moment it
// exists.
func writeValueFile(name string, blob []byte) (path string, err error) {
	root, dir, err := openSecretsRoot()
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	path = filepath.Join(dir, name)
	tmp := name + ".tmp"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return path, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		_ = root.Remove(tmp)
		return path, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmp)
		return path, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return path, fmt.Errorf("cannot write %s: %w", path, err)
	}
	return path, nil
}

// readValueFile returns the file at name, and fs.ErrNotExist when there is
// none. The path comes back either way, for the error a caller prints.
func readValueFile(name string) (blob []byte, path string, err error) {
	root, dir, err := openSecretsRoot()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = root.Close() }()
	path = filepath.Join(dir, name)
	blob, err = root.ReadFile(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, path, fs.ErrNotExist
		}
		return nil, path, fmt.Errorf("cannot read %s: %w", path, err)
	}
	return blob, path, nil
}

// removeValueFile removes the file at name, treating an absent one as done.
func removeValueFile(name string) error {
	root, dir, err := openSecretsRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot remove %s: %w", filepath.Join(dir, name), err)
	}
	return nil
}
