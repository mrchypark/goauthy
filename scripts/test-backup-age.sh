#!/bin/sh
# Isolated package evaluation; does not change the application's module files.
set -eu
umask 077
probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' 0
cat >"$probe_dir/go.mod" <<'MOD'
module goauthy-backup-age-probe

go 1.27.0

require filippo.io/age v1.3.2
MOD
cat >"$probe_dir/age_test.go" <<'GO'
package backup_test

import (
 "bytes"
 "io"
 "testing"

 "filippo.io/age"
)

func TestEncryptedBackupStream(t *testing.T) {
 key, err := age.GenerateX25519Identity()
 if err != nil { t.Fatal(err) }
 wrong, err := age.GenerateX25519Identity()
 if err != nil { t.Fatal(err) }
 plaintext := bytes.Repeat([]byte("goauthy-backup-probe-content\n"), 8192)
 var encrypted bytes.Buffer
 w, err := age.Encrypt(&encrypted, key.Recipient())
 if err != nil { t.Fatal(err) }
 if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil { t.Fatal(err) }
 unfinished := bytes.Clone(encrypted.Bytes())
 if err := w.Close(); err != nil { t.Fatal(err) }
 encoded := bytes.Clone(encrypted.Bytes())
 if bytes.Contains(encoded, []byte("goauthy-backup-probe-content")) { t.Fatal("plaintext exposed") }
 decrypt := func(data []byte, identity age.Identity) ([]byte, error) {
  reader, err := age.Decrypt(bytes.NewReader(data), identity)
  if err != nil { return nil, err }
  // A valid header or early plaintext is not whole-artifact authentication.
  return io.ReadAll(reader)
 }
 decoded, err := decrypt(encoded, key)
 if err != nil || !bytes.Equal(decoded, plaintext) { t.Fatal("round trip failed") }
 if _, err := decrypt(encoded, wrong); err == nil { t.Fatal("wrong key accepted") }
 changed := bytes.Clone(encoded)
 changed[len(changed)-1] ^= 1
 cases := map[string][]byte{
  "truncated": encoded[:len(encoded)-1],
  "tampered final chunk": changed,
  "trailing bytes": append(bytes.Clone(encoded), 1),
  "unclosed stream": unfinished,
 }
 for name, data := range cases {
  t.Run(name, func(t *testing.T) {
   if _, err := decrypt(data, key); err == nil { t.Fatal("invalid artifact accepted") }
  })
 }
}
GO
(cd "$probe_dir" && go mod tidy && go test -count=1 ./...)
