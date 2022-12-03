package ldap

import (
	"bytes"
	"hash"
)

// Key returns the RFC2307 key for the provided password and optional salt. Generally this is encoded with base64.
func Key(hashFunc func() hash.Hash, password, salt []byte) []byte {
	s := len(salt) != 0

	digest := hashFunc()

	digest.Write(password)

	if s {
		digest.Write(salt)
	}

	buf := &bytes.Buffer{}

	buf.Write(digest.Sum(nil))

	digest.Reset()

	if s {
		buf.Write(salt)
	}

	return buf.Bytes()
}
