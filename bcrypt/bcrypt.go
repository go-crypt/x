// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bcrypt implements Provos and Mazières's bcrypt adaptive hashing
// algorithm. See http://www.usenix.org/event/usenix99/provos/provos.pdf
package bcrypt // import "github.com/go-crypt/x/bcrypt"

// The code is a port of Provos and Mazières's C implementation.
import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strconv"

	"github.com/go-crypt/x/blowfish"
)

type hashed struct {
	hash  []byte
	salt  []byte
	cost  int // allowed range is MinCost to MaxCost
	major byte
	minor byte
}

// GenerateFromPassword returns the bcrypt hash of the password at the given
// cost. If the cost given is less than MinCost, the cost will be set to
// DefaultCost, instead. Use CompareHashAndPassword, as defined in this package,
// to compare the returned hashed password with its cleartext version.
func GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	p, err := newFromPassword(password, cost)
	if err != nil {
		return nil, err
	}
	return p.Hash(), nil
}

// CompareHashAndPassword compares a bcrypt hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return err
	}

	otherHash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return err
	}

	otherP := &hashed{otherHash, p.salt, p.cost, p.major, p.minor}
	if subtle.ConstantTimeCompare(p.Hash(), otherP.Hash()) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

// Cost returns the hashing cost used to create the given hashed
// password. When, in the future, the hashing cost of a password system needs
// to be increased in order to adjust for greater computational power, this
// function allows one to establish which passwords need to be updated.
func Cost(hashedPassword []byte) (int, error) {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return 0, err
	}
	return p.cost, nil
}

func newFromPassword(password []byte, cost int) (*hashed, error) {
	if cost < MinCost {
		cost = DefaultCost
	}
	p := new(hashed)
	p.major = majorVersion
	p.minor = minorVersion

	err := checkCost(cost)
	if err != nil {
		return nil, err
	}
	p.cost = cost

	unencodedSalt := make([]byte, maxSaltSize)
	_, err = io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return nil, err
	}

	p.salt = Base64Encode(unencodedSalt)
	hash, err := bcrypt(password, p.cost, p.salt)
	if err != nil {
		return nil, err
	}
	p.hash = hash
	return p, err
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	if len(hashedSecret) < minHashSize {
		return nil, ErrHashTooShort
	}
	p := new(hashed)
	n, err := p.decodeVersion(hashedSecret)
	if err != nil {
		return nil, err
	}
	hashedSecret = hashedSecret[n:]
	n, err = p.decodeCost(hashedSecret)
	if err != nil {
		return nil, err
	}
	hashedSecret = hashedSecret[n:]

	// The "+2" is here because we'll have to append at most 2 '=' to the salt
	// when base64 decoding it in expensiveBlowfishSetup().
	p.salt = make([]byte, encodedSaltSize, encodedSaltSize+2)
	copy(p.salt, hashedSecret[:encodedSaltSize])

	hashedSecret = hashedSecret[encodedSaltSize:]
	p.hash = make([]byte, len(hashedSecret))
	copy(p.hash, hashedSecret)

	return p, nil
}

func bcrypt(password []byte, cost int, salt []byte) ([]byte, error) {
	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	c, err := expensiveBlowfishSetup(password, uint32(cost), salt)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hsh := Base64Encode(cipherData[:maxCryptedHashSize])
	return hsh, nil
}

func expensiveBlowfishSetup(key []byte, cost uint32, salt []byte) (*blowfish.Cipher, error) {
	csalt, err := Base64Decode(salt)
	if err != nil {
		return nil, err
	}

	// Bug compatibility with C bcrypt implementations. They use the trailing
	// NULL in the key string during expansion.
	// We copy the key to prevent changing the underlying array.
	ckey := append(key[:len(key):len(key)], 0)

	c, err := blowfish.NewSaltedCipher(ckey, csalt)
	if err != nil {
		return nil, err
	}

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		blowfish.ExpandKey(ckey, c)
		blowfish.ExpandKey(csalt, c)
	}

	return c, nil
}

func (p *hashed) Hash() []byte {
	arr := make([]byte, 60)
	arr[0] = '$'
	arr[1] = p.major
	n := 2
	if p.minor != 0 {
		arr[2] = p.minor
		n = 3
	}
	arr[n] = '$'
	n++
	copy(arr[n:], []byte(fmt.Sprintf("%02d", p.cost)))
	n += 2
	arr[n] = '$'
	n++
	copy(arr[n:], p.salt)
	n += encodedSaltSize
	copy(arr[n:], p.hash)
	n += encodedHashSize
	return arr[:n]
}

func (p *hashed) decodeVersion(sbytes []byte) (int, error) {
	if sbytes[0] != '$' {
		return -1, InvalidHashPrefixError(sbytes[0])
	}
	if sbytes[1] > majorVersion {
		return -1, HashVersionTooNewError(sbytes[1])
	}
	p.major = sbytes[1]
	n := 3
	if sbytes[2] != '$' {
		p.minor = sbytes[2]
		n++
	}
	return n, nil
}

// sbytes should begin where decodeVersion left off.
func (p *hashed) decodeCost(sbytes []byte) (int, error) {
	cost, err := strconv.Atoi(string(sbytes[0:2]))
	if err != nil {
		return -1, err
	}
	err = checkCost(cost)
	if err != nil {
		return -1, err
	}
	p.cost = cost
	return 3, nil
}

func (p *hashed) String() string {
	return fmt.Sprintf("&{hash: %#v, salt: %#v, cost: %d, major: %c, minor: %c}", string(p.hash), p.salt, p.cost, p.major, p.minor)
}

func checkCost(cost int) error {
	if cost < MinCost || cost > MaxCost {
		return InvalidCostError(cost)
	}
	return nil
}
