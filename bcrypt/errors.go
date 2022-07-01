package bcrypt

import (
	"errors"
	"fmt"
)

// ErrMismatchedHashAndPassword is the error returned from CompareHashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("github.com/go-crypt/x/bcrypt: hashedPassword is not the hash of the given password")

// ErrHashTooShort is the error returned from CompareHashAndPassword when a hash is too short to
// be a bcrypt hash.
var ErrHashTooShort = errors.New("github.com/go-crypt/x/bcrypt: hashedSecret too short to be a bcrypted password")

// The error returned from CompareHashAndPassword when a hash was created with
// a bcrypt algorithm newer than this implementation.
type HashVersionTooNewError byte

func (hv HashVersionTooNewError) Error() string {
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: bcrypt algorithm version '%c' requested is newer than current version '%c'", byte(hv), majorVersion)
}

// The error returned from CompareHashAndPassword when a hash starts with something other than '$'
type InvalidHashPrefixError byte

func (ih InvalidHashPrefixError) Error() string {
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '%c'", byte(ih))
}

type InvalidCostError int

func (ic InvalidCostError) Error() string {
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: cost %d is outside allowed range (%d,%d)", int(ic), MinCost, MaxCost)
}

type InvalidSaltSizeError struct {
	salt []byte
}

func (iss InvalidSaltSizeError) Error() string {
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: salt %x with byte length %d does not have the correct byte length %d", iss.salt, len(iss.salt), maxSaltSize)
}
