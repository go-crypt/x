package bcrypt

import (
	"errors"
	"fmt"
)

var (
	// ErrMismatchedHashAndPassword is the error returned from CompareHashAndPassword when a password and hash do
	// not match.
	ErrMismatchedHashAndPassword = errors.New("github.com/go-crypt/x/bcrypt: the provided password is not a match for the provided hashed password")

	// ErrHashTooShort is the error returned from CompareHashAndPassword when a hash is too short to
	// be a bcrypt hash.
	ErrHashTooShort = errors.New("github.com/go-crypt/x/bcrypt: hashed secret key is too short to be a bcrypt hashed secret key")

	// ErrSecretInvalidLength is the error returned when a hash secret is too short to be a bcrypt secret.
	ErrSecretInvalidLength = errors.New("github.com/go-crypt/x/bcrypt: secret has an invalid length for a bcrypt secret")
)

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
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: cost %d is outside allowed inclusive range %d..%d", int(ic), MinCost, MaxCost)
}

type InvalidSaltSizeError struct {
	salt []byte
}

func (iss InvalidSaltSizeError) Error() string {
	return fmt.Sprintf("github.com/go-crypt/x/bcrypt: salt %x with byte length %d does not have the correct byte length %d", iss.salt, len(iss.salt), maxSaltSize)
}
