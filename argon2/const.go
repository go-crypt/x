package argon2

const (
	blockLength = 128
	syncPoints  = 4
)

// Version is the Argon2 version implemented by this package.
const Version = 0x13

const (
	argon2d = iota
	argon2i
	argon2id
)
