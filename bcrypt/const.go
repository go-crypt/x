package bcrypt

const (
	MinCost         int = 4  // the minimum allowable cost as passed in to GenerateFromPassword
	MaxCost         int = 31 // the maximum allowable cost as passed in to GenerateFromPassword
	DefaultCost     int = 10 // the cost that will actually be set if a cost below MinCost is passed into GenerateFromPassword
	EncodedSaltSize     = 22
	EncodedHashSize     = 31
)

const (
	majorVersion       = '2'
	minorVersion       = 'a'
	maxSaltSize        = 16
	maxCryptedHashSize = 23
	minHashSize        = 59
)

// magicCipherData is an IV for the 64 Blowfish encryption calls in
// bcrypt(). It's the string "OrpheanBeholderScryDoubt" in big-endian bytes.
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}
