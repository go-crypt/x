package blake2b

const (
	// BlockSize of BLAKE2b in bytes.
	BlockSize = 128

	// Size is the hash size of BLAKE2b-512 in bytes.
	Size = 64

	// Size384 is the hash size of BLAKE2b-384 in bytes.
	Size384 = 48

	// Size256 is the hash size of BLAKE2b-256 in bytes.
	Size256 = 32
)

const (
	// OutputLengthUnknown can be used as the size argument to NewXOF to indicate
	// the length of the output is not known in advance.
	OutputLengthUnknown = 0

	// magicUnknownOutputLength is a magic value for the output size that indicates
	// an unknown number of output bytes.
	magicUnknownOutputLength = (1 << 32) - 1

	// maxOutputLength is the absolute maximum number of bytes to produce when the
	// number of output bytes is unknown.
	maxOutputLength = (1 << 32) * 64
)

// the precomputed values for BLAKE2b
// there are 12 16-byte arrays - one for each round
// the entries are calculated from the sigma constants.
var precomputed = [12][16]byte{
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
	{11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
	{7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
	{9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
	{2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
	{12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
	{13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
	{6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
	{10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},
	{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15}, // equal to the first
	{14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3}, // equal to the second
}
