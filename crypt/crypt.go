package crypt

import (
	"encoding/base64"
	"hash"

	b64 "github.com/go-crypt/x/base64"
)

func Key(hashFunc func() hash.Hash, password, salt []byte, rounds int) []byte {
	length := len(password)

	// Step 1.
	digestA := hashFunc()
	keyLength := base64.RawStdEncoding.EncodedLen(digestA.Size())
	digestLength := digestA.Size()

	// Step 2.
	digestA.Write(password)

	// Step 3.
	digestA.Write(salt)

	// Step 4.
	digestB := hashFunc()

	// Step 5.
	digestB.Write(password)

	// Step 6.
	digestB.Write(salt)

	// Step 7.
	digestB.Write(password)

	// Step 8.
	sumB := digestB.Sum(nil)
	digestB.Reset()
	digestB = nil

	// Step 9 and 10:
	digestA.Write(repeat(sumB, length))

	// Step 11.
	for i := length; i > 0; i >>= 1 {
		if even(i) {
			digestA.Write(password)
		} else {
			digestA.Write(sumB)
		}
	}

	// Step 12.
	sumA := digestA.Sum(nil)
	digestA.Reset()
	digestA = nil
	sumB = nil

	// Step 13.
	digestDP := hashFunc()

	// Step 14.
	for i := 0; i < length; i++ {
		digestDP.Write(password)
	}

	// Step 15.
	sumDP := digestDP.Sum(nil)
	digestDP.Reset()
	digestDP = nil

	// Step 16.
	seqP := repeat(sumDP, length)
	sumDP = nil

	// Step 17.
	digestDS := hashFunc()

	// Step 18.
	for i := 0; i < 16+int(sumA[0]); i++ {
		digestDS.Write(salt)
	}

	// Step 19.
	sumDS := digestDS.Sum(nil)
	digestDS.Reset()
	digestDS = nil

	// Step 20.
	seqS := repeat(sumDS, len(salt))

	// Step 21.
	digestC := hashFunc()
	for i := 0; i < rounds; i++ {
		digestC.Reset()

		// Step 21 Sub-Step B and C.
		if i&1 != 0 {
			// Step 21 Sub-Step B.
			digestC.Write(seqP)
		} else {
			// Step 21 Sub-Step C.
			digestC.Write(sumA)
		}

		// Step 21 Sub-Step D.
		if i%3 != 0 {
			digestC.Write(seqS)
		}

		// Step 21 Sub-Step E.
		if i%7 != 0 {
			digestC.Write(seqP)
		}

		// Step 21 Sub-Step F and G.
		if i&1 != 0 {
			// Step 21 Sub-Step F.
			digestC.Write(sumA)
		} else {
			// Step 21 Sub-Step G.
			digestC.Write(seqP)
		}

		// Sub-Step H.
		copy(sumA, digestC.Sum(nil))
	}

	digestC.Reset()
	digestC = nil

	seqP, seqS = nil, nil

	switch keyLength {
	case sha256KeyLength:
		// Step 22 Sub Step E.
		return keyFromSum(sumA, sha256ByteMap, digestLength)
	case sha512KeyLength:
		// Step 22 Sub Step E.
		return keyFromSum(sumA, sha512ByteMap, digestLength)
	}

	return nil
}

func keyFromSum(sum []byte, keyMap []int, digestLength int) []byte {
	key := make([]byte, digestLength)

	for i := 0; i < digestLength; i++ {
		key[i] = sum[keyMap[i]]
	}

	return b64.EncodeCrypt(key)
}

func even(i int) bool {
	return i%2 == 0
}

var (
	cleanBytes = make([]byte, 64)
)

func clean(b []byte) {
	l := len(b)

	for ; l > 64; l -= 64 {
		copy(b[l-64:l], cleanBytes)
	}

	if l > 0 {
		copy(b[0:l], cleanBytes[0:l])
	}
}

func repeat(input []byte, length int) []byte {
	var (
		seq  = make([]byte, length)
		unit = len(input)
	)

	j := length / unit * unit
	for i := 0; i < j; i += unit {
		copy(seq[i:length], input)
	}
	if j < length {
		copy(seq[j:length], input[0:length-j])
	}

	return seq
}
