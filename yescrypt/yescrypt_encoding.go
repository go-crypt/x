package yescrypt

import (
	"errors"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var atoi64Partial = [...]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	64, 64, 64, 64, 64, 64, 64,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	64, 64, 64, 64, 64, 64,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
}

func atoi64(c byte) int {
	if c >= '.' && c <= 'z' {
		return int(atoi64Partial[c-'.'])
	}

	return 64
}

func byteEncode64(src byte) byte {
	return itoa64[src&0x3f]
}

func encode64(src []byte) []byte {
	dst := make([]byte, 0, (len(src)*8+5)/6)

	for i := 0; i < len(src); {
		value, bits := uint32(0), 0

		for ; bits < 24 && i < len(src); bits += 8 {
			value |= uint32(src[i]) << bits
			i++
		}

		for ; bits > 0; bits -= 6 {
			dst = append(dst, itoa64[value&0x3f])
			value >>= 6
		}
	}

	return dst
}

func decode64(src []byte) []byte {
	dst := make([]byte, 0, len(src)*3/4)

	for i := 0; i < len(src); {
		value, bits := uint32(0), uint32(0)

		for ; bits < 24 && i < len(src); bits += 6 {
			c := atoi64(src[i])
			if c > 63 {
				return nil
			}
			i++
			value |= uint32(c) << bits
		}

		if bits < 12 { // Must have at least one full byte
			return nil
		}

		for ; bits >= 8; bits -= 8 {
			dst = append(dst, byte(value))
			value >>= 8
		}

		if value != 0 { // May have 2 or 4 bits left, which must be 0
			return nil
		}
	}
	return dst
}

func EncodeSetting(flags, ln, r int) []byte {
	return []byte("j" + string(byteEncode64(byte(ln-1))) + string(byteEncode64(byte(r-1))))
}

func DecodeSetting(setting []byte) (flags, ln, r int, err error) {
	if len(setting) != 3 {
		return 0, 0, 0, errors.New("yescrypt: bad setting")
	}

	if setting[0] != byte(106) {
		return 0, 0, 0, errors.New("yescrypt: bad setting")
	}

	return 182, atoi64(setting[1]) + 1, atoi64(setting[2]) + 1, nil
}
