// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcrypt

import (
	"github.com/go-crypt/x/base64"
)

// Base64Encode is the base64 encoder for bcrypt.
func Base64Encode(src []byte) []byte {
	n := base64.BcryptEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	base64.BcryptEncoding.Encode(dst, src)
	for dst[n-1] == '=' {
		n--
	}
	return dst[:n]
}

// Base64Decode is the base64 decoder for bcrypt.
func Base64Decode(src []byte) ([]byte, error) {
	numOfEquals := 4 - (len(src) % 4)
	for i := 0; i < numOfEquals; i++ {
		src = append(src, '=')
	}

	dst := make([]byte, base64.BcryptEncoding.DecodedLen(len(src)))
	n, err := base64.BcryptEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
