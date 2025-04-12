// Copyright 2024 Solar Designer. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Alternatively, this specific source file is also available under more
// relaxed terms (0-clause BSD license):
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.

// yescrypt support sponsored by Sandfly Security https://sandflysecurity.com -
// Agentless Security for Linux

package yescrypt

import (
	"bytes"
	"errors"
)

// Hash computes yescrypt hash encoding given the password and existing yescrypt
// setting or full hash encoding. The salt and other parameters are decoded
// from setting.  Currently supports (only a little more than) the subset of
// yescrypt parameters that libxcrypt can generate (as of libxcrypt 4.4.36).
func Hash(password, setting []byte) ([]byte, error) {
	if len(setting) < 7 || string(setting[:4]) != "$y$j" || setting[6] != '$' {
		return nil, errors.New("yescrypt: unsupported parameters")
	}

	// Proper yescrypt uses variable-length integers
	// We take a shortcut approach that works in a more limited range
	Nlog2 := atoi64(setting[4]) + 1
	if Nlog2 < 10 || Nlog2 > 18 {
		return nil, errors.New("yescrypt: N out of supported range")
	}

	r := atoi64(setting[5]) + 1
	if r < 1 || r > 32 {
		return nil, errors.New("yescrypt: r out of supported range")
	}

	saltEnd := bytes.LastIndexByte(setting, '$')
	if saltEnd < 7 {
		saltEnd = len(setting)
	}

	salt := decode64(setting[7:saltEnd])
	if salt == nil {
		return nil, errors.New("yescrypt: bad salt encoding")
	}

	key, err := Key(password, salt, 1<<Nlog2, r, 1, 32)
	if err != nil {
		return nil, err
	}

	hash := encode64(key)

	return bytes.Join([][]byte{setting[0:saltEnd], hash}, []byte("$")), nil
}
