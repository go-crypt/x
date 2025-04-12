package yescrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeSetting(t *testing.T) {
	testCases := []struct {
		name string
		have []byte
		flag int
		ln   int
		r    int
		err  string
	}{
		{
			"ShouldDecodeDefault",
			[]byte("j9T"),
			182,
			12,
			32,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flag, ln, r, err := DecodeSetting(tc.have)

			if tc.err == "" {
				assert.Equal(t, tc.flag, flag)
				assert.Equal(t, tc.ln, ln)
				assert.Equal(t, tc.r, r)
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}

		})
	}
}

func TestEncodeSetting(t *testing.T) {
	testCases := []struct {
		name     string
		flag     int
		ln       int
		r        int
		expected []byte
	}{
		{
			"ShouldEncodeDefault",
			182,
			12,
			32,
			[]byte("j9T"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := EncodeSetting(tc.flag, tc.ln, tc.r)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
