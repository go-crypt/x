// Copyright 2012-2017 The Go Authors. All rights reserved.
// Copyright 2024 Solar Designer. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// yescrypt support sponsored by Sandfly Security https://sandflysecurity.com -
// Agentless Security for Linux

package yescrypt

import (
	"bytes"
	"testing"
)

type testVector struct {
	password string
	salt     string
	N, r, p  int
	output   []byte
}

var good = []testVector{
	{
		"p",
		"s",
		16, 8, 1,
		[]byte{
			0xc8, 0xc7, 0xff, 0x11, 0x22, 0xb0, 0xb2, 0x91,
			0xc3, 0xf2, 0x60, 0x89, 0x48, 0x78, 0x2c, 0xd6,
			0x89, 0xcc, 0x45, 0x57, 0x90, 0x17, 0xaa, 0xa5,
			0xff, 0x8b, 0xaa, 0x74, 0xa6, 0x32, 0xec, 0x99,
		},
	},
	{
		"p",
		"s",
		16, 8, 1,
		[]byte{
			0xc8, 0xc7, 0xff, 0x11, 0x22, 0xb0, 0xb2, 0x91,
		},
	},
	{
		"",
		"",
		4, 1, 1,
		[]byte{
			0x0c, 0xd5, 0xaf, 0x76, 0xeb, 0x24, 0x1d, 0xf8,
			0x11, 0x9a, 0x9a, 0x12, 0x2a, 0xe3, 0x69, 0x20,
			0xbc, 0xc7, 0xf4, 0x14, 0xb9, 0xc0, 0xd5, 0x8f,
			0x45, 0x00, 0x80, 0x60, 0xda, 0xde, 0x46, 0xb0,
			0xc8, 0x09, 0x22, 0xbd, 0xcc, 0x16, 0xa3, 0xab,
		},
	},
}

var bad = []testVector{
	{"p", "s", 0, 1, 1, nil},                    // N == 0
	{"p", "s", 1, 1, 1, nil},                    // N == 1
	{"p", "s", 7, 8, 1, nil},                    // N is not power of 2
	{"p", "s", 16, maxInt / 2, maxInt / 2, nil}, // p * r too large
	{"p", "s", 16, 0, 1, nil},                   // r too small
	{"p", "s", 16, 1, 0, nil},                   // p too small
	{
		"password",
		"salt",
		16, 100, 100,
		[]byte{
			0x88, 0xbd, 0x5e, 0xdb, 0x52, 0xd1, 0xdd, 0x0, 0x18,
			0x87, 0x72, 0xad, 0x36, 0x17, 0x12, 0x90, 0x22, 0x4e,
			0x74, 0x82, 0x95, 0x25, 0xb1, 0x8d, 0x73, 0x23, 0xa5,
			0x7f, 0x91, 0x96, 0x3c, 0x37,
		},
	},
}

func TestKey(t *testing.T) {
	for i, v := range good {
		k, err := Key([]byte(v.password), []byte(v.salt), v.N, v.r, v.p, len(v.output))
		if err != nil {
			t.Errorf("%d: got unexpected error: %s", i, err)
		}
		if !bytes.Equal(k, v.output) {
			t.Errorf("%d: expected %x, got %x", i, v.output, k)
		}
	}
	for i, v := range bad {
		_, err := Key([]byte(v.password), []byte(v.salt), v.N, v.r, v.p, 32)
		if err == nil {
			t.Errorf("%d: expected error, got nil", i)
		}
	}
}

var sink []byte

type testVectorHash struct {
	password string
	hash     string
}

/* Generated with:
#include <crypt.h>
#include <stdio.h>

int main(void)
{
	for (int count = 1; count <= 11; count++) {
		const char *setting = crypt_gensalt("$y$", count, NULL, 0);
		char pw[8];
		snprintf(pw, sizeof(pw), "test%d", count);
		printf("\t{\"%s\", \"%s\"},\n", pw, crypt(pw, setting));
	}
	for (int saltlen = 0; saltlen <= 24; saltlen++) {
		char pw[16], setting[32];
		snprintf(pw, sizeof(pw), "salt length %d", saltlen);
		snprintf(setting, sizeof(setting), "$y$j7.$%.*s", saltlen, "////////////////////////");
		printf("\t{\"%s\", \"%s\"},\n", pw, crypt(pw, setting) ?: setting);
	}
	return 0;
}
*/

var hashes = []testVectorHash{
	{"test1", "$y$j75$z7ztFz2FayrKI79/jEwlL.$u5x/j193MQ09wbFaRGYr0AH/A/jh3kunjuhYRVRNkmC"},
	{"test2", "$y$j85$uFLpki6/G99e8OAxVooij1$64Rji3LKk1v85LYVULHKh2YKeKoDu0ADrGt4l1JhQy8"},
	{"test3", "$y$j7T$aoovSEloTaFiZVMrFisfy.$wLTAPbITTB/XIpAGwcX0xxRCFEcDgPWpXTsij0SEbC5"},
	{"test4", "$y$j8T$P9xODwGnzlle5VHuP1/qA1$bAd4BXv1GBqNQZFzR0Ey42/w0/DFmnFkX1fRpjalAO2"},
	{"test5", "$y$j9T$fqIAg4Vpv9o1MKgWMnyax.$BxkUx27fLJlPOfyIfNEBPzjrDQ95LXKgN5OJii3GL7."},
	{"test6", "$y$jAT$70Rw91iJgO8Uzi3CLWfOo1$aYky8YP.XurVMdZfcXHY1do2RZ7Caav5iliKEkmJjhD"},
	{"test7", "$y$jBT$/YBmADVZsSMw3xfv8M76X0$14s2oH3zHEKh44d5eRVxmDvF8jgM/8SXd8mI4NBQIS1"},
	/*
		{"test8", "$y$jCT$JXJjOzzWl5vilbjjonN5N1$.HyIln8Y5//hXrEaSMIFPSHBAE24eR392XzBtFELSv9"},
		{"test9", "$y$jDT$pPCKQ.Jzpv90Nh7H.ioA9/$6fSLU.2dsGXHY1DZuRncQtItRzZNx9oClKgMpSEkyW0"},
		{"test10", "$y$jET$YA8uEtDHnx9Sv9OvDcwv81$zfxVIsTgxs6v/qL.nTBEE.o9du75wuSHnF5Sai6K.s7"},
		{"test11", "$y$jFT$c1pwXe.GpcUUeOK7BV6yX1$lys4J0.caCkYP6ZpfUj.2zuJAiTpMFj0O9HhN59/QI."},
	*/
	{"salt length 0", "$y$j7.$$cmp7v9bzgyAhctAaiyqG56MBYN2IYzfI5LvybJCKacD"},
	{"salt length 1", "$y$j7.$/"},
	{"salt length 2", "$y$j7.$//$DcruwIS63Fs/rFjEN0XX6h83bZyXgBTDICvINmSWVp5"},
	{"salt length 3", "$y$j7.$///$uo0SD4Xn0Bn1leZVH50teLu3Rje5GAIA.BKYA/jL3/C"},
	{"salt length 4", "$y$j7.$////$WXGIKO.4sthsRPnpY0/.OhyrlEkLcS1pymEGTbJA/l."},
	{"salt length 5", "$y$j7.$/////"},
	{"salt length 6", "$y$j7.$//////$9/wDzXoL4.VS3Ztb.NPiOu4wTpTBKrnJTxBwH1fK70A"},
	{"salt length 7", "$y$j7.$///////$iFpkxOqqnskGorbt2d.daPYT2vUWCRsisu0jr4sNF1."},
	{"salt length 8", "$y$j7.$////////$caDf7LpLxRuDzYqMUDha1Nvm9zX2M89hTuCi.33hpMA"},
	{"salt length 9", "$y$j7.$/////////"},
	{"salt length 10", "$y$j7.$//////////$w8.ijckeAcw8QTQFtNDzf6GAbpM0GS1tPF9.moe8DA6"},
	{"salt length 11", "$y$j7.$///////////$aNlOwAA3WuQ2GScDBr/fTD34oO0ZN/BksJ8d6ilH4O8"},
	{"salt length 12", "$y$j7.$////////////$9YMdFtGt/uJi6XsLbYVhRfnneKsMgoos2r.7fZ8Xn.."},
	{"salt length 13", "$y$j7.$/////////////"},
	{"salt length 14", "$y$j7.$//////////////$fPBNb956TRLinNI/LHoThcqdVO5gIGIg/nRpmyzB/T/"},
	{"salt length 15", "$y$j7.$///////////////$lzaOauYlT250iKS8qtIlo8Ail.PbSHjKSjRpPsEqcI6"},
	{"salt length 16", "$y$j7.$////////////////$DlYtorMMW/M1IdFxGPdfFS.STo61kYy/eHnOanwVvrC"},
	{"salt length 17", "$y$j7.$/////////////////"},
	{"salt length 18", "$y$j7.$//////////////////$3P/0DYS.t.P2VC4rnF9kWURChONU4ehShDJyGUIoYZ9"},
	{"salt length 19", "$y$j7.$///////////////////$.M.DTam6fr/7j36F7Mo0g3QGSYAD7PbZkwe8X9bJyd8"},
	{"salt length 20", "$y$j7.$////////////////////$dHX43Z/x85XNKoOu4UDromlyoPcD9isScOP8ZeW6l27"},
	{"salt length 21", "$y$j7.$/////////////////////"},
	{"salt length 22", "$y$j7.$//////////////////////$XXf4WJAUsQCV6TUulO3H/f3OWOuK8j8FX9ZtJluydw4"},
	{"salt length 23", "$y$j7.$///////////////////////$FOmK9/DdyesVtGrimp4GNqRPMQ5V6Z8/wfRPWZ.XhjA"},
	{"salt length 24", "$y$j7.$////////////////////////$xW7NvvbWPmxoFVWCDe.WNwrrSfuN/iVvy/05.lD/MO9"},
	// More expected errors
	{"", ""},
	{"", "$y$.7.$$"},
	{"", "$y$j..$$"},
}

func TestHash(t *testing.T) {
	for i, v := range hashes {
		cut := len(v.hash)
		if cut > 29 && (i&1) != 0 {
			cut = 29 + i/2
		}
		hash, err := Hash([]byte(v.password), []byte(v.hash)[:cut])
		if len(hash) < 51 {
			if err == nil {
				t.Errorf("%d: expected error, got %s, nil", i, hash)
			}
			continue
		}
		if err != nil {
			t.Errorf("Hash %d: got unexpected error: %s", i, err)
		}
		if string(hash) != v.hash {
			t.Errorf("Hash %d: expected %s, got %s", i, v.hash, hash)
		}
	}
}

