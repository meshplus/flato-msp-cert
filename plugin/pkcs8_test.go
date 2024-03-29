// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package plugin

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"github.com/meshplus/crypto"
	"testing"
)

// Generated using:
//   openssl ecparam -genkey -name secp256r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P256PrivateKeyHex = `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`

// Generated using:
//   openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P384PrivateKeyHex = `3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309bf832f6aaaeacb78ce47ffb15e6fd0fd48683ae79df6eca39bfb8e33829ac94aa29d08911568684c2264a08a4ceb679a164036200049070ad4ed993c7770d700e9f6dc2baa83f63dd165b5507f98e8ff29b5d2e78ccbe05c8ddc955dbf0f7497e8222cfa49314fe4e269459f8e880147f70d785e530f2939e4bf9f838325bb1a80ad4cf59272ae0e5efe9a9dc33d874492596304bd3`

// Generated using:
//   openssl ecparam -genkey -name secp521r1 | openssl pkcs8 -topk8 -nocrypt
//
// Note that OpenSSL will truncate the private Key if it can (i.e. it emits it
// like an integer, even though it's an OCTET STRING field). Thus if you
// regenerate this you may, randomly, find that it's a byte shorter than
// expected and the Go test will fail to recreate it exactly.
var pkcs8P521PrivateKeyHex = `3081ee020100301006072a8648ce3d020106052b810400230481d63081d3020101044200cfe0b87113a205cf291bb9a8cd1a74ac6c7b2ebb8199aaa9a5010d8b8012276fa3c22ac913369fa61beec2a3b8b4516bc049bde4fb3b745ac11b56ab23ac52e361a1818903818600040138f75acdd03fbafa4f047a8e4b272ba9d555c667962b76f6f232911a5786a0964e5edea6bd21a6f8725720958de049c6e3e6661c1c91b227cebee916c0319ed6ca003db0a3206d372229baf9dd25d868bf81140a518114803ce40c1855074d68c4e9dab9e65efba7064c703b400f1767f217dac82715ac1f6d88c74baf47a7971de4ea`

func TestPKCS8(t *testing.T) {
	tests := []struct {
		name    string
		keyHex  string
		keyType int
		curve   elliptic.Curve
	}{
		{
			name:    "P-256 private Key",
			keyHex:  pkcs8P256PrivateKeyHex,
			keyType: crypto.Secp256r1,
			curve:   elliptic.P256(),
		},
		{
			name:    "P-384 private Key",
			keyHex:  pkcs8P384PrivateKeyHex,
			keyType: crypto.Secp384r1,
			curve:   elliptic.P384(),
		},
		{
			name:    "P-521 private Key",
			keyHex:  pkcs8P521PrivateKeyHex,
			keyType: crypto.Secp521r1,
			curve:   elliptic.P521(),
		},
	}

	for i, test := range tests {
		derBytes, err := hex.DecodeString(test.keyHex)
		if err != nil {
			t.Errorf("%s: failed to decode hex: %s", test.name, err)
			continue
		}
		privKey, err := ParsePKCS8PrivateKey(derBytes)
		if err != nil {
			t.Errorf("%s: failed to decode PKCS#8: %s", test.name, err)
			continue
		}
		if privKey.GetKeyInfo() != test.keyType {
			t.Errorf("%s: decoded PKCS#8 returned unexpected Key type: %T", test.name, privKey)
			continue
		}
		if mode := privKey.GetKeyInfo(); i != 0 && mode != ModeFromCurve(test.curve) {
			t.Errorf("decoded PKCS#8 returned unexpected curve %#v", test.curve.Params().Name)
			continue
		}
		reserialised, err := MarshalPKCS8PrivateKey(privKey.(*PrivateKey))
		if err != nil {
			t.Errorf("%s: failed to marshal into PKCS#8: %s", test.name, err)
			continue
		}
		if !bytes.Equal(derBytes, reserialised) {
			t.Errorf("%s: marshalled PKCS#8 didn't match original: got %x, want %x", test.name, reserialised, derBytes)
			continue
		}
	}
}
