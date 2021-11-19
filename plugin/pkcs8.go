// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package plugin

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/ed25519"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private Key.
// See RFC 5208.
func ParsePKCS8PrivateKey(der []byte) (crypto.PrivateKey, error) {
	var privKey pkcs8
	if _, uerr := asn1.Unmarshal(der, &privKey); uerr != nil {
		return nil, uerr
	}
	switch {
	case privKey.Algo.Algorithm.Equal(OidPublicKeyECDSAOrSM2):
		param := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, uerr := asn1.Unmarshal(param, namedCurveOID); uerr != nil {
			namedCurveOID = nil
		}
		if bytes.Equal([]byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}, param) {
			key, err := parseSMprivateKeyWithSwitch(privKey.PrivateKey, false)
			if err != nil {
				return nil, errors.New("x509: failed to parse SM2 private Key embedded in PKCS#8: " + err.Error())
			}
			return &PrivateKey{
				PublicKey: PublicKey{
					Mode: crypto.Sm2p256v1,
					Key:  &key.PublicKey,
				},
				PrivKey: key,
			}, nil
		}
		key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private Key embedded in PKCS#8: " + err.Error())
		}
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: ModeFromCurve(key.Curve),
				Key:  &key.ECDSAPublicKey,
			},
			PrivKey: key,
		}, nil
	case privKey.Algo.Algorithm.Equal(oidSignatureEd25519):
		return nil, fmt.Errorf("x509: PKCS#8 not support unmarshal ed25519 private key")
	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private Key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private Key to PKCS#8 encoded form.
// The following Key types are supported: *rsa.PrivateKey, *ecdsa.PrivateKey.
// Unsupported Key types result in an error.
//
// See RFC 5208.
// support gm
func MarshalPKCS8PrivateKey(key *PrivateKey) ([]byte, error) {
	var privKey pkcs8
	switch key.Mode {
	case crypto.Secp256k1, crypto.Secp256r1, crypto.Secp384r1, crypto.Secp521r1, crypto.Secp256k1Recover:
		oid, ok := oidFromNamedCurve(key.PrivKey.(*asym.ECDSAPrivateKey).Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshalling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: OidPublicKeyECDSAOrSM2,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(key.PrivKey.(*asym.ECDSAPrivateKey), nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private Key while building PKCS#8: " + err.Error())
		}
	case crypto.Ed25519:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidSignatureEd25519,
		}
		var err error
		privKey.PrivateKey, err = asn1.Marshal(key.PrivKey.(*ed25519.EDDSAPrivateKey)[:32])
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal ed25519 private key: %v", err)
		}

	case crypto.Sm2p256v1:
		oidBytes, err := asn1.Marshal(oidNamedCurveP256Sm2)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: OidPublicKeyECDSAOrSM2,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}
		if privKey.PrivateKey, err = MarshalSMPrivateKey(key.PrivKey.(*gm.SM2PrivateKey), true); err != nil {
			return nil, errors.New("x509: failed to marshal sm2 private Key while building PKCS#8: " + err.Error())
		}
	default:
		return nil, fmt.Errorf("x509: unknown Key type while marshalling PKCS#8: %x", key.Mode)
	}

	return asn1.Marshal(privKey)
}
