package x509

import (
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
)

// pkixPublicKey reflects a PKIX public key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
//
// Supported key types include RSA, DSA, and ECDSA. Unknown key
// types result in an error.
//
// On success, pub will be of type *rsa.PublicKey, *dsa.PublicKey,
// or *ecdsa.PublicKey.
func ParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, errors.New("x509: unknown public key algorithm")
	}
	return parsePublicKey(algo, &pki)
}

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// https://tools.ietf.org/html/rfc3279#section-2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *asym.ECDSAPublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
		//SM2
	case *gm.SM2PublicKey:
		publicKeyBytes, err = pub.Bytes()
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: marshal sm key error:" + err.Error())
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeySM2
		publicKeyAlgorithm.Parameters.Class = 0
		publicKeyAlgorithm.Parameters.Tag = 6
		publicKeyAlgorithm.Parameters.IsCompound = false
		publicKeyAlgorithm.Parameters.FullBytes, _ = asn1.Marshal(oidNamedCurveP256Sm2)

	default:
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: only RSA and ECDSA public keys supported")
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// MarshalPKIXPublicKey serialises a public key to DER-encoded PKIX format.
// support sm2
func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyBytes, publicKeyAlgorithm, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	pkix := pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	}

	ret, _ := asn1.Marshal(pkix)
	return ret, nil
}
