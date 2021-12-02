package plugin

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"strconv"
)

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
//OID for algo
var (
	OidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	//oidPublicKeyDSA        = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OidPublicKeyECDSAOrSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// pkixPublicKey reflects a PKIX public Key structure. See SubjectPublicKeyInfo
// in RFC 3280.
type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

// ParsePKIXPublicKey parses a DER encoded public Key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
func ParsePKIXPublicKey(derBytes []byte) (rawPub []byte, mode int, err error) {
	var pki pkixPublicKey
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, crypto.None, errors.New("x509: failed to parse public Key (use ParsePKCS1PublicKey instead for this Key format)")
	} else if len(rest) != 0 {
		return nil, crypto.None, errors.New("x509: trailing data after ASN.1 of public-Key")
	}
	algo := GetPublicKeyAlgorithmFromAlgorithmIdentifier(pki.Algo)
	if algo == UnknownPublicKeyAlgorithm {
		return nil, crypto.None, errors.New("x509: unknown public Key algorithm")
	}
	return parsePublicKey(algo, &pki)
}

//GetPublicKeyAlgorithmFromAlgorithmIdentifier get PublicKeyAlgorithm
func GetPublicKeyAlgorithmFromAlgorithmIdentifier(algo pkix.AlgorithmIdentifier) PublicKeyAlgorithm {
	oid := algo.Algorithm
	param := algo.Parameters.FullBytes
	switch {
	case oid.Equal(OidPublicKeyRSA):
		return RSA
	//case oid.Equal(oidPublicKeyDSA):
	//	return DSA
	case oid.Equal(OidPublicKeyECDSAOrSM2):
		// asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		//See keygen's MarshalSm2PublicKey function
		//Enter the if description is the SM2 public Key
		if bytes.Equal([]byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}, param) {
			return SM2
		}
		return ECDSA
	}
	return UnknownPublicKeyAlgorithm
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *pkixPublicKey) (rawPub []byte, mode int, err error) {
	asn1Data := keyData.BitString.RightAlign()
	//var inner crypto.Verifier
	switch algo {
	case RSA:
		// RSA public keys must have a NULL in the parameters
		// (https://tools.ietf.org/html/rfc3279#section-2.3.1).
		if !bytes.Equal(keyData.Algo.Parameters.FullBytes, asn1.NullBytes) {
			return nil, crypto.None, errors.New("x509: RSA Key missing NULL parameters")
		}
		var p pkcs1PublicKey
		_, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, crypto.None, err
		}
		if mode, err = ModeFromRSAMod(p.N.BitLen()); err != nil {
			return nil, crypto.None, errors.New("x509: trailing data after RSA public Key")
		}
		rawPub = asn1Data
	case ECDSA:
		paramsData := keyData.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, crypto.None, err
		}
		if len(rest) != 0 {
			return nil, crypto.None, errors.New("x509: trailing data after DSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, crypto.None, errors.New("x509: unsupported elliptic curve")
		}

		mode, rawPub = ModeFromCurve(namedCurve), asn1Data
	case SM2:
		mode, rawPub = crypto.Sm2p256v1, asn1Data
	default:
		return nil, crypto.None, errors.New("x509: unsupported public Key algo type")
	}
	return
}

//GetPublicKeyAlgorithmFromMode get public pkix.AlgorithmIdentifier from mode
func GetPublicKeyAlgorithmFromMode(mode int) (pkix.AlgorithmIdentifier, error) {
	setECDSAKeyPublicKeyAlgorithm := func(c elliptic.Curve) (pkix.AlgorithmIdentifier, error) {
		var publicKeyAlgorithm pkix.AlgorithmIdentifier
		oid, ok := oidFromNamedCurve(c)
		if !ok {
			return pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = OidPublicKeyECDSAOrSM2
		paramBytes, err := asn1.Marshal(oid)
		if err != nil {
			return pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
		return publicKeyAlgorithm, err
	}
	switch {
	case ModeIsRSAAlgo(mode):
		return pkix.AlgorithmIdentifier{
			Algorithm: OidPublicKeyRSA,
			// This is a NULL parameters value which is required by
			// https://tools.ietf.org/html/rfc3279#section-2.3.1.
			Parameters: asn1.NullRawValue,
		}, nil
	case ModeIsECDSAAlgo(mode):
		curve, _ := ModeGetCurve(mode)
		return setECDSAKeyPublicKeyAlgorithm(curve)
	case mode == crypto.Sm2p256v1:
		fullBytes, _ := asn1.Marshal(oidNamedCurveP256Sm2)
		return pkix.AlgorithmIdentifier{
			Algorithm: OidPublicKeyECDSAOrSM2,
			Parameters: asn1.RawValue{
				Tag:       6,
				FullBytes: fullBytes,
			},
		}, nil
	default:
		return pkix.AlgorithmIdentifier{}, errors.New("x509: only RSA and ECDSA public keys supported")
	}
}

// MarshalPKIXPublicKey serialises a public Key to DER-encoded PKIX format.
func MarshalPKIXPublicKey(rawpub []byte, mode int) ([]byte, error) {
	var publicKeyAlgorithm pkix.AlgorithmIdentifier
	var err error

	if publicKeyAlgorithm, err = GetPublicKeyAlgorithmFromMode(mode); err != nil {
		return nil, err
	}

	ret, _ := asn1.Marshal(pkixPublicKey{
		Algo: publicKeyAlgorithm,
		BitString: asn1.BitString{
			Bytes:     rawpub,
			BitLength: 8 * len(rawpub),
		},
	})
	return ret, nil
}

//PublicKeyAlgorithm public Key algorithm
type PublicKeyAlgorithm int

//signature algorithm
const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	//DSA
	ECDSA
	SM2
)

var publicKeyAlgoName = [...]string{
	RSA: "RSA",
	//DSA:   "DSA",
	ECDSA: "ECDSA",
	SM2:   "SM2",
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}
