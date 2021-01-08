package x509

import (
	"bytes"
	"encoding/asn1"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"math/big"
	"strconv"
)

type dsaSignature struct {
	R, S *big.Int
}

//SignatureAlgorithm signature algorithm
type SignatureAlgorithm int

//signature with hash algorithm
const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA
	MD5WithRSA
	SHA1WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1
	DSAWithSHA256
	ECDSAWithSHA1
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS

	// Guomi SM2 based signature algorithm
	SM3WithSM2
	SHA1WithSM2
	SHA256WithSM2
	SHA512WithSM2
	SHA224WithSM2
	SHA384WithSM2
	RMD160WithSM2
)

func (algo SignatureAlgorithm) isRSAPSS() bool {
	switch algo {
	case SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

func (algo SignatureAlgorithm) String() string {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			return details.name
		}
	}
	return strconv.Itoa(int(algo))
}

// OIDs for signature algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }
//
//
// RFC 3279 2.2.1 RSA Signature Algorithms
//
// md2WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 2 }
//
// md5WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 4 }
//
// sha-1WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 5 }
//
// dsaWithSha1 OBJECT IDENTIFIER ::= {
//    iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
//
// RFC 3279 2.2.3 ECDSA Signature Algorithm
//
// ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
// 	  iso(1) member-body(2) us(840) ansi-x962(10045)
//    signatures(4) ecdsa-with-SHA1(1)}
//
//
// RFC 4055 5 PKCS #1 Version 1.5
//
// sha256WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 11 }
//
// sha384WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 12 }
//
// sha512WithRSAEncryption OBJECT IDENTIFIER ::= { pkcs-1 13 }
//
//
// RFC 5758 3.1 DSA Signature Algorithms
//
// dsaWithSha256 OBJECT IDENTIFIER ::= {
//    joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101)
//    csor(3) algorithms(4) id-dsa-with-sha2(3) 2}
//
// RFC 5758 3.2 ECDSA Signature Algorithm
//
// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
//
// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
//
// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//    us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }

var (
	oidSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	oidSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// oid of SM2 based signature algorithm
	// reference: http://gmssl.org/docs/oid.html
	oidSignatureSM3WithSM2    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidSignatureSHA1WithSM2   = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 502}
	oidSignatureSHA512WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 504}
	oidSignatureSHA224WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 505}
	oidSignatureSHA384WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 506}
	oidSignatureRMD160WithSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 507}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
	// but it's specified by ISO. Microsoft's makecert.exe has been known
	// to produce certificates with this OID.
	oidISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo       SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo PublicKeyAlgorithm
	hash       Hash
}{
	{MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, RSA, Hash(0)},
	{MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA, RSA, MD5},
	{SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA, RSA, SHA1},
	{SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA, RSA, SHA1},
	{SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA, RSA, SHA256},
	{SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA, RSA, SHA384},
	{SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA, RSA, SHA512},
	{SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS, RSA, SHA256},
	{SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS, RSA, SHA384},
	{SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS, RSA, SHA512},
	{DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, SHA1},
	{DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, SHA256},
	{ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1, ECDSA, SHA1},
	{ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256, ECDSA, SHA256},
	{ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384, ECDSA, SHA384},
	{ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512, ECDSA, SHA512},

	// Support for SM2 based signature algorithms
	// SM3 Hash supported
	{SM3WithSM2, "SM3-SM2", oidSignatureSM3WithSM2, SM2, SM3},
	{SHA1WithSM2, "SHA1-SM2", oidSignatureSHA1WithSM2, SM2, SHA1},
	{SHA256WithSM2, "SHA256-SM2", oidSignatureSHA224WithSM2, SM2, SHA256},
	{SHA512WithSM2, "SHA512-SM2", oidSignatureSHA512WithSM2, SM2, SHA512},
	{SHA224WithSM2, "SHA224-SM2", oidSignatureSHA224WithSM2, SM2, SHA224},
	{SHA384WithSM2, "SHA384-SM2", oidSignatureSHA384WithSM2, SM2, SHA384},
	{RMD160WithSM2, "RMD160-SM2", oidSignatureRMD160WithSM2, SM2, RIPEMD160},
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) SignatureAlgorithm {
	if !ai.Algorithm.Equal(oidSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces
	// them into three buckets by requiring that the MGF1 hash
	// function always match the message hash function (as
	// recommended in
	// https://tools.ietf.org/html/rfc3447#section-8.1), that the
	// salt length matches the hash length, and that the trailer
	// field has the default value.
	if !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes) ||
		!params.MGF.Algorithm.Equal(oidMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		!bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes) ||
		params.TrailerField != 1 {
		return UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(oidSHA256) && params.SaltLength == 32:
		return SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA384) && params.SaltLength == 48:
		return SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(oidSHA512) && params.SaltLength == 64:
		return SHA512WithRSAPSS
	}

	return UnknownSignatureAlgorithm
}
