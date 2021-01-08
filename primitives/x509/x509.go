// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
//
// On UNIX systems the environment variables SSL_CERT_FILE and SSL_CERT_DIR
// can be used to override the system default locations for the SSL certificate
// file and SSL certificate files directory, respectively.
package x509

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/elliptic"
	"crypto/rsa"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
	"github.com/meshplus/crypto-standard/hash"

	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CurveType curve name
type CurveType string

const (
	//CurveTypeSm2 indicates the input curvetype is sm2
	CurveTypeSm2 CurveType = "sm2"
	//CurveTypeK1 indicates the input curvetype is secp256k1
	CurveTypeK1 CurveType = "secp256k1"
	//CurveTypeP256 indicates the input curvetype is secp256r1
	CurveTypeP256 CurveType = "p256"
)

type dsaAlgorithmParameters struct {
	P, Q, G *big.Int
}

type validity struct {
	NotBefore, NotAfter time.Time
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RFC 5280,  4.2.1.1
type authKeyID struct {
	ID []byte `asn1:"optional,tag:0"`
}

//PublicKeyAlgorithm public key algorithm
type PublicKeyAlgorithm int

//signature algorithm
const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	ECDSA
	// Guomi SM2 algorithm
	SM2
)

var publicKeyAlgoName = [...]string{
	RSA:   "RSA",
	DSA:   "DSA",
	ECDSA: "ECDSA",
	// Guomi SM2 algorithm
	SM2: "SM2",
}

func (algo PublicKeyAlgorithm) String() string {
	if 0 < algo && int(algo) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See https://tools.ietf.org/html/rfc3447#appendix-A.2.3
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// rsaPSSParameters returns an asn1.RawValue suitable for use as the Parameters
// in an AlgorithmIdentifier that specifies RSA PSS.
func rsaPSSParameters(hashFunc crypto.Hash) asn1.RawValue {
	var hashOID asn1.ObjectIdentifier

	switch hashFunc {
	case crypto.SHA256:
		hashOID = oidSHA256
	case crypto.SHA384:
		hashOID = oidSHA384
	case crypto.SHA512:
		hashOID = oidSHA512
	}

	params := pssParameters{
		Hash: pkix.AlgorithmIdentifier{
			Algorithm:  hashOID,
			Parameters: asn1.NullRawValue,
		},
		MGF: pkix.AlgorithmIdentifier{
			Algorithm: oidMGF1,
		},
		SaltLength:   hashFunc.Size(),
		TrailerField: 1,
	}

	mgf1Params := pkix.AlgorithmIdentifier{
		Algorithm:  hashOID,
		Parameters: asn1.NullRawValue,
	}

	var err error
	params.MGF.Parameters.FullBytes, err = asn1.Marshal(mgf1Params)
	if err != nil {
		panic(err)
	}

	serialized, err := asn1.Marshal(params)
	if err != nil {
		panic(err)
	}

	return asn1.RawValue{FullBytes: serialized}
}

// ErrUnsupportedAlgorithm results from attempting to perform an operation that
// involves algorithms that are not currently implemented.
var ErrUnsupportedAlgorithm = errors.New("x509: cannot verify signature: algorithm unimplemented")

//InsecureAlgorithmError An InsecureAlgorithmError
type InsecureAlgorithmError SignatureAlgorithm

func (e InsecureAlgorithmError) Error() string {
	return fmt.Sprintf("x509: cannot verify signature: insecure algorithm %v", SignatureAlgorithm(e))
}

// ConstraintViolationError results when a requested usage is not permitted by
// a certificate. For example: checking a signature when the public key isn't a
// certificate signing key.
type ConstraintViolationError struct{}

func (ConstraintViolationError) Error() string {
	return "x509: invalid signature: parent certificate cannot sign this kind of certificate"
}

//Equal compare to certificate
func (c *Certificate) Equal(other *Certificate) bool {
	return bytes.Equal(c.Raw, other.Raw)
}

func (c *Certificate) hasSANExtension() bool {
	return oidInExtensions(oidExtensionSubjectAltName, c.Extensions)
}

// Entrust have a broken root certificate (CN=Entrust.net Certification
// Authority (2048)) which isn't marked as a CA certificate and is thus invalid
// according to PKIX.
// We recognise this certificate by its SubjectPublicKeyInfo and exempt it
// from the Basic Constraints requirement.
// See http://www.entrust.net/knowledge-base/technote.cfm?tn=7869
//
// TODO(agl): remove this hack once their reissued root is sufficiently
// widespread.
var entrustBrokenSPKI = []byte{
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0x97, 0xa3, 0x2d, 0x3c, 0x9e, 0xde, 0x05,
	0xda, 0x13, 0xc2, 0x11, 0x8d, 0x9d, 0x8e, 0xe3,
	0x7f, 0xc7, 0x4b, 0x7e, 0x5a, 0x9f, 0xb3, 0xff,
	0x62, 0xab, 0x73, 0xc8, 0x28, 0x6b, 0xba, 0x10,
	0x64, 0x82, 0x87, 0x13, 0xcd, 0x57, 0x18, 0xff,
	0x28, 0xce, 0xc0, 0xe6, 0x0e, 0x06, 0x91, 0x50,
	0x29, 0x83, 0xd1, 0xf2, 0xc3, 0x2a, 0xdb, 0xd8,
	0xdb, 0x4e, 0x04, 0xcc, 0x00, 0xeb, 0x8b, 0xb6,
	0x96, 0xdc, 0xbc, 0xaa, 0xfa, 0x52, 0x77, 0x04,
	0xc1, 0xdb, 0x19, 0xe4, 0xae, 0x9c, 0xfd, 0x3c,
	0x8b, 0x03, 0xef, 0x4d, 0xbc, 0x1a, 0x03, 0x65,
	0xf9, 0xc1, 0xb1, 0x3f, 0x72, 0x86, 0xf2, 0x38,
	0xaa, 0x19, 0xae, 0x10, 0x88, 0x78, 0x28, 0xda,
	0x75, 0xc3, 0x3d, 0x02, 0x82, 0x02, 0x9c, 0xb9,
	0xc1, 0x65, 0x77, 0x76, 0x24, 0x4c, 0x98, 0xf7,
	0x6d, 0x31, 0x38, 0xfb, 0xdb, 0xfe, 0xdb, 0x37,
	0x02, 0x76, 0xa1, 0x18, 0x97, 0xa6, 0xcc, 0xde,
	0x20, 0x09, 0x49, 0x36, 0x24, 0x69, 0x42, 0xf6,
	0xe4, 0x37, 0x62, 0xf1, 0x59, 0x6d, 0xa9, 0x3c,
	0xed, 0x34, 0x9c, 0xa3, 0x8e, 0xdb, 0xdc, 0x3a,
	0xd7, 0xf7, 0x0a, 0x6f, 0xef, 0x2e, 0xd8, 0xd5,
	0x93, 0x5a, 0x7a, 0xed, 0x08, 0x49, 0x68, 0xe2,
	0x41, 0xe3, 0x5a, 0x90, 0xc1, 0x86, 0x55, 0xfc,
	0x51, 0x43, 0x9d, 0xe0, 0xb2, 0xc4, 0x67, 0xb4,
	0xcb, 0x32, 0x31, 0x25, 0xf0, 0x54, 0x9f, 0x4b,
	0xd1, 0x6f, 0xdb, 0xd4, 0xdd, 0xfc, 0xaf, 0x5e,
	0x6c, 0x78, 0x90, 0x95, 0xde, 0xca, 0x3a, 0x48,
	0xb9, 0x79, 0x3c, 0x9b, 0x19, 0xd6, 0x75, 0x05,
	0xa0, 0xf9, 0x88, 0xd7, 0xc1, 0xe8, 0xa5, 0x09,
	0xe4, 0x1a, 0x15, 0xdc, 0x87, 0x23, 0xaa, 0xb2,
	0x75, 0x8c, 0x63, 0x25, 0x87, 0xd8, 0xf8, 0x3d,
	0xa6, 0xc2, 0xcc, 0x66, 0xff, 0xa5, 0x66, 0x68,
	0x55, 0x02, 0x03, 0x01, 0x00, 0x01,
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	// (except for Entrust, see comment above entrustBrokenSPKI)
	if (parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA) &&
		!bytes.Equal(c.RawSubjectPublicKeyInfo, entrustBrokenSPKI) {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) error {
	return checkSignature(algo, signed, signature, c.PublicKey)
}

func (c *Certificate) hasNameConstraints() bool {
	for _, e := range c.Extensions {
		if len(e.ID) == 4 && e.ID[0] == 2 && e.ID[1] == 5 && e.ID[2] == 29 && e.ID[3] == 30 {
			return true
		}
	}

	return false
}

func (c *Certificate) getSANExtension() []byte {
	for _, e := range c.Extensions {
		if len(e.ID) == 4 && e.ID[0] == 2 && e.ID[1] == 5 && e.ID[2] == 29 && e.ID[3] == 17 {
			return e.Value
		}
	}

	return nil
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo PublicKeyAlgorithm, pubKey interface{}) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
}

// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo SignatureAlgorithm, signed, signature []byte, parentPublicKey crypto.PublicKey) (err error) {
	// Add verify guomi signature support
	if algo == SM3WithSM2 {
		pk, ok := parentPublicKey.(*gm.SM2PublicKey)
		if ok {
			//_, err := pk.VerifySignature(signature, guomi.SignHashSM3(pk.X, pk.Y, signed))
			_, err := pk.Verify(nil, signature, gm.HashBeforeSM2(pk, signed))
			return err
		}
		return signaturePublicKeyAlgoMismatchError(SM2, pk)
	}

	var hashType Hash
	var pubKeyAlgo PublicKeyAlgorithm

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
		}
	}

	switch hashType {
	case Hash(0):
		return ErrUnsupportedAlgorithm
	case MD5:
		return InsecureAlgorithmError(algo)
	}

	if !hashType.Available() {
		return ErrUnsupportedAlgorithm
	}
	h := hashType.New()
	_, _ = h.Write(signed)
	digest := h.Sum(nil)

	switch pub := parentPublicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, crypto.Hash(hashType), digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, crypto.Hash(hashType), digest, signature)

	case *dsa.PublicKey:
		if pubKeyAlgo != DSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		dsaSig := new(dsaSignature)
		if rest, err := asn1.Unmarshal(signature, dsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after DSA signature")
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return errors.New("x509: DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
			return errors.New("x509: DSA verification failure")
		}
		return
	case *asym.ECDSAPublicKey:
		if pubKeyAlgo != ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if b, _ := pub.Verify(nil, signature, digest); !b {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

// CheckCRLSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCRLSignature(crl *CertificateList) error {
	algo := getSignatureAlgorithmFromAI(crl.SignatureAlgorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

//UnhandledCriticalExtension unhandled critical extension
type UnhandledCriticalExtension struct{}

func (h UnhandledCriticalExtension) Error() string {
	return "x509: unhandled critical extension"
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy asn1.ObjectIdentifier
	// policyQualifiers omitted
}

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// RFC 5280, 4.2.2.1
type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// RFC 5280, 4.2.1.14
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case RSA:
		// RSA public keys must have a NULL in the parameters
		// (https://tools.ietf.org/html/rfc3279#section-2.3.1).
		if !bytes.Equal(keyData.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
			return nil, errors.New("x509: RSA key missing NULL parameters")
		}

		p := new(pkcs1PublicKey)
		rest, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after RSA public key")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case DSA:
		var p *big.Int
		rest, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA public key")
		}
		paramsData := keyData.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		rest, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA parameters")
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	case ECDSA:
		paramsData := keyData.Algorithm.Parameters.FullBytes
		// asn1.Marshal(asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301})
		//See keygen's MarshalSm2PublicKey function
		//Enter the if description is the SM2 public key
		if bytes.Equal([]byte{6, 8, 42, 129, 28, 207, 85, 1, 130, 45}, paramsData) {
			pub := new(gm.SM2PublicKey).FromBytes(asn1Data)
			return pub, nil
		}
		namedCurveOID := new(asn1.ObjectIdentifier)
		rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}

		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		pub := &asym.ECDSAPublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}

		return pub, nil
	default:
		return nil, nil
	}
}

func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

func parseSANExtension(value []byte) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		switch tag {
		case nameTypeEmail:
			emailAddresses = append(emailAddresses, string(data))
		case nameTypeDNS:
			dnsNames = append(dnsNames, string(data))
		case nameTypeURI:
			uri, err := url.Parse(string(data))
			if err != nil {
				return fmt.Errorf("x509: cannot parse URI %q: %s", string(data), err)
			}
			if len(uri.Host) > 0 {
				if _, ok := domainToReverseLabels(uri.Host); !ok {
					return fmt.Errorf("x509: cannot parse URI %q: invalid domain", string(data))
				}
			}
			uris = append(uris, uri)
		case nameTypeIP:
			switch len(data) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, data)
			default:
				return errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(data)))
			}
		}

		return nil
	})

	return
}

// isValidIPMask returns true iff mask consists of zero or more 1 bits, followed by zero bits.
func isValidIPMask(mask []byte) bool {
	seenZero := false

	for _, b := range mask {
		if seenZero {
			if b != 0 {
				return false
			}

			continue
		}

		switch b {
		case 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe:
			seenZero = true
		case 0xff:
		default:
			return false
		}
	}

	return true
}

func parseNameConstraintsExtension(out *Certificate, e pkix.Extension) (unhandled bool, err error) {
	// RFC 5280, 4.2.1.10

	// NameConstraints ::= SEQUENCE {
	//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
	//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
	//
	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
	//
	// GeneralSubtree ::= SEQUENCE {
	//      base                    GeneralName,
	//      minimum         [0]     BaseDistance DEFAULT 0,
	//      maximum         [1]     BaseDistance OPTIONAL }
	//
	// BaseDistance ::= INTEGER (0..MAX)

	outer := cryptobyte.String(e.Value)
	var toplevel, permitted, excluded cryptobyte.String
	var havePermitted, haveExcluded bool
	if !outer.ReadASN1(&toplevel, cryptobyte_asn1.SEQUENCE) ||
		!outer.Empty() ||
		!toplevel.ReadOptionalASN1(&permitted, &havePermitted, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) ||
		!toplevel.ReadOptionalASN1(&excluded, &haveExcluded, cryptobyte_asn1.Tag(1).ContextSpecific().Constructed()) ||
		!toplevel.Empty() {
		return false, errors.New("x509: invalid NameConstraints extension")
	}

	if !havePermitted && !haveExcluded || len(permitted) == 0 && len(excluded) == 0 {
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.10:
		//   “either the permittedSubtrees field
		//   or the excludedSubtrees MUST be
		//   present”
		return false, errors.New("x509: empty name constraints extension")
	}

	getValues := func(subtrees cryptobyte.String) (dnsNames []string, ips []*net.IPNet, emails, uriDomains []string, err error) {
		for !subtrees.Empty() {
			var seq, value cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !subtrees.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
				!seq.ReadAnyASN1(&value, &tag) {
				return nil, nil, nil, nil, fmt.Errorf("x509: invalid NameConstraints extension")
			}

			var (
				dnsTag   = cryptobyte_asn1.Tag(2).ContextSpecific()
				emailTag = cryptobyte_asn1.Tag(1).ContextSpecific()
				ipTag    = cryptobyte_asn1.Tag(7).ContextSpecific()
				uriTag   = cryptobyte_asn1.Tag(6).ContextSpecific()
			)

			switch tag {
			case dnsTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain
					// itself, but that's not valid in a
					// normal domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse dnsName constraint %q", domain)
				}
				dnsNames = append(dnsNames, domain)

			case ipTag:
				l := len(value)
				var ip, mask []byte

				switch l {
				case 8:
					ip = value[:4]
					mask = value[4:]

				case 32:
					ip = value[:16]
					mask = value[16:]

				default:
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained value of length %d", l)
				}

				if !isValidIPMask(mask) {
					return nil, nil, nil, nil, fmt.Errorf("x509: IP constraint contained invalid mask %x", mask)
				}

				ips = append(ips, &net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)})

			case emailTag:
				constraint := string(value)
				if err := isIA5String(constraint); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				// If the constraint contains an @ then
				// it specifies an exact mailbox name.
				if strings.Contains(constraint, "@") {
					if _, ok := parseRFC2821Mailbox(constraint); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				} else {
					// Otherwise it's a domain name.
					domain := constraint
					if len(domain) > 0 && domain[0] == '.' {
						domain = domain[1:]
					}
					if _, ok := domainToReverseLabels(domain); !ok {
						return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse rfc822Name constraint %q", constraint)
					}
				}
				emails = append(emails, constraint)

			case uriTag:
				domain := string(value)
				if err := isIA5String(domain); err != nil {
					return nil, nil, nil, nil, errors.New("x509: invalid constraint value: " + err.Error())
				}

				if net.ParseIP(domain) != nil {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q: cannot be IP address", domain)
				}

				trimmedDomain := domain
				if len(trimmedDomain) > 0 && trimmedDomain[0] == '.' {
					// constraints can have a leading
					// period to exclude the domain itself,
					// but that's not valid in a normal
					// domain name.
					trimmedDomain = trimmedDomain[1:]
				}
				if _, ok := domainToReverseLabels(trimmedDomain); !ok {
					return nil, nil, nil, nil, fmt.Errorf("x509: failed to parse URI constraint %q", domain)
				}
				uriDomains = append(uriDomains, domain)

			default:
				unhandled = true
			}
		}

		return dnsNames, ips, emails, uriDomains, nil
	}

	if out.PermittedDNSDomains, out.PermittedIPRanges, out.PermittedEmailAddresses, out.PermittedURIDomains, err = getValues(permitted); err != nil {
		return false, err
	}
	if out.ExcludedDNSDomains, out.ExcludedIPRanges, out.ExcludedEmailAddresses, out.ExcludedURIDomains, err = getValues(excluded); err != nil {
		return false, err
	}
	out.PermittedDNSDomainsCritical = e.Critical

	return unhandled, nil
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER
// data. The certificates must be concatenated with no intermediate padding.
func ParseCertificates(asn1Data []byte) ([]*Certificate, error) {
	var v []*certificate

	for len(asn1Data) > 0 {
		cert := new(certificate)
		var err error
		asn1Data, err = asn1.Unmarshal(asn1Data, cert)
		if err != nil {
			return nil, err
		}
		v = append(v, cert)
	}

	ret := make([]*Certificate, len(v))
	for i, ci := range v {
		cert, err := parseCertificate(ci)
		if err != nil {
			return nil, err
		}
		ret[i] = cert
	}

	return ret, nil
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}

var (
	oidExtensionSubjectKeyID          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyID        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

// oidNotInExtensions returns whether an extension with the given oid exists in
// extensions.
func oidInExtensions(oid asn1.ObjectIdentifier, extensions []pkix.Extension) bool {
	for _, e := range extensions {
		if e.ID.Equal(oid) {
			return true
		}
	}
	return false
}

// marshalSANs marshals a list of addresses into a the contents of an X.509
// SubjectAlternativeName extension.
func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) (derBytes []byte, err error) {
	var rawValues []asn1.RawValue
	for _, name := range dnsNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range emailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeEmail, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIP, Class: 2, Bytes: ip})
	}
	for _, uri := range uris {
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeURI, Class: 2, Bytes: []byte(uri.String())})
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		if r >= utf8.RuneSelf {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func buildExtensions(template *Certificate, subjectIsEmpty bool, AKI, SKI []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n].ID = oidExtensionKeyUsage
		ret[n].Critical = true

		var a [2]byte
		a[0] = reverseBitsInAByte(byte(template.KeyUsage))
		a[1] = reverseBitsInAByte(byte(template.KeyUsage >> 8))

		l := 1
		if a[1] != 0 {
			l = 2
		}

		bitString := a[:l]
		ret[n].Value, err = asn1.Marshal(asn1.BitString{Bytes: bitString, BitLength: asn1BitLength(bitString)})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n].ID = oidExtensionExtendedKeyUsage

		var oids []asn1.ObjectIdentifier
		for _, u := range template.ExtKeyUsage {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				panic("internal error")
			}
		}

		oids = append(oids, template.UnknownExtKeyUsage...)

		ret[n].Value, err = asn1.Marshal(oids)
		if err != nil {
			return
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		// Leaving MaxPathLen as zero indicates that no maximum path
		// length is desired, unless MaxPathLenZero is set. A value of
		// -1 causes encoding/asn1 to omit the value as desired.
		maxPathLen := template.MaxPathLen
		if maxPathLen == 0 && !template.MaxPathLenZero {
			maxPathLen = -1
		}
		ret[n].ID = oidExtensionBasicConstraints
		ret[n].Value, err = asn1.Marshal(basicConstraints{template.IsCA, maxPathLen})
		ret[n].Critical = true
		if err != nil {
			return
		}
		n++
	}

	if len(SKI) > 0 && !oidInExtensions(oidExtensionSubjectKeyID, template.ExtraExtensions) {
		ret[n].ID = oidExtensionSubjectKeyID
		ret[n].Value, err = asn1.Marshal(SKI)
		if err != nil {
			return
		}
		n++
	}

	if len(AKI) > 0 && !oidInExtensions(oidExtensionAuthorityKeyID, template.ExtraExtensions) {
		ret[n].ID = oidExtensionAuthorityKeyID
		ret[n].Value, err = asn1.Marshal(authKeyID{AKI})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].ID = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0 || len(template.URIs) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].ID = oidExtensionSubjectAltName
		// https://tools.ietf.org/html/rfc5280#section-4.2.1.6
		// “If the subject field contains an empty sequence ... then
		// subjectAltName extension ... is marked as critical”
		ret[n].Critical = subjectIsEmpty
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses, template.URIs)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n].ID = oidExtensionCertificatePolicies
		policies := make([]policyInformation, len(template.PolicyIdentifiers))
		for i, policy := range template.PolicyIdentifiers {
			policies[i].Policy = policy
		}
		ret[n].Value, err = asn1.Marshal(policies)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.PermittedDNSDomains) > 0 || len(template.ExcludedDNSDomains) > 0 ||
		len(template.PermittedIPRanges) > 0 || len(template.ExcludedIPRanges) > 0 ||
		len(template.PermittedEmailAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 ||
		len(template.PermittedURIDomains) > 0 || len(template.ExcludedURIDomains) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].ID = oidExtensionNameConstraints
		ret[n].Critical = template.PermittedDNSDomainsCritical

		ipAndMask := func(ipNet *net.IPNet) []byte {
			maskedIP := ipNet.IP.Mask(ipNet.Mask)
			ipAndMask := make([]byte, 0, len(maskedIP)+len(ipNet.Mask))
			ipAndMask = append(ipAndMask, maskedIP...)
			ipAndMask = append(ipAndMask, ipNet.Mask...)
			return ipAndMask
		}

		serialiseConstraints := func(dns []string, ips []*net.IPNet, emails []string, uriDomains []string) (der []byte, err error) {
			var b cryptobyte.Builder

			for _, name := range dns {
				if err = isIA5String(name); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(name))
					})
				})
			}

			for _, ipNet := range ips {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(7).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes(ipAndMask(ipNet))
					})
				})
			}

			for _, email := range emails {
				if err = isIA5String(email); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(email))
					})
				})
			}

			for _, uriDomain := range uriDomains {
				if err = isIA5String(uriDomain); err != nil {
					return nil, err
				}

				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cryptobyte_asn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddBytes([]byte(uriDomain))
					})
				})
			}

			return b.Bytes()
		}

		var permitted []byte
		permitted, err = serialiseConstraints(template.PermittedDNSDomains, template.PermittedIPRanges, template.PermittedEmailAddresses, template.PermittedURIDomains)
		if err != nil {
			return nil, err
		}
		var excluded []byte
		excluded, err = serialiseConstraints(template.ExcludedDNSDomains, template.ExcludedIPRanges, template.ExcludedEmailAddresses, template.ExcludedURIDomains)
		if err != nil {
			return nil, err
		}

		var b cryptobyte.Builder
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if len(permitted) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(permitted)
				})
			}

			if len(excluded) > 0 {
				b.AddASN1(cryptobyte_asn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddBytes(excluded)
				})
			}
		})

		ret[n].Value, err = b.Bytes()
		if err != nil {
			return nil, err
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].ID = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: []asn1.RawValue{
						{Tag: 6, Class: 2, Bytes: []byte(name)},
					},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the maximum number
	// of elements in the make() at the top of the function.

	return append(ret[:n], template.ExtraExtensions...), nil
}

func subjectBytes(cert *Certificate) ([]byte, error) {
	if len(cert.RawSubject) > 0 {
		return cert.RawSubject, nil
	}

	return asn1.Marshal(cert.Subject.ToRDNSequence())
}

// signingParamsForPublicKey returns the parameters to use for signing with
// priv. If requestedSigAlgo is not zero then it overrides the default
// signature algorithm.
func signingParamsForPublicKey(pub interface{}, requestedSigAlgo SignatureAlgorithm) (hashFunc Hash, sigAlgo pkix.AlgorithmIdentifier, err error) {
	var pubType PublicKeyAlgorithm

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubType = RSA
		hashFunc = SHA256
		sigAlgo.Algorithm = oidSignatureSHA256WithRSA
		sigAlgo.Parameters = asn1.NullRawValue

	case *asym.ECDSAPublicKey:
		pubType = ECDSA
		switch pub.Curve {
		case elliptic.P224(), elliptic.P256(), secp256k1.S256():
			hashFunc = SHA256
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA256
		case elliptic.P384():
			hashFunc = SHA384
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA384
		case elliptic.P521():
			hashFunc = SHA512
			sigAlgo.Algorithm = oidSignatureECDSAWithSHA512
		default:
			err = errors.New("x509: unknown elliptic curve")
		}
	case *gm.SM2PublicKey:
		pubType = SM2
		hashFunc = SM3
		sigAlgo.Algorithm = oidSignatureSM3WithSM2
		//fixme : maybe we do not need curve
		switch pub.Curve {
		case gm.GetSm2Curve():
			hashFunc = SM3
			sigAlgo.Algorithm = oidSignatureSM3WithSM2
		default:
			err = errors.New("x509: unknown SM2 curve")
		}
	default:
		err = errors.New("x509: only RSA and ECDSA keys supported")
	}

	if err != nil {
		return
	}

	if requestedSigAlgo == 0 {
		return
	}

	found := false
	for _, details := range signatureAlgorithmDetails {
		if details.algo == requestedSigAlgo {
			if details.pubKeyAlgo != pubType {
				err = errors.New("x509: requested SignatureAlgorithm does not match private key type")
				return
			}
			sigAlgo.Algorithm, hashFunc = details.oid, details.hash
			if hashFunc == 0 {
				err = errors.New("x509: cannot sign with hash function requested")
				return
			}
			if requestedSigAlgo.isRSAPSS() {
				sigAlgo.Parameters = rsaPSSParameters(crypto.Hash(hashFunc))
			}
			found = true
			break
		}
	}

	if !found {
		err = errors.New("x509: unknown SignatureAlgorithm")
	}

	return
}

// emptyASN1Subject is the ASN.1 DER encoding of an empty Subject, which is
// just an empty SEQUENCE.
var emptyASN1Subject = []byte{0x30, 0}

// CreateCertificate creates a new X.509v3 certificate based on a template.
// The following members of template are used: AuthorityKeyID,
// BasicConstraintsValid, DNSNames, ExcludedDNSDomains, ExtKeyUsage,
// IsCA, KeyUsage, MaxPathLen, MaxPathLenZero, NotAfter, NotBefore,
// PermittedDNSDomains, PermittedDNSDomainsCritical, SerialNumber,
// SignatureAlgorithm, Subject, SubjectKeyID, and UnknownExtKeyUsage.
//
// The certificate is signed by parent. If parent is equal to template then the
// certificate is self-signed. The parameter pub is the public key of the
// signee and priv is the private key of the signer.
//
// The returned slice is the certificate in DER encoding.
//
// All keys types that are implemented via crypto.Signer are supported (This
// includes *rsa.PublicKey and *ecdsa.PublicKey.)
//
// The AuthorityKeyID will be taken from the SubjectKeyID of parent, if any,
// unless the resulting certificate is self-signed. Otherwise the value from
// template will be used.
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub crypto.PublicKey, priv crypto.Signer) (cert []byte, err error) {

	if template.SerialNumber == nil {
		return nil, errors.New("x509: no SerialNumber given")
	}

	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv.Public(), template.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}

	SKI := template.SubjectKeyID
	AKI := template.AuthorityKeyID
	if len(template.SubjectKeyID) == 0 {
		hasher := hash.NewHasher(hash.SHA1)
		SKI, _ = hasher.Hash(publicKeyBytes)
	}

	if len(template.AuthorityKeyID) == 0 && len(parent.SubjectKeyID) > 0 {
		AKI = parent.SubjectKeyID
	}

	asn1Issuer, err := subjectBytes(parent)
	if err != nil {
		return
	}

	asn1Subject, err := subjectBytes(template)
	if err != nil {
		return
	}

	extensions, err := buildExtensions(template, bytes.Equal(asn1Subject, emptyASN1Subject), AKI, SKI)
	if err != nil {
		return
	}

	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}
	c := tbsCertificate{
		Version:            2,
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: asn1Issuer},
		Validity:           validity{template.NotBefore.UTC(), template.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: asn1Subject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         extensions,
	}

	tbsCertContents, err := asn1.Marshal(c)
	if err != nil {
		return
	}
	c.Raw = tbsCertContents
	var digest []byte
	if p, ok := priv.(*gm.SM2PrivateKey); ok {
		digest = gm.HashBeforeSM2(&p.PublicKey, tbsCertContents)
	} else {
		h := hashFunc.New()
		_, _ = h.Write(tbsCertContents)
		digest = h.Sum(nil)
	}

	var signerOpts crypto.SignerOpts
	if template.SignatureAlgorithm != 0 && template.SignatureAlgorithm.isRSAPSS() {
		signerOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.Hash(hashFunc),
		}
	} else if template.SignatureAlgorithm != 0 {
		signerOpts = crypto.SHA256
	}

	var signature []byte
	signature, err = priv.Sign(rand, digest, signerOpts)
	if err != nil {
		return
	}

	return asn1.Marshal(certificate{
		nil,
		c,
		signatureAlgorithm,
		asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
