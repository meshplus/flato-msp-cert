// Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
// It is intended for decoding P12/PFX files for use with the crypto/tls
// package, and for encoding P12/PFX files for use by legacy applications which
// do not support newer formats.  Since PKCS#12 uses weak encryption
// primitives, it SHOULD NOT be used for new applications.
//
// This package is forked from golang.org/x/crypto/pkcs12, which is frozen.
// The implementation is distilled from https://tools.ietf.org/html/rfc7292
// and referenced documents.
package pkcs12

import (
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"io"
)

// DefaultPassword is the string "HYPERCHAIN", a commonly-used password for PKCS#12 files.
// Due to the weak encryption used by PKCS#12, it is RECOMMENDED that you use DefaultPassword when encoding PKCS#12 files,
// and protect the PKCS#12 files using other means.
const DefaultPassword = "HYPERCHAIN"

var (
	oidDataContentType          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidEncryptedDataContentType = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})
	oidLocalKeyID               = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 9, 21})
)

type pfxPdu struct { //PFX
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.AlgorithmIdentifier
}

func (i encryptedPrivateKeyInfo) Data() []byte {
	return i.EncryptedData
}

func (i *encryptedPrivateKeyInfo) SetData(data []byte) {
	i.EncryptedData = data
}

// unmarshal calls asn1.Unmarshal, but also returns an error if there is any
// trailing data after unmarshaling.
func unmarshal(in []byte, out interface{}) error {
	trailing, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(trailing) != 0 {
		return errors.New("pkcs12: trailing data found")
	}
	return nil
}

// Decode extracts a certificate and private key from pfxData. This function
// assumes that there is only one certificate and only one private key in the
// pfxData.  Since PKCS#12 files often contain more than one certificate, you
// probably want to use DecodeChain instead.
func Decode(pfxData []byte, password string) (privateKey interface{}, certificate *gmx509.Certificate, err error) {
	var caCerts []*gmx509.Certificate
	privateKey, certificate, caCerts, err = DecodeChain(pfxData, password)
	if len(caCerts) != 0 {
		err = errors.New("pkcs12: expected exactly two safe bags in the PFX PDU")
	}
	return
}

// DecodeChain extracts a certificate, a CA certificate chain, and private key
// from pfxData. This function assumes that there is at least one certificate
// and only one private key in the pfxData.  The first certificate is assumed to
// be the leaf certificate, and subsequent certificates, if any, are assumed to
// comprise the CA certificate chain.
func DecodeChain(pfxData []byte, password string) (privateKey interface{}, certificate *gmx509.Certificate, caCerts []*gmx509.Certificate, err error) {
	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, nil, nil, err
	}

	bags, encodedPassword, err := getSafeContents(pfxData, encodedPassword)
	if err != nil {
		return nil, nil, nil, err
	}

	for _, bag := range bags {
		switch {
		case bag.ID.Equal(oidCertBag):
			certsData, error := decodeCertBag(bag.Value.Bytes)
			if error != nil {
				return nil, nil, nil, error
			}
			engine := plugin.GetSoftwareEngine("")
			certs, error := gmx509.ParseCertificates(engine, certsData)
			if error != nil {
				return nil, nil, nil, error
			}
			if len(certs) != 1 {
				return nil, nil, nil, errors.New("pkcs12: expected exactly one certificate in the certBag")
			}
			if certificate == nil {
				certificate = certs[0]
			} else {
				caCerts = append(caCerts, certs[0])
			}

		case bag.ID.Equal(oidPKCS8ShroundedKeyBag):
			if privateKey != nil {
				return nil, nil, nil, errors.New("pkcs12: expected exactly one key bag")
			}

			if privateKey, err = decodePkcs8ShroudedKeyBag(bag.Value.Bytes, encodedPassword); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	if certificate == nil {
		return nil, nil, nil, errors.New("pkcs12: certificate missing")
	}
	if privateKey == nil {
		return nil, nil, nil, errors.New("pkcs12: private key missing")
	}

	return
}

func getSafeContents(p12Data, password []byte) (bags []safeBag, updatedPassword []byte, err error) {
	pfx := new(pfxPdu)
	if err = unmarshal(p12Data, pfx); err != nil {
		return nil, nil, errors.New("pkcs12: error reading P12 data: " + err.Error())
	}

	if pfx.Version != 3 {
		return nil, nil, NotImplementedError("can only decode v3 PFX PDU's")
	}

	if !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, nil, NotImplementedError("only password-protected PFX is implemented")
	}

	// unmarshal the explicit bytes in the content for type 'data'
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, errors.New("pkcs12: no MAC in data")
	}

	if err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password); err != nil {
		if err == ErrIncorrectPassword && len(password) == 2 && password[0] == 0 && password[1] == 0 {
			// some implementations use an empty byte array
			// for the empty string password try one more
			// time with empty-empty password
			password = nil
			err = verifyMac(&pfx.MacData, pfx.AuthSafe.Content.Bytes, password)
		}
		if err != nil {
			return nil, nil, err
		}
	}

	var authenticatedSafe []contentInfo
	if err = unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil {
		return nil, nil, err
	}

	if len(authenticatedSafe) != 2 {
		return nil, nil, NotImplementedError("expected exactly two items in the authenticated safe")
	}

	for _, ci := range authenticatedSafe {
		var data []byte

		switch {
		case ci.ContentType.Equal(oidDataContentType):
			if err = unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, nil, err
			}
		case ci.ContentType.Equal(oidEncryptedDataContentType):
			var encrypteData encryptedData
			if err = unmarshal(ci.Content.Bytes, &encrypteData); err != nil {
				return nil, nil, err
			}
			if encrypteData.Version != 0 {
				return nil, nil, NotImplementedError("only version 0 of EncryptedData is supported")
			}
			if data, err = pbDecrypt(encrypteData.EncryptedContentInfo, password); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, NotImplementedError("only data and encrypteData content types are supported in authenticated safe")
		}

		var safeContents []safeBag
		if err := unmarshal(data, &safeContents); err != nil {
			return nil, nil, err
		}
		bags = append(bags, safeContents...)
	}

	return bags, password, nil
}

// Encode produces pfxData containing one private key (privateKey), an
// end-entity certificate (certificate), and any number of CA certificates
// (caCerts).
//
// The private key is encrypted with the provided password, but due to the
// weak encryption primitives used by PKCS#12, it is RECOMMENDED that you
// specify a hard-coded password (such as pkcs12.DefaultPassword) and protect
// the resulting pfxData using other means.
//
// The rand argument is used to provide entropy for the encryption, and
// can be set to rand.Reader from the crypto/rand package.
//
// Encode emulates the behavior of OpenSSL's PKCS12_create: it creates two
// SafeContents: one that's encrypted with RC2 and contains the certificates,
// and another that is unencrypted and contains the private key shrouded with
// 3DES  The private key bag and the end-entity certificate bag have the
// LocalKeyId attribute set to the SHA-1 fingerprint of the end-entity
// certificate.
func Encode(
	rand io.Reader,
	privateKey crypto.SignKey,
	certificate *gmx509.Certificate,
	caCerts []*gmx509.Certificate,
	password string) (pfxData []byte, err error) {

	encodedPassword, err := bmpString(password)
	if err != nil {
		return nil, err
	}

	//1 构造cert bags
	var certBags []safeBag
	var certFingerprint = sha1.Sum(certificate.Raw)
	lvb, err := asn1.Marshal(certFingerprint[:])
	if err != nil {
		return nil, err
	}

	var localKeyIDAttr = pkcs12Attribute{
		ID: oidLocalKeyID,
		Value: asn1.RawValue{
			Class:      0,
			Tag:        17,
			IsCompound: true,
			Bytes:      lvb,
			FullBytes:  nil,
		},
	}

	var certBag *safeBag
	if certBag, err = makeCertBag(certificate.Raw, []pkcs12Attribute{localKeyIDAttr}); err != nil {
		return nil, err
	}
	certBags = append(certBags, *certBag)

	for _, cert := range caCerts {
		if certBag, err = makeCertBag(cert.Raw, []pkcs12Attribute{}); err != nil {
			return nil, err
		}
		certBags = append(certBags, *certBag)
	}

	//2 构造Pkcs8ShroudedKeyBag
	kvb, err := encodePkcs8ShroudedKeyBag(rand, privateKey.(*plugin.PrivateKey).PrivKey, encodedPassword)
	if err != nil {
		return nil, err
	}
	keyBag := safeBag{
		ID: oidPKCS8ShroundedKeyBag,
		Value: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      kvb,
			FullBytes:  nil,
		},
		Attributes: nil,
	}
	keyBag.Attributes = append(keyBag.Attributes, localKeyIDAttr)

	// Construct an authenticated safe with two SafeContents.
	// The first SafeContents is encrypted and contains the cert bags.
	// The second SafeContents is unencrypted and contains the shrouded key bag.
	var authenticatedSafeBytes []byte
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = makeSafeContents(rand, certBags, encodedPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = makeSafeContents(rand, []safeBag{keyBag}, nil); err != nil {
		return nil, err
	}
	if authenticatedSafeBytes, err = asn1.Marshal(authenticatedSafe[:]); err != nil {
		return nil, err
	}

	// compute the MAC
	pMM := make([]byte, 8)
	_, _ = rand.Read(pMM)
	mac := macData{
		Mac: digestInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidSHA1,
				Parameters: asn1.RawValue{},
			},
			Digest: nil,
		},
		MacSalt:    pMM,
		Iterations: 1,
	}
	//computed mac.Mac.digest
	if err = computeMac(&mac, authenticatedSafeBytes, encodedPassword); err != nil {
		return nil, err
	}

	pACBytes, err := asn1.Marshal(authenticatedSafeBytes)
	if err != nil {
		return nil, err
	}
	pfx := pfxPdu{
		Version: 3,
		AuthSafe: contentInfo{
			ContentType: oidDataContentType,
			Content: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      pACBytes,
			},
		},
		MacData: mac,
	}
	if pfxData, err = asn1.Marshal(pfx); err != nil {
		return nil, errors.New("pkcs12: error writing P12 data: " + err.Error())
	}
	return
}

func makeCertBag(certBytes []byte, attributes []pkcs12Attribute) (certBag *safeBag, err error) {
	certBag = new(safeBag)
	certBag.ID = oidCertBag
	certBag.Value.Class = 2
	certBag.Value.Tag = 0
	certBag.Value.IsCompound = true
	if certBag.Value.Bytes, err = encodeCertBag(certBytes); err != nil {
		return nil, err
	}
	certBag.Attributes = attributes
	return
}

func makeSafeContents(rand io.Reader, bags []safeBag, password []byte) (ci contentInfo, err error) {
	var data []byte
	if data, err = asn1.Marshal(bags); err != nil {
		return
	}

	if password == nil {
		ci.ContentType = oidDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(data); err != nil {
			return
		}
	} else {
		randomSalt := make([]byte, 8)
		_, _ = rand.Read(randomSalt)
		var algo pkix.AlgorithmIdentifier
		algo.Algorithm = oidPBEWithSHAAnd40BitRC2CBC
		if algo.Parameters.FullBytes, err = asn1.Marshal(pbeParams{Salt: randomSalt, Iterations: 2048}); err != nil {
			return
		}

		var encryptData encryptedData
		encryptData.Version = 0
		encryptData.EncryptedContentInfo.ContentType = oidDataContentType
		encryptData.EncryptedContentInfo.ContentEncryptionAlgorithm = algo
		if err = pbEncrypt(&encryptData.EncryptedContentInfo, data, password); err != nil {
			return
		}

		ci.ContentType = oidEncryptedDataContentType
		ci.Content.Class = 2
		ci.Content.Tag = 0
		ci.Content.IsCompound = true
		if ci.Content.Bytes, err = asn1.Marshal(encryptData); err != nil {
			return
		}
	}
	return
}
