package x509

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"io"
	"math/big"
	"reflect"
	"time"
)

//ra  http://ucrl.cfca.com.cn/OCA1/SM2/allCRL.crl
//crl http://114.55.107.52:8080/raWeb/CSHttpServlet

// CertificateList represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1. Use Certificate.CheckCRLSignature to verify the
// signature.
type CertificateList struct {
	TBSCertList        TBSCertificateList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// HasExpired reports whether certList should have been updated by now.
func (certList *CertificateList) HasExpired(now time.Time) bool {
	return !now.Before(certList.TBSCertList.NextUpdate)
}

// TBSCertificateList represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1.
type TBSCertificateList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              pkix.RDNSequence
	ThisUpdate          time.Time
	NextUpdate          time.Time            `asn1:"optional"`
	RevokedCertificates []RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension     `asn1:"tag:0,optional,explicit"`
}

// RevokedCertificate represents the ASN.1 structure of the same name. See RFC
// 5280, section 5.1.
type RevokedCertificate struct {
	SerialNumber   *big.Int
	RevocationTime time.Time
	Extensions     []pkix.Extension `asn1:"optional"`
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// pemType is the type of a PEM encoded CRL.
var pemType = "X509 CRL"

// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
func ParseCRL(crlBytes []byte) (*CertificateList, error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		block, _ := pem.Decode(crlBytes)
		if block != nil && block.Type == pemType {
			crlBytes = block.Bytes
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL parses a DER encoded CRL from the given bytes.
func ParseDERCRL(derBytes []byte) (*CertificateList, error) {
	certList := new(CertificateList)
	if rest, err := asn1.Unmarshal(derBytes, certList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after CRL")
	}
	return certList, nil
}

// CreateCRL returns a DER encoded CRL, signed by this Certificate, that
// contains the given list of revoked certificates.
func (c *Certificate) CreateCRL(rand io.Reader, priv crypto.SignKey, revokedCerts []RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	if reflect.DeepEqual(priv, nil) {
		return nil, fmt.Errorf("private key is nil")
	}
	hashFunc, signatureAlgorithm, err := signingParamsForPublicKey(priv, 0)
	if err != nil {
		return nil, err
	}

	// Force revocation times to UTC per RFC 5280.
	revokedCertsUTC := make([]RevokedCertificate, len(revokedCerts))
	for i, rc := range revokedCerts {
		rc.RevocationTime = rc.RevocationTime.UTC()
		revokedCertsUTC[i] = rc
	}

	tbsCertList := TBSCertificateList{
		Version:             1,
		Signature:           signatureAlgorithm,
		Issuer:              c.Subject.ToRDNSequence(),
		ThisUpdate:          now.UTC(),
		NextUpdate:          expiry.UTC(),
		RevokedCertificates: revokedCertsUTC,
	}

	// Authority Key ID
	if len(c.SubjectKeyID) > 0 {
		var aki pkix.Extension
		aki.ID = oidExtensionAuthorityKeyID
		aki.Value, err = asn1.Marshal(authKeyID{ID: c.SubjectKeyID})
		if err != nil {
			return
		}
		tbsCertList.Extensions = append(tbsCertList.Extensions, aki)
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return
	}

	var signature []byte
	//pkcs1v15
	if plugin.ModeIsRSAAlgo(priv.GetKeyInfo()) {
		var hashTypeUsedInPKCS1v15 [4]byte
		binary.BigEndian.PutUint32(hashTypeUsedInPKCS1v15[:], uint32(hashFunc))
		signature, err = priv.Sign(append(tbsCertListContents, hashTypeUsedInPKCS1v15[:]...), hashFunc.New(), rand)
	} else {
		signature, err = priv.Sign(tbsCertListContents, hashFunc.New(), rand)
	}
	if err != nil {
		return
	}

	return asn1.Marshal(CertificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}
