package primitives

import (
	"bytes"
	"encoding/asn1"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
)

//CertType a data type to present cert type，like tcert，ecert and so on
type CertType int

// the value of CertType
const (
	ECert CertType = iota
	RCert
	SDKCert
	TCert
	ERCert
	IDCert
	UnknownCertType
)

//CertTypeOID oid fo certType
var CertTypeOID asn1.ObjectIdentifier = []int{1, 2, 86, 1}

var certTypeList = [...][]byte{
	ECert:           []byte("ecert"),
	RCert:           []byte("rcert"),
	SDKCert:         []byte("sdkcert"),
	TCert:           []byte("tcert"),
	ERCert:          []byte("ercert"),
	IDCert:          []byte("idcert"),
	UnknownCertType: []byte("unknown cert type"),
}

//NewCertType get a CertType
func NewCertType(certType string) CertType {
	switch certType {
	case "ecert":
		return ECert
	case "rcert":
		return RCert
	case "sdkcert":
		return SDKCert
	case "tcert":
		return TCert
	case "ercert":
		return ERCert
	case "idcert":
		return IDCert
	}
	return UnknownCertType
}

//ParseCertType unmarshal cert Type
func ParseCertType(certType []byte) CertType {
	for i := len(certTypeList) - 1; i >= 0; i-- {
		if bytes.Contains(certType, certTypeList[i]) {
			return CertType(i)
		}
	}
	return UnknownCertType
}

//GetValue return bytes slice of a certType，marshal cert Type
func (c CertType) GetValue() []byte {
	if c < 0 || c > UnknownCertType {
		return []byte("illegal type")
	}
	return certTypeList[c]
}

//AssertCertType assert cert type with specified type，return boolean
func AssertCertType(expect CertType, certificate *gmx509.Certificate) bool {
	for _, v := range certificate.Extensions {
		if CertTypeOID.Equal(v.ID) {
			value := ParseCertType(v.Value)
			if value == expect {
				return true
			}
			if value == ERCert && (expect == ECert || expect == RCert) {
				return true
			}
		}
	}
	return false
}
