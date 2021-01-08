package primitives

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

//PEMType is pem type
type PEMType int

//pem type enum
const (
	PEMECCPrivateKey  PEMType = 0x0000
	PEMRSAPrivateKey  PEMType = 0x0001
	PEMPublicKey      PEMType = 0x0010
	PEMCertificate    PEMType = 0x0100
	PEMInvalidPEMType PEMType = 0x10000
)

//pem file header
const (
	pemTypeECPrivateKey  = "EC PRIVATE KEY"
	pemTypeCertificate   = "CERTIFICATE"
	pemTypePublicKey     = "PUBLIC KEY"
	pemTypeRSAPrivateKey = "RSA PRIVATE KEY"
)

// PEM2DER pem to der
func PEM2DER(raw []byte) ([]byte, PEMType) {
	if len(raw) == 0 {
		return nil, PEMInvalidPEMType
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, PEMInvalidPEMType
	}
	return block.Bytes, getPemType(block.Type)
}

//DER2PEM encode der to pem
func DER2PEM(in []byte, t PEMType) ([]byte, error) {
	pb := new(pem.Block)
	if t >= PEMInvalidPEMType || t < 0 {
		return nil, errors.New("unknown pem type")
	}
	switch t {
	case PEMPublicKey:
		pb.Type = pemTypePublicKey
	case PEMECCPrivateKey:
		pb.Type = pemTypeECPrivateKey
	case PEMRSAPrivateKey:
		pb.Type = pemTypeRSAPrivateKey
	case PEMCertificate:
		pb.Type = pemTypeCertificate
	}
	pb.Bytes = in
	buf := bytes.NewBuffer(nil)
	err := pem.Encode(buf, pb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

//DER2PEMWithEncryption encode der to pem with encryption
func DER2PEMWithEncryption(in []byte, t PEMType, pwd [32]byte) ([]byte, error) {
	var pemType string
	if t >= PEMInvalidPEMType || t < 0 {
		return nil, errors.New("unknown pem type")
	}
	switch t {
	case PEMPublicKey:
		pemType = pemTypePublicKey
	case PEMECCPrivateKey:
		pemType = pemTypeECPrivateKey
	case PEMRSAPrivateKey:
		pemType = pemTypeRSAPrivateKey
	case PEMCertificate:
		pemType = pemTypeCertificate
	}

	buf := bytes.NewBuffer(nil)
	pb, err := x509.EncryptPEMBlock(rand.Reader, pemType, in, pwd[:], x509.PEMCipherAES256)
	if err != nil {
		return nil, err
	}

	err = pem.Encode(buf, pb)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PEM2DERWithEncryption decode pem to der with password
// if pem is encrypted pem ,pwd is mast not nil
func PEM2DERWithEncryption(raw []byte, pwd *[32]byte) ([]byte, PEMType) {
	if len(raw) == 0 {
		return nil, PEMInvalidPEMType
	}
	//block := new(pem.Block)
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, PEMInvalidPEMType
	}

	if x509.IsEncryptedPEMBlock(block) {
		if pwd == nil {
			return nil, PEMInvalidPEMType
		}
		var err error
		block.Bytes, err = x509.DecryptPEMBlock(block, pwd[:])
		if err != nil {
			return nil, PEMInvalidPEMType
		}
	}

	return block.Bytes, getPemType(block.Type)
}

func getPemType(blockType string) PEMType {
	r := PEMInvalidPEMType
	switch {
	case strings.Contains(blockType, "CERT"):
		r = PEMCertificate
	case strings.Contains(blockType, "RSA"):
		r = PEMRSAPrivateKey
	case strings.Contains(blockType, "PUB"):
		r = PEMPublicKey
	case strings.Contains(blockType, "EC"):
		r = PEMECCPrivateKey
	}
	return r
}
