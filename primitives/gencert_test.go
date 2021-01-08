package primitives

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/pem"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"
)

var from = time.Now()
var to = time.Now().Add(time.Hour)

var CAECC = `-----BEGIN CERTIFICATE-----
MIIB6DCCAY2gAwIBAgIBATAKBggqhkjOPQQDAjBOMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5jbjELMAkGA1UEBhMCWkgxDjAM
BgNVBCoTBWVjZXJ0MCAXDTIwMDMxODExMjMxOFoYDzIxMjAwMjIzMTIyMzE4WjBO
MRMwEQYDVQQKEwpIeXBlcmNoYWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5j
bjELMAkGA1UEBhMCWkgxDjAMBgNVBCoTBWVjZXJ0MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEI2nX0hpuSsB+JS0TX/4vc6Yn4DGEqnEhDgShwEOFdOwc2efbILgU
SUkwASz6eXd64gUrDUsYYe8ojT8zaKi4aaNaMFgwDgYDVR0PAQH/BAQDAgKEMCYG
A1UdJQQfMB0GCCsGAQUFBwMCBggrBgEFBQcDAQYCKgMGA4ELATAPBgNVHRMBAf8E
BTADAQH/MA0GA1UdDgQGBAQBAgMEMAoGCCqGSM49BAMCA0kAMEYCIQC1woBGO/jb
ztF1nFMqqf+Jyw2w+DtTspnoqfSSWnwYSwIhAP8rj93Pc10O15pMBvljhy+Dgl4K
qWLpPojqywKwlep/
-----END CERTIFICATE-----`

var CAPrivateECC = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ/f7jUTSJAhbzeoE5upJa/DIL4x8Mgbb/Jxg9YKgpMqoAoGCCqGSM49
AwEHoUQDQgAEI2nX0hpuSsB+JS0TX/4vc6Yn4DGEqnEhDgShwEOFdOwc2efbILgU
SUkwASz6eXd64gUrDUsYYe8ojT8zaKi4aQ==
-----END EC PRIVATE KEY-----`
var CAGM = `-----BEGIN CERTIFICATE-----
MIIB5jCCAY2gAwIBAgIBATAKBggqgRzPVQGDdTBOMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5jbjELMAkGA1UEBhMCWkgxDjAM
BgNVBCoTBWVjZXJ0MCAXDTIwMDMxODAxNDQxM1oYDzIxMjAwMjIzMDI0NDEzWjBO
MRMwEQYDVQQKEwpIeXBlcmNoYWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5j
bjELMAkGA1UEBhMCWkgxDjAMBgNVBCoTBWVjZXJ0MFkwEwYHKoZIzj0CAQYIKoEc
z1UBgi0DQgAEUHz09LByI4IJbg5AruKdR6+qJwWV7PQhJicnvjtOlrZU6q08qicg
vYGSqJCU9zuNpQADjodhWSbByautDEg+pqNaMFgwDgYDVR0PAQH/BAQDAgKEMCYG
A1UdJQQfMB0GCCsGAQUFBwMCBggrBgEFBQcDAQYCKgMGA4ELATAPBgNVHRMBAf8E
BTADAQH/MA0GA1UdDgQGBAQBAgMEMAoGCCqBHM9VAYN1A0cAMEQCIHaMnRSYoPDh
oSvnukP86EKd5EutcFpNneluAr3wYi8IAiBrfXy0mD+WLB2QSTNEQQvwNb8kJJs6
VM4iJS6Dkpz7AQ==
-----END CERTIFICATE-----`

var CAPrivateGM = `-----BEGIN EC PRIVATE KEY-----
MHgCAQECIQCpMnEYWMpmoJFidYwYdUsKUqdKYY2UYrETZ06AtK/mU6AKBggqgRzP
VQGCLaFEA0IABFB89PSwciOCCW4OQK7inUevqicFlez0ISYnJ747Tpa2VOqtPKon
IL2BkqiQlPc7jaUAA46HYVkmwcmrrQxIPqY=
-----END EC PRIVATE KEY-----`

func TestGenCA(t *testing.T) {
	_, _, err := NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ercert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.NotNil(t, err)
	// CAECC with secp256r1 private key
	ca, private, err := NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	caca := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: ca,
	}
	var cacaBytes []byte
	cacaBuf := bytes.NewBuffer(cacaBytes)
	err = pem.Encode(cacaBuf, caca)
	assert.Nil(t, err)
	der, err := MarshalPrivateKey(private)
	assert.Nil(t, err)
	caPrivate, err := DER2PEM(der, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, caPrivate)
	// CAECC with sm2 private key
	smCa, smPrivate, err := NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ecert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	smCaca := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: smCa,
	}
	var smCacaBytes []byte
	smCacaBuf := bytes.NewBuffer(smCacaBytes)
	err = pem.Encode(smCacaBuf, smCaca)
	assert.Nil(t, err)
	smDer, err := MarshalPrivateKey(smPrivate)
	assert.Nil(t, err)
	smCaPrivate, err := DER2PEM(smDer, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, smCaPrivate)
}

func TestGenCert(t *testing.T) {
	testPrivatePem := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHi/GzLCeFQmaNxi+D1LKu/UcidgUUVd0w/CsMVdV7oloAoGCCqGSM49
AwEHoUQDQgAEstBaQTi1I0/Lrwl8/5bHDRjaSmGPqjV3EXdA1dpu+V5uzgGxj4Jp
m56DcVzpCusmhxObe1unGJeML896Cg7mfg==
-----END EC PRIVATE KEY-----`
	testPrivateDer, pt := PEM2DER([]byte(testPrivatePem))
	assert.True(t, pt == PEMECCPrivateKey)
	testPrivateECC, err := UnmarshalPrivateKey(testPrivateDer)
	assert.Nil(t, err)
	certBlock := &pem.Block{
		Type: pemTypeCertificate,
	}
	caPrivateECCDER, pt := PEM2DER([]byte(CAPrivateECC))
	assert.True(t, pt == PEMECCPrivateKey)
	caPrivateECC, err := UnmarshalPrivateKey(caPrivateECCDER)
	assert.Nil(t, err)
	caStructECC, err := ParseCertificate([]byte(CAECC))
	assert.Nil(t, err)

	caPrivateGMDER, pt := PEM2DER([]byte(CAPrivateGM))
	assert.True(t, pt == PEMECCPrivateKey)
	caPrivateGM, err := UnmarshalPrivateKey(caPrivateGMDER)
	assert.Nil(t, err)
	caStructGM, err := ParseCertificate([]byte(CAGM))
	assert.Nil(t, err)
	certPrivateGM, err := gm.GenerateSM2Key()
	assert.Nil(t, err)
	certPrivateECC, err := asym.GenerateKey(asym.AlgoP256R1)
	assert.Nil(t, err)
	//generate cert with invalid gn
	_, err = GenCert(caStructECC, caPrivateGM.(crypto.Signer), certPrivateGM.Public(), "hyperchain", "node1", "ercert", false, from, to)
	assert.NotNil(t, err)
	_, err = GenCert(caStructECC, caPrivateGM.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "rcert", false, from, to)
	assert.NotNil(t, err)
	_, err = GenCert(caStructECC, testPrivateECC.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "rcert", false, from, to)
	assert.NotNil(t, err)
	//ecc ca can generate cert with ecc public key and gm public key
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "ecert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "sdkcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateGM.Public(), "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateGM.Public(), "hyperchain", "node1", "ecert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC.(crypto.Signer), certPrivateGM.Public(), "hyperchain", "node1", "sdkcert", false, from, to)
	assert.Nil(t, err)
	//gm ca only generate cert with gm public key
	//_, err = GenCert(caStructGM, caPrivateGM.(crypto.Signer), certPrivateECC.Public(), "hyperchain", "node1", "rcert", false)
	//assert.Nil(t, err)
	cert, err := GenCert(caStructGM, caPrivateGM.(crypto.Signer), certPrivateGM.Public(), "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	var certCertBytes []byte
	certCertBuf := bytes.NewBuffer(certCertBytes)
	certBlock.Bytes = cert
	err = pem.Encode(certCertBuf, certBlock)
	assert.Nil(t, err)

	der, err := MarshalPrivateKey(certPrivateGM)
	assert.Nil(t, err)
	caPrivate, err := DER2PEM(der, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, caPrivate)
}

func TestGenK1Cert(t *testing.T) {
	Subject := pkix.Name{
		CommonName:   "hyperchain.cn",
		Organization: []string{"dev"},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}

	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: gmx509.ECDSAWithSHA256,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage: []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth,
			gmx509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	//1.root
	rootT := template
	rootPriv, err := asym.GenerateKey(asym.AlgoP256K1)
	assert.Nil(t, err)
	rootPub := rootPriv.Public()
	root, err := gmx509.CreateCertificate(rand.Reader, &rootT, &rootT, rootPub, rootPriv)
	assert.Nil(t, err)
	rootPem, err := DER2PEM(root, PEMCertificate)
	assert.Nil(t, err)
	rootPrivDER, err := MarshalPrivateKey(rootPriv)
	assert.Nil(t, err)
	rootPrivPem, err := DER2PEM(rootPrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("root.priv", rootPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("root.cert", rootPem, 0666))

	//2.ecert
	eT, err := ParseCertificate(root)
	assert.Nil(t, err)
	ePriv, err := asym.GenerateKey(asym.AlgoP256K1)
	assert.Nil(t, err)
	ePub := ePriv.Public()
	e, err := GenCert(eT, rootPriv, ePub, "dev", "hyperchain.cn", "ecert", true, from, to)
	assert.Nil(t, err)
	ePem, err := DER2PEM(e, PEMCertificate)
	assert.Nil(t, err)
	ePrivDER, err := MarshalPrivateKey(ePriv)
	assert.Nil(t, err)
	ePrivPem, err := DER2PEM(ePrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("ecert.priv", ePrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("ecert.cert", ePem, 0666))

	//3.rcert
	rT, err := ParseCertificate(root)
	assert.Nil(t, err)
	Subject.ExtraNames = Subject.ExtraNames[:1]
	rPriv, err := asym.GenerateKey(asym.AlgoP256K1)
	assert.Nil(t, err)
	rPub := rPriv.Public()
	r, err := GenCert(rT, rootPriv, rPub, "dev", "hyperchain.cn", "rcert", false, from, to)
	assert.Nil(t, err)
	rPem, err := DER2PEM(r, PEMCertificate)
	assert.Nil(t, err)
	rPrivDER, err := MarshalPrivateKey(rPriv)
	assert.Nil(t, err)
	rPrivPem, err := DER2PEM(rPrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("rcert.priv", rPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("rcert.cert", rPem, 0666))

	//4.sdkcert
	sdkT, err := ParseCertificate(e)
	assert.Nil(t, err)
	sdkPriv, err := asym.GenerateKey(asym.AlgoP256K1)
	assert.Nil(t, err)
	sdkPub := sdkPriv.Public()
	sdk, err := GenCert(sdkT, ePriv, sdkPub, "dev", "hyperchain.cn", "sdkcert", false, from, to)
	assert.Nil(t, err)
	sdkPem, err := DER2PEM(sdk, PEMCertificate)
	assert.Nil(t, err)
	sdkPrivDER, err := MarshalPrivateKey(sdkPriv)
	assert.Nil(t, err)
	sdkPrivPem, err := DER2PEM(sdkPrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("sdkcert.priv", sdkPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("sdkcert.cert", sdkPem, 0666))

	//verify
	parseRoot, err := ParseCertificate(rootPem)
	assert.Nil(t, err)
	parseE, err := ParseCertificate(ePem)
	assert.Nil(t, err)
	parseR, err := ParseCertificate(rPem)
	assert.Nil(t, err)
	parseSDK, err := ParseCertificate(sdkPem)
	assert.Nil(t, err)
	//root
	_, err = VerifyCert(parseRoot, parseRoot)
	assert.Nil(t, err)
	//e
	_, err = VerifyCert(parseE, parseRoot)
	assert.Nil(t, err)
	//r
	_, err = VerifyCert(parseR, parseRoot)
	assert.Nil(t, err)
	//sdk
	_, err = VerifyCert(parseSDK, parseE)
	assert.Nil(t, err)

	_ = os.Remove("./ecert.cert")
	_ = os.Remove("./ecert.priv")
	_ = os.Remove("./rcert.cert")
	_ = os.Remove("./rcert.priv")
	_ = os.Remove("./sdkcert.cert")
	_ = os.Remove("./sdkcert.priv")
	_ = os.Remove("./root.cert")
	_ = os.Remove("./root.priv")
}
