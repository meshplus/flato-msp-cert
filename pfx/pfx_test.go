package pkcs12

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"flag"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/flato-msp-cert/primitives"
	"github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

var rsaBits = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")

func newSelfSignedCertWithRSA() ([]byte, interface{}, error) {
	var (
		err                error
		privKeyRSA         *rsa.PrivateKey
		signatureAlgorithm x509.SignatureAlgorithm
		privKey            crypto.Signer
		pubKey             interface{}
	)

	privKeyRSA, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	signatureAlgorithm = x509.SHA256WithRSA
	privKey = privKeyRSA
	pubKey = privKeyRSA.Public()

	if err != nil {
		return nil, nil, err
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	commonName := "hyperchain.cn"
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Develop",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

func TestPfxWithGM(t *testing.T) {
	CertGM, PrivKeyGM, err := primitives.NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ecert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	ca, err := primitives.ParseCertificate(CertGM)
	assert.Nil(t, err)

	data, err := Encode(rand.Reader, PrivKeyGM.(*gm.SM2PrivateKey), ca, []*x509.Certificate{ca}, "")
	assert.Nil(t, err)
	_, cert, _, err := DecodeChain(data, "")
	assert.Nil(t, err)
	certDer, err := x509.MarshalCertificate(cert)
	assert.Nil(t, err)

	assert.Equal(t, CertGM, certDer, "The two certificates should be the same.")
}

func TestPfxWithECDSA(t *testing.T) {
	CertECDSA, PrivKeyECDSA, err := primitives.NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ecert", "p256", time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	ca, err := primitives.ParseCertificate(CertECDSA)
	assert.Nil(t, err)
	CertBefore, err := primitives.DER2PEM(CertECDSA, primitives.PEMCertificate)
	assert.Nil(t, err)
	data, err := Encode(rand.Reader, PrivKeyECDSA.(*asym.ECDSAPrivateKey), ca, []*x509.Certificate{ca}, "")
	assert.Nil(t, err)
	_, cert, _, err := DecodeChain(data, "")
	assert.Nil(t, err)
	certDer, err := x509.MarshalCertificate(cert)
	assert.Nil(t, err)
	CertAfter, err := primitives.DER2PEM(certDer, primitives.PEMCertificate)
	assert.Nil(t, err)
	assert.Equal(t, CertBefore, CertAfter, "The two certificates should be the same.")
}

func TestPfxWithRSA(t *testing.T) {
	CertRSA, PrivKeyRSA, err := newSelfSignedCertWithRSA()
	assert.Nil(t, err)
	ca, err := primitives.ParseCertificate(CertRSA)
	assert.Nil(t, err)

	data, err := Encode(rand.Reader, PrivKeyRSA.(*rsa.PrivateKey), ca, []*x509.Certificate{ca}, "")
	assert.Nil(t, err)
	_, cert, _, err := DecodeChain(data, "")
	assert.Nil(t, err)
	certDer, err := x509.MarshalCertificate(cert)
	assert.Nil(t, err)

	assert.Equal(t, CertRSA, certDer, "The two certificates should be the same.")
}
