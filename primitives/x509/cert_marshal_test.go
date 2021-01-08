package x509

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

func TestMarshalCertificateError(t *testing.T) {
	certificate := new(Certificate)
	big := new(big.Int).SetUint64(uint64(10000000))
	certificate.SerialNumber = big
	sm2pk, err := gm.GenerateSM2Key()
	assert.Nil(t, err)
	certificate.SignatureAlgorithm = UnknownSignatureAlgorithm
	certificate.PublicKey = sm2pk.PublicKey
	_, err = MarshalCertificate(certificate)
	assert.NotNil(t, err)

	certificate.SignatureAlgorithm = SHA256WithRSA
	certificate.PublicKey = rsa.PublicKey{N: big, E: 10}
	_, err = MarshalCertificate(certificate)
	assert.NotNil(t, err)

	certificate.SignatureAlgorithm = ECDSAWithSHA256
	certificate.PublicKey = asym.ECDSAPublicKey{Curve: elliptic.P256(), X: big, Y: big}
	_, err = MarshalCertificate(certificate)
	assert.NotNil(t, err)

	certificate.SignatureAlgorithm = SM3WithSM2
	certificate.PublicKey = sm2pk.PublicKey
	_, err = MarshalCertificate(certificate)
	assert.NotNil(t, err)

	certificate.SerialNumber = nil
	certificate.SignatureAlgorithm = SM3WithSM2
	certificate.PublicKey = sm2pk.PublicKey
	cert, err := MarshalCertificate(certificate)

	assert.NotNil(t, err)
	assert.IsType(t, []byte{}, cert, "should be the type of der")

}

func TestMarshalCertificate(t *testing.T) {
	var (
		privKey crypto.Signer
		pubKey  crypto.PublicKey
	)

	privKeyECDSA, err := asym.GenerateKey(asym.AlgoP256R1)
	assert.Nil(t, err)
	signatureAlgorithm := ECDSAWithSHA256
	privKey = privKeyECDSA
	pubKey = privKeyECDSA.Public()

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}

	Subject := pkix.Name{
		CommonName:   "www.hyperchain.cn",
		Organization: []string{"Hyperchain"},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}
	Subject.ExtraNames = append(Subject.ExtraNames,
		pkix.AttributeTypeAndValue{
			Type:  []int{2, 5, 4, 42},
			Value: "ecert",
		})

	template := Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: signatureAlgorithm,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign | KeyUsageDigitalSignature,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	assert.Nil(t, err)

	block, _ := pem.Decode(cert)
	if block != nil {
		cert = block.Bytes
	}
	ca, err := ParseCertificate(cert)
	assert.Nil(t, err)

	_, err = MarshalCertificate(ca)
	assert.Nil(t, err)
}

func TestSubjectBytesWhenMarshal(t *testing.T) {

	cert := new(Certificate)
	var template = new(Certificate)

	template.SerialNumber = cert.SerialNumber
	template.Subject = cert.Subject
	template.NotBefore = cert.NotBefore
	template.NotAfter = cert.NotAfter
	template.SignatureAlgorithm = cert.SignatureAlgorithm
	template.SubjectKeyID = cert.SubjectKeyID
	template.KeyUsage = cert.KeyUsage
	template.ExtKeyUsage = cert.ExtKeyUsage
	template.UnknownExtKeyUsage = cert.UnknownExtKeyUsage
	template.BasicConstraintsValid = cert.BasicConstraintsValid
	template.IsCA = cert.IsCA
	template.ExtraExtensions = cert.ExtraExtensions
	template.Version = cert.Version - 1
	template.Subject.Names = []pkix.AttributeTypeAndValue{{Type: []int{1, 2, 3}, Value: "111"}, {Type: []int{1, 2, 3}, Value: "222"}}

	_, err := SubjectBytesWhenMarshal(template)
	assert.Nil(t, err)

	template.RawSubject = []byte{1}
	asn1Subject, err := SubjectBytesWhenMarshal(template)

	assert.IsType(t, []byte{}, asn1Subject, "SubjectBytesWhenMarshal failed!")
	assert.Nil(t, err, "SubjectBytesWhenMarshal failed!")
}

func TestSignParamsForPublicKey(t *testing.T) {

	_, _, err := signParamsForPublicKey(0)
	assert.NotNil(t, err)

	_, _, err = signParamsForPublicKey(ECDSAWithSHA384)
	assert.Nil(t, err)

	_, _, err = signParamsForPublicKey(MD2WithRSA)
	assert.NotNil(t, err)

	_, _, err = signParamsForPublicKey(ECDSAWithSHA512)
	assert.Nil(t, err)

	_, _, err = signParamsForPublicKey(ECDSAWithSHA1)
	assert.NotNil(t, err)

	_, _, err = signParamsForPublicKey(SHA1WithSM2)
	assert.NotNil(t, err)

	signatureAlgorithm := ECDSAWithSHA384
	assert.IsType(t, SM3WithSM2, signatureAlgorithm)

}
