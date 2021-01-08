package primitives

import (
	"crypto/rsa"
	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
	"time"
)

func getConfig(path string) ([]byte, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return content, nil

}

func TestDERCertToPEM(t *testing.T) {
	cert, _, err := NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	pem, err := DER2PEM(cert, PEMCertificate)
	assert.Nil(t, err)
	x, err := ParseCertificate(pem)
	assert.Nil(t, err)
	assert.NotNil(t, x)
}

func TestGetConfig(t *testing.T) {
	_, err := getConfig("")
	assert.NotNil(t, err)
}

func TestParseCertificate(t *testing.T) {
	_, err := ParseCertificate([]byte(""))
	assert.NotNil(t, err)
	cerPem, err := getConfig("./test/cert.cer")
	assert.Nil(t, err)
	cer, err := ParseCertificate(cerPem)
	assert.Nil(t, err)
	assert.Equal(t, int64(69396857094), cer.SerialNumber.Int64())
}

func TestVerifyCertChain(t *testing.T) {
	// CA cert
	cerPem, err := getConfig("./test/CFCA_TEST_SM2_OCA1.cer")
	assert.Nil(t, err)
	ca, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	// user cert
	cerPem, err = getConfig("./test/cert.cer")
	assert.Nil(t, err)
	cer, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	isValid, err := VerifyCert(cer, ca)
	assert.Nil(t, err)
	assert.True(t, isValid)
}

func TestVerifyCert(t *testing.T) {
	// CA cert
	cerPem, err := getConfig("./test/eca.ca")
	assert.Nil(t, err)
	ca, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	// user cert
	cerPem, err = getConfig("./test/ecert.cert")
	assert.Nil(t, err)
	cer, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	isValid, err := VerifyCert(cer, ca)
	assert.Nil(t, err)
	assert.True(t, isValid)

	ca.PublicKeyAlgorithm = x509.UnknownPublicKeyAlgorithm
	isValid, _ = VerifyCert(cer, ca)
	assert.False(t, isValid)

	cer.NotBefore = cer.NotBefore.AddDate(3, 0, 0)
	_, err = VerifyCert(cer, ca)
	assert.NotNil(t, err)
}

func TestParseKey(t *testing.T) {

	priPem, err := getConfig("./test/ecert.cert")
	assert.Nil(t, err)
	var der []byte
	var pt PEMType

	der, pt = PEM2DER(priPem)
	_, err = UnmarshalPrivateKey(der)
	assert.NotNil(t, err)
	assert.Equal(t, PEMCertificate, pt)

	priPem, err = getConfig("./test/rsa_private_key.pem")
	assert.Nil(t, err)

	der, pt = PEM2DER(priPem)
	assert.Equal(t, PEMRSAPrivateKey, pt)
	key, err := UnmarshalPrivateKey(der)
	assert.Nil(t, err)
	assert.IsType(t, new(rsa.PrivateKey), key)

	priPem, err = getConfig("./test/root_guomi.priv")
	assert.Nil(t, err)

	der, pt = PEM2DER(priPem)
	assert.Equal(t, PEMECCPrivateKey, pt)
	key, err = UnmarshalPrivateKey(der)
	assert.Nil(t, err)
	assert.IsType(t, new(gm.SM2PrivateKey), key)
}

func TestParsePubKey(t *testing.T) {

	_, err := UnmarshalPublicKey([]byte(""))
	assert.NotNil(t, err)

	publicPem, err := getConfig("./test/rsa_private_key.pem")
	assert.Nil(t, err)
	var der []byte
	var pt PEMType

	der, pt = PEM2DER(publicPem)
	assert.Equal(t, PEMRSAPrivateKey, pt)
	_, err = UnmarshalPublicKey(der)
	assert.NotNil(t, err)

	publicPem, err = getConfig("./test/rsa_public_key.pem")
	assert.Nil(t, err)
	der, pt = PEM2DER(publicPem)
	assert.Equal(t, PEMPublicKey, pt)
	key, err := UnmarshalPublicKey(der)
	assert.Nil(t, err)
	assert.IsType(t, new(rsa.PublicKey), key)
}

func TestSM2Verify(t *testing.T) {
	cerPem, err := getConfig("./test/gmsslCA.crt")
	assert.Nil(t, err)
	ca, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	cerPem, err = getConfig("./test/gmsslCert.crt")
	assert.Nil(t, err)
	cer, err := ParseCertificate(cerPem)
	assert.Nil(t, err)

	isValid, err := VerifyCert(cer, ca)
	assert.Nil(t, err)
	assert.True(t, isValid)
}

func TestNewSelfSignedCert(t *testing.T) {
	cert, PrivKey, err := NewSelfSignedCert("Hyperchain", "www.hyperchain.cn", "", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	_, ok := PrivKey.(*asym.ECDSAPrivateKey)
	assert.True(t, ok)
	x, err := ParseCertificate(cert)
	assert.Nil(t, err)
	assert.NotNil(t, x)
}
