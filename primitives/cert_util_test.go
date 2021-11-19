package primitives

import (
	"github.com/meshplus/flato-msp-cert/plugin"
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
	engine := getEngine(t)
	cert, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	pem, err := DER2PEM(cert, PEMCertificate)
	assert.Nil(t, err)
	x, err := ParseCertificate(engine, pem)
	assert.Nil(t, err)
	assert.NotNil(t, x)
}

func TestGetConfig(t *testing.T) {
	_, err := getConfig("")
	assert.NotNil(t, err)
}

func TestParseCertificate(t *testing.T) {
	engine := getEngine(t)
	_, err := ParseCertificate(engine, []byte(""))
	assert.NotNil(t, err)
	cerPem, err := getConfig("./test/cert.cer")
	assert.Nil(t, err)
	cer, err := ParseCertificate(engine, cerPem)
	assert.Nil(t, err)
	assert.Equal(t, int64(69396857094), cer.SerialNumber.Int64())
}

func TestVerifyCert(t *testing.T) {
	engine := getEngine(t)
	// CA cert
	cerPem, err := getConfig("./test/eca.ca")
	assert.Nil(t, err)
	ca, err := ParseCertificate(engine, cerPem)
	assert.Nil(t, err)

	// user cert
	cerPem, err = getConfig("./test/ecert.cert")
	assert.Nil(t, err)
	cer, err := ParseCertificate(engine, cerPem)
	assert.Nil(t, err)

	isValid, err := VerifyCert(cer, ca)
	assert.Nil(t, err)
	assert.True(t, isValid)

	ca.PublicKeyAlgorithm = plugin.UnknownPublicKeyAlgorithm
	isValid, _ = VerifyCert(cer, ca)
	assert.False(t, isValid)

	cer.NotBefore = cer.NotBefore.AddDate(3, 0, 0)
	_, err = VerifyCert(cer, ca)
	assert.NotNil(t, err)
}

func TestParseKey(t *testing.T) {
	engine := getEngine(t)
	priPem, err := getConfig("./test/ecert.cert")
	assert.Nil(t, err)
	var der []byte
	var pt PEMType

	der, pt = PEM2DER(priPem)
	_, err = UnmarshalPrivateKey(engine, der)
	assert.NotNil(t, err)
	assert.Equal(t, PEMCertificate, pt)

	priPem, err = getConfig("./test/root_guomi.priv")
	assert.Nil(t, err)

	der, pt = PEM2DER(priPem)
	assert.Equal(t, PEMAnyPrivateKey, pt)
	_, err = UnmarshalPrivateKey(engine, der)
	assert.Nil(t, err)
}

func TestNewSelfSignedCert(t *testing.T) {
	engine := getEngine(t)
	cert, PrivKey, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	assert.NotNil(t, PrivKey)

	x, err := ParseCertificate(engine, cert)
	assert.Nil(t, err)
	assert.NotNil(t, x)
}
