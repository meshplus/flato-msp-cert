package pkcs12

import (
	"crypto/rand"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	"github.com/meshplus/flato-msp-cert/primitives"
	"github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPfxWithGM(t *testing.T) {
	engine := plugin.GetCryptoEngine()

	CertGM, PrivKeyGM, err := primitives.NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	ca, err := primitives.ParseCertificate(engine, CertGM)
	assert.Nil(t, err)
	vk, err := engine.GetSignKey(PrivKeyGM, crypto.None)
	//vk, err := engine.GetSignKey(PrivKeyGM, crypto.Sm2p256v1)
	assert.Nil(t, err)
	data, err := Encode(rand.Reader, vk, ca, []*x509.Certificate{ca}, "")
	assert.Nil(t, err)
	_, cert, _, err := DecodeChain(data, "")
	assert.Nil(t, err)
	certDer, err := x509.MarshalCertificate(cert)
	assert.Nil(t, err)

	assert.Equal(t, CertGM, certDer, "The two certificates should be the same.")
}

func TestPfxWithECDSA(t *testing.T) {
	engine := plugin.GetCryptoEngine()

	CertECDSA, PrivKeyECDSA, err := primitives.NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256", time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	ca, err := primitives.ParseCertificate(engine, CertECDSA)
	assert.Nil(t, err)
	CertBefore, err := primitives.DER2PEM(CertECDSA, primitives.PEMCertificate)
	assert.Nil(t, err)
	vk, err := engine.GetSignKey(PrivKeyECDSA, crypto.None)
	assert.Nil(t, err)
	data, err := Encode(rand.Reader, vk, ca, []*x509.Certificate{ca}, "")
	assert.Nil(t, err)
	_, cert, _, err := DecodeChain(data, "")
	assert.Nil(t, err)
	certDer, err := x509.MarshalCertificate(cert)
	assert.Nil(t, err)
	CertAfter, err := primitives.DER2PEM(certDer, primitives.PEMCertificate)
	assert.Nil(t, err)
	assert.Equal(t, CertBefore, CertAfter, "The two certificates should be the same.")
}
