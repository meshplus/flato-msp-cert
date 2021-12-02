package primitives

import (
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCertType_NewCertType(t *testing.T) {
	assert.Equal(t, ECert, NewCertType("ecert"))
	assert.Equal(t, TCert, NewCertType("tcert"))
	assert.Equal(t, RCert, NewCertType("rcert"))
	assert.Equal(t, SDKCert, NewCertType("sdkcert"))
	assert.Equal(t, ERCert, NewCertType("ercert"))
	assert.Equal(t, UnknownCertType, NewCertType("cert"))
}

func TestCertType_ParseCertType(t *testing.T) {
	assert.Equal(t, ECert, ParseCertType([]byte("ecert")))
	assert.Equal(t, RCert, ParseCertType([]byte("rcert")))
	assert.Equal(t, TCert, ParseCertType([]byte("tcert")))
	assert.Equal(t, SDKCert, ParseCertType([]byte("sdkcert")))
	assert.Equal(t, ERCert, ParseCertType([]byte("ercert")))
	assert.Equal(t, UnknownCertType, ParseCertType([]byte("cert")))
}

func TestCertType_GetValue(t *testing.T) {
	assert.Equal(t, []byte("ecert"), ECert.GetValue())
	assert.Equal(t, []byte("tcert"), TCert.GetValue())
	assert.Equal(t, []byte("rcert"), RCert.GetValue())
	assert.Equal(t, []byte("ercert"), ERCert.GetValue())
	assert.Equal(t, []byte("sdkcert"), SDKCert.GetValue())
	assert.Equal(t, []byte("idcert"), IDCert.GetValue())
	assert.Equal(t, []byte("unknown cert type"), CertType(6).GetValue())
	assert.Equal(t, []byte("illegal type"), CertType(-1).GetValue())
}

func TestAssertCertType(t *testing.T) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)
	cert.Extensions = []pkix.Extension{{ID: []int{1, 2, 86, 1}, Critical: true, Value: []byte("ecert")}}
	assert.True(t, AssertCertType(ECert, cert))
	cert.Extensions[0].Value = []byte("rcert")
	assert.True(t, AssertCertType(RCert, cert))
	cert.Extensions[0].Value = []byte("tcert")
	assert.True(t, AssertCertType(TCert, cert))
	cert.Extensions[0].Value = []byte("ercert")
	assert.True(t, AssertCertType(ECert, cert))
	cert.Extensions[0].Value = []byte("sdkcert")
	assert.True(t, AssertCertType(SDKCert, cert))
	cert.Extensions[0].Value = []byte("ercert")
	assert.False(t, AssertCertType(TCert, cert))
}
