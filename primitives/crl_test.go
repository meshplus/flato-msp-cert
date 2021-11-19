package primitives

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func getEngine(t *testing.T) crypto.Engine {
	engine := plugin.GetCryptoEngine()
	return engine
}

func TestCRL(t *testing.T) {
	const filepath = "./test/allCRL.crl"
	crlDer, err := ioutil.ReadFile(filepath)
	assert.Nil(t, err)
	assert.NotNil(t, crlDer)
	crl, err := x509.ParseDERCRL(crlDer)
	assert.Nil(t, err)
	assert.NotNil(t, crl)
	crlList := sendCertificateList(*crl)
	server := httptest.NewUnstartedServer(crlList)
	url := "http://" + server.Listener.Addr().String()
	go func() {
		server.Start()
	}()

	testNewCRL(t, url)
	testCheckRevocationWithCRL(t, url)
	testCheckRevocationWithRA(t, url)
	testCheckRevocationWithURL(t, url)
	testCRLCheckRevocation(t, url)
	testCRLCheckRevocationByCRLDistributionPoint(t, url)
	testFetchCRL(t, url)
	testCheckRevocation(t, url)
}

func sendCertificateList(crlList pkix.CertificateList) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		crlBytes, _ := asn1.Marshal(crlList)
		_, _ = writer.Write(crlBytes)
	}
}
func testNewCRL(t *testing.T, url string) {
	q := *new(chan bool)

	_, err := NewCRL("", q)
	assert.NotNil(t, err)

	CRL, err := NewCRL(url, q)
	assert.Nil(t, err)
	assert.NotNil(t, CRL)
	assert.Equal(t, new(big.Int).SetUint64(uint64(68722118962)), CRL.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
}

func testCheckRevocation(t *testing.T, url string) {
	engine := getEngine(t)
	cerPem, err := getConfig("./test/cert.cer")
	assert.Nil(t, err)
	cert, err := ParseCertificate(engine, cerPem)
	assert.Nil(t, err)

	// Test CRL fetch from a given address
	crl, err := FetchCRL(url)
	assert.Nil(t, err)

	isRevoked, err := CheckRevocationWithCRL(cert, crl)
	assert.Nil(t, err)
	assert.False(t, isRevoked)
	// Test CRL fetch from cert
	isRevoked, err = CheckRevocation(cert)
	assert.Nil(t, err)
	assert.False(t, isRevoked)

	cert.CRLDistributionPoints[0] = ""
	isRevoked, err = CheckRevocation(cert)
	assert.NotNil(t, err)
	assert.False(t, isRevoked)
}

func testCRLCheckRevocation(t *testing.T, url string) {
	engine := getEngine(t)
	CRL, err := NewCRL(url, *new(chan bool))
	assert.Nil(t, err)

	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)

	ok, err := CRL.CheckRevocation(cert)
	assert.Nil(t, err)
	assert.Equal(t, false, ok)
}

func testFetchCRL(t *testing.T, url string) {
	crl, err := FetchCRL("")
	assert.Nil(t, crl)
	assert.NotNil(t, err)

	crl, err = FetchCRL("https://github.com/stretchr/testify/test")
	assert.Nil(t, crl)
	assert.NotNil(t, err)

	crl, err = FetchCRL(url)
	assert.Nil(t, err)
	assert.Equal(t, new(big.Int).SetUint64(uint64(68722118962)), crl.TBSCertList.RevokedCertificates[0].SerialNumber)
}

func testCheckRevocationWithCRL(t *testing.T, url string) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)

	CRL, err := NewCRL(url, *new(chan bool))
	assert.Nil(t, err)

	ok, err := CheckRevocationWithCRL(nil, CRL.crl)
	assert.False(t, ok)
	assert.NotNil(t, err)

	ok, err = CheckRevocationWithCRL(cert, nil)
	assert.False(t, ok)
	assert.NotNil(t, err)

	cert.SerialNumber = new(big.Int).SetUint64(uint64(68722118963))
	ok, err = CheckRevocationWithCRL(cert, CRL.crl)
	assert.Nil(t, err)
	assert.Equal(t, true, ok)

}

func testCRLCheckRevocationByCRLDistributionPoint(t *testing.T, url string) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)

	ok, err := CheckRevocation(cert)
	assert.NotNil(t, err)
	assert.False(t, ok)

	ok, err = CheckRevocation(new(gmx509.Certificate))
	assert.NotNil(t, err)
	assert.False(t, ok)

	cert.CRLDistributionPoints = []string{"", ""}
	ok, err = CheckRevocation(cert)
	assert.NotNil(t, err)
	assert.False(t, ok)

	cert.SerialNumber = new(big.Int).SetUint64(uint64(68722118963))
	cert.CRLDistributionPoints[0] = url
	ok, err = CheckRevocation(cert)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func testCheckRevocationWithURL(t *testing.T, url string) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)

	ok, err := CheckRevocationWithURL(cert, "")
	assert.NotNil(t, err)
	assert.False(t, ok)

	cert.SerialNumber = new(big.Int).SetUint64(uint64(68722118963))
	ok, err = CheckRevocationWithURL(cert, url)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func testCheckRevocationWithRA(t *testing.T, url string) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	cert, err := gmx509.ParseCertificate(engine, certificate)
	assert.Nil(t, err)

	cert.Subject.OrganizationalUnit = append(cert.Subject.OrganizationalUnit, "Hangzhou Qulian technology co., LTD")
	assert.Equal(t, "CN=www.hyperchain.cn,OU=Hangzhou Qulian technology co., LTD,OU=ecert,O=Hyperchain,C=CN", getDN(cert))

	ok, err := CheckRevocationWithRA(cert, url)
	assert.Nil(t, err)
	assert.False(t, ok)
}
