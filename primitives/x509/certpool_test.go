package x509

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewCertPool(t *testing.T) {
	pool := NewCertPool()
	assert.IsType(t, &CertPool{}, pool, "new certpool failed!")
}

func TestCopy(t *testing.T) {
	pool1 := NewCertPool()
	pool1.bySubjectKeyID["cert1"] = []int{1, 1, 1}
	pool1.bySubjectKeyID["cert2"] = []int{2, 2, 2}
	pool1.byName["cert1"] = []int{1, 1, 1}
	pool1.byName["cert2"] = []int{2, 2, 2}
	pool2 := pool1.copy()
	assert.IsType(t, pool1, pool2, "can not copy a certpool!")
}

func TestFindPotentialParents(t *testing.T) {
	cert := new(Certificate)
	var pool1 *CertPool
	_ = pool1.findPotentialParents(cert)

	pool2 := NewCertPool()
	pool2.certs = append(pool2.certs, cert)
	_ = pool2.findPotentialParents(cert)

	cert.AuthorityKeyID = []byte{1}
	parent := pool2.findPotentialParents(cert)
	assert.IsType(t, []int{}, parent, "can not find potential parents!")
}

func TestContains(t *testing.T) {
	pool := NewCertPool()
	cert := new(Certificate)
	pool.AddCert(cert)

	var nilPool *CertPool
	nilPool.contains(cert)

	assert.Equal(t, true, pool.contains(cert), "cert should be contained!")
}

func TestAddCert(t *testing.T) {
	pool := NewCertPool()
	cert := new(Certificate)
	pool.AddCert(cert)
	pool.AddCert(cert)

	pool2 := NewCertPool()
	cert2 := new(Certificate)
	cert2.SubjectKeyID = []byte{1, 2}
	pool2.AddCert(cert2)

	assert.Equal(t, true, pool.contains(cert), "cert should be contained!")
}

func TestAppendCertsFromPEM(t *testing.T) {

	roots := NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM2))
	assert.False(t, ok)
	ok = roots.AppendCertsFromPEM([]byte(rootPEM))
	assert.Equal(t, true, ok, "failed to parse root certificate")
}

func TestSubjects(t *testing.T) {
	roots := NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	res := roots.Subjects()
	assert.IsType(t, [][]byte{}, res, "failed to return the subjects of the certificates")
}

const rootPEM = `
-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

const rootPEM2 = `
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----`
