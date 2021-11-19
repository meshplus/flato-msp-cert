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
