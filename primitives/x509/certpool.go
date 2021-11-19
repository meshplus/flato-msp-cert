package x509

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/meshplus/crypto"
)

// CertPool is a set of certificates.
type CertPool struct {
	bySubjectKeyID map[string][]int
	byName         map[string][]int
	certs          []*Certificate
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool() *CertPool {
	return &CertPool{
		bySubjectKeyID: make(map[string][]int),
		byName:         make(map[string][]int),
	}
}

func (s *CertPool) copy() *CertPool {
	p := &CertPool{
		bySubjectKeyID: make(map[string][]int, len(s.bySubjectKeyID)),
		byName:         make(map[string][]int, len(s.byName)),
		certs:          make([]*Certificate, len(s.certs)),
	}
	for k, v := range s.bySubjectKeyID {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.bySubjectKeyID[k] = indexes
	}
	for k, v := range s.byName {
		indexes := make([]int, len(v))
		copy(indexes, v)
		p.byName[k] = indexes
	}
	copy(p.certs, s.certs)
	return p
}

// SystemCertPool returns a copy of the system cert pool.
//
// Any mutations to the returned pool are not written to disk and do
// not affect any other pool.
//
// New changes in the the system cert pool might not be reflected
// in subsequent calls.
//func SystemCertPool() (*CertPool, error) {
//	if runtime.GOOS == "windows" {
//		// Issue 16736, 18609:
//		return nil, errors.New("crypto/x509: system root pool is not available on Windows")
//	}
//
//	if sysRoots := systemRootsPool(); sysRoots != nil {
//		return sysRoots.copy(), nil
//	}
//
//	return loadSystemRoots()
//}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
func (s *CertPool) findPotentialParents(cert *Certificate) []int {
	if s == nil {
		return nil
	}
	if len(cert.AuthorityKeyID) > 0 {
		return s.bySubjectKeyID[string(cert.AuthorityKeyID)]
	}
	return s.byName[string(cert.RawIssuer)]
}

func (s *CertPool) contains(cert *Certificate) bool {
	if s == nil {
		return false
	}

	candidates := s.byName[string(cert.RawSubject)]
	for _, c := range candidates {
		if s.certs[c].Equal(cert) {
			return true
		}
	}

	return false
}

// AddCert adds a certificate to a pool.
func (s *CertPool) AddCert(cert *Certificate) {
	if cert == nil {
		panic("adding nil Certificate to CertPool")
	}

	// Check that the certificate isn't being added twice.
	if s.contains(cert) {
		return
	}

	n := len(s.certs)
	s.certs = append(s.certs, cert)

	if len(cert.SubjectKeyID) > 0 {
		keyID := string(cert.SubjectKeyID)
		s.bySubjectKeyID[keyID] = append(s.bySubjectKeyID[keyID], n)
	}
	name := string(cert.RawSubject)
	s.byName[name] = append(s.byName[name], n)
}

//PrintDebugInfo Print debug info about CertPool
func (s *CertPool) PrintDebugInfo() string {
	r := ""
	for i := range s.certs {
		cert, err := MarshalCertificate(s.certs[i])
		if err != nil {
			r += fmt.Sprintf("cert %v : parse error : %v\n", i, err.Error())
		} else {
			r += fmt.Sprintf("cert %v : %v\n", i, base64.StdEncoding.EncodeToString(cert))
		}

	}
	return r
}

// AppendCertsFromPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func (s *CertPool) AppendCertsFromPEM(manager crypto.Engine, pemCerts []byte) (ok bool) {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := ParseCertificate(manager, block.Bytes)
		if err != nil {
			continue
		}

		s.AddCert(cert)
		ok = true
	}

	return
}

// Subjects returns a list of the DER-encoded subjects of
// all of the certificates in the pool.
func (s *CertPool) Subjects() [][]byte {
	res := make([][]byte, len(s.certs))
	for i, c := range s.certs {
		res[i] = c.RawSubject
	}
	return res
}
