package x509

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func getEngine(t *testing.T) crypto.Engine {
	return plugin.GetSoftwareEngine("")
}

func TestCertificateInvalidError_Error(t *testing.T) {
	e := CertificateInvalidError{
		new(Certificate),
		0,
		"0",
	}
	for i := 0; i < 10; i++ {
		e.Reason = InvalidReason(i)
		_ = e.Error()
	}
	e.Reason = 10
	errmsg := e.Error()
	assert.Equal(t, "x509: unknown error", errmsg)
}

func TestHostnameError_Error(t *testing.T) {
	cert := new(Certificate)
	cert.Subject.CommonName = ".abc"
	h := HostnameError{cert, ".abc"}
	_ = h.Error()

	cert2 := new(Certificate)
	cert.Subject.CommonName = "127.0.0.1"
	h = HostnameError{cert2, "127.0.0.1"}
	_ = h.Error()

	cert3 := new(Certificate)
	cert.Subject.CommonName = "127.0.0.1"
	cert3.IPAddresses = []net.IP{[]byte{1, 2, 3}, []byte{1, 2, 3}}
	h = HostnameError{cert3, "127.0.0.1"}
	_ = h.Error()

	cert4 := new(Certificate)
	cert.Subject.CommonName = "127001"
	h = HostnameError{cert4, "127001"}
	_ = h.Error()

	//assert.Equal(t,"x509: certificate is valid for " + valid + ", not " + h.Host)
}

func TestUnknownAuthorityError_Error(t *testing.T) {
	cert1 := new(Certificate)
	e := UnknownAuthorityError{cert1, errors.New(""), cert1}
	e.hintCert.Subject.CommonName = ""
	_ = e.Error()

	e.hintCert.Subject.Organization = []string{"org1", "org2"}
	errmsg := e.Error()

	assert.IsType(t, "", errmsg)
}

func TestSystemRootsError_Error(t *testing.T) {

	e := SystemRootsError{}
	_ = e.Error()

	e = SystemRootsError{errors.New("")}
	errmsg := e.Error()

	assert.IsType(t, "", errmsg)
}

func TestParseRFC2821Mailbox(t *testing.T) {
	_, ok := parseRFC2821Mailbox("")
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`"`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`""`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`"\`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`"\11`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`"11`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`\\\r\n`)
	assert.False(t, ok)

	_, ok = parseRFC2821Mailbox(`\\\r@""`)
	assert.True(t, ok)
}

func TestMatchEmailConstraint(t *testing.T) {
	mailBox := rfc2821Mailbox{"127.0.0.1", "8080"}
	_, err := matchEmailConstraint(mailBox, "example@163.com")
	assert.Nil(t, err)

	ok, err := matchEmailConstraint(mailBox, "example163.com")
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestMatchURIConstraint(t *testing.T) {
	url := new(url.URL)

	url.Host = ""
	ok, err := matchURIConstraint(url, "example@163.com")
	assert.NotNil(t, err)
	assert.False(t, ok)

	url.Host = "127.0.0.1"
	ok, err = matchURIConstraint(url, "example@163.com")
	assert.NotNil(t, err)
	assert.False(t, ok)

	url.Host = "127.0.0.1:8080"
	ok, err = matchURIConstraint(url, "example@163.com")
	assert.NotNil(t, err)
	assert.False(t, ok)

	url.Host = "[]270018080"
	ok, err = matchURIConstraint(url, "example@163.com")
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestMatchIPConstraint(t *testing.T) {
	ip := net.IP{byte(1), byte(2), byte(3), byte(4)}
	b := []byte(ip)
	constraint := net.IPNet{IP: b, Mask: b}
	ok, err := matchIPConstraint(ip, &constraint)
	assert.Nil(t, err)
	assert.True(t, ok)

	constraint.IP = b[:1]
	ok, err = matchIPConstraint(ip, &constraint)
	assert.Nil(t, err)
	assert.False(t, ok)

	constraint.IP = b
	constraint.IP[0] = 99
	ok, err = matchIPConstraint([]byte{byte(1), byte(2), byte(3), byte(4)}, &constraint)
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestMatchDomainConstraint(t *testing.T) {
	d := "hyperchain.cn"
	ok, err := matchDomainConstraint(d, "")
	assert.Nil(t, err)
	assert.True(t, ok)

	d = "hyperchain."
	ok, err = matchDomainConstraint(d, ".")
	assert.NotNil(t, err)
	assert.False(t, ok)

	d = "hyperchain.cn"
	ok, err = matchDomainConstraint(d, ".")
	assert.Nil(t, err)
	assert.True(t, ok)

	d = "hyperchain.cn"
	ok, err = matchDomainConstraint(d, ".cn")
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestCheckNameConstraints(t *testing.T) {

	cert := new(Certificate)
	n := 1
	err := cert.checkNameConstraints(&n, 1, "", "", "", func(parsedName, constraint interface{}) (match bool, err error) {

		return false, nil
	}, "", "")
	assert.Nil(t, err)

	n = 2
	err = cert.checkNameConstraints(&n, 1, "", "", "", func(parsedName, constraint interface{}) (match bool, err error) {

		return false, nil
	}, "", "")
	assert.NotNil(t, err)
}

func TestCertificate_Verify(t *testing.T) {
	// Verifying with a custom list of root certificates.

	var (
		privKey crypto.SignKey
		pubKey  crypto.VerifyKey
	)
	engine := getEngine(t)
	_, privKeyECDSA, err := engine.CreateSignKey(false, crypto.Secp256r1)
	assert.Nil(t, err)
	privKey = privKeyECDSA
	pubKey = privKeyECDSA

	template := Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "www.hyperchain.cn",
			Organization: []string{"Hyperchain"},
			Country:      []string{"CHN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "ZH",
				},
				{
					Type:  []int{2, 5, 4, 42},
					Value: "ecert",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: ECDSAWithSHA256,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign | KeyUsageDigitalSignature,

		ExtKeyUsage:        []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := NewCertPool()
	ca, err := CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	assert.Nil(t, err)

	root, err := ParseCertificate(engine, ca)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	roots.AddCert(root)

	opts := VerifyOptions{
		DNSName: "www.hyperchain.cn",
		Roots:   roots,
	}

	if _, err = root.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

}

var nameConstraintTests = []struct {
	constraint, domain string
	expectError        bool
	shouldMatch        bool
}{
	{"", "anything.com", false, true},
	{"example.com", "example.com", false, true},
	{"example.com.", "example.com", true, false},
	{"example.com", "example.com.", true, false},
	{"example.com", "ExAmPle.coM", false, true},
	{"example.com", "exampl1.com", false, false},
	{"example.com", "www.ExAmPle.coM", false, true},
	{"example.com", "sub.www.ExAmPle.coM", false, true},
	{"example.com", "notexample.com", false, false},
	{".example.com", "example.com", false, false},
	{".example.com", "www.example.com", false, true},
	{".example.com", "www..example.com", true, false},
}

func TestNameConstraints(t *testing.T) {
	for i, test := range nameConstraintTests {
		result, err := matchDomainConstraint(test.domain, test.constraint)

		if err != nil && !test.expectError {
			t.Errorf("unexpected error for test #%d: domain=%s, constraint=%s, err=%s", i, test.domain, test.constraint, err)
			continue
		}

		if err == nil && test.expectError {
			t.Errorf("unexpected success for test #%d: domain=%s, constraint=%s", i, test.domain, test.constraint)
			continue
		}

		if result != test.shouldMatch {
			t.Errorf("unexpected result for test #%d: domain=%s, constraint=%s, result=%t", i, test.domain, test.constraint, result)
		}
	}
}

func TestValidHostname(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"eXample123-.com", true},
		{"-eXample123-.com", false},
		{"", false},
		{".", false},
		{"example..com", false},
		{".example.com", false},
		{"*.example.com", true},
		{"*foo.example.com", false},
		{"foo.*.example.com", false},
		{"exa_mple.com", true},
		{"foo,bar", false},
		{"project-dev:us-central1:main", true},
	}
	for _, tt := range tests {
		if got := validHostname(tt.host); got != tt.want {
			t.Errorf("validHostname(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func generateCert(engine crypto.Engine, cn string, isCA bool, issuer *Certificate, issuerKey crypto.SignKey) (*Certificate, crypto.SignKey, error) {
	_, priv, err := engine.CreateSignKey(false, crypto.Secp256r1)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              KeyUsageKeyEncipherment | KeyUsageDigitalSignature | KeyUsageCertSign,
		ExtKeyUsage:           []ExtKeyUsage{ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := CreateCertificate(rand.Reader, template, issuer, priv, issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := ParseCertificate(engine, derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestPathologicalChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	// Build a chain where all intermediates share the same subject, to hit the
	// path building worst behavior.
	roots, intermediates := NewCertPool(), NewCertPool()
	engine := getEngine(t)
	parent, parentKey, err := generateCert(engine, "Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 101; i++ {
		parent, parentKey, err = generateCert(engine, "Intermediate CA", true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert(engine, "Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	t.Logf("verification took %v", time.Since(start))

	if err == nil || !strings.Contains(err.Error(), "signature check attempts limit") {
		t.Errorf("expected verification to fail with a signature checks limit error; got %v", err)
	}
}

func TestLongChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping generation of a long chain of certificates in short mode")
	}

	roots, intermediates := NewCertPool(), NewCertPool()
	engine := getEngine(t)
	parent, parentKey, err := generateCert(engine, "Root CA", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parent)

	for i := 1; i < 15; i++ {
		name := fmt.Sprintf("Intermediate CA #%d", i)
		parent, parentKey, err = generateCert(engine, name, true, parent, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(parent)
	}

	leaf, _, err := generateCert(engine, "Leaf", false, parent, parentKey)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if _, err := leaf.Verify(VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		t.Error(err)
	}
	t.Logf("verification took %v", time.Since(start))
}

func TestIsValid(t *testing.T) {
	var (
		privKeyECDSA       crypto.SignKey
		signatureAlgorithm SignatureAlgorithm
		privKey            crypto.SignKey
		pubKey             crypto.VerifyKey
	)

	engine := getEngine(t)
	_, privKeyECDSA, err := engine.CreateSignKey(false, crypto.Secp256r1)
	assert.Nil(t, err)
	signatureAlgorithm = ECDSAWithSHA256
	privKey = privKeyECDSA
	pubKey = privKeyECDSA

	Subject := pkix.Name{
		CommonName:   "/////",
		Organization: []string{"Hyperchain"},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type:  []int{2, 5, 4, 42},
				Value: "ecert",
			},
		},
	}

	template := Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            Subject,
		NotBefore:          time.Now().Add(-1 * time.Hour),
		NotAfter:           time.Now().Add(876000 * time.Hour), //100年
		SignatureAlgorithm: signatureAlgorithm,
		KeyUsage:           KeyUsageCertSign | KeyUsageDigitalSignature,
		ExtKeyUsage:        []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	assert.Nil(t, err)

	block, _ := pem.Decode(cert)
	if block != nil {
		cert = block.Bytes
	}

	c, err := ParseCertificate(engine, cert)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	c.Extensions = append(c.Extensions, pkix.Extension{ID: asn1.ObjectIdentifier{2, 5, 29, 30}, Critical: true, Value: []byte("ecert")}, pkix.Extension{ID: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: []byte("")})

	chain := make([]*Certificate, 0)
	chain = append(chain, c)

	opts := VerifyOptions{
		Intermediates: NewCertPool(),
		DNSName:       "www.google.com",
		CurrentTime:   time.Unix(3339436154, 0),
		KeyUsages:     []ExtKeyUsage{ExtKeyUsageServerAuth},
	}

	chain[0].Extensions[len(chain[0].Extensions)-1].Value = []byte("12345")
	err = c.isValid(intermediateCertificate, chain, &opts)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "data truncated")

	err = c.isValid(intermediateCertificate, nil, &opts)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "empty chain when appending CA cert")

	id := chain[0].Extensions[len(chain[0].Extensions)-1].ID
	chain[0].Subject.CommonName = "www.hyperchain.cn"
	chain[0].Extensions[len(chain[0].Extensions)-1].ID = asn1.ObjectIdentifier{2, 5, 29, 18}
	err = c.isValid(intermediateCertificate, chain, &opts)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "issuer has name constraints but leaf doesn't have a SAN extension")
	chain[0].Subject.CommonName = "/////"
	chain[0].Extensions[len(chain[0].Extensions)-1].ID = id

	ext := c.UnhandledCriticalExtensions
	c.UnhandledCriticalExtensions = append(c.UnhandledCriticalExtensions, []int{1, 2, 840, 113549, 1, 12, 1, 3})
	err = c.isValid(intermediateCertificate, chain, &opts)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unhandled critical extension")
	c.UnhandledCriticalExtensions = ext
}

func TestToLowerCaseASCII(t *testing.T) {
	assert.Equal(t, "abc", toLowerCaseASCII("ABC"))
}
