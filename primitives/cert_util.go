package primitives

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"github.com/meshplus/crypto"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

//ParseCertificate already support ra
func ParseCertificate(engine crypto.Engine, cert []byte) (*gmx509.Certificate, error) {
	//if input is pem format, try to parse
	block, _ := pem.Decode(cert)

	if block != nil {
		cert = block.Bytes
	}

	x509Cert, err := gmx509.ParseCertificate(engine, cert)

	if err != nil {
		return nil, err
	}

	return x509Cert, nil
}

//MarshalCertificate Marshal Certificate
func MarshalCertificate(template *gmx509.Certificate) (cert []byte, err error) {
	return gmx509.MarshalCertificate(template)
}

//VerifyCert already support ra
func VerifyCert(cert *gmx509.Certificate, ca *gmx509.Certificate) (bool, error) {
	if cert.NotBefore.After(time.Now()) || cert.NotAfter.Before(time.Now()) {
		return false, errors.New("this cert is expired")
	}

	err := cert.CheckSignatureFrom(ca)
	if err != nil {
		return false, err
	}

	return true, nil
}

//GenCert generate cert
func GenCert(ca *gmx509.Certificate, privatekey crypto.SignKey, publicKey crypto.VerifyKey,
	o, cn, gn string, isCA bool, from, to time.Time, webAddr ...string) ([]byte, error) {

	if !bytes.Equal(ca.PublicKey.Bytes(), privatekey.Bytes()) {
		return nil, errors.New("public key in ca does not match private key")
	}

	return createCertByCaAndPublicKey(ca, privatekey, publicKey, isCA, o, cn, gn, from, to, webAddr...)
}

//NewSelfSignedCert generate self-signature certificate
func NewSelfSignedCert(engine crypto.Engine, o, cn, gn string, ct gmx509.CurveType, from, to time.Time, webAddr ...string) (
	[]byte, []byte, error) {
	var (
		err                error
		mode               int
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            crypto.SignKey
		privDer            []byte
	)
	switch ct {
	case gmx509.CurveTypeSm2:
		signatureAlgorithm = gmx509.SM3WithSM2
		mode = crypto.Sm2p256v1
	case gmx509.CurveTypeP256:
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		mode = crypto.Secp256r1
	case gmx509.CurveTypeK1:
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		mode = crypto.Secp256k1
	}
	privDer, privKey, err = engine.CreateSignKey(false, mode)
	if err != nil {
		return nil, nil, err
	}

	t, err := generateTemplate(o, cn, gn, from, to, signatureAlgorithm, webAddr...)
	if err != nil {
		return nil, nil, err
	}
	t.IsCA = true

	cert, err := gmx509.CreateCertificate(rand.Reader, t, t, privKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	return cert, privDer, nil
}

//SelfSignedCert generate self-signature certificate by privKey and pubKey
func SelfSignedCert(o, cn, gn string, webAddr []string, privKey crypto.SignKey, from, to time.Time) (
	[]byte, error) {
	var (
		err                error
		signatureAlgorithm gmx509.SignatureAlgorithm
	)

	t, err := generateTemplate(o, cn, gn, from, to, signatureAlgorithm, webAddr...)
	if err != nil {
		return nil, err
	}
	t.IsCA = true

	cert, err := gmx509.CreateCertificate(rand.Reader, t, t, privKey, privKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func createCertByCaAndPublicKey(ca *gmx509.Certificate, caPrivate crypto.SignKey, subPublic crypto.VerifyKey, isCa bool,
	o, cn, gn string, from, to time.Time, webAddr ...string) (certDER []byte, err error) {
	var signatureAlgorithm gmx509.SignatureAlgorithm
	//If the private key of ca is sm2,
	// the generated private key of the cert is also sm2.
	switch caPrivate.GetKeyInfo() {
	case crypto.Sm2p256v1:
		signatureAlgorithm = gmx509.SM3WithSM2
	case crypto.Secp256k1, crypto.Secp256r1:
		signatureAlgorithm = gmx509.ECDSAWithSHA256
	default:
		return nil, errors.New("private curve neither k1 nor r1")
	}
	template, gerr := generateTemplate(o, cn, gn, from, to, signatureAlgorithm, webAddr...)
	if gerr != nil {
		return nil, gerr
	}
	template.IsCA = isCa
	cert, cerr := gmx509.CreateCertificate(rand.Reader, template, ca, subPublic, caPrivate)
	if cerr != nil {
		return nil, cerr
	}
	return cert, nil
}

func generateTemplate(o, cn, gn string, from, to time.Time, signatureAlgorithm gmx509.SignatureAlgorithm, webAddr ...string) (*gmx509.Certificate, error) {
	gn = strings.ToLower(gn)
	if gn != "ecert" && gn != "rcert" && gn != "sdkcert" && gn != "" && gn != "idcert" {
		return nil, errors.New("gn should be one of ecert, rcert, sdkcert, idcert or empty")
	}

	//parse SAN
	var IP []net.IP
	var DNSName []string
	if len(webAddr) > 0 {
		var URL []*url.URL
		IP, URL = parseSAN(webAddr)
		for _, u := range URL {
			DNSName = append(DNSName, u.String())
		}
	}

	Subject := pkix.Name{
		CommonName:         cn,
		Organization:       []string{o},
		OrganizationalUnit: []string{gn},
		Country:            []string{"CN"},
		ExtraNames:         []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 42}, Value: gn}},
	}
	random, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	template := &gmx509.Certificate{
		SerialNumber: random,
		Subject:      Subject,

		NotBefore: from,
		NotAfter:  to,

		SignatureAlgorithm: signatureAlgorithm,
		KeyUsage: gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature | gmx509.KeyUsageCRLSign |
			gmx509.KeyUsageContentCommitment | gmx509.KeyUsageKeyEncipherment | gmx509.KeyUsageKeyAgreement,
		ExtKeyUsage: []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth,
			gmx509.ExtKeyUsageCodeSigning, gmx509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		IPAddresses:           IP,
		DNSNames:              DNSName,
	}

	t := ParseCertType([]byte(gn))
	if t != UnknownCertType {
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{
				ID:    CertTypeOID,
				Value: t.GetValue(),
			})
	}
	return template, nil
}

func parseSAN(in []string) (IPAddresses []net.IP, URIs []*url.URL) {
	IPAddresses = make([]net.IP, 0)
	URIs = make([]*url.URL, 0)
	for _, v := range in {
		if ip := net.ParseIP(v); ip != nil {
			IPAddresses = append(IPAddresses, ip)
			continue
		}
		if u, err := url.Parse(v); err == nil {
			URIs = append(URIs, u)
			continue
		}
	}
	return
}
