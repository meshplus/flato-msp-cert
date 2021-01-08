package primitives

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"errors"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"math/big"
	"reflect"
	"strings"
	"time"
)

//ParseCertificate already support ra
func ParseCertificate(cert []byte) (*gmx509.Certificate, error) {
	//if input is pem format, try to parse
	block, _ := pem.Decode(cert)

	if block != nil {
		cert = block.Bytes
	}

	x509Cert, err := gmx509.ParseCertificate(cert)

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
func GenCert(ca *gmx509.Certificate, privatekey crypto.Signer, publicKey crypto.PublicKey,
	o, cn, gn string, isCA bool, from, to time.Time) ([]byte, error) {

	if !reflect.DeepEqual(ca.PublicKey, privatekey.Public()) {
		return nil, errors.New("public key in ca does not match private key")
	}

	return createCertByCaAndPublicKey(ca, privatekey, publicKey, isCA, o, cn, gn, from, to)
}

//NewSelfSignedCert generate self-signature certificate
func NewSelfSignedCert(o, cn, gn string, ct gmx509.CurveType, from, to time.Time) (
	[]byte, interface{}, error) {
	var (
		err                error
		privKeyECDSA       *asym.ECDSAPrivateKey
		privKeySM          *gm.SM2PrivateKey
		signatureAlgorithm gmx509.SignatureAlgorithm
		privKey            crypto.Signer
		pubKey             interface{}
	)

	switch ct {
	case gmx509.CurveTypeSm2:
		privKeySM, err = gm.GenerateSM2Key()
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = gmx509.SM3WithSM2
		privKey = privKeySM
		pubKey = privKeySM.Public()
	case gmx509.CurveTypeP256:
		privKeyECDSA, err = asym.GenerateKey(asym.AlgoP256R1)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		privKey = privKeyECDSA
		pubKey = privKeyECDSA.Public()
	case gmx509.CurveTypeK1:
		privKeyECDSA, err = asym.GenerateKey(asym.AlgoP256K1)
		if err != nil {
			return nil, nil, err
		}
		signatureAlgorithm = gmx509.ECDSAWithSHA256
		privKey = privKeyECDSA
		pubKey = privKeyECDSA.Public()

	}
	t, err := generateTemplate(o, cn, gn, from, to, signatureAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	t.IsCA = true

	cert, err := gmx509.CreateCertificate(rand.Reader, t, t, pubKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

//SelfSignedCert generate self-signature certificate by privKey and pubKey
func SelfSignedCert(o, cn, gn string, privKey crypto.Signer, from, to time.Time) (
	[]byte, error) {
	var (
		err                error
		signatureAlgorithm gmx509.SignatureAlgorithm
	)

	t, err := generateTemplate(o, cn, gn, from, to, signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	t.IsCA = true

	cert, err := gmx509.CreateCertificate(rand.Reader, t, t, privKey.Public(), privKey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func createCertByCaAndPublicKey(ca *gmx509.Certificate, caPrivate crypto.Signer, subPublic crypto.PublicKey, isCa bool,
	o, cn, gn string, from, to time.Time) (certDER []byte, err error) {
	var signatureAlgorithm gmx509.SignatureAlgorithm
	//If the private key of ca is sm2,
	// the generated private key of the cert is also sm2.
	switch caPrivate.(type) {
	case *gm.SM2PrivateKey:
		signatureAlgorithm = gmx509.SM3WithSM2
	case *asym.ECDSAPrivateKey:
		signatureAlgorithm = gmx509.ECDSAWithSHA256
	default:
		return nil, errors.New("private neither *gmx509.PrivateKey nor *ecdsa.PrivateKey")
	}
	template, gerr := generateTemplate(o, cn, gn, from, to, signatureAlgorithm)
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

func generateTemplate(o, cn, gn string, from, to time.Time, signatureAlgorithm gmx509.SignatureAlgorithm) (*gmx509.Certificate, error) {
	gn = strings.ToLower(gn)
	if gn != "ecert" && gn != "rcert" && gn != "sdkcert" && gn != "" && gn != "idcert" {
		return nil, errors.New("gn should be one of ecert, rcert, sdkcert, idcert or empty")
	}
	Subject := pkix.Name{
		CommonName:   cn,
		Organization: []string{o},
		Country:      []string{"CN"},
		ExtraNames:   []pkix.AttributeTypeAndValue{{Type: []int{2, 5, 4, 42}, Value: gn}},
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
