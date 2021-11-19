package primitives

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"github.com/meshplus/crypto"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"
)

var from = time.Now()
var to = time.Now().Add(time.Hour)

var CAECC = `-----BEGIN CERTIFICATE-----
MIIB6DCCAY2gAwIBAgIBATAKBggqhkjOPQQDAjBOMRMwEQYDVQQKEwpIeXBlcmNo
YWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5jbjELMAkGA1UEBhMCWkgxDjAM
BgNVBCoTBWVjZXJ0MCAXDTIwMDMxODExMjMxOFoYDzIxMjAwMjIzMTIyMzE4WjBO
MRMwEQYDVQQKEwpIeXBlcmNoYWluMRowGAYDVQQDExF3d3cuaHlwZXJjaGFpbi5j
bjELMAkGA1UEBhMCWkgxDjAMBgNVBCoTBWVjZXJ0MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEI2nX0hpuSsB+JS0TX/4vc6Yn4DGEqnEhDgShwEOFdOwc2efbILgU
SUkwASz6eXd64gUrDUsYYe8ojT8zaKi4aaNaMFgwDgYDVR0PAQH/BAQDAgKEMCYG
A1UdJQQfMB0GCCsGAQUFBwMCBggrBgEFBQcDAQYCKgMGA4ELATAPBgNVHRMBAf8E
BTADAQH/MA0GA1UdDgQGBAQBAgMEMAoGCCqGSM49BAMCA0kAMEYCIQC1woBGO/jb
ztF1nFMqqf+Jyw2w+DtTspnoqfSSWnwYSwIhAP8rj93Pc10O15pMBvljhy+Dgl4K
qWLpPojqywKwlep/
-----END CERTIFICATE-----`

var CAPrivateECC = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn9/uNRNIkCFvN6gT
m6klr8MgvjHwyBtv8nGD1gqCkyqhRANCAAQjadfSGm5KwH4lLRNf/i9zpifgMYSq
cSEOBKHAQ4V07BzZ59sguBRJSTABLPp5d3riBSsNSxhh7yiNPzNoqLhp
-----END PRIVATE KEY-----`

var CAGM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAXkCFAlTFR4OP+o3KYLG+HWxmx+N3D1hMAoGCCqBHM9VAYN1MGwxCzAJ
BgNVBAYTAkNOMQswCQYDVQQIDAJCSjEQMA4GA1UEBwwHSGFpRGlhbjEPMA0GA1UE
CgwGemhhbmcuMRUwEwYDVQQLDAxTT1JCIG9mIFRBU1MxFjAUBgNVBAMMDVRlc3Qg
Q0EgKFNNMikwHhcNMjAxMjI1MDI0NzAyWhcNMjUwMjAyMDI0NzAyWjBsMQswCQYD
VQQGEwJDTjELMAkGA1UECAwCQkoxEDAOBgNVBAcMB0hhaURpYW4xDzANBgNVBAoM
BnpoYW5nLjEVMBMGA1UECwwMU09SQiBvZiBUQVNTMRYwFAYDVQQDDA1UZXN0IENB
IChTTTIpMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEuMPJqgQ9dPR/yy/GMqnq
MzSyx+FNinJvhQG577FceuSfnSW3I9UsNFDk2Bs1y0rX6/TBMxgESrJIa8VY3Ijl
azAKBggqgRzPVQGDdQNIADBFAiAdK3KjN5ZN6F+3CLqzpbUOj1xRTIDJUbtUvbqZ
77MxDgIhALlZh4oM3bQ0iRxgQIQi382Y3o0wu2fhOqgGCRUTyu9O
-----END CERTIFICATE-----`

var CAPrivateGM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgjNu88jQ4e6Fgyjik
MLugdU4KdpDMGr2m7UogbRFK8IGhRANCAAS4w8mqBD109H/LL8YyqeozNLLH4U2K
cm+FAbnvsVx65J+dJbcj1Sw0UOTYGzXLStfr9MEzGARKskhrxVjciOVr
-----END PRIVATE KEY-----
`

func TestGenCA(t *testing.T) {
	engine := getEngine(t)
	_, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ercert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.NotNil(t, err)
	// CAECC with secp256r1 private key
	ca, privDer, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "p256",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	caca := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: ca,
	}
	var cacaBytes []byte
	cacaBuf := bytes.NewBuffer(cacaBytes)
	err = pem.Encode(cacaBuf, caca)
	assert.Nil(t, err)
	caPrivate, err := DER2PEM(privDer, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, caPrivate)
	// CAECC with sm2 private key
	smCa, smPrivate, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchain.cn", "ecert", "sm2",
		time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	smCaca := &pem.Block{
		Type:  pemTypeCertificate,
		Bytes: smCa,
	}
	var smCacaBytes []byte
	smCacaBuf := bytes.NewBuffer(smCacaBytes)
	err = pem.Encode(smCacaBuf, smCaca)
	assert.Nil(t, err)
	smCaPrivate, err := DER2PEM(smPrivate, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, smCaPrivate)
}

func TestGenCert(t *testing.T) {
	engine := getEngine(t)
	testPrivatePem := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgR7APMHZpEcoUVKoZ
Kz/SBmzNrs0HSmetji6VpCesxZahRANCAARb1T3lL+7WSr1ifE45Un7C/PFRPCOq
LstSsesG2cUMD2Be1WBHTztOaPjSTBzmKw03k+PlTlwOo067GdaM76ry
-----END PRIVATE KEY-----`
	testPrivateDer, pt := PEM2DER([]byte(testPrivatePem))
	assert.True(t, pt == PEMAnyPrivateKey)
	testPrivateECC, err := UnmarshalPrivateKey(engine, testPrivateDer)
	assert.Nil(t, err)

	certBlock := &pem.Block{
		Type: pemTypeCertificate,
	}
	caPrivateECCDER, pt := PEM2DER([]byte(CAPrivateECC))
	assert.True(t, pt == PEMAnyPrivateKey)
	caPrivateECC, err := UnmarshalPrivateKey(engine, caPrivateECCDER)
	assert.Nil(t, err)
	caStructECC, err := ParseCertificate(engine, []byte(CAECC))
	assert.Nil(t, err)

	caPrivateGMDER, pt := PEM2DER([]byte(CAPrivateGM))
	assert.True(t, pt == PEMAnyPrivateKey)
	caPrivateGM, err := UnmarshalPrivateKey(engine, caPrivateGMDER)
	assert.Nil(t, err)
	caStructGM, err := ParseCertificate(engine, []byte(CAGM))
	assert.Nil(t, err)
	_, certPrivateGM, err := engine.CreateSignKey(false, crypto.Sm2p256v1)
	assert.Nil(t, err)
	_, certPrivateECC, err := engine.CreateSignKey(false, crypto.Secp256r1)
	assert.Nil(t, err)
	//generate cert with invalid gn
	_, err = GenCert(caStructECC, caPrivateGM, certPrivateGM, "hyperchain", "node1", "ercert", false, from, to)
	assert.NotNil(t, err)
	_, err = GenCert(caStructECC, testPrivateECC, certPrivateECC, "hyperchain", "node1", "rcert", false, from, to)
	assert.NotNil(t, err)
	//ecc ca can generate cert with ecc public key and gm public key
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateECC, "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateECC, "hyperchain", "node1", "ecert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateECC, "hyperchain", "node1", "sdkcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateGM, "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateGM, "hyperchain", "node1", "ecert", false, from, to)
	assert.Nil(t, err)
	_, err = GenCert(caStructECC, caPrivateECC, certPrivateGM, "hyperchain", "node1", "sdkcert", false, from, to)
	assert.Nil(t, err)
	//gm ca only generate cert with gm public key
	//_, err = GenCert(caStructGM, caPrivateGM.(crypto.Signer), certPrivateECC, "hyperchain", "node1", "rcert", false)
	//assert.Nil(t, err)
	cert, err := GenCert(caStructGM, caPrivateGM, certPrivateGM, "hyperchain", "node1", "rcert", false, from, to)
	assert.Nil(t, err)
	var certCertBytes []byte
	certCertBuf := bytes.NewBuffer(certCertBytes)
	certBlock.Bytes = cert
	err = pem.Encode(certCertBuf, certBlock)
	assert.Nil(t, err)

	caPrivate, err := DER2PEM(caPrivateGMDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, caPrivate)
}

func TestGenK1Cert(t *testing.T) {
	engine := getEngine(t)
	Subject := pkix.Name{
		CommonName:   "hyperchain.cn",
		Organization: []string{"dev"},
		Country:      []string{"CHN"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			// This should override the Country, above.
			{
				Type:  []int{2, 5, 4, 6},
				Value: "ZH",
			},
		},
	}

	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(876000 * time.Hour), //暂定证书有效期为100年

		SignatureAlgorithm: gmx509.ECDSAWithSHA256,

		SubjectKeyID: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign | gmx509.KeyUsageDigitalSignature,

		ExtKeyUsage: []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth,
			gmx509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	//1.root
	rootT := template
	rootPrivDer, rootPriv, err := engine.CreateSignKey(false, crypto.Secp256k1)
	assert.Nil(t, err)
	rootPub := rootPriv
	root, err := gmx509.CreateCertificate(rand.Reader, &rootT, &rootT, rootPub, rootPriv)
	assert.Nil(t, err)
	rootPem, err := DER2PEM(root, PEMCertificate)
	assert.Nil(t, err)
	rootPrivPem, err := DER2PEM(rootPrivDer, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("root.priv", rootPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("root.cert", rootPem, 0666))

	//2.ecert
	eT, err := ParseCertificate(engine, root)
	assert.Nil(t, err)
	ePrivDer, ePriv, err := engine.CreateSignKey(false, crypto.Secp256k1)
	assert.Nil(t, err)
	ePub := ePriv
	e, err := GenCert(eT, rootPriv, ePub, "dev", "hyperchain.cn", "ecert", true, from, to)
	assert.Nil(t, err)
	ePem, err := DER2PEM(e, PEMCertificate)
	assert.Nil(t, err)
	ePrivPem, err := DER2PEM(ePrivDer, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("ecert.priv", ePrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("ecert.cert", ePem, 0666))

	//3.rcert
	rT, err := ParseCertificate(engine, root)
	assert.Nil(t, err)
	Subject.ExtraNames = Subject.ExtraNames[:1]
	rPrivDER, rPriv, err := engine.CreateSignKey(false, crypto.Secp256k1)
	assert.Nil(t, err)
	rPub := rPriv
	r, err := GenCert(rT, rootPriv, rPub, "dev", "hyperchain.cn", "rcert", false, from, to)
	assert.Nil(t, err)
	rPem, err := DER2PEM(r, PEMCertificate)
	assert.Nil(t, err)
	rPrivPem, err := DER2PEM(rPrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("rcert.priv", rPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("rcert.cert", rPem, 0666))

	//4.sdkcert
	sdkT, err := ParseCertificate(engine, e)
	assert.Nil(t, err)
	sdkPrivDER, sdkPriv, err := engine.CreateSignKey(false, crypto.Secp256k1)
	assert.Nil(t, err)
	sdkPub := sdkPriv
	sdk, err := GenCert(sdkT, ePriv, sdkPub, "dev", "hyperchain.cn", "sdkcert", false, from, to)
	assert.Nil(t, err)
	sdkPem, err := DER2PEM(sdk, PEMCertificate)
	assert.Nil(t, err)
	sdkPrivPem, err := DER2PEM(sdkPrivDER, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Nil(t, ioutil.WriteFile("sdkcert.priv", sdkPrivPem, 0666))
	assert.Nil(t, ioutil.WriteFile("sdkcert.cert", sdkPem, 0666))

	//verify
	parseRoot, err := ParseCertificate(engine, rootPem)
	assert.Nil(t, err)
	parseE, err := ParseCertificate(engine, ePem)
	assert.Nil(t, err)
	parseR, err := ParseCertificate(engine, rPem)
	assert.Nil(t, err)
	parseSDK, err := ParseCertificate(engine, sdkPem)
	assert.Nil(t, err)
	//root
	_, err = VerifyCert(parseRoot, parseRoot)
	assert.Nil(t, err)
	//e
	_, err = VerifyCert(parseE, parseRoot)
	assert.Nil(t, err)
	//r
	_, err = VerifyCert(parseR, parseRoot)
	assert.Nil(t, err)
	//sdk
	_, err = VerifyCert(parseSDK, parseE)
	assert.Nil(t, err)

	_ = os.Remove("./ecert.cert")
	_ = os.Remove("./ecert.priv")
	_ = os.Remove("./rcert.cert")
	_ = os.Remove("./rcert.priv")
	_ = os.Remove("./sdkcert.cert")
	_ = os.Remove("./sdkcert.priv")
	_ = os.Remove("./root.cert")
	_ = os.Remove("./root.priv")
}
