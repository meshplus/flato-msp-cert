package pkcs12

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/flato-msp-cert/primitives/x509/pkix"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDecodePkcs8ShroudedKeyBagError(t *testing.T) {
	params, _ := asn1.Marshal(pbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	})
	alg := pkix.AlgorithmIdentifier{
		Algorithm: sha1WithTripleDES,
		Parameters: asn1.RawValue{
			FullBytes: params,
		},
	}
	_, err := decodePkcs8ShroudedKeyBag(alg.Parameters.FullBytes, params)
	assert.NotNil(t, err)
}

func TestEncodePkcs8ShroudedKeyBagError(t *testing.T) {
	key, err := gm.GenerateSM2Key()
	assert.Nil(t, err)
	_, err = encodePkcs8ShroudedKeyBag(rand.Reader, key, []byte(""))
	assert.Nil(t, err)
}

func TestCertBag(t *testing.T) {
	certificate, _, err := newSelfSignedCertWithRSA()
	assert.Nil(t, err)

	_, err = encodeCertBag(nil)
	assert.Nil(t, err)

	data, err := encodeCertBag(certificate)
	assert.Nil(t, err)

	_, err = decodeCertBag(nil)
	assert.NotNil(t, err)

	cert, err := decodeCertBag(data)
	assert.Nil(t, err)
	assert.Equal(t, certificate, cert)
}
