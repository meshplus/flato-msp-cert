package pkcs12

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
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
	engine := plugin.GetCryptoEngine()

	_, key, err := engine.CreateSignKey(false, crypto.Sm2p256v1)
	assert.Nil(t, err)
	_, err = encodePkcs8ShroudedKeyBag(rand.Reader, key.(*plugin.PrivateKey).PrivKey, []byte(""))
	assert.Nil(t, err)
}
