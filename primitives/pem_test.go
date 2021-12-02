package primitives

import (
	"github.com/meshplus/crypto"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestPEM2DER(t *testing.T) {
	engine := getEngine(t)
	skDER, sk, err := engine.CreateSignKey(false, crypto.Sm2p256v1)
	assert.Nil(t, err)
	pk := sk
	assert.NotNil(t, pk)

	key := new([32]byte)
	_, _ = rand.Read(key[:])
	t.Run("生成PEM", func(t *testing.T) {
		skPEM, err := DER2PEM(skDER, PEMECCPrivateKey)
		assert.Nil(t, err)

		t.Run("解析PEM", func(t *testing.T) {
			skDERInner, pemType := PEM2DER(skPEM)
			assert.Equal(t, pemType, PEMECCPrivateKey)
			assert.Equal(t, skDER, skDERInner)
		})
	})

	t.Run("生成加密PEM", func(t *testing.T) {
		skPEM, err := DER2PEMWithEncryption(skDER, PEMECCPrivateKey, *key)
		assert.Nil(t, err)

		t.Run("解析加密PEM,不传入密码", func(t *testing.T) {
			skDERInner, pemType := PEM2DERWithEncryption(skPEM, nil)
			assert.Equal(t, PEMInvalidPEMType, pemType)
			assert.Nil(t, skDERInner)
		})

		t.Run("解析加密PEM", func(t *testing.T) {
			skDERInner, pemType := PEM2DERWithEncryption(skPEM, key)
			assert.Equal(t, pemType, PEMECCPrivateKey)
			assert.Equal(t, skDER, skDERInner)
		})
	})
}
