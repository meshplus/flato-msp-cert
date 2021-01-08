package primitives

import (
	gm "github.com/meshplus/crypto-gm"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestPEM2DER(t *testing.T) {
	sk, err := gm.GenerateSM2Key()
	assert.Nil(t, err)
	pk := sk.PublicKey
	assert.NotNil(t, pk)
	skDER, err := MarshalPrivateKey(sk)
	assert.Nil(t, err)

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
