package primitives

import (
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSM2Sign(t *testing.T) {
	privKey, err := gm.GenerateSM2Key()
	assert.Nil(t, err)

	signature, err := SM2Sign(privKey, []byte("hello world"))
	assert.Nil(t, err)

	pubKey := privKey.Public().(*gm.SM2PublicKey)
	ok, err := SM2Verify(pubKey, []byte("hello world"), signature)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestECDSASign(t *testing.T) {
	privKey, err := asym.GenerateKey(asym.AlgoP256K1)
	assert.Nil(t, err)

	signature, err := ECDSASign(privKey, []byte("hello world"))
	assert.Nil(t, err)

	pubKey := privKey.Public().(*asym.ECDSAPublicKey)
	ok, err := ECDSAVerify(pubKey, []byte("hello world"), signature)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestParseSMPrivateKey(t *testing.T) {
	in := `-----BEGIN EC PRIVATE KEY-----
MHgCAQECIQCYYik3ZSYpg67bkwT+XV0jqvvY8MgBfEB6lCg2//fkMqAKBggqgRzP
VQGCLaFEA0IABKMj2Hel+WRjhzQGxCnWl8/96RjPWhqqZjvSeyFHP+8UIUls2zj4
3nC/Gqk0rbVAvWZIAb0V/yhR04FcjgVLJZg=
-----END EC PRIVATE KEY-----
`
	out, tp := PEM2DER([]byte(in))
	assert.Equal(t, PEMECCPrivateKey, tp)
	assert.NotNil(t, out)
	key, err := parseSMPrivateKey(out)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	out2, err := marshalSMPrivateKey(key)
	assert.Nil(t, err)
	in2, err := DER2PEM(out2, PEMECCPrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, in2, []byte(in))
}
