package primitives

import (
	"github.com/meshplus/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

var msg = []byte("hello world")

func TestSign(t *testing.T) {
	engine := getEngine(t)
	t.Run("sm2", func(t *testing.T) {
		_, privKey, ecerr := engine.CreateSignKey(false, crypto.Sm2p256v1)
		assert.Nil(t, ecerr)
		signature, ecerr := Sign(engine, privKey, msg)
		assert.Nil(t, ecerr)

		pubKeyBytes := privKey.Bytes()
		pubKey, ierr := engine.GetVerifyKey(pubKeyBytes, crypto.Sm2p256v1)
		assert.Nil(t, ierr)
		ok, ecerr := Verify(engine, pubKey, []byte("hello world"), signature)
		assert.Nil(t, ecerr)
		assert.True(t, ok)
	})

	t.Run("ecdsa", func(t *testing.T) {
		_, privKey, cerr := engine.CreateSignKey(false, crypto.Secp256k1)
		assert.Nil(t, cerr)
		signature, cerr := Sign(engine, privKey, msg)
		assert.Nil(t, cerr)

		pubKeyBytes := privKey.Bytes()
		pubKey, ierr := engine.GetVerifyKey(pubKeyBytes, crypto.Secp256k1)
		assert.Nil(t, ierr)
		ok, cerr := Verify(engine, pubKey, []byte("hello world"), signature)
		assert.Nil(t, cerr)
		assert.True(t, ok)
	})
}

func TestParseSMPrivateKey(t *testing.T) {
	in := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg9X/V5LggL+k3dPMD
TcIUtMz54cuqBp6EzoEzw9QnOjmhRANCAARXPvBzzqDFEgOhbmauN5P3RxBUFz43
Wt8x8z/s4Ai/TODbbvr/sVH9i9vo3yNzXqASZ8XdWiTuF3QQ/N+s7/DB
-----END PRIVATE KEY-----
`
	engine := getEngine(t)
	out, tp := PEM2DER([]byte(in))
	assert.Equal(t, PEMAnyPrivateKey, tp)
	assert.NotNil(t, out)
	key, err := engine.ImportSignKey(out, crypto.None)
	assert.Nil(t, err)
	assert.NotNil(t, key)

	_, err = engine.GetSignKey(key, crypto.None)
	assert.Nil(t, err)
	in2, err := DER2PEM(key, PEMAnyPrivateKey)
	assert.Nil(t, err)
	if string(in2) != in {
		t.Log(in)
		t.Log(string(in2))
		t.FailNow()
	}
}
