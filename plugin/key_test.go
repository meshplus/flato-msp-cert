package plugin

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMarshalPrivateKey(t *testing.T) {
	type args struct {
		privateKey crypto.Signer
	}
	engine := GetCryptoEngine()
	ecdsaKey, _ := asym.GenerateKey(asym.AlgoP256K1)
	ecdsaKey2, _ := asym.GenerateKey(asym.AlgoP256R1)
	ecdsaKey3, _ := asym.GenerateKey(asym.AlgoP384R1)
	ecdsaKey4, _ := asym.GenerateKey(asym.AlgoP521R1)
	sm2Key, _ := gm.GenerateSM2Key()

	tests := []struct {
		name string
		args args
		mode int
	}{
		{"256", args{privateKey: ecdsaKey}, crypto.Secp256r1},
		{"k1", args{privateKey: ecdsaKey2}, crypto.Secp256k1},
		{"384", args{privateKey: ecdsaKey3}, crypto.Secp384r1},
		{"521", args{privateKey: ecdsaKey4}, crypto.Secp521r1},
		{"sm2", args{privateKey: sm2Key}, crypto.Sm2p256v1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.args.privateKey.Bytes() //pkcs1 or raw
			assert.Nil(t, err)
			got, err := engine.ImportSignKey(b, tt.mode) //pkcs8
			if err != nil {
				t.Errorf("MarshalPrivateKey() error = %v", err)
				return
			}

			sk, err := engine.GetSignKey(got, crypto.None)
			assert.Nil(t, err)

			//test public Key
			gotpub, err := engine.GetVerifyKey(sk.Bytes(), tt.mode)
			assert.Nil(t, err)
			assert.Equal(t, hex.EncodeToString(gotpub.Bytes()), hex.EncodeToString(sk.Bytes()))
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	//engine, _ := GetCryptoEngine(config.GetMSPClassicConfig(), logger.MSPLoggerSingleCase)
	engine := GetSoftwareEngine("")
	msg := []byte("flato")
	t.Run("sm2", func(t *testing.T) {
		_, key, err := engine.CreateSignKey(false, crypto.Sm2p256v1)
		assert.Nil(t, err)
		hasher, err := engine.GetHash(crypto.Sm3WithPublicKey)
		assert.Nil(t, err)
		s, serr := key.Sign(msg, hasher, rand.Reader)
		assert.Nil(t, serr)

		assert.True(t, key.Verify(msg, hasher, s))

		vk, ierr := engine.GetVerifyKey(key.Bytes(), crypto.Sm2p256v1)
		assert.Nil(t, ierr)
		assert.True(t, vk.Verify(msg, hasher, s))
	})

	t.Run("sm2 with data", func(t *testing.T) {
		k, _ := hex.DecodeString("efcd432b9be540b1e5d910afecb2c9db0813e4e3ed56e5d6f14817cd595c3d69")
		s, _ := hex.DecodeString("3046022100af9c1ca1638de6b99646e4131f4da89f8163000bce7c8b7aa021801e81f10d82022100d6ff75e443246d0ac96a806ed63f432ac36cac5c1d57aa6d5e2ed847bf5d8f9a")
		pkcs8, err := engine.ImportSignKey(k, crypto.Sm2p256v1)
		assert.Nil(t, err)
		key, err := engine.GetSignKey(pkcs8, crypto.None)
		assert.Nil(t, err)
		hasher, err := engine.GetHash(crypto.Sm3WithPublicKey)
		assert.Nil(t, err)
		assert.True(t, key.Verify(msg, hasher, s))

		t.Run("sm2 with data - sign", func(t *testing.T) {
			reader := bytes.NewBuffer(bytes.Repeat([]byte{1, 2, 3, 4}, 8))
			ss, err := key.Sign(msg, hasher, reader)
			assert.Nil(t, err)
			assert.Equal(t, s, ss)
		})
	})
}
