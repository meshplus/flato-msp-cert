package primitives

import (
	"crypto/rand"
	"fmt"
	"github.com/meshplus/crypto"
)

// Sign sign a msg
func Sign(engine crypto.Engine, key crypto.SignKey, msg []byte) ([]byte, error) {
	var hasher crypto.Hasher
	var err error
	switch key.GetKeyInfo() {
	case crypto.Sm2p256v1:
		hasher, err = engine.GetHash(crypto.Sm3WithPublicKey)
		if err != nil {
			return nil, err
		}
	case crypto.Secp256r1, crypto.Secp384r1, crypto.Secp521r1, crypto.Secp256k1, crypto.Secp256k1Recover:
		hasher, err = engine.GetHash(crypto.KECCAK_256)
		if err != nil {
			return nil, err
		}
	default:
		hasher, err = engine.GetHash(crypto.SHA2_256)
		if err != nil {
			return nil, err
		}
	}
	return key.Sign(msg, hasher, rand.Reader)
}

// Verify verifies signature
func Verify(engine crypto.Engine, key crypto.VerifyKey, msg, signature []byte) (bool, error) {
	var hasher crypto.Hasher
	var err error
	switch key.GetKeyInfo() {
	case crypto.Sm2p256v1:
		hasher, err = engine.GetHash(crypto.Sm3WithPublicKey)
		if err != nil {
			return false, err
		}
	case crypto.Secp256r1, crypto.Secp384r1, crypto.Secp521r1, crypto.Secp256k1, crypto.Secp256k1Recover:
		hasher, err = engine.GetHash(crypto.KECCAK_256)
		if err != nil {
			return false, err
		}
	default:
		hasher, err = engine.GetHash(crypto.SHA2_256)
		if err != nil {
			return false, err
		}
	}
	b := key.Verify(msg, hasher, signature)
	if b {
		return true, nil
	}
	return false, fmt.Errorf("invlide signature")
}
