package primitives

import (
	"crypto/rand"
	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/hash"
)

// SM2Sign sign a msg by SM3.
func SM2Sign(key *gm.SM2PrivateKey, msg []byte) ([]byte, error) {
	digest := gm.HashBeforeSM2(&key.PublicKey, msg)
	return key.Sign(rand.Reader, digest, nil)
}

// SM2Verify verifies signature by SM3.
func SM2Verify(pub *gm.SM2PublicKey, msg, signature []byte) (bool, error) {
	digest := gm.HashBeforeSM2(pub, msg)
	return pub.Verify(nil, signature, digest)
}

// ECDSASign sign a msg by sha3.
func ECDSASign(key *asym.ECDSAPrivateKey, msg []byte) ([]byte, error) {
	h := hash.NewHasher(hash.KECCAK_256)
	digest, _ := h.Hash(msg)
	return key.Sign(rand.Reader, digest, nil)
}

// ECDSAVerify verifies signature by sha3.
func ECDSAVerify(pub *asym.ECDSAPublicKey, msg, signature []byte) (bool, error) {
	h := hash.NewHasher(hash.KECCAK_256)
	digest, _ := h.Hash(msg)
	return pub.Verify(nil, signature, digest)
}
