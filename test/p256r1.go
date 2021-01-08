package test

import (
	"crypto/rand"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/hash"
	"sync"
)

var p256r1VerifyOnce sync.Once
var p256r1SignOnce sync.Once
var digest []byte

var p256r1PK *asym.ECDSAPublicKey
var p256r1VK *asym.ECDSAPrivateKey

//P256r1_golang_go_verify P256r1 golang go verify
//nolint
func P256r1_golang_go_verify() {
	signForBT.Verify(digest, &pubKeyForBT)
}

//P256r1_golang_go_sign P256r1 golang go ed25519Sign
//nolint
func P256r1_golang_go_sign() {
	vk.Sign(rand.Reader, digest, nil)
}

//P256r1_hyperchain_cgo_verify P256k1 hyperchain cgo verify
//nolint
func P256r1验签_golang_verify_1() {
	p256r1VerifyOnce.Do(func() {
		var err error
		p256r1VK, _ = asym.GenerateKey(asym.AlgoP256R1)
		p256r1PK = &p256r1VK.ECDSAPublicKey
		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)
		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}
		signature, err = p256r1VK.Sign(rand.Reader, digest, nil)
		if err != nil {
			panic(err)
		}
	})
	p256r1PK.Verify(nil, signature, digest)
}

//P256r1_hyperchain_cgo_sign P256k1 hyperchain cgo ed25519Sign
//nolint
func P256r1签名_golang_sign_1() {
	p256r1SignOnce.Do(func() {
		var err error
		p256r1VK, _ = asym.GenerateKey(asym.AlgoP256R1)
		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)

		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}
	})
	p256r1VK.Sign(rand.Reader, digest, nil)
}
