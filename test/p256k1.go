package test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/btcsuite/btcd/btcec"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/hash"
	"math/big"
	"sync"
)

var p256k1HyperVerifyOnce sync.Once
var p256k1BtcVerifyOnce sync.Once
var p256k1HyperSignOnce sync.Once
var p256k1BtcSignOnce sync.Once

var data []byte
var signature []byte
var vk *asym.ECDSAPrivateKey
var pk *asym.ECDSAPublicKey

//P256k1_hyperchain_cgo_verify P256k1 hyperchain cgo verify
//nolint
func P256k1验签_hyperchain_verify_1() {

	p256k1HyperVerifyOnce.Do(func() {
		var err error
		vk, err = asym.GenerateKey(asym.AlgoP256K1)
		if err != nil {
			panic(err)
		}
		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)
		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}
		signature, err = vk.Sign(rand.Reader, digest, nil)
		if err != nil {
			panic(err)
		}
		pk = &vk.ECDSAPublicKey
		if err != nil {
			panic(err)
		}
	})
	pk.Verify(nil, signature, digest)
}

var x, y, r, s, d *big.Int
var signForBT btcec.Signature
var pubKeyForBT btcec.PublicKey
var privKeyForBT btcec.PrivateKey

//P256k1_btcsuite_go_verify P256k1 btcsuite go verify
//nolint
func P256k1验签_btcsuite_verify_1() {

	p256k1BtcVerifyOnce.Do(func() {
		var err error
		vk, _ = asym.GenerateKey(asym.AlgoP256K1)
		pk = &vk.ECDSAPublicKey
		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)
		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}
		signature, err = vk.Sign(rand.Reader, digest, nil)

		r = big.NewInt(0).SetBytes(signature[:32])
		s = big.NewInt(0).SetBytes(signature[32:64])
		b, _ := pk.Bytes()
		x = big.NewInt(0).SetBytes(b[1:33])
		y = big.NewInt(0).SetBytes(b[33:])
		b, _ = vk.Bytes()
		d = big.NewInt(0).SetBytes(b)
		signForBT = btcec.Signature{
			R: r,
			S: s,
		}
		pubKeyForBT = btcec.PublicKey(ecdsa.PublicKey{
			Curve: btcec.S256(),
			X:     x,
			Y:     y,
		})
	})
	signForBT.Verify(digest, &pubKeyForBT)
}

//P256k1_hyperchain_cgo_sign P256k1 hyperchain cgo ed25519Sign
//nolint
func P256k1签名_hyperchain_sign_1() {
	p256k1HyperSignOnce.Do(func() {
		var err error
		vk, err = asym.GenerateKey(asym.AlgoP256K1)
		if err != nil {
			panic(err)
		}
		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)
		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}
	})
	vk.Sign(rand.Reader, digest, nil)
}

//P256k1_btcsuite_go_sign P256k1 btcsuite go ed25519Sign
//nolint
func P256k1签名_btcsuite_sign_1() {
	p256k1BtcSignOnce.Do(func() {
		var err error
		vk, err = asym.GenerateKey(asym.AlgoP256K1)
		if err != nil {
			panic(err)
		}
		pk = &vk.ECDSAPublicKey

		data = make([]byte, 1024*1024)
		_, _ = rand.Read(data)
		hasher := hash.NewHasher(hash.KECCAK_256)
		digest, err = hasher.Hash(data)
		if err != nil {
			panic(err)
		}

		b, _ := pk.Bytes()
		x = big.NewInt(0).SetBytes(b[1:33])
		y = big.NewInt(0).SetBytes(b[33:])
		b, _ = vk.Bytes()
		d = big.NewInt(0).SetBytes(b)

		pubKeyForBT = btcec.PublicKey(ecdsa.PublicKey{
			Curve: btcec.S256(),
			X:     x,
			Y:     y,
		})
		privKeyForBT = btcec.PrivateKey(ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey(pubKeyForBT),
			D:         d,
		})
	})
	privKeyForBT.Sign(digest)
}
