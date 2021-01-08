package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/meshplus/crypto-standard/ecc"
	"sync"
)

var eccEncryptOnce sync.Once
var eccDecryptOnce sync.Once

var eccvk *ecdsa.PrivateKey
var eccpk *ecdsa.PublicKey
var out []byte

// ECC加密_hyperchain_enc_1 ecc hyperchain go ecc encrypt
//nolint
func ECC加密_hyperchain_enc_1() {
	eccEncryptOnce.Do(func() {
		var err error
		eccvk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		data = make([]byte, 1024*1024)
		rand.Read(data)
		eccpk = &eccvk.PublicKey
	})
	ecc.Encrypt(eccpk, data)
}

// ECC解密_hyperchain_dec_1 ecc hyperchain go ecc decrypt
//nolint
func ECC解密_hyperchain_dec_1() {
	eccDecryptOnce.Do(func() {
		var err error
		eccvk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		data = make([]byte, 1024*1024)
		rand.Read(data)
		eccpk = &eccvk.PublicKey
		out, err = ecc.Encrypt(eccpk, data)
		if err != nil {
			panic(err)
		}
	})
	ecc.Decrypt(eccvk, out)
}
