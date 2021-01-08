package test

import (
	"crypto/rand"
	"github.com/meshplus/crypto-standard/ed25519"
	"strconv"
	"sync"
)

var ed25519Batch64SignOnce sync.Once
var ed25519Batch64VerifyOnce sync.Once
var ed25519Batch1024SignOnce sync.Once
var ed25519Batch1024VerifyOnce sync.Once
var msgGroup, vkGroup, signGroup, pkGroup [][]byte

// Ed25519签名batch64_hyperchain_sign_64 ed25519 hyperchain go batch sign
//nolint
func Ed25519签名batch64_hyperchain_sign_64() {
	ed25519Batch64SignOnce.Do(func() {
		msgGroup, vkGroup, signGroup = make([][]byte, 64), make([][]byte, 64), make([][]byte, 64)
		for i := 0; i < 64; i++ {
			var err error
			tmp, _ := ed25519.GenerateKey(rand.Reader)
			vkGroup[i], err = tmp.Bytes()
			if err != nil {
				panic(err)
			}
			msgGroup[i] = []byte("hyperchainhyperchainhyperchainhyperchain" + strconv.Itoa(i))
		}
	})
	for i := 0; i < 64; i++ {
		tempKey := new(ed25519.EDDSAPrivateKey)
		tempKey.FromBytes(vkGroup[i], nil)
		signGroup[i], _ = tempKey.Sign(rand.Reader, msgGroup[i], nil)
	}
}

// Ed25519验签batch64_hyperchain_verify_64 ed25519 hyperchain go batch verify
//nolint
func Ed25519验签batch64_hyperchain_verify_64() {
	ed25519Batch64VerifyOnce.Do(func() {
		msgGroup, vkGroup, signGroup = make([][]byte, 64), make([][]byte, 64), make([][]byte, 64)
		for i := 0; i < 64; i++ {
			var err error
			tmp, _ := ed25519.GenerateKey(rand.Reader)
			vkGroup[i], err = tmp.Bytes()
			if err != nil {
				panic(err)
			}
			msgGroup[i] = []byte("hyperchainhyperchainhyperchainhyperchain" + strconv.Itoa(i))
			tempKey := new(ed25519.EDDSAPrivateKey)
			tempKey.FromBytes(vkGroup[i], nil)
			signGroup[i], err = tempKey.Sign(rand.Reader, msgGroup[i], nil)
			if err != nil {
				panic("ed25519 init sign err:" + err.Error())
			}
		}
		pkGroup = make([][]byte, 64)
		for i := range vkGroup {
			pkGroup[i] = make([]byte, 32)
			copy(pkGroup[i], vkGroup[i][32:])
		}
	})
	new(ed25519.EDDSAPublicKey).BatchVerify(pkGroup, signGroup, msgGroup)
}

// Ed25519签名batch1024_hyperchain_sign_1024 ed25519 hyperchain go batch sign
//nolint
func Ed25519签名batch1024_hyperchain_sign_1024() {
	ed25519Batch1024SignOnce.Do(func() {
		msgGroup, vkGroup, signGroup = make([][]byte, 1024), make([][]byte, 1024), make([][]byte, 1024)
		for i := 0; i < 1024; i++ {
			var err error
			tmp, _ := ed25519.GenerateKey(rand.Reader)
			vkGroup[i], err = tmp.Bytes()
			if err != nil {
				panic(err)
			}
			msgGroup[i] = []byte("hyperchainhyperchainhyperchainhyperchain" + strconv.Itoa(i))
		}
	})
	for i := 0; i < 1024; i++ {
		tempKey := new(ed25519.EDDSAPrivateKey)
		tempKey.FromBytes(vkGroup[i], nil)
		signGroup[i], _ = tempKey.Sign(rand.Reader, msgGroup[i], nil)
	}
}

// Ed25519验签batch1024_hyperchain_verify_1024 ed25519 hyperchain go batch verify
//nolint
func Ed25519验签batch1024_hyperchain_verify_1024() {
	ed25519Batch1024VerifyOnce.Do(func() {
		msgGroup, vkGroup, signGroup = make([][]byte, 1024), make([][]byte, 1024), make([][]byte, 1024)
		for i := 0; i < 1024; i++ {
			var err error
			tmp, _ := ed25519.GenerateKey(rand.Reader)
			vkGroup[i], err = tmp.Bytes()
			if err != nil {
				panic(err)
			}
			msgGroup[i] = []byte("hyperchainhyperchainhyperchainhyperchain" + strconv.Itoa(i))
			tempKey := new(ed25519.EDDSAPrivateKey)
			tempKey.FromBytes(vkGroup[i], nil)
			signGroup[i], err = tempKey.Sign(rand.Reader, msgGroup[i], nil)
			if err != nil {
				panic("ed25519 init sign err:" + err.Error())
			}
		}
		pkGroup = make([][]byte, 1024)
		for i := range vkGroup {
			pkGroup[i] = make([]byte, 32)
			copy(pkGroup[i], vkGroup[i][32:])
		}
	})
	new(ed25519.EDDSAPublicKey).BatchVerify(pkGroup, signGroup, msgGroup)
}
