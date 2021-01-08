package test

import (
	"crypto/rand"
	"sync"

	ourEd25519 "github.com/meshplus/crypto-standard/ed25519"
	"golang.org/x/crypto/ed25519"
)

var ed25519SignOnce sync.Once
var ed25519VerifyOnce sync.Once
var ed25519OurSignOnce sync.Once
var ed25519OurVerifyOnce sync.Once

var ed25519vk ed25519.PrivateKey
var ed25519CGOmsg = []byte("hyperchain")
var ed25519Signature []byte
var ed25519pk ed25519.PublicKey

var ourEd25519vk *ourEd25519.EDDSAPrivateKey
var ourEd25519pk *ourEd25519.EDDSAPublicKey

// ED25519签名_golang_sign_1 ED25519 golang go ed25519Sign
//nolint
func ED25519签名_golang_sign_1() {
	ed25519SignOnce.Do(func() {
		var err error
		_, ed25519vk, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	})
	ed25519.Sign(ed25519vk, ed25519CGOmsg)
}

//ED25519验签_golang_verify_1 ED25519 golang go verify
//nolint
func ED25519验签_golang_verify_1() {

	ed25519VerifyOnce.Do(func() {
		var err error
		ed25519pk, ed25519vk, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		ed25519Signature = ed25519.Sign(ed25519vk, ed25519CGOmsg)
	})
	ed25519.Verify(ed25519pk, ed25519CGOmsg, ed25519Signature)
}

// ED25519签名_hyperchain_sign_1 ED25519 hyperchain go ed25519Sign
//nolint
func ED25519签名_hyperchain_sign_1() {
	ed25519OurSignOnce.Do(func() {
		ourEd25519vk, _ = ourEd25519.GenerateKey(rand.Reader)
	})
	ourEd25519vk.Sign(rand.Reader, ed25519CGOmsg, nil)
}

// ED25519验签_hyperchain_verify_1 ED25519 hyperchain go ed25519Verify
//nolint
func ED25519验签_hyperchain_verify_1() {
	ed25519OurVerifyOnce.Do(func() {
		var err error
		ourEd25519vk, ourEd25519pk = ourEd25519.GenerateKey(rand.Reader)
		ed25519Signature, err = ourEd25519vk.Sign(rand.Reader, ed25519CGOmsg, nil)
		if err != nil {
			panic(err)
		}
	})
	ourEd25519pk.Verify(nil, ed25519Signature, ed25519CGOmsg)
}
