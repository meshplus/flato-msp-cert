package test

import (
	"crypto/rand"
	"github.com/meshplus/crypto-standard/ed25519"
	"sync"
)

var ed25519AggSignOnce sync.Once
var ed25519AggVerifyOnce sync.Once
var ed25519WitnessSignOnce sync.Once
var ed25519PartVerifyOnce sync.Once

var message = []byte("Hello World")

var pubKey1 *ed25519.EDDSAPublicKey
var priKey1 *ed25519.EDDSAPrivateKey
var pubKey2 *ed25519.EDDSAPublicKey
var priKey2 *ed25519.EDDSAPrivateKey
var leader ed25519.Leader
var r1 ed25519.SignaturePart
var r2 ed25519.SignaturePart
var c ed25519.Commitment
var sign []byte
var w1 ed25519.Witness
var w2 ed25519.Witness
var v1 ed25519.Commitment
var v2 ed25519.Commitment

var datePrivKey = [64]byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}
var datePubKey = [32]byte{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}

// Ed25519签名Witness_hyperchain_sign_1 ed25519 hyperchain go witness sign
//nolint
func Ed25519签名Witness_hyperchain_sign_1() {
	ed25519WitnessSignOnce.Do(func() {
		ed25519AggVk, ed25519AggPk := ed25519.EDDSAPrivateKey(datePrivKey), ed25519.EDDSAPublicKey(datePubKey)
		pubKey1, priKey1, pubKey2, priKey2 = &ed25519AggPk, &ed25519AggVk, &ed25519AggPk, &ed25519AggVk
		pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
		leader = ed25519.NewEd25519Leader(pubKeys)
	})
	w1, w2 := ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)
	V1, V2 := w1.Commit(rand.Reader), w2.Commit(rand.Reader)
	c = leader.Challenge([]ed25519.Commitment{V1, V2})
	r1 := w1.Response(message, c, leader.GetAggPublicKey())
	if r1 == nil {
		panic("witness sign failed")
	}
	r2 := w2.Response(message, c, leader.GetAggPublicKey())
	if r2 == nil {
		panic("witness sign failed")
	}
}

// Ed25519验签Part_hyperchain_verify_1 ed25519 hyperchain go part verify
//nolint
func Ed25519验签Part_hyperchain_verify_1() {
	ed25519PartVerifyOnce.Do(func() {
		ed25519AggVk, ed25519AggPk := ed25519.EDDSAPrivateKey(datePrivKey), ed25519.EDDSAPublicKey(datePubKey)
		pubKey1, priKey1, pubKey2, priKey2 = &ed25519AggPk, &ed25519AggVk, &ed25519AggPk, &ed25519AggVk
		pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
		leader = ed25519.NewEd25519Leader(pubKeys)
		w1, w2 = ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)

		v1, v2 = w1.Commit(rand.Reader), w2.Commit(rand.Reader)
		c = leader.Challenge([]ed25519.Commitment{v1, v2})

		r1, r2 = w1.Response(message, c, leader.GetAggPublicKey()), w2.Response(message, c, leader.GetAggPublicKey())
	})
	isTrue := leader.VerifyPartSign(message, c, 0, v1, r1)
	if !isTrue {
		panic("part verify failed")
	}
	isTrue = leader.VerifyPartSign(message, c, 1, v2, r2)
	if !isTrue {
		panic("part verify failed")
	}
}

// Ed25519签名Leader_hyperchain_sign_1 ed25519 hyperchain go leader sign
//nolint
func Ed25519签名Leader_hyperchain_sign_1() {
	ed25519AggSignOnce.Do(func() {
		ed25519AggVk, ed25519AggPk := ed25519.EDDSAPrivateKey(datePrivKey), ed25519.EDDSAPublicKey(datePubKey)
		pubKey1, priKey1, pubKey2, priKey2 = &ed25519AggPk, &ed25519AggVk, &ed25519AggPk, &ed25519AggVk
		pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
		w1, w2 = ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)
		leader = ed25519.NewEd25519Leader(pubKeys)

		V1, V2 := w1.Commit(rand.Reader), w2.Commit(rand.Reader)
		c = leader.Challenge([]ed25519.Commitment{V1, V2})

		r1, r2 = w1.Response(message, c, leader.GetAggPublicKey()), w2.Response(message, c, leader.GetAggPublicKey())

	})
	bytesTmp := leader.AggSign(c, []ed25519.SignaturePart{r1, r2})
	if len(bytesTmp) == 0 {
		panic("leader sign failed")
	}
}

// Ed25519验签Agg_hyperchain_verify_1 ed25519 hyperchain go agg verify
//nolint
func Ed25519验签Agg_hyperchain_verify_1() {
	ed25519AggVerifyOnce.Do(func() {
		ed25519AggVk, ed25519AggPk := ed25519.EDDSAPrivateKey(datePrivKey), ed25519.EDDSAPublicKey(datePubKey)
		pubKey1, priKey1, pubKey2, priKey2 = &ed25519AggPk, &ed25519AggVk, &ed25519AggPk, &ed25519AggVk
		pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
		w1, w2 = ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)
		leader = ed25519.NewEd25519Leader(pubKeys)

		V1, V2 := w1.Commit(rand.Reader), w2.Commit(rand.Reader)
		c = leader.Challenge([]ed25519.Commitment{V1, V2})

		r1, r2 = w1.Response(message, c, leader.GetAggPublicKey()), w2.Response(message, c, leader.GetAggPublicKey())
		sign = leader.AggSign(c, []ed25519.SignaturePart{r1, r2})
	})
	// Now verify the resulting collective signature.
	// This can be done by anyone any time, not just the leader.
	isTrue := w1.AggVerify(2, message, sign, leader.GetAggPublicKey())
	if !isTrue {
		panic("agg verify failed")
	}
}
