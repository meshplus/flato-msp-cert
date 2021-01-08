package test

import (
	"crypto/rand"
	"github.com/bford/golang-x-crypto/ed25519"
	"github.com/bford/golang-x-crypto/ed25519/cosi"
)

var cosignPKs []ed25519.PublicKey
var cosignVKs []ed25519.PrivateKey
var cosignMSG []byte

func init() {
	cosignMSG = make([]byte, 1024)
	_, _ = rand.Read(cosignMSG)
	cosignPKs = make([]ed25519.PublicKey, 64)
	cosignVKs = make([]ed25519.PrivateKey, 64)
	// Create keypairs for the two cosigners.
	for i := range cosignPKs {
		cosignPKs[i], cosignVKs[i], _ = ed25519.GenerateKey(nil)
	}

	// Sign a test message.
	sig := Sign(cosignMSG, cosignPKs, cosignVKs...)

	// Now verify the resulting collective signature.
	// This can be done by anyone any time, not just the leader.
	valid := cosi.Verify(cosignPKs, nil, cosignMSG, sig)
	if !valid {
		panic("ed25519 init false, validate fail")
	}
}

// Sign Sign
func Sign(message []byte, pubKeys []ed25519.PublicKey,
	priKeys ...ed25519.PrivateKey) []byte {

	// Each cosigner first needs to produce a per-message commit.
	commits := make([]cosi.Commitment, len(pubKeys))
	secrets := make([]*cosi.Secret, len(pubKeys))
	for i := range commits {
		commits[i], secrets[i], _ = cosi.Commit(nil)
	}

	// The leader then combines these into an aggregate commit.
	cosigners := cosi.NewCosigners(pubKeys, nil)
	aggregatePublicKey := cosigners.AggregatePublicKey()
	aggregateCommit := cosigners.AggregateCommit(commits)

	// The cosigners now produce their parts of the collective signature.
	sigParts := make([]cosi.SignaturePart, len(pubKeys))
	for i := range sigParts {
		sigParts[i] = cosi.Cosign(priKeys[i], secrets[i], message, aggregatePublicKey, aggregateCommit)
	}

	// Finally, the leader combines the two signature parts
	// into a final collective signature.
	sig := cosigners.AggregateSignature(aggregateCommit, sigParts)

	return sig
}
