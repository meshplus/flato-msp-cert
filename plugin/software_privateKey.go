package plugin

import (
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"hash"
	"io"
)

var errNotSupport = errors.New("not support")
var errUninitialized = errors.New("this Key hasn't init")

//PrivateKey private Key
type PrivateKey struct {
	PublicKey
	//the first is gm, the second is ecdsa, the third is rsa
	PrivKey crypto.Signer
}

//Sign generate signature
func (p *PrivateKey) Sign(msg []byte, hasher hash.Hash, rand io.Reader) ([]byte, error) {
	if p.PrivKey == nil {
		return nil, errUninitialized
	}
	if p.Mode == crypto.Ed25519 {
		return p.PrivKey.Sign(nil, msg, nil)
	}

	hasher.Reset()
	//PKCS1v15
	var hashTypeUsedInPKCS1v15 []byte
	if ModeIsRSAAlgo(p.Mode) {
		if len(msg) < 4 {
			return nil, fmt.Errorf("need hashTypeUsedInPKCS1v15")
		}
		hashTypeUsedInPKCS1v15 = msg[len(msg)-4:]
		msg = msg[:len(msg)-4]
	}
	//write public Key
	if _, ok := hasher.(*gm.IDHasher); ok && p.Mode == crypto.Sm2p256v1 {
		_, _ = hasher.Write(p.Bytes())
	}
	_, _ = hasher.Write(msg)
	digst := hasher.Sum(nil)

	r, err := p.PrivKey.Sign(hashTypeUsedInPKCS1v15, digst, rand)
	return r, err
}

//Decrypt decrypt
func (p *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	if p.PrivKey == nil {
		return nil, errUninitialized
	}
	switch p.Mode {
	case crypto.Sm2p256v1:
		key := p.PrivKey.(*gm.SM2PrivateKey)
		return gm.Decrypt(key, data)
	case crypto.Secp256k1, crypto.Secp256r1, crypto.Secp384r1, crypto.Secp521r1, crypto.Secp256k1Recover, crypto.Ed25519:
		return nil, errNotSupport
	default:
		return nil, fmt.Errorf("this Key hasn't Init")
	}
}

//Destroy destroy Key
func (p *PrivateKey) Destroy() {
	p.Mode = crypto.None
	p.PrivKey = nil
}
