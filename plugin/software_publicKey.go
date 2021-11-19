package plugin

import (
	"fmt"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/ed25519"
	"hash"
	"io"
)

//PublicKey public Key
type PublicKey struct {
	Mode int
	//gm, ecdsa or rsa
	Key crypto.Verifier
}

//GetKeyInfo get Key information
func (p *PublicKey) GetKeyInfo() int {
	return p.Mode
}

//Verify verify signature
func (p *PublicKey) Verify(msg []byte, hasher hash.Hash, sig []byte) bool {
	if p.Key == nil {
		return false
	}

	if p.Mode == crypto.Ed25519 {
		b, _ := p.Key.Verify(nil, sig, msg)
		return b
	}

	hasher.Reset()
	//PKCS1v15
	var hashTypeUsedInPKCS1v15 []byte
	if ModeIsRSAAlgo(p.Mode) {
		if len(msg) < 4 {
			return false
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
	b, err := p.Key.Verify(hashTypeUsedInPKCS1v15, sig, digst)
	return b && err == nil
}

//Encrypt encrypt
func (p *PublicKey) Encrypt(data []byte, reader io.Reader) ([]byte, error) {
	if p.Key == nil {
		return nil, errUninitialized
	}
	switch p.Mode {
	case crypto.Sm2p256v1:
		key := p.Key.(*gm.SM2PublicKey)
		return gm.Encrypt(key, data, reader)
	case crypto.Secp256k1, crypto.Secp256r1, crypto.Secp384r1, crypto.Secp521r1, crypto.Secp256k1Recover, crypto.Ed25519:
		return nil, errNotSupport
	default:
		return nil, fmt.Errorf("this Key hasn't Init")
	}
}

//Bytes return der
func (p *PublicKey) Bytes() (ret []byte) {
	if p.Key == nil {
		return nil
	}
	switch {
	case p.Mode == crypto.Sm2p256v1:
		k, ok := p.Key.(*gm.SM2PublicKey)
		if !ok {
			return nil
		}
		ret, _ = k.Bytes()
	case ModeIsECDSAAlgo(p.Mode):
		k, ok := p.Key.(*asym.ECDSAPublicKey)
		if !ok {
			return nil
		}
		ret, _ = k.Bytes()
	case p.Mode == crypto.Ed25519:
		k, ok := p.Key.(*ed25519.EDDSAPublicKey)
		if !ok {
			return nil
		}
		ret, _ = k.Bytes()
	default:
		return nil
	}
	return ret
}
