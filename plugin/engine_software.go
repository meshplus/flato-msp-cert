package plugin

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	inter "github.com/meshplus/crypto-standard"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/crypto-standard/ed25519"
	"github.com/meshplus/crypto-standard/hash"
	"io"
	"io/ioutil"
	"path"
	"sync"
)

type softwareEngine struct {
	sync.Mutex
	keyStorePath string
}

func (s *softwareEngine) Init(engine *EncryptEngineMux, keyStorePath string) {
	s.Lock()
	defer s.Unlock()
	s.keyStorePath = keyStorePath
	signC, decC := &softwareCreateSignFunc{keyStore: &s.keyStorePath}, &softwareCreateDecKeyFunc{keyStore: &s.keyStorePath}

	engine.random = (&softwareRandomFunc{}).Rander
	engine.hash = (&softwareHashFunc{}).GetHash
	engine.crypt = (&softwareCryptFunc{}).GetSecretKey
	engine.verify = (&softwareVerifyFunc{}).GetVerifyKey
	engine.signGet = (&softwareSignFunc{}).GetSignKey
	engine.signImport = (&softwareSignFunc{}).ImportSignKey
	engine.signCreate = signC.CreateSignKey
	engine.encKey = (&softwareEncKeyFunc{}).GetEncKey
	engine.decGet = (&softwareDecKeyFunc{}).GetDecKey
	engine.decImport = (&softwareDecKeyFunc{}).ImportDecKey
	engine.decCreate = decC.CreateDecKey
}

/*
1.softwareRandomFunc get random reader
*/
type softwareRandomFunc struct{}

func (s *softwareRandomFunc) GetLevel() ([]int, uint8) {
	return []int{crypto.None}, 1
}

func (s *softwareRandomFunc) Rander() (io.Reader, error) {
	return rand.Reader, nil
}

/*
2.softwareHashFunc get hash function
*/
type softwareHashFunc struct{}

func (s *softwareHashFunc) GetLevel() ([]int, uint8) {
	return copySlice(hashAlgoAll), crypto.None
}

func (s *softwareHashFunc) GetHash(mode int) (crypto.Hasher, error) {
	switch mode {
	case crypto.SM3:
		return gm.NewSM3Hasher(), nil
	case crypto.Sm3WithPublicKey:
		return gm.NewSM3IDHasher().(crypto.Hasher), nil
	case crypto.FakeHash:
		return hash.GetFakeHasher(), nil
	default:
		return hash.NewHasher(hash.HashType(mode)), nil
	}
}

/*
3.softwareCryptFunc get secret Key function
*/
type softwareCryptFunc struct{}

func (s *softwareCryptFunc) GetLevel() ([]int, uint8) {
	return copySlice(symAlgoAll), 1
}

func (s *softwareCryptFunc) GetSecretKey(mode int, pwd, key []byte) (crypto.SecretKey, error) {
	if len(key) == 0 {

	}
	r := &SecretKey{
		key: key,
	}
	switch mode {
	case crypto.Sm4 | crypto.CBC:
		r.c = &gm.SM4{}
	case crypto.Aes | crypto.CBC:
		r.c = &inter.AES{}
	case crypto.Des3 | crypto.CBC:
		r.c = &inter.TripleDES{}
	}
	return r, nil
}

/*
4.softwareVerifyFunc import public Key for verify signature
*/
type softwareVerifyFunc struct{}

func (s *softwareVerifyFunc) GetVerifyKey(derBytes []byte, mode int) (crypto.VerifyKey, error) {
	return getPublicKey(derBytes, mode)
}

func (s *softwareVerifyFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

/*
5.softwareVerifyFunc import private Key for generate signature
*/
type softwareSignFunc struct {
}

//GetSignKey software implement, input is pkcs8
func (s *softwareSignFunc) GetSignKey(key []byte, mode int) (crypto.SignKey, error) {
	switch {
	case ModeIsECDSAAlgo(mode):
		k := new(asym.ECDSAPrivateKey)
		if err := k.FromBytes(key, mode); err != nil {
			return nil, err
		}
		k.CalculatePublicKey()
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: mode,
				Key:  &k.ECDSAPublicKey,
			},
			PrivKey: k,
		}, nil
	case mode == crypto.Sm2p256v1:
		k := new(gm.SM2PrivateKey)
		if err := k.FromBytes(key, mode); err != nil {
			return nil, err
		}
		k.CalculatePublicKey()
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: mode,
				Key:  &k.PublicKey,
			},
			PrivKey: k,
		}, nil
	case mode == crypto.Ed25519:
		var k ed25519.EDDSAPrivateKey
		if err := k.FromBytes(key, mode); err != nil {
			return nil, err
		}
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: mode,
				Key:  k.Public().(*ed25519.EDDSAPublicKey),
			},
			PrivKey: &k,
		}, nil
	default:
		return nil, crypto.ErrNotSupport
	}
}

//ImportSignKey software implement, input is pkcs8 or raw, return pkcs8
func (s *softwareSignFunc) ImportSignKey(key []byte, mode int) (index []byte, err error) {
	return importPrivateKey(key, mode)
}

func (s *softwareSignFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

/*
6.softwareCreateSignFunc create a private Key for generate signature
*/
type softwareCreateSignFunc struct {
	keyStore *string
}

//CreateSignKey index: pkcs8
func (s *softwareCreateSignFunc) CreateSignKey(write bool, mode int) ([]byte, crypto.SignKey, error) {
	return createPrivateKey(s.keyStore, write, mode)
}

func getRandomStr(length int) string {
	ret := make([]byte, length)
	_, _ = rand.Read(ret)
	return hex.EncodeToString(ret)
}

func (s *softwareCreateSignFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

/*
7.softwareEncKeyFunc import a public Key for encrypt
*/
type softwareEncKeyFunc struct{}

func (s *softwareEncKeyFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

func (s *softwareEncKeyFunc) GetEncKey(derBytes []byte, mode int) (crypto.EncKey, error) {
	return getPublicKey(derBytes, mode)
}

/*
8.softwareDecKeyFunc import a private Key for decrypt
*/
type softwareDecKeyFunc struct {
}

func (s *softwareDecKeyFunc) GetDecKey(key []byte, mode int) (crypto.DecKey, error) {
	ret, err := parsePrivateKey(key)
	return ret, err
}

func (s *softwareDecKeyFunc) ImportDecKey(key []byte, mode int) (index []byte, err error) {
	return importPrivateKey(key, mode)
}

func (s *softwareDecKeyFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

/*
8.softwareDecKeyFunc create a private Key for decrypt
*/
type softwareCreateDecKeyFunc struct {
	keyStore *string
}

func (s *softwareCreateDecKeyFunc) CreateDecKey(write bool, mode int) ([]byte, crypto.DecKey, error) {
	return createPrivateKey(s.keyStore, write, mode)
}

func (s *softwareCreateDecKeyFunc) GetLevel() ([]int, uint8) {
	return copySlice(asymAlgoAll), 1
}

func getPublicKey(pkixInner []byte, mode int) (crypto.PublicKey, error) {
	var inner crypto.Verifier
	switch {
	case ModeIsECDSAAlgo(mode):
		tmp := new(asym.ECDSAPublicKey)
		err := tmp.FromBytes(pkixInner, mode)
		if err != nil {
			return nil, err
		}
		inner = tmp
	case mode == crypto.Sm2p256v1:
		tmp := new(gm.SM2PublicKey)
		if err := tmp.FromBytes(pkixInner, crypto.Sm2p256v1); err != nil {
			return nil, err
		}
		inner = tmp
	case mode == crypto.Ed25519:
		tmp := new(ed25519.EDDSAPublicKey)
		if err := tmp.FromBytes(pkixInner, crypto.Ed25519); err != nil {
			return nil, err
		}
		inner = tmp
	default:
		return nil, fmt.Errorf("unknown mode")
	}
	return &PublicKey{
		Mode: mode,
		Key:  inner,
	}, nil
}

func createPrivateKey(keyStorePath *string, write bool, mode int) ([]byte, crypto.PrivateKey, error) {
	var sk crypto.Signer
	var vk crypto.Verifier
	switch {
	case ModeIsECDSAAlgo(mode):
		tmp, _ := asym.GenerateKey(mode)
		sk, vk = tmp, &tmp.ECDSAPublicKey
	case mode == crypto.Sm2p256v1:
		tmp, _ := gm.GenerateSM2Key()
		sk, vk = tmp, &tmp.PublicKey
	case mode == crypto.Ed25519:
		tmp, _ := ed25519.GenerateKey(rand.Reader)
		sk, vk = tmp, tmp.Public().(*ed25519.EDDSAPublicKey)
	default:
		return nil, nil, fmt.Errorf("createPrivateKey unknown mode")
	}
	k := &PrivateKey{
		PublicKey: PublicKey{
			Mode: mode,
			Key:  vk,
		},
		PrivKey: sk,
	}
	index, err := MarshalPKCS8PrivateKey(k)

	//persist
	if write {
		if *keyStorePath == "" ||  *keyStorePath == "no store"{
			return nil, nil, fmt.Errorf("this engine has no Key store")
		}
		name := getRandomStr(10) + ".priv"
		var pemCode []byte
		if bytes.HasPrefix(index, []byte("plugin")) {
			pemCode = index
		} else {
			buf := bytes.NewBuffer(nil)
			err = pem.Encode(buf, &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: index,
			})
			if err != nil {
				return nil, nil, err
			}
			pemCode = buf.Bytes()
		}
		werr := ioutil.WriteFile(path.Join(*keyStorePath, name), pemCode, 0666)
		if werr != nil {
			return nil, nil, werr
		}
	}
	return index, k, err
}

func importPrivateKey(key []byte, mode int) (index []byte, err error) {
	var sk crypto.Signer
	var vk crypto.Verifier
	switch {
	case ModeIsECDSAAlgo(mode):
		tmp := new(asym.ECDSAPrivateKey)
		if err := tmp.FromBytes(key, mode); err != nil {
			return nil, err
		}
		tmp.CalculatePublicKey()
		sk, vk = tmp, &tmp.ECDSAPublicKey
	case mode == crypto.Sm2p256v1:
		tmp := new(gm.SM2PrivateKey)
		if err := tmp.FromBytes(key, mode); err != nil {
			return nil, err
		}
		tmp.CalculatePublicKey()
		sk, vk = tmp, &tmp.PublicKey
	default:
		return nil, fmt.Errorf("unknown mode")
	}
	tmp := &PrivateKey{
		PublicKey: PublicKey{
			Mode: mode,
			Key:  vk,
		},
		PrivKey: sk,
	}
	return MarshalPKCS8PrivateKey(tmp)
}


//parsePrivateKey parse private Key in pkcs8, sec1, pkcs1, sm2
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := ParseECPrivateKey(der); err == nil {
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: ModeFromCurve(k.Curve),
				Key:  &k.ECDSAPublicKey,
			},
			PrivKey: k,
		}, nil
	}
	if k, err := ParseSMPrivateKey(der); err == nil {
		return &PrivateKey{
			PublicKey: PublicKey{
				Mode: crypto.Sm2p256v1,
				Key:  &k.PublicKey,
			},
			PrivKey: k,
		}, nil
	}
	return nil, crypto.ErrNotSupport
}