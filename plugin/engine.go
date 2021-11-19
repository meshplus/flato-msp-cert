package plugin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/meshplus/crypto"
)


//Function function
type Function uint32

func (f Function) String() string {
	switch f {
	case Random:
		return "[Random]"
	case Hash:
		return "[Hash]"
	case Crypt:
		return "[Crypt]"
	case Verify:
		return "[Verify]"
	case SignImport:
		return "[SignImport]"
	case SignGet:
		return "[SignGet]"
	case CreateSign:
		return "[CreateSign]"
	case EncKey:
		return "[EncKey]"
	case DecKeyImport:
		return "[DecImport]"
	case DecKeyGet:
		return "[DecGet]"
	case CreateDecKey:
		return "[CreateDec]"
	default:
		return fmt.Sprintf("[0x%X]", int(f))
	}
}

const (
	configDefault  = "default"
	configPriority = "priority"
)

//Function function
const (
	Random Function = iota
	Hash            //always soft
	Crypt           //always soft
	Verify
	SignImport
	SignGet
	CreateSign
	EncKey       //always soft
	DecKeyImport //always soft
	DecKeyGet
	CreateDecKey //always soft
	FunctionMax
)

type randomFuncSlot func() (io.Reader, error)
type hashFuncSlot func(mode int) (crypto.Hasher, error)
type cryptFuncSlot func(mode int, pwd, key []byte) (crypto.SecretKey, error)
type verifyFuncSlot func(key []byte, mode int) (crypto.VerifyKey, error)
type signGetFuncSlot func(key []byte, mode int) (crypto.SignKey, error)
type signImportFuncSlot func(key []byte, mode int) (index []byte, err error)
type signCreateFuncSlot func(write bool, mode int) (index []byte, k crypto.SignKey, err error)
type encKeyFuncSlot func(index []byte, mode int) (crypto.EncKey, error)
type decGetFuncSlot func(key []byte, mode int) (crypto.DecKey, error)
type decImportFuncSlot func(key []byte, mode int) (index []byte, err error)
type decCreateFuncSlot func(write bool, mode int) (index []byte, k crypto.DecKey, err error)

type unLoadError struct {
	code        int
	otherReason string
	k           uint64
}

func (e *unLoadError) Error() string {
	f := Function(e.k >> 32)
	modename := getModeName(getModeFromKey(e.k))
	switch e.code {
	case 0:
		//config reason
		return fmt.Sprintf("config reason, %s for %s, detail: %s", modename, f, e.otherReason)
	case 1:
		//algo implement error
		return fmt.Sprintf("implement err, %s for %s, detail: %s", modename, f, e.otherReason)
	default:
		//return unexpect error
		return fmt.Sprintf("unexpect error, %s for %s, detail: %v", modename, f, e.otherReason)
	}
}

//EncryptEngineMux encryption mux
type EncryptEngineMux struct {
	note   *[FunctionMax]bool
	detail map[uint64]string

	s          *softwareEngine
	random     randomFuncSlot
	hash       hashFuncSlot
	crypt      cryptFuncSlot
	verify     verifyFuncSlot
	signGet    signGetFuncSlot
	signImport signImportFuncSlot
	signCreate signCreateFuncSlot
	encKey     encKeyFuncSlot
	decGet     decGetFuncSlot
	decImport  decImportFuncSlot
	decCreate  decCreateFuncSlot
}

func getModeName(mode int) (m string) {
	switch {
	//hash
	case mode&0xffffff00 == 0:
		switch mode {
		case crypto.SHA2_224:
			m = "SHA2_224"
		case crypto.SHA2_256:
			m = "SHA2_256"
		case crypto.SHA2_384:
			m = "SHA2_384"
		case crypto.SHA2_512:
			m = "SHA2_512"
		case crypto.SHA3_224:
			m = "SHA3_224"
		case crypto.SHA3_256:
			m = "SHA3_256"
		case crypto.SHA3_384:
			m = "SHA3_384"
		case crypto.SHA3_512:
			m = "SHA3_512"
		case crypto.KECCAK_224:
			m = "KECCAK_224"
		case crypto.KECCAK_256:
			m = "KECCAK_256"
		case crypto.KECCAK_384:
			m = "KECCAK_384"
		case crypto.KECCAK_512:
			m = "KECCAK_512"
		case crypto.SM3:
			m = "SM3"
		case crypto.Sm3WithPublicKey:
			m = "Sm3WithPublicKey"
		}
	//Asymmetric Algo
	case mode&0xffff00ff == 0:
		switch mode {
		case crypto.Sm2p256v1:
			m = "Sm2p256v1"
		case crypto.Secp256k1:
			m = "Secp256k1"
		case crypto.Secp256r1:
			m = "Secp256r1"
		case crypto.Secp384r1:
			m = "Secp384r1"
		case crypto.Secp521r1:
			m = "Secp521r1"
		case crypto.Secp256k1Recover:
			m = "Secp256k1Recover"
		case crypto.Ed25519:
			m = "Ed25519"
		case crypto.Rsa2048:
			m = "Rsa2048"
		case crypto.Rsa3072:
			m = "Rsa3072"
		case crypto.Rsa4096:
			m = "Rsa4096"
		default:
			m = "None"
		}
	//Symmetrical Algo for Encrypt and Decrypt
	case mode&0xff00ffff == 0:
		switch mode {
		case crypto.Sm4 | crypto.CBC:
			m = "SM4_CBC"
		case crypto.Sm4 | crypto.ECB:
			m = "SM4_ECB"
		case crypto.Aes | crypto.CBC:
			m = "AES_CBC"
		case crypto.Aes | crypto.ECB:
			m = "AES_ECB"
		case crypto.Aes | crypto.GCM:
			m = "AES_GCM"
		case crypto.Des3 | crypto.CBC:
			m = "3DES_CBC"
		case crypto.Des3 | crypto.ECB:
			m = "3DES_ECB"
		case crypto.Des3 | crypto.GCM:
			m = "3DES_GCM"
		}
	}
	if m == "" {
		return "None"
	}
	return m
}

//String output
func (e *EncryptEngineMux) String() string {
	if len(e.detail) == 0 {
		return "[all software]"
	}
	//k: algo type, v: algo (plugin name)
	var ret = make(map[string]string)
	for k, v := range e.detail {
		name := Function(k >> 32).String()
		ret[name] = ret[name] + fmt.Sprintf("%v -> %v", getModeName(getModeFromKey(k)), v)
	}
	var s string
	for k, v := range ret {
		k += strings.Repeat(" ", 15-len(k))
		s += fmt.Sprintf("%v : %v\n", k, v)
	}
	return s
}

//GetLevel get level
func (e *EncryptEngineMux) GetLevel() ([]int, uint8) {
	return nil, 0
}

//Rander random reader
func (e *EncryptEngineMux) Rander() (io.Reader, error) {
	return e.random()
}

//GetHash get hash function
func (e *EncryptEngineMux) GetHash(mode int) (crypto.Hasher, error) {
	return e.hash(mode)
}

//GetSecretKey get secret Key
func (e *EncryptEngineMux) GetSecretKey(mode int, pwd, key []byte) (crypto.SecretKey, error) {
	return e.crypt(mode, pwd, key)
}

//GetVerifyKey get verify Key
func (e *EncryptEngineMux) GetVerifyKey(key []byte, mode int) (crypto.VerifyKey, error) {
	if mode != crypto.None {
		return e.verify(key, mode)
	}

	if raw, modeInner, err := ParsePKIXPublicKey(key); err == nil {
		return e.verify(raw, modeInner)
	}

	return nil, fmt.Errorf("parse pkix public Key error")
}

//GetSignKey get sign Key
func (e *EncryptEngineMux) GetSignKey(key []byte, mode int) (crypto.SignKey, error) {
	if mode == crypto.None {
		if bytes.HasPrefix(key, []byte("plugin")) {
			m, index, err := parseIndex(key)
			if err != nil {
				return nil, err
			}
			return e.signGet(index, m)
		}
		if k, err := parsePrivateKey(key); err == nil {
			//private key raw bytes
			rawKey, berr := k.(*PrivateKey).PrivKey.Bytes()
			if berr != nil {
				return nil, berr
			}
			return e.signGet(rawKey, k.GetKeyInfo())
		}
	}
	return e.signGet(key, mode)
}

//ImportSignKey import sign Key
func (e *EncryptEngineMux) ImportSignKey(key []byte, mode int) (index []byte, err error) {
	if mode != crypto.None {
		return e.signImport(key, mode)
	}

	sk, err := parsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse Key error, expect pkcs8 private Key")
	}
	//private key bytes
	vk, err := sk.(*PrivateKey).PrivKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("parse Key error, expect pkcs8 private Key")
	}
	mode = sk.GetKeyInfo()
	return e.signImport(vk, mode)
}

//CreateSignKey sign Key
func (e *EncryptEngineMux) CreateSignKey(persistent bool, mode int) (index []byte, k crypto.SignKey, err error) {
	return e.signCreate(persistent, mode)
}

//GetEncKey get enc Key
func (e *EncryptEngineMux) GetEncKey(key []byte, mode int) (crypto.EncKey, error) {
	if mode != crypto.None {
		return e.encKey(key, mode)
	}

	if raw, modeInner, err := ParsePKIXPublicKey(key); err == nil {
		return e.encKey(raw, modeInner)
	}

	return nil, crypto.ErrNotSupport
}

//GetDecKey get dec Key
func (e *EncryptEngineMux) GetDecKey(key []byte, mode int) (crypto.DecKey, error) {
	if mode == crypto.None {
		if bytes.HasPrefix(key, []byte("plugin")) {
			m, index, err := parseIndex(key)
			if err != nil {
				return nil, err
			}
			return e.decGet(index, m)
		}
		if k, err := parsePrivateKey(key); err == nil {
			//private key raw bytes
			rawKey, berr := k.(*PrivateKey).PrivKey.Bytes()
			if berr != nil {
				return nil, berr
			}
			return e.decGet(rawKey, k.GetKeyInfo())
		}
	}
	return e.decGet(key, mode)
}

//ImportDecKey import dec Key
func (e *EncryptEngineMux) ImportDecKey(key []byte, mode int) (index []byte, err error) {
	if mode != crypto.None {
		return e.decImport(key, mode)
	}

	sk, err := parsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse Key error, expect pkcs8 private Key")
	}
	//private key bytes
	vk, err := sk.(*PrivateKey).PrivKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("parse Key error, expect pkcs8 private Key")
	}
	mode = sk.GetKeyInfo()
	return e.decImport(vk, mode)
}

//CreateDecKey create dec Key
func (e *EncryptEngineMux) CreateDecKey(persistent bool, mode int) (index []byte, k crypto.DecKey, err error) {
	return e.decCreate(persistent, mode)
}

//GetCryptoEngine get crypto engine
func GetCryptoEngine() crypto.Engine {
	return GetSoftwareEngine("")
}

//GetSoftwareEngine get software engine
func GetSoftwareEngine(keyStoreAbsPath string) crypto.Engine {
	soft, ret := &softwareEngine{keyStorePath: keyStoreAbsPath}, &EncryptEngineMux{}
	ret.s = soft
	soft.Init(ret, keyStoreAbsPath)
	return ret
}

func parseIndex(in []byte) (int, []byte, error) {
	inStr := strings.TrimSpace(string(in))
	lists := strings.Split(inStr, " ")
	if len(lists) != 3 {
		return crypto.None, nil, fmt.Errorf("parse index error, num of fileds should be 3")
	}
	content, err := hex.DecodeString(lists[2])
	if err != nil {
		return crypto.None, nil, fmt.Errorf("parse index error, parse hex error")
	}

	switch lists[1] {
	case "sm2":
		return crypto.Sm2p256v1, content, nil
	case "secp256k1":
		return crypto.Secp256k1, content, nil
	case "secp256r1":
		return crypto.Secp256r1, content, nil
	case "secp256k1Recover":
		return crypto.Secp256k1Recover, content, nil
	case "ed25519":
		return crypto.Ed25519, content, nil
	default:
		return crypto.None, content, fmt.Errorf("parse index error, unkenown algo")
	}
}
