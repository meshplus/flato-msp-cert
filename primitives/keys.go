package primitives

import (
	"fmt"
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
)

// UnmarshalPrivateKey unmarshals a pkcs8 der to private key
func UnmarshalPrivateKey(engine crypto.Engine, index []byte) (key crypto.SignKey, err error) {
	//todo transfer to pkcs8
	//sm2 sec1
	//if sm2key, err := parseSMPrivateKey(index); err == nil {
	//	plugin.MarshalPKCS8PrivateKey(&plugin.PrivateKey{})
	//}
	//ecc sec1

	//rsa pkcs1

	//parse pkcs8
	k, err := engine.GetSignKey(index, crypto.None)
	if err == nil {
		return k, nil
	}
	return
}

// MarshalPublicKey marshal a public key to the pem forma
func MarshalPublicKey(publicKey crypto.VerifyKey) ([]byte, error) {
	return plugin.MarshalPKIXPublicKey(publicKey.Bytes(), publicKey.GetKeyInfo())
}

// UnmarshalPublicKey unmarshal a der to public key
func UnmarshalPublicKey(engine crypto.Engine, derBytes []byte) (pub crypto.VerifyKey, err error) {
	//parse der
	rawpub, mode, err := plugin.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix pub error: %v", err.Error())
	}
	return engine.GetVerifyKey(rawpub, mode)
}
