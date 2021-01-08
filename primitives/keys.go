package primitives

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/meshplus/flato-msp-cert/primitives/x509"
)

//MarshalPrivateKey converts a private key to DER
func MarshalPrivateKey(privateKey interface{}) ([]byte, error) {
	switch x := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return nil, errors.New("please use asym.ECDSAPrivateKey")
	case *asym.ECDSAPrivateKey:
		return x509.MarshalECPrivateKey(x)
	case *gm.SM2PrivateKey:
		return marshalSMPrivateKey(x)
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(x), nil
	default:
		return nil, errors.New("invalid key")
	}
}

// UnmarshalPrivateKey unmarshals a der to private key
func UnmarshalPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil { //parsing the pkcs1 private key
		return
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil { //parsing the pkcs8 private key
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return
		case *asym.ECDSAPrivateKey:
			if k.Curve == gm.GetSm2Curve() {
				return new(gm.SM2PrivateKey).FromBytes(k.D.Bytes()).CalculatePublicKey(), nil
			}
			return
		case *gm.SM2PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = parseSMPrivateKey(der); err == nil { //parsing the guomi private key
		return
	}
	if key, err = x509.ParseECPrivateKey(der); err == nil { //parsing the ecdsa private key
		return
	}
	return nil, errors.New("failed to parse private key")
}

// MarshalPublicKey marshal a public key to the pem forma
func MarshalPublicKey(publicKey interface{}) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}

// UnmarshalPublicKey unmarshal a der to public key
func UnmarshalPublicKey(derBytes []byte) (pub interface{}, err error) {
	key, err := x509.ParsePKIXPublicKey(derBytes)
	return key, err
}
