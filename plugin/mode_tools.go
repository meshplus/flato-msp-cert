package plugin

import (
	"crypto/elliptic"
	"fmt"
	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
)

//ModeIsSignatureAlgo is it a signature algorithm
func ModeIsSignatureAlgo(mode int) bool {
	return mode != 0 && mode&0xffff00ff == 0
}

//ModeIsHashAlgo is it a hash algorithm
func ModeIsHashAlgo(mode int) bool {
	return mode != 0 && mode&0xffffff00 == 0
}

//ModeIsEncryptAlgo is it a encrypt algorithm
func ModeIsEncryptAlgo(mode int) bool {
	return mode != 0 && mode&0xff00ffff == 0
}

//ModeIsRSAAlgo is it a RSA signature algorithm
func ModeIsRSAAlgo(mode int) bool {
	return ModeIsSignatureAlgo(mode) && mode&0xf000 == crypto.Rsa2048
}

//ModeIsECDSAAlgo is it a ECDSA signature algorithm
func ModeIsECDSAAlgo(mode int) bool {
	return mode != 0 && mode&0xfffff0ff == 0 && mode != crypto.Sm2p256v1
}

//ModeGetCurve get curve form mode
func ModeGetCurve(mode int) (elliptic.Curve, error) {
	switch mode {
	case crypto.Secp521r1:
		return elliptic.P521(), nil
	case crypto.Secp384r1:
		return elliptic.P384(), nil
	case crypto.Secp256r1:
		return elliptic.P256(), nil
	case crypto.Secp256k1, crypto.Secp256k1Recover:
		return secp256k1.S256(), nil
	case crypto.Sm2p256v1:
		return gm.GetSm2Curve(), nil
	default:
		return nil, fmt.Errorf("unknown mode")
	}
}

//ModeFromCurve get mode from curve
func ModeFromCurve(curve elliptic.Curve) int {
	switch curve {
	case elliptic.P521():
		return crypto.Secp521r1
	case elliptic.P384():
		return crypto.Secp384r1
	case elliptic.P256():
		return crypto.Secp256r1
	case secp256k1.S256():
		return crypto.Secp256k1
	case gm.GetSm2Curve():
		return crypto.Sm2p256v1
	default:
		return crypto.None
	}
}

//ModeGetRSAMod get RSA mod from mode
func ModeGetRSAMod(mode int) (int, error) {
	if !ModeIsRSAAlgo(mode) {
		return 0, fmt.Errorf("it is'n RSA algo mode")
	}
	return (mode&0x0f00 + 0x200) << 2, nil
}

//ModeFromRSAMod get mode from RSA mode
func ModeFromRSAMod(rsaMod int) (int, error) {
	r := (rsaMod + 1023) >> 10
	if r < 3 {
		return crypto.Rsa2048, nil
	}
	mode := crypto.Rsa2048 | ((r - 2) << 8)
	if !ModeIsRSAAlgo(mode) {
		return crypto.None, fmt.Errorf("it is'n RSA algo mode")
	}
	return mode, nil
}
