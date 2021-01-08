package test

import (
	"crypto/rand"
	gm "github.com/meshplus/crypto-gm"
	tj "github.com/tjfoc/gmsm/sm2"
	"math/big"
	"sync"
)

var sm2SignOnce sync.Once
var sm2VerifyOnce sync.Once
var sm3HashOnce sync.Once
var sm4EncOnce sync.Once
var sm4DecOnce sync.Once
var sm2TjSignOnce sync.Once
var sm2TjVerifyOnce sync.Once

var smvk *gm.SM2PrivateKey
var smpk *gm.SM2PublicKey
var guomiData []byte
var smSignature []byte
var smDigest []byte
var sm4Key []byte
var sm4data []byte
var sm4 gm.SM4
var sm4cipher []byte
var tjvk *tj.PrivateKey
var tjpk *tj.PublicKey
var tjSignature []byte

//命名规范
//名称_作者_类型_数量
//类型可以为 sign verify hash enc dec singleSM doubleSM

// GM_hyperchain_cgo_sign GM hyperchain cgo sign
//nolint
func SM2签名_hyperchain_sign_1() {
	sm2SignOnce.Do(func() {
		guomiData = make([]byte, 1024)
		_, _ = rand.Read(guomiData)
		var err error
		smvk, err = gm.GenerateSM2Key()
		if err != nil {
			panic(err)
		}
		smpk = &smvk.PublicKey
	})
	degist := gm.HashBeforeSM2(smpk, guomiData)
	_, _ = smvk.Sign(rand.Reader, degist, nil)
}

//GM_hyperchain_cgo_verify GM hyperchain cgo verify
//nolint
func SM2验签_hyperchain_verify_1() {
	sm2VerifyOnce.Do(func() {
		guomiData = make([]byte, 1024)
		_, _ = rand.Read(guomiData)
		var err error
		smvk, err = gm.GenerateSM2Key()
		if err != nil {
			panic(err)
		}
		smpk = &smvk.PublicKey
		smDigest = gm.HashBeforeSM2(smpk, guomiData)
		smSignature, err = smvk.Sign(rand.Reader, smDigest, nil)
	})

	degist := gm.HashBeforeSM2(smpk, guomiData)
	_, _ = smpk.Verify(nil, smSignature, degist)
}

//GM_hyperchain_cgo_verify GM hyperchain cgo verify
//nolint
func SM3哈希_hyperchian_hash_1() {
	sm3HashOnce.Do(func() {
		guomiData = make([]byte, 1024)
		_, _ = rand.Read(guomiData)
		var err error
		smvk, err = gm.GenerateSM2Key()
		if err != nil {
			panic(err)
		}
		smpk = &smvk.PublicKey
	})
	_ = gm.HashBeforeSM2(smpk, guomiData)
}

//GM_hyperchain_cgo_verify GM hyperchain cgo verify
//nolint
func SM4加密_hyperchian_enc_1() {
	sm4EncOnce.Do(func() {
		sm4Key = make([]byte, 16)
		sm4data = make([]byte, 32)
		_, _ = rand.Read(sm4Key)
		_, _ = rand.Read(sm4data)
	})

	_, _ = sm4.Encrypt(gm.SM4Key(sm4Key), sm4data, rand.Reader)
}

//GM_hyperchain_cgo_verify GM hyperchain cgo verify
//nolint
func SM4解密_hyperchian_dec_1() {
	sm4DecOnce.Do(func() {
		sm4Key = make([]byte, 16)
		_, _ = rand.Read(sm4Key)
		_, _ = rand.Read(sm4data)
		sm4cipher, _ = sm4.Encrypt(gm.SM4Key(sm4Key), sm4data, rand.Reader)
	})
	_, _ = sm4.Decrypt(gm.SM4Key(sm4Key), sm4cipher)
}

// GM_tj_go_cgo_sign GM tj go sign
//nolint
func SM2签名_tj_sign_1() {
	sm2TjSignOnce.Do(func() {
		guomiData = make([]byte, 1024)
		_, _ = rand.Read(guomiData)
		var err error
		smvk, err = gm.GenerateSM2Key()
		if err != nil {
			panic(err)
		}
		smpk = &smvk.PublicKey
		d, _ := smvk.Bytes()
		xy, _ := smpk.Bytes()
		tjvk = new(tj.PrivateKey)
		tjvk.Curve = tj.P256Sm2()
		tjvk.D, tjvk.X, tjvk.Y = new(big.Int), new(big.Int), new(big.Int)
		tjvk.D.SetBytes(d)
		tjvk.X.SetBytes(xy[1:33])
		tjvk.Y.SetBytes(xy[33:])
	})
	_, _ = tjvk.Sign(rand.Reader, guomiData, nil)
}

//GM_tj_go_verify GM tj go verify
//nolint
func SM2验签_tj_verify_1() {
	sm2TjVerifyOnce.Do(func() {
		guomiData = make([]byte, 1024)
		_, _ = rand.Read(guomiData)
		var err error
		smvk, err = gm.GenerateSM2Key()
		if err != nil {
			panic(err)
		}
		smpk = &smvk.PublicKey
		d, _ := smvk.Bytes()
		xy, _ := smpk.Bytes()
		tjvk = new(tj.PrivateKey)
		tjvk.Curve = tj.P256Sm2()
		tjvk.D, tjvk.X, tjvk.Y = new(big.Int), new(big.Int), new(big.Int)
		tjvk.D.SetBytes(d)
		tjvk.X.SetBytes(xy[1:33])
		tjvk.Y.SetBytes(xy[33:])
		tjpk = &tjvk.PublicKey
		tjSignature, _ = tjvk.Sign(rand.Reader, guomiData, nil)
	})
	_ = tjpk.Verify(guomiData, tjSignature)
}
