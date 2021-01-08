package test_test

import (
	"github.com/meshplus/flato-msp-cert/test"
	"testing"
)

func TestName(t *testing.T) {
	test.SM2签名_hyperchain_sign_1()
	test.SM2验签_hyperchain_verify_1()
	test.SM3哈希_hyperchian_hash_1()
	test.SM4加密_hyperchian_enc_1()
	test.SM4解密_hyperchian_dec_1()
	test.SM2签名_tj_sign_1()
	test.SM2验签_tj_verify_1()
	//test.ED25519签名_golang_sign_1()
	//test.ED25519验签_golang_verify_1()
	test.P256k1验签_hyperchain_verify_1()
	test.P256k1验签_btcsuite_verify_1()
	test.P256k1签名_hyperchain_sign_1()
	test.P256k1签名_btcsuite_sign_1()
}
