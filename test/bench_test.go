package test

import "testing"

func BenchmarkECC解密_hyperchain_dec_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ECC解密_hyperchain_dec_1()
	}
}

func BenchmarkECC加密_hyperchain_enc_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ECC加密_hyperchain_enc_1()
	}
}

func BenchmarkSM2签名_hyperchain_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM2签名_hyperchain_sign_1()
	}
}

func BenchmarkSM2验签_hyperchain_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM2验签_hyperchain_verify_1()
	}
}

func BenchmarkSM2签名_tj_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM2签名_tj_sign_1()
	}
}

func BenchmarkSM2验签_tj_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM2验签_tj_verify_1()
	}
}

func BenchmarkSM3哈希_hyperchian_hash_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM3哈希_hyperchian_hash_1()
	}
}

func BenchmarkSM4加密_hyperchian_enc_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM4加密_hyperchian_enc_1()
	}
}

func BenchmarkSM4加密_hyperchian_enc_12(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SM4加密_hyperchian_enc_1()
	}
}

func BenchmarkED25519签名_golang_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ED25519签名_golang_sign_1()
	}
}

func BenchmarkED25519验签_golang_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ED25519验签_golang_verify_1()
	}
}

func BenchmarkP256k1签名_hyperchain_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256k1签名_hyperchain_sign_1()
	}
}

func BenchmarkP256k1签名_btcsuite_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256k1签名_btcsuite_sign_1()
	}
}

func BenchmarkP256k1验签_hyperchain_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256k1验签_hyperchain_verify_1()
	}
}

func BenchmarkP256k1验签_btcsuite_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256k1验签_btcsuite_verify_1()
	}
}

func BenchmarkP256r1签名_hyperchain_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256r1签名_golang_sign_1()
	}
}

func BenchmarkP256r1验签_hyperchain_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		P256r1验签_golang_verify_1()
	}
}

func BenchmarkEd25519签名Witness_hyperchain_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519签名Witness_hyperchain_sign_1()
	}
}

func BenchmarkEd25519验签Part_hyperchain_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519验签Part_hyperchain_verify_1()
	}
}

func BenchmarkEd25519签名Leader_hyperchain_sign_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519签名Leader_hyperchain_sign_1()
	}
}

func BenchmarkEd25519验签Agg_hyperchain_verify_1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519验签Agg_hyperchain_verify_1()
	}
}

func BenchmarkEd25519签名batch64_hyperchain_sign_64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519签名batch64_hyperchain_sign_64()
	}
}

func BenchmarkEd25519验签batch64_hyperchain_verify_64(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519验签batch64_hyperchain_verify_64()
	}
}

func BenchmarkEd25519签名batch1024_hyperchain_sign_1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519签名batch1024_hyperchain_sign_1024()
	}
}

func BenchmarkEd25519验签batch1024_hyperchain_verify_1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Ed25519验签batch1024_hyperchain_verify_1024()
	}
}
