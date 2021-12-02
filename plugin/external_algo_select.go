package plugin

import (
	"github.com/meshplus/crypto"
)

//FakeHash,SHA1,SM3,Sm3WithPublicKey, {SHA2,SHA3,KECCAK}X{Size224,Size256,Size384,Size512},total=16
var hashAlgoAll = []int{crypto.FakeHash, crypto.SHA1, crypto.SM3, crypto.Sm3WithPublicKey,
	crypto.SHA2_224, crypto.SHA2_256, crypto.SHA2_384, crypto.SHA2_512,
	crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	crypto.KECCAK_224, crypto.KECCAK_256, crypto.KECCAK_384, crypto.KECCAK_512}

//{AES, 3DES}X{CBC, ECB, GCM}, SM2_CBC, total=7
var symAlgoAll = []int{crypto.Aes | crypto.CBC, crypto.Aes | crypto.ECB, crypto.Aes | crypto.GCM,
	crypto.Des3 | crypto.CBC, crypto.Des3 | crypto.ECB, crypto.Des3 | crypto.GCM,
	crypto.Sm4 | crypto.CBC}

//Sm2p256v1, Secp256k1, Secp256r1, Secp256k1Recover, Secp384r1, Secp521r1, total=6
var asymAlgoAll = []int{crypto.Sm2p256v1, crypto.Secp256k1, crypto.Secp256r1,
	crypto.Secp256k1Recover, crypto.Secp384r1, crypto.Secp521r1,
	crypto.Rsa2048, crypto.Rsa3072, crypto.Rsa4096}

func getKey(function Function, mode int) uint64 {
	return uint64(function)<<32 | uint64(mode)
}
func getModeFromKey(k uint64) int {
	return int(k & 0x00000000ffffffff)
}

func copySlice(in []int) []int {
	ret := make([]int, 0, len(in))
	copy(ret, in)
	return ret
}
