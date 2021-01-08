package x509

import "encoding/asn1"

// RFC 3279, 2.3 Public Key Algorithms
//
// pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
// id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//    x9-57(10040) x9cm(4) 1 }
//
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
// id-ecPublicKey OBJECT IDENTIFIER ::= {
//       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPublicKeySM2   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
	switch {
	case oid.Equal(oidPublicKeyRSA):
		return RSA
	case oid.Equal(oidPublicKeyDSA):
		return DSA
	case oid.Equal(oidPublicKeyECDSA):
		return ECDSA
		//case oid.Equal(oidPublicKeySM2):
		//	return SM2
	}
	return UnknownPublicKeyAlgorithm
}
