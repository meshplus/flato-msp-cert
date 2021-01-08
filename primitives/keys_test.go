package primitives

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestMarshalPrivateKey(t *testing.T) {
	type args struct {
		privateKey interface{}
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	ecdsaKey, _ := asym.GenerateKey(asym.AlgoP256K1)
	ecdsaKey2, _ := asym.GenerateKey(asym.AlgoP256R1)
	ecdsaKey3, _ := asym.GenerateKey(asym.AlgoP384R1)
	sm2Key, _ := gm.GenerateSM2Key()

	tests := []struct {
		name string
		args args
	}{
		{"rsa", args{privateKey: rsaKey}},
		{"256", args{privateKey: ecdsaKey}},
		{"k1", args{privateKey: ecdsaKey2}},
		{"384", args{privateKey: ecdsaKey3}},
		{"sm2", args{privateKey: sm2Key}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPrivateKey(tt.args.privateKey)
			if err != nil {
				t.Errorf("MarshalPrivateKey() error = %v", err)
				return
			}
			key, err := UnmarshalPrivateKey(got)
			if err != nil {
				t.Errorf("MarshalPrivateKey() error = %v", err)
				return
			}
			if !reflect.DeepEqual(key, tt.args.privateKey) {
				t.Errorf("MarshalPrivateKey()")
			}
		})
	}
	//generate key with ecdsa.privateKey not asym.ECDSAPrivateKey
	ecdsaKey4, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := MarshalPrivateKey(ecdsaKey4)
	assert.NotNil(t, err)
	_, err = MarshalPrivateKey(ecdsaKey4.PublicKey)
	assert.NotNil(t, err)
}

func TestMarshalPublicKey(t *testing.T) {
	type args struct {
		publicKey interface{}
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	ecdsaKey, _ := asym.GenerateKey(asym.AlgoP256K1)
	ecdsaKey2, _ := asym.GenerateKey(asym.AlgoP256R1)
	ecdsaKey3, _ := asym.GenerateKey(asym.AlgoP384R1)
	//sm2Key, _ := GenerateSM2Key()

	rsaPK := rsaKey.Public()
	ecdsaPK := ecdsaKey.Public()
	ecdsaPK2 := ecdsaKey2.Public()
	ecdsaPK3 := ecdsaKey3.Public()
	//sm2PK := sm2Key.Public()

	tests := []struct {
		name string
		args args
	}{
		{"rsa", args{publicKey: rsaPK}},
		{"256", args{publicKey: ecdsaPK}},
		{"k1", args{publicKey: ecdsaPK2}},
		{"384", args{publicKey: ecdsaPK3}},
		//{"sm2", args{publicKey: sm2PK}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalPublicKey(tt.args.publicKey)
			if err != nil {
				t.Errorf("TestMarshalPublicKey() error = %v", err)
				return
			}
			key, err := UnmarshalPublicKey(got)
			if err != nil {
				t.Errorf("TestMarshalPublicKey() error = %v", err)
				return
			}
			if !reflect.DeepEqual(key, tt.args.publicKey) {
				t.Errorf("TestMarshalPublicKey()")
			}
		})
	}
}

func TestUnmarshalPrivateKey(t *testing.T) {
	type args struct {
		der []byte
	}

	certPem, _ := getConfig("./test/ecert.cert")
	ecertPem, _ := getConfig("./test/ecert.priv")
	rsaPem, _ := getConfig("./test/rsa_private_key.pem")
	rootPem, _ := getConfig("./test/root_guomi.priv")
	certDER, _ := PEM2DER(certPem)
	ecertDER, _ := PEM2DER(ecertPem)
	rsaDER, _ := PEM2DER(rsaPem)
	rootDER, _ := PEM2DER(rootPem)

	tests := []struct {
		name      string
		args      args
		wantKey   string
		wantErr   bool
		deepEqual bool
	}{
		{"256r1", args{ecertDER}, "*asym.ECDSAPrivateKey", false, true},
		{"rsa", args{rsaDER}, "*rsa.PrivateKey", false, true},
		//not deep equal, because transfer gmssl to cfca
		{"sm2", args{rootDER}, "*gm.SM2PrivateKey", false, false},
		{"cert", args{certDER}, "<nil>", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := UnmarshalPrivateKey(tt.args.der)
			if !tt.wantErr && err != nil {
				t.Error(err)
				return
			}
			if fmt.Sprintf("%T", gotKey) != tt.wantKey {
				t.Errorf("UnmarshalPrivateKey() got = %v, want %v", fmt.Sprintf("%T", gotKey), tt.wantKey)
			}

			if tt.wantErr {
				return
			}

			back, err := MarshalPrivateKey(gotKey)
			if err != nil {
				t.Error(err)
				return
			}
			if !tt.deepEqual {
				return
			}
			if !reflect.DeepEqual(tt.args.der, back) {
				t.Fail()
			}
		})
	}
}

func ExamplePEM2DER() {
	input := `-----BEGIN EC PRIVATE KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEo51rGof4xs+iDgFHrCxLJskSxoT2+69f
12zvlF2z2qR8MquUs5bpTCD0y/WT9+I+bOxEB+5/Amjf7zAG1mplOA==
-----END EC PRIVATE KEY-----` //secp256k1
	raw, head := PEM2DER([]byte(input))
	if head != PEMECCPrivateKey {
		panic(head)
	}
	pk, uerr := UnmarshalPublicKey(raw)
	if uerr != nil {
		panic(uerr)
	}

	pkDER, err := MarshalPublicKey(pk)
	if err != nil {
		panic(err)
	}
	pkPEM, err := DER2PEM(pkDER, PEMECCPrivateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pkPEM))
	//output:
	//-----BEGIN EC PRIVATE KEY-----
	//MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEo51rGof4xs+iDgFHrCxLJskSxoT2+69f
	//12zvlF2z2qR8MquUs5bpTCD0y/WT9+I+bOxEB+5/Amjf7zAG1mplOA==
	//-----END EC PRIVATE KEY-----
}
