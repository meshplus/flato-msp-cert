package plugin

import (
	"crypto/elliptic"
	"reflect"
	"strconv"
	"testing"

	"github.com/meshplus/crypto"
	gm "github.com/meshplus/crypto-gm"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
)

func TestModeFromCurve(t *testing.T) {
	type args struct {
		curve elliptic.Curve
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{name: "sm2", args: args{curve: gm.GetSm2Curve()}, want: crypto.Sm2p256v1},
		{name: "r1", args: args{curve: elliptic.P256()}, want: crypto.Secp256r1},
		{name: "k1", args: args{curve: secp256k1.S256()}, want: crypto.Secp256k1},
		{name: "384", args: args{curve: elliptic.P384()}, want: crypto.Secp384r1},
		{name: "521", args: args{curve: elliptic.P521()}, want: crypto.Secp521r1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ModeFromCurve(tt.args.curve); got != tt.want {
				t.Errorf("ModeFromCurve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModeFromRSAMod(t *testing.T) {
	tests := []struct {
		rsaMod  int
		want    int
		wantErr bool
	}{
		{rsaMod: 53, want: crypto.Rsa2048, wantErr: false},
		{rsaMod: 1029, want: crypto.Rsa2048, wantErr: false},
		{rsaMod: 3000, want: crypto.Rsa3072, wantErr: false},
		{rsaMod: 4000, want: crypto.Rsa4096, wantErr: false},
		{rsaMod: 5000, want: 0x1300, wantErr: false},
		{rsaMod: 7000, want: 0x1500, wantErr: false},
		{rsaMod: 15361, want: 0x1e00, wantErr: false},
		{rsaMod: 160000, want: crypto.None, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.rsaMod), func(t *testing.T) {
			got, err := ModeFromRSAMod(tt.rsaMod)
			if (err != nil) != tt.wantErr {
				t.Errorf("ModeFromRSAMod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ModeFromRSAMod() got = 0x%x, want 0x%x", got, tt.want)
			}
		})
	}
}

func TestModeGetCurve(t *testing.T) {
	type args struct {
		mode int
	}
	tests := []struct {
		name    string
		args    args
		want    elliptic.Curve
		wantErr bool
	}{
		{name: "sm2", args: args{mode: crypto.Sm2p256v1}, want: gm.GetSm2Curve(), wantErr: false},
		{name: "k1", args: args{mode: crypto.Secp256k1}, want: secp256k1.S256(), wantErr: false},
		{name: "r1", args: args{mode: crypto.Secp256r1}, want: elliptic.P256(), wantErr: false},
		{name: "384", args: args{mode: crypto.Secp384r1}, want: elliptic.P384(), wantErr: false},
		{name: "521", args: args{mode: crypto.Secp521r1}, want: elliptic.P521(), wantErr: false},
		{name: "err", args: args{mode: crypto.Rsa4096}, want: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ModeGetCurve(tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ModeGetCurve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ModeGetCurve() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModeGetRSAMod(t *testing.T) {
	type args struct {
		mode int
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{name: "2048", args: args{mode: crypto.Rsa2048}, want: 2048, wantErr: false},
		{name: "3072", args: args{mode: crypto.Rsa3072}, want: 3072, wantErr: false},
		{name: "4096", args: args{mode: crypto.Rsa4096}, want: 4096, wantErr: false},
		{name: "err", args: args{mode: crypto.Secp256k1Recover}, want: 0, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ModeGetRSAMod(tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ModeGetRSAMod() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ModeGetRSAMod() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModeIsEncryptAlgo(t *testing.T) {
	type args struct {
		mode int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "sm4 with cbc", args: args{mode: crypto.Sm4 | crypto.CBC}, want: true},
		{name: "aes with cbc", args: args{mode: crypto.Aes | crypto.CBC}, want: true},
		{name: "aes with gcm", args: args{mode: crypto.Aes | crypto.GCM}, want: true},
		{name: "3DES", args: args{mode: crypto.Des3}, want: true},
		{name: "err hash", args: args{mode: crypto.KECCAK_256 | crypto.CBC}, want: false},
		{name: "err signature", args: args{mode: crypto.Secp256k1Recover | crypto.Sm4}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ModeIsEncryptAlgo(tt.args.mode); got != tt.want {
				t.Errorf("ModeIsEncryptAlgo() = 0x%v, want %v", got, tt.want)
			}
		})
	}
}

func TestModeAssert(t *testing.T) {
	type args struct {
		mode int
	}
	tests := []struct {
		name        string
		args        args
		iSHash      bool
		isSignature bool
		isECDSA     bool
		isRSA       bool
	}{
		{name: "sha3", args: args{mode: crypto.SHA3}, iSHash: true},
		{name: "sha256", args: args{mode: crypto.SHA3}, iSHash: true},
		{name: "sha1", args: args{mode: crypto.SHA3}, iSHash: true},
		{name: "signature", args: args{mode: crypto.Secp384r1}, isSignature: true, isECDSA: true},
		{name: "crypto", args: args{mode: crypto.Sm4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ModeIsHashAlgo(tt.args.mode); got != tt.iSHash {
				t.Errorf("ModeIsHashAlgo() = %v", got)
			}
			if got := ModeIsSignatureAlgo(tt.args.mode); got != tt.isSignature {
				t.Errorf("ModeIsSignatureAlgo() = %v", got)
			}
			if got := ModeIsRSAAlgo(tt.args.mode); got != tt.isRSA {
				t.Errorf("ModeIsRSAAlgo() = %v", got)
			}
			if got := ModeIsECDSAAlgo(tt.args.mode); got != tt.isECDSA {
				t.Errorf("ModeIsECDSAAlgo() = %v", got)
			}
		})
	}
}
