package primitives

import (
	"fmt"
	"github.com/meshplus/flato-msp-cert/plugin"
)

func ExamplePEM2DER() {
	input := `-----BEGIN EC PRIVATE KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEo51rGof4xs+iDgFHrCxLJskSxoT2+69f
12zvlF2z2qR8MquUs5bpTCD0y/WT9+I+bOxEB+5/Amjf7zAG1mplOA==
-----END EC PRIVATE KEY-----` //secp256k1
	engine := plugin.GetCryptoEngine()
	raw, head := PEM2DER([]byte(input))
	if head != PEMECCPrivateKey {
		panic(head)
	}
	pk, uerr := UnmarshalPublicKey(engine, raw)
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
