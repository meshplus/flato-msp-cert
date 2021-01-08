flato-msp-cert
=========

>  Implementation of certificate operations.

## Table of Contents

- [Usage](#usage)
- [API](#api)
- [Mockgen](#mockgen)
- [GitCZ](#gitcz)
- [Contribute](#contribute)
- [License](#license)

## Mockgen

Install **mockgen** : `go get github.com/golang/mock/mockgen`

How to use?

- source： Specify interface file
- destination: Generated file name
- package:The package name of the generated file
- imports: Dependent package that requires import
- aux_files: Attach a file when there is more than one file in the interface file
- build_flags: Parameters passed to the build tool

Eg.`mockgen -destination mock/mock_crypto.go -package crypto -source crypto.go`

## GitCZ

**Note**: Please use command `npm install` if you are the first time to use `git cz` in this repo.

## api
### parse key
```
//ParseSMPrivateKey Parse guomi private key, support gmssl private key and cfca private key
// return the gmx509.PrivateKey type.
// first try to resolve to the private key of type gmssl.
// if it fails, try to resolve to the private key of cfca.
func ParseSMPrivateKey(der []byte) (interface{}, error) 
```
### generate cert
```
//GenCert generate ecert
func GenCert(ca *gmx509.Certificate, privatekey interface{}, publicKey interface{},
	o, cn, gn string, isCA bool) ([]byte, error) 
```
### generate root cert
```
//NewSelfSignedCert generate self-signature certificate
func NewSelfSignedCert(o, cn, gn string, useGuomi bool) (
	[]byte, interface{}, error) 
```

## Contribute

PRs are welcome!

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

LGPL © flato
