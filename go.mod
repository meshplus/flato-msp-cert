module github.com/meshplus/flato-msp-cert

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/meshplus/crypto v0.0.8
	github.com/meshplus/crypto-gm v0.1.1
	github.com/meshplus/crypto-standard v0.1.2
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

go 1.15

replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20190911031432-227b76d455e7
