# Change Log

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

<a name="0.1.0"></a>
# 0.1.0 (2021-01-12)


### Features

* **init:** init ([c467e70](http://git.hyperchain.cn/meshplus/crypto/commits/c467e70))



<a name="0.1.9-1"></a>
## [0.1.9-1](http://git.hyperchain.cn/meshplus/crypto/compare/v0.1.1...v0.1.9-1) (2020-12-28)


### Bug Fixes

* **cert_util.go:** pre version cannot generate secp256k1 certificate ([856022c](http://git.hyperchain.cn/meshplus/crypto/commits/856022c))
* **ci:** port ([d27ab91](http://git.hyperchain.cn/meshplus/crypto/commits/d27ab91))
* **pem.go:** pemTypeCertificate ([b12183e](http://git.hyperchain.cn/meshplus/crypto/commits/b12183e))
* **primitives/crl_test:** fix some error in golint ([e4029de](http://git.hyperchain.cn/meshplus/crypto/commits/e4029de))
* **primitives/crl_test:** use local crl server to get certificateList ([2195111](http://git.hyperchain.cn/meshplus/crypto/commits/2195111))
* **sm2:** fix some bug with new gm.sm2PrivateKey ([d803159](http://git.hyperchain.cn/meshplus/crypto/commits/d803159))
* **test:** fix some golint error in test function ([9252bf7](http://git.hyperchain.cn/meshplus/crypto/commits/9252bf7))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([4101848](http://git.hyperchain.cn/meshplus/crypto/commits/4101848))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([c9a233f](http://git.hyperchain.cn/meshplus/crypto/commits/c9a233f))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([53a9f48](http://git.hyperchain.cn/meshplus/crypto/commits/53a9f48))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([7bb7ce1](http://git.hyperchain.cn/meshplus/crypto/commits/7bb7ce1))
* **x509/sm2:** repalce x509.PrivateKey with crypto-gm.SM2PrivateKey ([a3a14a5](http://git.hyperchain.cn/meshplus/crypto/commits/a3a14a5))


### Features

* **all:** all ([1f57455](http://git.hyperchain.cn/meshplus/crypto/commits/1f57455))
* **all:** package ([cb70040](http://git.hyperchain.cn/meshplus/crypto/commits/cb70040))
* **all:** remove ecdsa ([948df9e](http://git.hyperchain.cn/meshplus/crypto/commits/948df9e))
* **all:** remove ecdsa` ([6fe4b89](http://git.hyperchain.cn/meshplus/crypto/commits/6fe4b89))
* **all:** remove_ecdsa_package ([8fcd93d](http://git.hyperchain.cn/meshplus/crypto/commits/8fcd93d))
* **cert:** #flato-2355, cert time limit ([b6e79f6](http://git.hyperchain.cn/meshplus/crypto/commits/b6e79f6)), closes [#flato-2355](http://git.hyperchain.cn/meshplus/crypto/issues/flato-2355)
* **cert_keyid:** set sha1 value as keyid ([90415f8](http://git.hyperchain.cn/meshplus/crypto/commits/90415f8))
* **cert_type.go:** #flato-2517, add idcert ([e8d0187](http://git.hyperchain.cn/meshplus/crypto/commits/e8d0187)), closes [#flato-2517](http://git.hyperchain.cn/meshplus/crypto/issues/flato-2517)
* **cert_util:** add TestSM2Verify ([3898c5a](http://git.hyperchain.cn/meshplus/crypto/commits/3898c5a))
* **ci:** fix ci ([2f56565](http://git.hyperchain.cn/meshplus/crypto/commits/2f56565))
* **crl:** add crl and delete gitlib-ci.yml ([f848878](http://git.hyperchain.cn/meshplus/crypto/commits/f848878))
* **crl:** test for darwin ([e6b6277](http://git.hyperchain.cn/meshplus/crypto/commits/e6b6277))
* **feat:** add gmssl certificate verify ([6f26871](http://git.hyperchain.cn/meshplus/crypto/commits/6f26871))
* **feat:** add self signed cert from private and public key ([a95d55f](http://git.hyperchain.cn/meshplus/crypto/commits/a95d55f))
* **genCA:** isCA = true ([cdda80c](http://git.hyperchain.cn/meshplus/crypto/commits/cdda80c))
* **go.mod:** go.mod ([4118334](http://git.hyperchain.cn/meshplus/crypto/commits/4118334))
* **go.mod:** update crypto version ([6566ae4](http://git.hyperchain.cn/meshplus/crypto/commits/6566ae4))
* **go.mod:** update version ([cb9f3bf](http://git.hyperchain.cn/meshplus/crypto/commits/cb9f3bf))
* **pem.go:** encryption pem ([b424a63](http://git.hyperchain.cn/meshplus/crypto/commits/b424a63))
* **private:** fix internal ([af803e8](http://git.hyperchain.cn/meshplus/crypto/commits/af803e8))
* **ra:** fix ra ([d1ef560](http://git.hyperchain.cn/meshplus/crypto/commits/d1ef560))
* **sonar:** add sonar-project.properties ([3ffd07c](http://git.hyperchain.cn/meshplus/crypto/commits/3ffd07c))
* **test:** random net port for test ([eca4a46](http://git.hyperchain.cn/meshplus/crypto/commits/eca4a46))
* **tls:** add function LoadX509KeyPairs ([0e01f4f](http://git.hyperchain.cn/meshplus/crypto/commits/0e01f4f))
* **tls:** gmtls go ([8d8a217](http://git.hyperchain.cn/meshplus/crypto/commits/8d8a217))
* **tsc:** tsc arm ([8362eda](http://git.hyperchain.cn/meshplus/crypto/commits/8362eda))
* **x509:** fix ISK and IAK ([755fe00](http://git.hyperchain.cn/meshplus/crypto/commits/755fe00))



<a name="0.1.9"></a>
## [0.1.9](http://git.hyperchain.cn/meshplus/crypto/compare/v0.1.1...v0.1.9) (2020-12-28)


### Bug Fixes

* **cert_util.go:** pre version cannot generate secp256k1 certificate ([856022c](http://git.hyperchain.cn/meshplus/crypto/commits/856022c))
* **ci:** port ([d27ab91](http://git.hyperchain.cn/meshplus/crypto/commits/d27ab91))
* **pem.go:** pemTypeCertificate ([b12183e](http://git.hyperchain.cn/meshplus/crypto/commits/b12183e))
* **primitives/crl_test:** fix some error in golint ([e4029de](http://git.hyperchain.cn/meshplus/crypto/commits/e4029de))
* **primitives/crl_test:** use local crl server to get certificateList ([2195111](http://git.hyperchain.cn/meshplus/crypto/commits/2195111))
* **sm2:** fix some bug with new gm.sm2PrivateKey ([d803159](http://git.hyperchain.cn/meshplus/crypto/commits/d803159))
* **test:** fix some golint error in test function ([9252bf7](http://git.hyperchain.cn/meshplus/crypto/commits/9252bf7))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([4101848](http://git.hyperchain.cn/meshplus/crypto/commits/4101848))
* **tls:** change verifyHostname using www.baidu.com to localhost, fix some mistake in primitive ([c9a233f](http://git.hyperchain.cn/meshplus/crypto/commits/c9a233f))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([53a9f48](http://git.hyperchain.cn/meshplus/crypto/commits/53a9f48))
* **tls:** fix some test in primitives, add test function about secp256k1 and sm2 in tls ([7bb7ce1](http://git.hyperchain.cn/meshplus/crypto/commits/7bb7ce1))
* **x509/sm2:** repalce x509.PrivateKey with crypto-gm.SM2PrivateKey ([a3a14a5](http://git.hyperchain.cn/meshplus/crypto/commits/a3a14a5))


### Features

* **all:** all ([1f57455](http://git.hyperchain.cn/meshplus/crypto/commits/1f57455))
* **all:** package ([cb70040](http://git.hyperchain.cn/meshplus/crypto/commits/cb70040))
* **all:** remove ecdsa ([948df9e](http://git.hyperchain.cn/meshplus/crypto/commits/948df9e))
* **all:** remove ecdsa` ([6fe4b89](http://git.hyperchain.cn/meshplus/crypto/commits/6fe4b89))
* **all:** remove_ecdsa_package ([8fcd93d](http://git.hyperchain.cn/meshplus/crypto/commits/8fcd93d))
* **cert:** #flato-2355, cert time limit ([b6e79f6](http://git.hyperchain.cn/meshplus/crypto/commits/b6e79f6)), closes [#flato-2355](http://git.hyperchain.cn/meshplus/crypto/issues/flato-2355)
* **cert_keyid:** set sha1 value as keyid ([90415f8](http://git.hyperchain.cn/meshplus/crypto/commits/90415f8))
* **cert_type.go:** #flato-2517, add idcert ([e8d0187](http://git.hyperchain.cn/meshplus/crypto/commits/e8d0187)), closes [#flato-2517](http://git.hyperchain.cn/meshplus/crypto/issues/flato-2517)
* **cert_util:** add TestSM2Verify ([3898c5a](http://git.hyperchain.cn/meshplus/crypto/commits/3898c5a))
* **ci:** fix ci ([2f56565](http://git.hyperchain.cn/meshplus/crypto/commits/2f56565))
* **crl:** add crl and delete gitlib-ci.yml ([f848878](http://git.hyperchain.cn/meshplus/crypto/commits/f848878))
* **crl:** test for darwin ([e6b6277](http://git.hyperchain.cn/meshplus/crypto/commits/e6b6277))
* **feat:** add gmssl certificate verify ([6f26871](http://git.hyperchain.cn/meshplus/crypto/commits/6f26871))
* **feat:** add self signed cert from private and public key ([a95d55f](http://git.hyperchain.cn/meshplus/crypto/commits/a95d55f))
* **genCA:** isCA = true ([cdda80c](http://git.hyperchain.cn/meshplus/crypto/commits/cdda80c))
* **go.mod:** go.mod ([4118334](http://git.hyperchain.cn/meshplus/crypto/commits/4118334))
* **go.mod:** update crypto version ([6566ae4](http://git.hyperchain.cn/meshplus/crypto/commits/6566ae4))
* **go.mod:** update version ([cb9f3bf](http://git.hyperchain.cn/meshplus/crypto/commits/cb9f3bf))
* **pem.go:** encryption pem ([b424a63](http://git.hyperchain.cn/meshplus/crypto/commits/b424a63))
* **private:** fix internal ([af803e8](http://git.hyperchain.cn/meshplus/crypto/commits/af803e8))
* **ra:** fix ra ([d1ef560](http://git.hyperchain.cn/meshplus/crypto/commits/d1ef560))
* **sonar:** add sonar-project.properties ([3ffd07c](http://git.hyperchain.cn/meshplus/crypto/commits/3ffd07c))
* **test:** random net port for test ([eca4a46](http://git.hyperchain.cn/meshplus/crypto/commits/eca4a46))
* **tls:** add function LoadX509KeyPairs ([0e01f4f](http://git.hyperchain.cn/meshplus/crypto/commits/0e01f4f))
* **tls:** gmtls go ([8d8a217](http://git.hyperchain.cn/meshplus/crypto/commits/8d8a217))
* **tsc:** tsc arm ([8362eda](http://git.hyperchain.cn/meshplus/crypto/commits/8362eda))
* **x509:** fix ISK and IAK ([755fe00](http://git.hyperchain.cn/meshplus/crypto/commits/755fe00))



# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

### [0.1.1](///compare/v0.1.0...v0.1.1) (2019-12-21)


### Features

* **key:** #flato-955, add rand reader ([62391ef](///commit/62391ef4b913306ddb36994fdbe111cf5bd1b6dd)), closes [#flato-955](///issues/flato-955)
* **README.md:** modify README.md ([e93dd31](///commit/e93dd31ab108a20a17b43185871e0de5e4610c5c))
* **test:** remove failpoint ([b68f987](///commit/b68f9879da9e78aa1d54913d9160a4317ef5576d))
* **tests:** increase test coverage ([71cab60](///commit/71cab60c1eb00dc9fd996130c7bba793bdf04f02))


### Bug Fixes

* **script,go.mod:** change script and go.mod ([6a827d3](///commit/6a827d3ddb439d1619cb7ae1901fcf8f522efde2))

## 0.1.0 (2019-08-23)


### Bug Fixes

* **all:** update goalngci-lint ([edb6770](///commit/edb6770))
* **log.go:** log ([26efce7](///commit/26efce7))
* **log.go:** log ([a09d987](///commit/a09d987))
* **script,go.mod:** change script and go.mod ([6a827d3](///commit/6a827d3))
* pfx ([2f80394](///commit/2f80394))


### Features

* **camanager:** first init msp cert repo ([bf5981e](///commit/bf5981e))
* **cert_util.go:** change function para type ([de35999](///commit/de35999))
* **generateCert:** add cert generation ([6acd3b7](///commit/6acd3b7))
* **log:** add log ([aadee85](///commit/aadee85))
* **pre-commit:** add pre-commit ([2bc18ed](///commit/2bc18ed))
* **primitives:** init ([9502f20](///commit/9502f20))
* **primitives:** init ([1a26f9b](///commit/1a26f9b))
* **test:** add tests of primitives ([290ea39](///commit/290ea39))
* **test:** remove failpoint ([b68f987](///commit/b68f987))
* **tests:** add tests of primitives ([1422226](///commit/1422226))
* **tests:** increase test coverage ([71cab60](///commit/71cab60))
* **tls:** add guomi tls, not finish ([d46a18b](///commit/d46a18b))
* **tls:** add https unit test ([f3755e9](///commit/f3755e9))
* **tls:** add https_test ([ee04490](///commit/ee04490))
* **tls:** add tls ([7013ebf](///commit/7013ebf))
* **tls:** tls ([674d2b8](///commit/674d2b8))
* **tls:** tls ([dea5258](///commit/dea5258))
* **tls:** tls support guomi ([ad14f1a](///commit/ad14f1a))
* **vendor:** add go mod and delete vendor ([7d031d0](///commit/7d031d0))
* **vendor:** fix verndor golang_.org ([201caa4](///commit/201caa4))
* **verndor/golang.org/x/sys:** add verndor ([462cedb](///commit/462cedb))
* **x509:** ci ([a9cd659](///commit/a9cd659))
