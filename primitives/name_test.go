package primitives

import (
	"github.com/meshplus/crypto"
	"github.com/meshplus/flato-msp-cert/plugin"
	"github.com/meshplus/flato-msp-cert/primitives/x509"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func getEngine(t *testing.T) crypto.Engine {
	return plugin.GetSoftwareEngine("")
}


func TestIdentityName_String(t *testing.T) {
	idName := IdentityName{"Hyperchain", "www.hyperchan.cn", "ecert", "fd26a860237b461d1baec332"}
	assert.Equal(t, "GN=ecert,O=Hyperchain,CN=www.hyperchan.cn,SERIALNUMBER=fd26a860237b461d1baec332", idName.String())
}

func TestGetIdentityNameFromString(t *testing.T) {
	idName := "GN=ecert,O=Hyperchain,CN=www.hyperchan.cn,SERIALNUMBER=fd26a860237b461d1baec332"
	assert.Equal(t, &IdentityName{"Hyperchain", "www.hyperchan.cn", "ecert", "fd26a860237b461d1baec332"}, GetIdentityNameFromString(idName))
}

func TestGetIdentityNameFromPKIXName(t *testing.T) {
	engine := getEngine(t)
	certificate, _, err := NewSelfSignedCert(engine, "Hyperchain", "www.hyperchan.cn", "ecert", x509.CurveTypeP256, time.Now(),
		time.Now().Add(time.Hour))
	assert.Nil(t, err)
	cert, err := ParseCertificate(engine, certificate)
	assert.Nil(t, err)
	idName := GetIdentityNameFromPKIXName(cert.Issuer)
	assert.Equal(t, &IdentityName{O: "Hyperchain", CN: "www.hyperchan.cn", GN: "ecert", SerialNumber: ""}, idName)
}

//todo 下面注释代码移到msp包
//func TestGetIdentityNameFromIdentity(t *testing.T) {
//	db := mock.NewMockFlatoDB()
//	im, err := NewIdentityManager(config.MSPConfigMock, logger.MSPLoggerSingleCase, db)
//	assert.Nil(t, err)
//	cert, _, err := NewSelfSignedCert("flato", "hyperchain.cn", "ecert", x509.CurveTypeP256, time.Now(),
//		time.Now().Add(time.Hour))
//	assert.Nil(t, err)
//
//	peerEIdentity, err := im.NewIdentity(cert, nil, false)
//	if err != nil {
//		t.Error(err)
//	}
//	peerSDKIdentity, err := im.NewIdentity([]byte(sdkcert), nil, false)
//	if err != nil {
//		t.Error(err)
//	}
//	assert.Equal(t, "GN=ecert,O=flato,CN=hyperchain.cn,", getIdentityNameFromIdentity(peerEIdentity).String())
//	assert.Equal(t, "GN=ecert,O=hyperchain,CN=node1,", getIdentityNameFromIdentity(peerSDKIdentity).String())
//	developCert, _, err := NewSelfSignedCert("flato", "hyperchain.cn", "", x509.CurveTypeP256, time.Now(),
//		time.Now().Add(time.Hour))
//	if err != nil {
//		t.Error(err)
//	}
//	developIdentity, err := im.NewIdentity(developCert, nil, false)
//	if err != nil {
//		t.Error(err)
//	}
//	getIdentityNameFromIdentity(developIdentity)
//}
