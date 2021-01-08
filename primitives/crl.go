package primitives

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"fmt"
	gmx509 "github.com/meshplus/flato-msp-cert/primitives/x509"
	"io/ioutil"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//CFCA mode
const (
	CFCAModeNone = "none"
	CFCAModeRA   = "ra"
	CFCAModeCRL  = "crl"
)

//ra response status
const (
	RACertStatusNotDownloaded = 3 + iota
	RACertStatusValid
	RACertStatusFrozen
	RACertStatusRevoked
)

//error content
const (
	ERRUnknownStatus = "unknown certificate status"
	ERRNotDownload   = "certificate not downloaded"
	ERRRevoked       = "certificate has been revoked"
	ERRFrozen        = "the certificate has been frozen"
	ERRNotExit       = "certificate does not exist"
)

//CRL CRL is a Thread-safe certificate revocation list
type CRL struct {
	url   string
	crl   *pkix.CertificateList
	mutex *sync.RWMutex
}

//NewCRL create a crl Instance
func NewCRL(url string, quit <-chan bool) (*CRL, error) {
	result := &CRL{
		url:   url,
		mutex: new(sync.RWMutex),
	}
	if err := result.update(); err != nil {
		return nil, err
	}
	go func() {
		for {
			now := time.Now()
			next := now.Add(time.Hour * 24)
			next = time.Date(next.Year(), next.Month(), next.Day(), 8, 0, rand.Intn(60), 0, next.Location())
			t := time.NewTimer(next.Sub(now))
			select {
			case <-t.C:
				err := result.update()
				if err != nil {
					continue
				}
			case <-quit:
				return
			}
		}
	}()
	return result, nil
}

//CheckRevocation Verify that the certificate has been revoked
func (c *CRL) CheckRevocation(cert *gmx509.Certificate) (bool, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return CheckRevocationWithCRL(cert, c.crl)
}

func (c *CRL) update() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	newCRL, err := FetchCRL(c.url)
	if err != nil {
		return err
	}
	c.crl = newCRL
	return nil
}

// FetchCRL fetch CRL with a HTTP GET request to a given URL
// returns a reference to a pkix.CertificateList instance
func FetchCRL(url string) (cl *pkix.CertificateList, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch CRL,the status code is %v", resp.StatusCode)
	}

	crl, err := ioutil.ReadAll(resp.Body)
	defer func() {
		err = resp.Body.Close()
	}()
	if err != nil {
		return nil, err
	}

	return x509.ParseDERCRL(crl)
}

//CheckRevocationWithCRL CheckRevocation verifies if a given certificate is revoked in
// reference to current CRL
func CheckRevocationWithCRL(cert *gmx509.Certificate, crl *pkix.CertificateList) (bool, error) {
	if cert == nil {
		return false, errors.New("invalid cert")
	}
	if crl == nil {
		return false, errors.New("invalid crl")
	}

	for _, i := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(i.SerialNumber) == 0 {
			return true, nil
		}
	}
	return false, nil
}

// CheckRevocation verifies if a given certificate is revoked via
// its CRL distribution point
func CheckRevocation(cert *gmx509.Certificate) (bool, error) {
	for _, url := range cert.CRLDistributionPoints {
		crl, err := FetchCRL(url)
		if err != nil {
			continue
		} else {
			revoked, err := CheckRevocationWithCRL(cert, crl)
			if err != nil {
				return false, err
			}
			return revoked, nil
		}
	}
	return false, errors.New("failed to check revocation state")
}

//CheckRevocationWithURL check revocation from specific url
func CheckRevocationWithURL(cert *gmx509.Certificate, url string) (bool, error) {
	crl, err := FetchCRL(url)
	if err != nil {
		return false, err
	}
	return CheckRevocationWithCRL(cert, crl)
}

//CheckRevocationWithRA check revocation from ra
func CheckRevocationWithRA(cert *gmx509.Certificate, url string) (bool, error) {
	return verifyWithRA(getDN(cert), url)
}

func verifyWithRA(DN string, url string) (b bool, err error) {
	request := `
<Request>
<Head>
<TxCode>7102</TxCode>
<Remark/>
<Locale/>
</Head>
<Body>
<SerialNo/>
<Dn>%s</Dn>
</Body>
</Request>
`
	type RPbody struct {
		Dn           string `xml:"Dn"`
		SequenceNo   string `xml:"SequenceNo"`
		SerialNo     string `xml:"SerialNo"`
		CertStatus   string `xml:"CertStatus"`
		Duration     string `xml:"Duration"`
		ApplyTime    string `xml:"ApplyTime"`
		SendcodeTime string `xml:"SendcodeTime"`
		StartTime    string `xml:"StartTime"`
		EndTime      string `xml:"EndTime"`
		BranchCode   string `xml:"BranchCode"`
		KeyAlg       string `xml:"keyAlg"`
		KeyLength    string `xml:"KeyLength"`
		DomainName   string `xml:"DomainName"`
		Email        string `xml:"Email"`
	}
	type RPhead struct {
		TxCode        string `xml:"TxCode"`
		TxTime        string `xml:"TxTime"`
		ResultCode    string `xml:"ResultCode"`
		ResultMessage string `xml:"ResultMessage"`
	}
	var RP struct {
		Head RPhead `xml:"Head"`
		Body RPbody `xml:"Body"`
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", url,
		strings.NewReader(fmt.Sprintf(request, DN)))
	if err != nil {
		return false, err
	}
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "CFCARAClient 3.5")
	req.Header.Add("Accept", "test/xml")
	req.Header.Add("Content-Type", "text/xml")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Del("Accept-Encoding")

	resp, derr := client.Do(req)
	if derr != nil {
		return false, fmt.Errorf("request ra web error:%v, url:%v ", derr.Error(), url)
	}
	defer func() {
		err = resp.Body.Close()
	}()

	body, rerr := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, rerr
	}
	if xml.Unmarshal(body, &RP) != nil {
		return false, err
	}

	if RP.Head.ResultCode == "0000" {
		temp, err := strconv.Atoi(RP.Body.CertStatus)
		if err != nil {
			return false, errors.New(ERRUnknownStatus)
		}
		switch temp {
		case RACertStatusNotDownloaded:
			return false, errors.New(ERRNotDownload)
		case RACertStatusRevoked:
			return false, errors.New(ERRRevoked)
		case RACertStatusFrozen:
			return false, errors.New(ERRFrozen)
		case RACertStatusValid:
			return true, nil
		default:
			return false, errors.New(ERRUnknownStatus)
		}
	} else if RP.Head.ResultMessage == "证书不存在" {
		return false, errors.New(ERRNotExit)
	}

	return false, errors.New(ERRUnknownStatus)
}

//CN=051@hyperchain@Zclientname@10,OU=Individual-2,OU=Local RA,O=CFCA TEST CA,C=CN
func getDN(cert *gmx509.Certificate) string {
	start := "CN=" + cert.Subject.CommonName + ","

	ou := make([]string, len(cert.Subject.OrganizationalUnit))
	for i := range cert.Subject.OrganizationalUnit {
		ou[i] = "OU=" + cert.Subject.OrganizationalUnit[i] + ","
	}
	sort.Strings(ou)
	if len(ou) != 0 {
		start += strings.Join(ou, "")
	}

	o := make([]string, len(cert.Subject.Organization))
	for i := range cert.Subject.Organization {
		o[i] = "O=" + cert.Subject.Organization[i] + ","
	}
	sort.Strings(o)
	if len(o) != 0 {
		start += strings.Join(o, "")
	}

	c := make([]string, len(cert.Subject.Country))
	for i := range cert.Subject.Country {
		c[i] = "C=" + cert.Subject.Country[i] + ","
	}
	sort.Strings(c)
	if len(c) != 0 {
		start += strings.Join(c, "")
	}

	return strings.Trim(start, ",")
}
