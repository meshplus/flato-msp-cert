//+build darwin

package primitives

import "testing"

/* our ra http://114.55.107.52:8080/raWeb/CSHttpServlet
cfca crl http://ucrl.cfca.com.cn/SM2/crl2326.crl
*/

func TestRA(t *testing.T) {
	testCheckRevocationWithRA(t, "http://114.55.107.52:8080/raWeb/CSHttpServlet")
}
