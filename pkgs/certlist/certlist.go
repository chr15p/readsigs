package certlist

import (
    "crypto/x509"
)

type X509Cert interface {
    GetRawCert() []byte
    GetParsedCert() *x509.Certificate
}

type Certlist struct{
    List []X509Cert
}

func (c *Certlist) AddCert(newCert X509Cert){
    c.List = append(c.List, newCert)
}

