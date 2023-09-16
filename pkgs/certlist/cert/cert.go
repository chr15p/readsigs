package cert

import (
    "os"
    "fmt"

    "crypto/x509"
)

type Cert struct {
    Filename string
    Cert []byte
    ParsedCert *x509.Certificate    
}

func NewCertFromFile(filename string) (*Cert, error) {
	buffer, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to read cert %s: %s\n", filename, err)
	}
    c, err := NewCertFromBuffer(filename, buffer) 
	if err != nil {
        return nil, err
    }

    return c, nil
}


func NewCertFromBuffer(filename string, buffer []byte) (*Cert, error) {
	pubCert, err := x509.ParseCertificate(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate %s\n", err)
	}

    c := Cert{
        Filename: filename,
        Cert: buffer,
        ParsedCert: pubCert,
    }
    return &c, nil
}

func (c *Cert) GetRawCert() []byte {
    return c.Cert
}

func (c *Cert) GetParsedCert() *x509.Certificate {
    return c.ParsedCert
}

/*
func (c *cert) checkSig(buffer []byte) (bool, error) {

}


func checkSig(buffer []byte, cert []byte) (bool, error) {

	hash := sha256.Sum256(buffer)

	pubCert, err := x509.ParseCertificate(cert)
	if err != nil {
		fmt.Printf("invalid public key %s\n", err)
		return false, fmt.Errorf("invalid public key %s\n", err)
	}

	pubKey := pubCert.PublicKey.(*rsa.PublicKey)
	if err != nil {
		fmt.Printf("invalid public key %s\n", err)
		return false, fmt.Errorf("invalid public key %s\n", err)
	}

	sigDigest, err := s.getDigest()
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], *sigDigest)
	if err != nil {
		fmt.Printf("  signature not verified\n")
		return false, nil
	}


	fmt.Printf("  signature verified\n\tsubject: %s\n\tserial: %s\n", pubCert.Subject.ToRDNSequence(), pubCert.SerialNumber)

	return true, nil
}
*/
