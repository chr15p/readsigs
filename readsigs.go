package main

import (
	//"crypto"
	//"crypto/rsa"
	//"crypto/sha256"
	//"crypto/x509"
	//"encoding/binary"
	"flag"
	"fmt"
	//"go.mozilla.org/pkcs7"
	"os"

//    "github.com/chr15p/readsigs/pkgs/kmod"
    "github.com/chr15p/readsigs/pkgs/certlist"
    "github.com/chr15p/readsigs/pkgs/certlist/cert"
    "github.com/chr15p/readsigs/pkgs/certlist/moklist"
)

func main() {
	var kmodPath string
	var certPath string

	flag.StringVar(&kmodPath, "kmod", "", "a kernel module to anaylse")
	flag.StringVar(&certPath, "cert", "", "a certificate to validate against")

	flag.Parse()
	if kmodPath == "" || certPath == "" {
		fmt.Println("both the -kmod and -cert arguments are required")
		os.Exit(0)
	}
    fmt.Println("kmod:", kmodPath)
	fmt.Println("cert:", certPath)

	//buffer, err := os.ReadFile(kmodPath) // just pass the file name
/*
    kmod, err := kmod.GetKmod(kmodPath)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
    fmt.Printf("kmod %s has %d sigs\n", kmod.Name, kmod.SigCount)
    for i,v := range kmod.Signatures {
        fmt.Printf("i=%d sectionlen=%d\n", i, v.Siglen)
    }
*/

    c, err := cert.NewCertFromFile(certPath)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}


    moklist, err := moklist.CertListFromMOKDB()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}


    certlist := certlist.Certlist{}
    certlist.AddCert(c)

    for _,v := range *moklist {
        fmt.Printf("cert %+v\n", v)
        certlist.AddCert(v)
    }

    for _,v := range certlist.List {
        fmt.Printf("%+v\n", v)
    }
}

/*
func (s *signatureSection) getDigest() (*[]byte, error) {

	sigCert, err := pkcs7.Parse(s.signature)
	if err != nil {
		fmt.Print("ParseCertificat failed %s\n", err)
		return nil, fmt.Errorf("ParseCertificate failed %s\n", err)
	}
	if len(sigCert.Signers) != 1 {
		return nil, fmt.Errorf("Multiple signers found in signature\n")
	}

	return &sigCert.Signers[0].EncryptedDigest, nil
}

func (s *signatureSection) checkSig(buffer []byte, cert []byte) (bool, error) {

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
