package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	//"encoding/binary"
	"flag"
	"fmt"
	"go.mozilla.org/pkcs7"
	"os"
	"strings"

    "github.com/chr15p/readsigs/pkgs/kmod"
    //"github.com/chr15p/readsigs/pkgs/certlist"
    "github.com/chr15p/readsigs/pkgs/certlist/cert"
    "github.com/chr15p/readsigs/pkgs/certlist/moklist"
)



type X509Cert interface {
    GetRawCert() []byte
    GetParsedCert() *x509.Certificate
    GetPublicKey() *rsa.PublicKey
    GetCertSubject() string
    GetCertIssuer() string
}


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

    certFilesArr := strings.Split(certPath, ",")
    //fmt.Println("kmod:", kmodPath)
	//fmt.Println("cert:", certPath)


    kmod, err := kmod.GetKmod(kmodPath)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}

    ml, err := moklist.CertListFromMOKDB()
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
 
    fmt.Println("checking MOKList")
    for _,cert := range ml {
        fmt.Printf("\t%s\n", cert.GetCertSubject())
        match, err := checkSig(kmod, cert)
        if err != nil {
		    fmt.Printf("failed to check signature: %v\n", err)
            continue
        }
        if match == true {
	       // fmt.Printf("  signature verified\n\tsubject: %s\n\tserial: %s\n", cert.ParsedCert.Subject.ToRDNSequence(), cert.ParsedCert.SerialNumber)
	        fmt.Printf("  signature verified\n\tsubject: %s\n\tIssuer: %s\n", cert.GetCertSubject(), cert.GetCertIssuer())
        }
    }

    for _, certPath := range certFilesArr {
        certFile, err := cert.NewCertFromFile(certPath)
	    if err != nil {
		    fmt.Printf("%s: %v", certPath ,err)
		    os.Exit(1)
	    }
        fmt.Println("\nParsed cert file", certFile.Filename)
    
        fmt.Println("\nchecking Certificate Files\n")
        match, err := checkSig(kmod, certFile)
        if err != nil {
	        fmt.Printf("failed to check signature: %v\n", err)
        }
        if match == true {
	        //fmt.Printf("  signature verified\n\tsubject: %s\n\tserial: %s\n", certFile.ParsedCert.Subject.ToRDNSequence(), certFile.ParsedCert.SerialNumber)
	        fmt.Printf("  signature verified\n\tsubject: %s\n\tIssuer: %s\n", certFile.GetCertSubject(), certFile.GetCertIssuer())
        }
    }
    os.Exit(0)
}


func checkSig(k *kmod.Kmod, cert X509Cert) (bool, error) {

// TODO: this is ugly and the hardwired zero doubly so
    buffer := k.Content[:k.Signatures[0].Payloadlen]
	hash := sha256.Sum256(buffer)

    pubKey := cert.GetPublicKey()

	sigDigest, err := getDigest(k)
	if err != nil {
		return false, err
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], *sigDigest)
	if err != nil {
		return false, nil
	}

	return true, nil
}


func getDigest(k *kmod.Kmod) (*[]byte, error) {
// TODO: this is ugly and the hardwired zero doubly so
    wrapper := 0

	sigCert, err := pkcs7.Parse(k.Signatures[wrapper].Signature)
	if err != nil {
		return nil, fmt.Errorf("GetDigest() failed %s\n", err)
	}
	if len(sigCert.Signers) != 1 {
		return nil, fmt.Errorf("Multiple signers found in signature\n")
	}

	return &sigCert.Signers[0].EncryptedDigest, nil
}

