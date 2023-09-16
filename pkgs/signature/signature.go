package signature

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"go.mozilla.org/pkcs7"
	"os"
)

const (
	MAGICNUMBER = "~Module signature appended~\n"
)

type Signature struct {
	name       []byte
	kid        []byte
	signature  []byte
	algo       byte
	hash       byte
	sigtype    byte
	namelen    uint64
	kidlen     uint64
	siglen     uint64
	sectionlen uint64
}

func ParseSignatures(buffer []bytes) []Signature {

    var allsigs  []SignatureSection

    kmodLen := uint64(len(buffer))

    for kmodLen > 0 {
        sig := newSigFromBuffer(buffer[:kmodLen])
        if sig == nil {
            break
        }

        allsigs = append(allsigs, sig)

        kmodLen -= sig.sectionlen
   }

    return allsigs
}


func newSigFromBuffer(buffer []byte) *Signature {
	kmodLen := uint64(len(buffer))
	if !checkMagic(buffer[:kmodLen], kmodLen) {
		return nil
	}

	signatureSec := signature{}

	offset := uint64(kmodLen - 40)

	signatureSec.algo = buffer[offset+0]
	signatureSec.hash = buffer[offset+1]
	signatureSec.sigtype = buffer[offset+2]
	signatureSec.namelen = uint64(buffer[offset+3])
	signatureSec.kidlen = uint64(buffer[offset+4])
	signatureSec.siglen = uint64(binary.BigEndian.Uint32(buffer[offset+8 : offset+12]))

	sigSectionLen := uint64(signatureSec.siglen + signatureSec.namelen + signatureSec.kidlen)
	offset -= sigSectionLen

	if signatureSec.namelen > 0 {
		signatureSec.name = buffer[offset : offset+signatureSec.namelen]
	}
	if signatureSec.kidlen > 0 {
		signatureSec.kid = buffer[offset+signatureSec.namelen : offset+signatureSec.kidlen]
	}
	signatureSec.signature = buffer[offset+signatureSec.namelen+signatureSec.kidlen : kmodLen-40]
	signatureSec.sectionlen = kmodLen - offset

	return &signatureSec
}


func checkMagic(buffer []byte, length uint64) bool {

	magicNumPos := length - uint64(len(MAGICNUMBER))
	return string(buffer[magicNumPos:]) == MAGICNUMBER
}


func (s *signature) getDigest() (*[]byte, error) {

	sigCert, err := pkcs7.Parse(s.signature)
	if err != nil {
		fmt.Print("ParseCertificate failed %s\n", err)
		return nil, fmt.Errorf("ParseCertificate failed %s\n", err)
	}
	if len(sigCert.Signers) != 1 {
		return nil, fmt.Errorf("Multiple signers found in signature\n")
	}

	return &sigCert.Signers[0].EncryptedDigest, nil
}

func (s *signature) checkSig(buffer []byte, cert []byte) (bool, error) {

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
