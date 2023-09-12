package main

import (
    "fmt"
    "os"
    "encoding/binary"
    "crypto"
    "crypto/rsa"
    //"bytes"
    //"encoding/pem"
    "crypto/sha256"
    "crypto/x509"
    "go.mozilla.org/pkcs7"
)
const (
    MAGICNUMBER = "~Module signature appended~\n"
)

type signatureSection struct {
    name []byte
    kid []byte
    signature []byte
    algo byte
    hash byte
    sigtype byte
    namelen uint64
    kidlen uint64
    siglen uint64
    sectionlen uint64
}

func main() {
    kmodPath :=  os.Args[1] // "./gfs2.ko"


    buffer, err := os.ReadFile(kmodPath) // just pass the file name
    if err != nil {
        fmt.Print(err)
    }

    cert, err := os.ReadFile("testkey_pub.der")

    kmodLen := uint64(len(buffer))
    for kmodLen > 0 {

        sig := newSigFromBuffer(buffer[:kmodLen])
        if sig == nil {
            break
        }
        kmodLen -= sig.sectionlen
        sig.checkSig(buffer[:kmodLen], cert)
   }

}


func newSigFromBuffer(buffer []byte) (*signatureSection) {
    kmodLen := uint64(len(buffer))
    if !checkMagic(buffer[:kmodLen], kmodLen) {
        return nil
    }

    signatureSec := signatureSection{}

    offset := uint64(kmodLen - 40)

    signatureSec.algo = buffer[offset + 0]
    signatureSec.hash = buffer[offset + 1]
    signatureSec.sigtype = buffer[offset + 2]
    signatureSec.namelen = uint64(buffer[offset + 3])
    signatureSec.kidlen = uint64(buffer[offset + 4])
    signatureSec.siglen = uint64(binary.BigEndian.Uint32(buffer[offset + 8:offset + 12]))

    sigSectionLen := uint64(signatureSec.siglen + signatureSec.namelen + signatureSec.kidlen)
    offset -= sigSectionLen

    if signatureSec.namelen > 0 {
        signatureSec.name = buffer[offset: offset +signatureSec.namelen]
    } 
    if signatureSec.kidlen > 0 {
        signatureSec.kid = buffer[offset + signatureSec.namelen: offset +signatureSec.kidlen]
    }
    signatureSec.signature = buffer[offset + signatureSec.namelen + signatureSec.kidlen : kmodLen - 40]
    signatureSec.sectionlen = kmodLen - offset

    return &signatureSec
}


func checkMagic(buffer []byte, length uint64) bool {

    magicNumPos := length - uint64(len(MAGICNUMBER))
    return string(buffer[magicNumPos:]) == MAGICNUMBER
}


func (s * signatureSection) checkSig(buffer []byte, cert []byte){
    //kmodLen := uint64(len(buffer))

    hash := sha256.Sum256(buffer)

    //fmt.Printf("hash=%x (%d bytes)\n", hash, kmodLen)

    c, err := x509.ParseCertificate(cert)
    if err != nil {
        fmt.Printf("invalid public key %s\n", err)
    }

    pubKey := c.PublicKey.(*rsa.PublicKey)
    if err != nil {
        fmt.Printf("invalid public key %s\n", err)
        return 
    }

    //fmt.Printf("%x\n", s.signature)
    //fmt.Printf("siglen =%d\n", len(s.signature))
    //fmt.Printf("%x\n", s.signature[s.siglen-512:])
    //signature := s.signature[s.siglen-512:]

    p, err := pkcs7.Parse(s.signature)
    if err != nil {
        fmt.Print("ParseCertificat failed %s\n",err)
    }
    signature := p.Signers[0].EncryptedDigest
    //fmt.Printf("%x\n",p.Signers[0].EncryptedDigest)
    //fmt.Printf("%x\n",p.Signers[0].IssuerAndSerialNumber.SerialNumber)
    //fmt.Printf("%+v\n",p.GetOnlySigner())
    //PrintFields(*p.Signers[0])

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature)
    if err != nil {
        fmt.Printf("not verified: %s\n", p.Signers[0].IssuerAndSerialNumber.SerialNumber)
        return
    }


    fmt.Printf("\nsignature verified by serial number %x\n", p.Signers[0].IssuerAndSerialNumber.SerialNumber)

    return
}
