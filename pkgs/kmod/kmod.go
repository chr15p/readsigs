package kmod

import (
    "os"
    "fmt"
	"encoding/binary"
)

const (
	MAGICNUMBER = "~Module signature appended~\n"
)

type Signature struct {
	Name       []byte
	Kid        []byte
	Signature  []byte
	Algo       byte
	Hash       byte
	Sigtype    byte
	Namelen    uint64
	Kidlen     uint64
	Siglen     uint64
	Sectionlen uint64
	Payloadlen uint64
}


type Kmod struct{
    Name string
    Length uint64
    Content []byte
    Signatures []Signature
    SigCount int
}


func GetKmod(filename string) (*Kmod, error) {
	buffer, err := os.ReadFile(filename) // just pass the file name
	if err != nil {
		return nil, fmt.Errorf("Failed to open kmod %s:\n", err)
	}

    k := &Kmod{
            Name: filename,
            Length: uint64(len(buffer)),
            Content: buffer,
            SigCount: 0,
    }

    k.parseSignatures()

    return k, nil
}


func (k *Kmod) parseSignatures() {

    kmodLen := k.Length

    for kmodLen > 0 {
        //sig := k.parseNextSig()
        sig := GetSignature(k)
        if sig == nil {
            break
        }

        k.Signatures = append(k.Signatures, *sig)
        k.SigCount++

        kmodLen -= sig.Sectionlen
   }

    return
}


func (k *Kmod) checkMagic(offset uint64) bool {
    if offset == 0 {
        offset = k.Length
    }

	magicNumPos := offset - uint64(len(MAGICNUMBER))
	return string(k.Content[magicNumPos:offset]) == MAGICNUMBER
}


func GetSignature(k *Kmod) *Signature {
    kmodLen := k.Length
    if k.SigCount > 0 {
        kmodLen = k.Signatures[k.SigCount-1].Payloadlen
    }

	//kmodLen := uint64(len(buffer))
	if !k.checkMagic(kmodLen) {
		return nil
	}

	signatureSec := Signature{}

	offset := uint64(kmodLen - 40)

	signatureSec.Algo = k.Content[offset+0]
	signatureSec.Hash = k.Content[offset+1]
	signatureSec.Sigtype = k.Content[offset+2]
	signatureSec.Namelen = uint64(k.Content[offset+3])
	signatureSec.Kidlen = uint64(k.Content[offset+4])
	signatureSec.Siglen = uint64(binary.BigEndian.Uint32(k.Content[offset+8 : offset+12]))

	sigSectionLen := uint64(signatureSec.Siglen + signatureSec.Namelen + signatureSec.Kidlen)
	offset -= sigSectionLen

	if signatureSec.Namelen > 0 {
		signatureSec.Name = k.Content[offset : offset + signatureSec.Namelen]
	}
	if signatureSec.Kidlen > 0 {
		signatureSec.Kid = k.Content[offset+signatureSec.Namelen : offset+signatureSec.Kidlen]
	}
	signatureSec.Signature = k.Content[offset+signatureSec.Namelen+signatureSec.Kidlen : kmodLen-40]
	signatureSec.Sectionlen = kmodLen - offset
	signatureSec.Payloadlen = kmodLen - signatureSec.Sectionlen

	return &signatureSec
}


