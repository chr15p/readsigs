package main

import (
	"fmt"
	"os"
	"encoding/binary"
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
	namelen uint32
	kidlen uint32
	siglen uint32
	sectionlen int64
}

func main() {
	kmodPath :=  os.Args[1] // "./gfs2.ko"

	fileInfo, err := os.Stat(kmodPath)
        if err != nil {
                fmt.Printf("unable to stat file %s: %v", kmodPath, err)
		os.Exit(0)
        }

	filesize := fileInfo.Size()
	for {
		//sig, siglen, err := readSignature(kmodPath, filesize)
		sig, err := readSignature2(kmodPath, filesize)
		if sig == nil {
			if filesize == fileInfo.Size() {
				fmt.Printf("no signature found\n")
				os.Exit(0)
			}
			break
		}
		if err != nil {
			fmt.Printf("%s\n",err)
			os.Exit(1)
		}
		//filesize -= siglen
		filesize -= sig.sectionlen
		fmt.Printf("%+v\n",sig)
		//fmt.Printf("%+d\n", filesize)
	}
}

func checkMagic(buffer []byte) bool {

	magicNumPos := len(buffer) - len(MAGICNUMBER)
	return string(buffer[magicNumPos:]) == MAGICNUMBER
}

func readChunk(file *os.File, fileSize int64, chunkLen int64) ([]byte, error) {
	buffer := make([]byte, chunkLen)

	startPosition := fileSize - chunkLen

	_, err := file.ReadAt(buffer, startPosition)
	if err != nil {
		return nil, fmt.Errorf("Failed to readat %d: %s", startPosition, err)
	}

	return buffer, nil
}
	
func readSignature2(kmodPath string, fileSize int64) (*signatureSection, error)  {
	file, err := os.Open(kmodPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s: %s", kmodPath, err)
	}
        defer file.Close()

	signatureSec := signatureSection{}

	buffer, err := readChunk(file, fileSize, 40)
	if err != nil {
		return nil, err
	}

	if ! checkMagic(buffer) {
		return nil, fmt.Errorf("not a signed kernel module")
	}

	signatureSec.algo = buffer[0]
	signatureSec.hash = buffer[1]
	signatureSec.sigtype = buffer[2]
	signatureSec.namelen = uint32(buffer[3])
	signatureSec.kidlen = uint32(buffer[4])
	signatureSec.siglen = binary.BigEndian.Uint32(buffer[8:12])

	sigSectionLen := int64(signatureSec.siglen + signatureSec.namelen + signatureSec.kidlen)
	sigSectionBuf, err := readChunk(file, fileSize - 40, sigSectionLen)
	if err != nil {
		return nil, err
	}

	// signature name and kidlen may be zero so check before we read them
	if signatureSec.namelen > 0 {
		signatureSec.name = sigSectionBuf[:signatureSec.namelen]
	} 
	if signatureSec.kidlen > 0 {
		signatureSec.kid = sigSectionBuf[signatureSec.namelen:signatureSec.kidlen]
	}
	signatureSec.signature = sigSectionBuf[signatureSec.namelen + signatureSec.kidlen :]
	signatureSec.sectionlen = sigSectionLen+40

	return &signatureSec, nil
}


func readSignature(kmodPath string, fileSize int64) (*signatureSection, int64, error)  {

	file, err := os.Open(kmodPath)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to open %s: %s", kmodPath, err)
	}
        defer file.Close()


	signatureSec := signatureSection{}
	// footer is always 40 bytes so wind back from EOF
	footerPos := fileSize - 40
	footerBuf := make([]byte, 40)
	_, err = file.ReadAt(footerBuf, footerPos)
	magicNumPos := 40 - (len(MAGICNUMBER) )
	siglenPos := magicNumPos - 4
	// do we have the magic number at the end of file?
	if string(footerBuf[magicNumPos:magicNumPos + len(MAGICNUMBER)]) != MAGICNUMBER {
		return nil, 0, fmt.Errorf("not a signed kernel module")
	}

	// populate the fields we have so far
	signatureSec.siglen = binary.BigEndian.Uint32(footerBuf[siglenPos:siglenPos+4])
	signatureSec.algo = footerBuf[0]
	signatureSec.hash = footerBuf[1]
	signatureSec.sigtype = footerBuf[2]
	signatureSec.namelen = uint32(footerBuf[3])
	signatureSec.kidlen = uint32(footerBuf[4])

	// calculate how much we need to wind back from EOF to get the actual signature
	sigSectionLen := int64(signatureSec.siglen + signatureSec.namelen + signatureSec.kidlen)
	sigSectionPos := footerPos - sigSectionLen

	sigSectionBuf := make([]byte, sigSectionLen)
	_, err = file.ReadAt(sigSectionBuf, sigSectionPos)
	if err != nil {
		return nil, 0, fmt.Errorf("Failed to readat %d: %s", sigSectionPos, err)
	}

	// signature name and kidlen may be zero so check before we read them
	if signatureSec.namelen > 0 {
		signatureSec.name = sigSectionBuf[:signatureSec.namelen]
	} 
	if signatureSec.kidlen > 0 {
		signatureSec.kid = sigSectionBuf[signatureSec.namelen:signatureSec.kidlen]
	}
	signatureSec.signature = sigSectionBuf[signatureSec.namelen + signatureSec.kidlen :]
	signatureSec.sectionlen = sigSectionLen+40

	return &signatureSec, signatureSec.sectionlen, nil
}
