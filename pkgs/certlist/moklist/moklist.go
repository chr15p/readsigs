package moklist

import (
    "os"
    "fmt"
    "bytes"
    "encoding/binary"
    "crypto/x509"
)

const (
    moklist = "/sys/firmware/efi/mok-variables/MokListRT"
    certOffset =45
)

type MokListHeader struct {
    Sigtype [16]byte
    SigListSize uint32
    HeaderSize uint32
    SigSize uint32
    SigOwner [16]byte
    Padding byte
}

type MokListEntry struct {
    Header  MokListHeader
    cert    []byte
    ParsedCert  *x509.Certificate
}



func CertListFromMOKDB() (*[]*MokListEntry, error) {
	buffer, err := os.ReadFile(moklist)
	if err != nil {
		return nil, fmt.Errorf("Failed to read cert %s: %s\n", moklist, err)
	}

    var certlist []*MokListEntry


    offset := uint32(0)
    moklen := uint32(len(buffer))
    for offset < moklen {
        header := MokListHeader{}

       	buf := bytes.NewReader(buffer[offset: offset +45])
        err := binary.Read(buf, binary.LittleEndian, &header)

        cert := buffer[offset + certOffset -1 : offset + certOffset+ header.SigSize -17]
	    pubCert, err := x509.ParseCertificate(cert)
    	if err != nil {
	    	return nil, fmt.Errorf("failed to parse MOK cert %s\n", err)
    	}

        entry := MokListEntry{
            Header: header,
            cert: cert,
            ParsedCert: pubCert, 
        }
 
        certlist = append(certlist[:], &entry)

        offset += (certOffset + header.SigListSize)
    }


    return &certlist, nil
}


func (m *MokListEntry) GetRawCert() []byte {
    return m.cert
}

func (m *MokListEntry) GetParsedCert() *x509.Certificate {
    return m.ParsedCert
}
