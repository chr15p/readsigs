package moklist

import (
    "os"
    "fmt"
    "bytes"
    "encoding/binary"
    "crypto/x509"
    "crypto/rsa"

//    "github.com/chr15p/readsigs/pkgs/certlist"
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
    ParsedCert *x509.Certificate
}



//func CertListFromMOKDB() (*certlist.Certlist, error) {
func CertListFromMOKDB() ( []*MokListEntry, error) {
	buffer, err := os.ReadFile(moklist)
	if err != nil {
		return nil, fmt.Errorf("Failed to read cert %s: %s\n", moklist, err)
	}

    var certlist []*MokListEntry

    offset := uint32(0)
    moklen := uint32(len(buffer))
    for offset < moklen {
        entry, err := ParseCert(buffer[offset: ])
    	if err != nil {
	    	return nil, err
    	}

        certlist = append(certlist[:], entry)

        offset += (certOffset + entry.Header.SigListSize)
    }


    return certlist, nil
}


func ParseCert(buffer []byte) (*MokListEntry, error) {
    header := MokListHeader{}

   	buf := bytes.NewReader(buffer[:certOffset])
    err := binary.Read(buf, binary.LittleEndian, &header)

    cert := buffer[certOffset -1 : certOffset+ header.SigSize -17]
    pubCert, err := x509.ParseCertificate(cert)
	if err != nil {
    	return nil, fmt.Errorf("failed to parse MOK cert %s\n", err)
	}

    entry := MokListEntry{
        Header: header,
        cert: cert,
        ParsedCert: pubCert, 
    }
 
    return &entry, nil
}

func (m *MokListEntry) GetRawCert() []byte {
    return m.cert
}

func (m *MokListEntry) GetParsedCert() *x509.Certificate {
    return m.ParsedCert
}

func (m *MokListEntry) GetPublicKey() *rsa.PublicKey {
	return m.ParsedCert.PublicKey.(*rsa.PublicKey)
}

func (m *MokListEntry) GetCertSubject() string {
    return m.ParsedCert.Subject.ToRDNSequence().String()
}

func (m *MokListEntry) GetCertIssuer() string {
    return m.ParsedCert.Issuer.ToRDNSequence().String()
}
