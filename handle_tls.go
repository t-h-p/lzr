package lzr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"

	"golang.org/x/crypto/curve25519" // needs 'go get golang.org/x/crypto/curve25519' to work
)

func getHostNames(ip string) []string {
	hostnames, err := net.LookupAddr(ip)

	if err != nil {
		log.Printf("While getting hostname for %s (tls_connect.go), error: %s", ip, err)
		return []string{}
	}

	for _, name := range hostnames {
		log.Printf("%s\n", name)
	}

	return hostnames
}

func connectTLS(host string) *tls.Conn {

	// Can enable if we don't care about security
	/*config := &tls.Config{
		InsecureSkipVerify: false,
	}*/
	config := &tls.Config{}

	conn, err := tls.Dial("tcp", host, config)

	if err != nil {
		log.Printf("While dialing TLS connection for %s (tls_connect.go), error: %s", host, err)
		errVal := err.Error()
		// example error (solution below only resolves this specific kind of error)
		// tls: failed to verify certificate: x509: certificate is valid for pkg.go.dev, not 181.140.149.34.bc.googleusercontent.com.
		parts := strings.Split(errVal, " ")
		// Debug
		/*for i := 0; i < len(parts); i++ {
			log.Printf("%s : %s", i, parts[i])
		}*/
		newHost := parts[10][:len(parts[10])-1]
		// Check "correct" hostname
		// log.Printf(newHost)
		// two layers of tls.Dial
		conn, err := tls.Dial("tcp", newHost+":443", config)
		if err != nil {
			log.Printf("While dialing TLS connection for %s (tls_connect.go, depth 2), error: %s", newHost, err)
			return nil
		}
		return conn
	}

	return conn
}

func generatePrivateKey(certPath string) ([]byte, error) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}

	privateKeyAsBytes, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	return privateKeyAsBytes, nil

}

func generatePublicKey(privateKey []byte) []byte {

	// Clamp
	privateKey[0] &= 248
	privateKey[0] &= 127
	privateKey[0] |= 64

	var fixedPrivateKey [32]byte = [32]byte(privateKey)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &fixedPrivateKey)

	return publicKey[:]
}

func buildClientHello(name string, privateKey []byte) ([]byte, error) {

	/* https://tls13.xargs.org/#client-hello/annotated */
	/* Must provide some kind of valid hostname for this to work */

	clientHello := []byte("\x16\x03\x01")

	messageLength := make([]byte, 2)
	if len(name) <= 253 {
		binary.BigEndian.PutUint16(messageLength, uint16(len(name)))
	} else {
		return nil, errors.New("Invalid hostname format")
	}
	clientHello = append(clientHello, messageLength...)

	handshakeHeaderAndVersion := ("\x01\x00\x00\xf4\x03\x03")
	clientHello = append(clientHello, handshakeHeaderAndVersion...)

	randomToken := make([]byte, 32)
	rand.Read(randomToken) // using crypto/rand for csrng
	clientHello = append(clientHello, randomToken...)

	middleBytes := []byte("\x00\x08\x13\x02\x13\x03\x13\x01\x00\xff\x01\x00\x00\xa3\x00\x00\x00\x18\x00\x16\x00\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x75\x6c\x66\x68\x65\x69\x6d\x2e\x6e\x65\x74\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x16\x00\x14\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x23\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x1e\x00\x1c\x04\x03\x05\x03\x06\x03\x08\x07\x08\x08\x08\x09\x08\x0a\x08\x0b\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x00\x2b\x00\x03\x02\x03\x04\x00\x2d\x00\x02\x01\x01")
	clientHello = append(clientHello, middleBytes...)

	publicKey := generatePublicKey(privateKey)
	clientHello = append(clientHello, publicKey...)

	return clientHello, nil
}

func main() {
	log.Printf("start")

	ip := "142.251.40.36" // 131.179.128.29 works, 34.149.140.181 and 142.251.40.36 do not (without the added changes)

	hostname := getHostNames(ip)[0]

	conn := connectTLS(hostname + ":443")

	if conn == nil {
		log.Printf("Could not connect")
	} else {
		log.Printf("Connected")
	}

	conn.Close()
}
