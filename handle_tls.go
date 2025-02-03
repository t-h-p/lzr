package lzr

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"os"
	"strings"
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
	// use provided certificates, get private key

	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		log.Printf("failed to get certificate from: %s", certPath)
		return nil, err
	}

	block, _ := pem.Decode(rawCert)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Printf("bad certificate")
		return nil, errors.New("Bad certificate in buildClientHello")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Could not parse certificate")
		return nil, err
	}

	curve := pubKey.Curve
	key, err := ecdsa.GenerateKey(curve, nil)
	if err != nil {
		log.Printf("Could not generate ecdsa key")
		return nil, err
	}

	return key, nil

}

func buildClientHello() []byte {

	data := []byte("\x16\x03\x01\x00\x75\x01\x00\x00\x71\x03\x03") // tls header

	token := make([]byte, 32)
	token := rand.Read(token) // using crypto/rand for csrng
	data2 := []byte("\x00\x00\x1a\xc0\x2f\xc0\x2b\xc0\x11\xc0\x07\xc0\x13\xc0\x09\xc0\x14\xc0\x0a\x00\x05\x00\x2f\x00\x35\xc0\x12\x00\x0a\x01\x00\x00\x2e\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x08\x00\x06\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x0a\x00\x08\x04\x01\x04\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00")
	data = append(data, token...)
	data = append(data, data2...)
	return data

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
