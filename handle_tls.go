package main

import (
	"crypto/tls"
	"log"
	"net"
	"strings"
)

func getHostNames(ip string) []string {
	hostnames, err := net.LookupAddr(ip)

	if err != nil {
		log.Printf("While getting hostname for %s (tls_connect.go), error: %s", ip, err)
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
