package lzr

import (
	"log"
	"net"
	"strings"

	"github.com/zmap/zcrypto/tls"
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

func getHost(ip string) string {
	config := &tls.Config{}
	_, err := tls.Dial("tcp", ip, config)

	words := strings.Split((err.Error()), " ")
	hostname := words[10][:len(words[10])-1]

	return hostname
}

func IsTLSVersion2(serverHello []byte) bool {

	if len(serverHello) < 6 {
		return false
	}

	return serverHello[1] == 0x03 && serverHello[2] == 0x03
}

// Read ServerHello bytes to find supported application layer protocl
func GetALPN(serverhello string) string {
	// Possibly could change this later to check for all protocols and return
	// an array of protocol strings
	if strings.Contains(serverhello, string([]byte{0x02, 0x68, 0x32})) {
		return "h2"
	}
	if strings.Contains(serverhello, string([]byte{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31})) {
		return "http/1.1"
	}
	if strings.Contains(serverhello, string([]byte{0x03, 0x68, 0x32, 0x63})) {
		return "h2c"
	}
	if strings.Contains(serverhello, string([]byte{0x02, 0x68, 0x33})) {
		return "h3"
	}
	if strings.Contains(serverhello, string([]byte{0x06, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63})) {
		return "webrtc"
	}
	if strings.Contains(serverhello, string([]byte{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x30})) {
		return "http/1.0"
	}
	if strings.Contains(serverhello, string([]byte{0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x30, 0x2e, 0x39})) {
		return "http/0.9"
	}
	if strings.Contains(serverhello, string([]byte{0x03, 0x66, 0x74, 0x70})) {
		return "ftp"
	}
	if strings.Contains(serverhello, string([]byte{0x04, 0x69, 0x6d, 0x61, 0x70})) {
		return "imap"
	}
	if strings.Contains(serverhello, string([]byte{0x04, 0x70, 0x6f, 0x70, 0x33})) {
		return "pop3"
	}
	if strings.Contains(serverhello, string([]byte{0x03, 0x73, 0x6D, 0x62})) {
		return "smb"
	}
	if strings.Contains(serverhello, string([]byte{0x10, 0x70, 0x6F, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x71, 0x6C})) {
		return "postgresql"
	}
	if strings.Contains(serverhello, string([]byte{0x04, 0x6d, 0x71, 0x74, 0x74})) {
		return "mqtt"
	}

	return ""
}
