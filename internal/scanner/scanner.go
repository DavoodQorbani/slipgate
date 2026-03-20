package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"net"
	"time"
)

// verifyEncoding is the same lowercase base32 alphabet used by verify.go,
// so the probe looks identical to a normal dnstt/noizdns tunnel query.
var verifyEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// VerifyResolver sends 5 probes with different nonces.
// Returns true if 3+ succeed (tolerates UDP packet loss).
func VerifyResolver(host string, port int, domain string, pubkey []byte, timeoutMs int) bool {
	passed := 0
	for i := 0; i < 5; i++ {
		if verifyOnce(host, port, domain, pubkey, timeoutMs) {
			passed++
			if passed >= 3 {
				return true
			}
		}
	}
	return false
}

func verifyOnce(host string, port int, domain string, pubkey []byte, timeoutMs int) bool {
	// 1. Random 16-byte nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return false
	}

	// 2. Client proof: HMAC-SHA256(key, nonce)[:16]
	mac := hmac.New(sha256.New, pubkey)
	mac.Write(nonce)
	proof := mac.Sum(nil)[:16]

	// 3. Encode nonce||proof in lowercase base32 (no padding) → 52 chars, 1 label
	encoded := verifyEncoding.EncodeToString(append(nonce, proof...))
	queryDomain := encoded + "." + domain

	// 4. Build TXT DNS query
	query := buildTXTQuery(queryDomain)

	// 5. Send via UDP and receive
	addr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	timeout := time.Duration(timeoutMs) * time.Millisecond
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(query); err != nil {
		return false
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return false
	}

	// 6. Extract raw binary TXT data
	rawData := extractFirstTXTRaw(respBuf[:n])
	if len(rawData) < 32 {
		return false
	}

	// 7. First 32 bytes = HMAC-SHA256(key, nonce||0x01)
	mac2 := hmac.New(sha256.New, pubkey)
	mac2.Write(nonce)
	mac2.Write([]byte{0x01})
	expected := mac2.Sum(nil)

	return hmac.Equal(rawData[:32], expected)
}

// buildTXTQuery builds a minimal DNS TXT query for the given domain.
func buildTXTQuery(domain string) []byte {
	var buf []byte

	// Transaction ID (random-ish: use 2 bytes from the system)
	var txid [2]byte
	rand.Read(txid[:])
	buf = append(buf, txid[0], txid[1])

	// Flags: standard query, RD=1
	buf = append(buf, 0x01, 0x00)
	// QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf = append(buf, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Question: domain name
	for _, label := range splitLabels(domain) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root

	// QTYPE=TXT(16), QCLASS=IN(1)
	buf = append(buf, 0x00, 0x10, 0x00, 0x01)

	return buf
}

func splitLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

// extractFirstTXTRaw parses a raw DNS response and returns the concatenated
// binary data of the first TXT answer record.
func extractFirstTXTRaw(buf []byte) []byte {
	if len(buf) < 12 {
		return nil
	}
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if ancount == 0 {
		return nil
	}

	// Skip question section
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(buf[4:6]))
	for i := 0; i < qdcount; i++ {
		offset = skipName(buf, offset)
		if offset < 0 || offset+4 > len(buf) {
			return nil
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answer section
	for i := 0; i < ancount; i++ {
		offset = skipName(buf, offset)
		if offset < 0 || offset+10 > len(buf) {
			return nil
		}
		rrtype := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 8 // TYPE + CLASS + TTL
		rdlen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
		offset += 2
		if offset+rdlen > len(buf) {
			return nil
		}
		if rrtype == 16 { // TXT
			end := offset + rdlen
			var out []byte
			pos := offset
			for pos < end {
				strLen := int(buf[pos])
				pos++
				if pos+strLen > end {
					break
				}
				out = append(out, buf[pos:pos+strLen]...)
				pos += strLen
			}
			return out
		}
		offset += rdlen
	}
	return nil
}

// skipName advances offset past a DNS name (labels or pointer).
func skipName(buf []byte, offset int) int {
	for offset < len(buf) {
		length := int(buf[offset])
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 { // pointer
			return offset + 2
		}
		offset += 1 + length
	}
	return -1
}
