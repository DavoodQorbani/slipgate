package dnsrouter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"net"
	"strconv"
	"strings"
)

// verifyPrefix is the first DNS label that triggers HMAC verification.
// Designed to look like a CDN cache key lookup.
const verifyPrefix = "_ck"

// verifyRoute holds the pubkey and MTU for a domain's HMAC verification.
type verifyRoute struct {
	domainLabels []string // tunnel domain split into lowercase labels
	pubkey       []byte   // server public key used as HMAC key
	mtu          int      // default response size (0 = no padding)
}

// handleVerify checks if packet is a _ck.* verification query and responds
// with HMAC-SHA256(pubkey, nonce) padded to target size.
// Query formats:
//
//	_ck.<nonce-hex>.<domain>           → response padded to server MTU
//	_ck.<size>.<nonce-hex>.<domain>    → response padded to requested size
func (r *Router) handleVerify(packet []byte, clientAddr *net.UDPAddr) bool {
	if len(packet) < 12 {
		return false
	}
	// Must be a query (QR=0)
	if packet[2]&0x80 != 0 {
		return false
	}
	// QDCOUNT must be 1
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return false
	}

	// Parse the question name into labels
	offset := 12
	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		if length == 0 {
			offset++
			break
		}
		if length >= 0xC0 {
			return false // pointer in query — unexpected
		}
		offset++
		if offset+length > len(packet) {
			return false
		}
		labels = append(labels, strings.ToLower(string(packet[offset:offset+length])))
		offset += length
	}

	// Need QTYPE + QCLASS after name
	if offset+4 > len(packet) {
		return false
	}
	qtype := binary.BigEndian.Uint16(packet[offset : offset+2])
	if qtype != 16 { // must be TXT
		return false
	}
	qEnd := offset + 4

	// First label must be "_ck"
	if len(labels) < 3 || labels[0] != verifyPrefix {
		return false
	}

	// Find matching verify route by domain suffix
	vr := r.findVerifyRoute(labels)
	if vr == nil {
		return false
	}

	dl := len(vr.domainLabels)
	off := len(labels) - dl

	// Check if second label is a size request (all digits)
	targetSize := vr.mtu
	nonceStart := 1
	if off > 2 {
		if size, err := strconv.Atoi(labels[1]); err == nil && size > 0 && size <= 4096 {
			targetSize = size
			nonceStart = 2
		}
	}

	// Extract nonce hex (labels between prefix/size and domain)
	nonceHex := strings.Join(labels[nonceStart:off], "")
	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonceBytes) == 0 {
		return false
	}

	// Compute HMAC-SHA256(pubkey, nonce)
	mac := hmac.New(sha256.New, vr.pubkey)
	mac.Write(nonceBytes)
	sig := mac.Sum(nil)
	sigHex := hex.EncodeToString(sig)

	// Build TXT content and pad to target size
	txt := sigHex
	if targetSize > 0 {
		// Calculate DNS response overhead to determine TXT padding
		// Header(12) + Question(qEnd-12) + Answer pointer(2) + type(2) + class(2) + TTL(4) + rdlen(2) + txtlen(1) = 25
		overhead := qEnd + 25
		targetTXT := targetSize - overhead
		if targetTXT > len(txt) {
			txt = padResponse(txt, targetTXT)
		}
	}

	// Build and send TXT response
	resp := buildTXTResponse(packet, qEnd, txt)
	if _, err := r.conn.WriteToUDP(resp, clientAddr); err != nil {
		log.Printf("verify: write: %v", err)
	}
	return true
}

// padResponse pads the HMAC hex with deterministic fill bytes to reach targetLen.
func padResponse(hmacHex string, targetLen int) string {
	if targetLen <= len(hmacHex) {
		return hmacHex
	}
	// Pad with repeating hex chars derived from HMAC (deterministic, looks like cache data)
	var b strings.Builder
	b.WriteString(hmacHex)
	for b.Len() < targetLen {
		b.WriteByte(hmacHex[b.Len()%len(hmacHex)])
	}
	return b.String()[:targetLen]
}

// findVerifyRoute finds a verify route matching the domain suffix of the labels.
func (r *Router) findVerifyRoute(labels []string) *verifyRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := range r.verifyRoutes {
		vr := &r.verifyRoutes[i]
		dl := len(vr.domainLabels)
		if len(labels) < 2+dl {
			continue
		}
		off := len(labels) - dl
		match := true
		for j, want := range vr.domainLabels {
			if labels[off+j] != want {
				match = false
				break
			}
		}
		if match {
			return vr
		}
	}
	return nil
}

// buildTXTResponse constructs a minimal DNS TXT response.
// For TXT data longer than 255 bytes, splits into multiple character-strings.
func buildTXTResponse(query []byte, qEnd int, txt string) []byte {
	var resp []byte

	// Header
	resp = append(resp, query[0], query[1])              // Transaction ID
	resp = append(resp, 0x84|(query[2]&0x01), 0x00)      // QR=1, AA=1, RD=copy
	resp = append(resp, 0x00, 0x01)                      // QDCOUNT = 1
	resp = append(resp, 0x00, 0x01)                      // ANCOUNT = 1
	resp = append(resp, 0x00, 0x00)                      // NSCOUNT = 0
	resp = append(resp, 0x00, 0x00)                      // ARCOUNT = 0

	// Question section (copy from query)
	resp = append(resp, query[12:qEnd]...)

	// Answer: name pointer + TXT RR
	resp = append(resp, 0xC0, 0x0C) // name pointer to offset 12
	resp = append(resp, 0x00, 0x10) // TYPE = TXT
	resp = append(resp, 0x00, 0x01) // CLASS = IN
	resp = append(resp, 0x00, 0x01, 0x51, 0x80) // TTL = 86400

	// Build RDATA with character-strings (max 255 bytes each)
	txtBytes := []byte(txt)
	var rdata []byte
	for len(txtBytes) > 0 {
		chunk := txtBytes
		if len(chunk) > 255 {
			chunk = chunk[:255]
		}
		rdata = append(rdata, byte(len(chunk)))
		rdata = append(rdata, chunk...)
		txtBytes = txtBytes[len(chunk):]
	}

	// RDLENGTH
	resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
	resp = append(resp, rdata...)

	return resp
}
