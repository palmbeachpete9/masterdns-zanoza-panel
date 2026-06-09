// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package dnsparser

import (
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

func TestParsePacketLiteParsesAllQuestions(t *testing.T) {
	request := buildMultiQuestionDNSQuery(
		0x4242,
		[]liteQuestionSpec{
			{Name: "example.com", Type: Enums.DNS_RECORD_TYPE_A, Class: Enums.DNSQ_CLASS_IN},
			{Name: "example.org", Type: Enums.DNS_RECORD_TYPE_AAAA, Class: Enums.DNSQ_CLASS_IN},
		},
		true,
	)

	parsed, err := ParsePacketLite(request)
	if err != nil {
		t.Fatalf("ParsePacketLite returned error: %v", err)
	}

	if !parsed.HasQuestion {
		t.Fatal("expected HasQuestion to be true")
	}
	if len(parsed.Questions) != 2 {
		t.Fatalf("unexpected question count: got=%d want=2", len(parsed.Questions))
	}
	if parsed.FirstQuestion.Name != "example.com" {
		t.Fatalf("unexpected first question name: got=%q want=%q", parsed.FirstQuestion.Name, "example.com")
	}
	if parsed.Questions[1].Name != "example.org" {
		t.Fatalf("unexpected second question name: got=%q want=%q", parsed.Questions[1].Name, "example.org")
	}
	if parsed.QuestionEndOffset <= dnsHeaderSize {
		t.Fatalf("unexpected QuestionEndOffset: got=%d want>%d", parsed.QuestionEndOffset, dnsHeaderSize)
	}
}

type liteQuestionSpec struct {
	Name  string
	Type  uint16
	Class uint16
}

func buildMultiQuestionDNSQuery(id uint16, questions []liteQuestionSpec, withOPT bool) []byte {
	totalQuestionLen := 0
	for _, question := range questions {
		totalQuestionLen += len(encodeDNSName(question.Name)) + 4
	}

	arCount := uint16(0)
	opt := []byte(nil)
	if withOPT {
		arCount = 1
		opt = []byte{
			0x00,
			0x00, 0x29,
			0x10, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00,
		}
	}

	packet := make([]byte, dnsHeaderSize+totalQuestionLen+len(opt))
	packet[0] = byte(id >> 8)
	packet[1] = byte(id)
	packet[2] = 0x01
	packet[3] = 0x00
	packet[4] = byte(len(questions) >> 8)
	packet[5] = byte(len(questions))
	packet[10] = byte(arCount >> 8)
	packet[11] = byte(arCount)

	offset := dnsHeaderSize
	for _, question := range questions {
		qname := encodeDNSName(question.Name)
		offset += copy(packet[offset:], qname)
		packet[offset] = byte(question.Type >> 8)
		packet[offset+1] = byte(question.Type)
		packet[offset+2] = byte(question.Class >> 8)
		packet[offset+3] = byte(question.Class)
		offset += 4
	}

	copy(packet[offset:], opt)
	return packet
}

// R-06 — MinAnswerTTL returns the smallest answer TTL.
func TestMinAnswerTTL(t *testing.T) {
	// Header: ID 0, flags 0x8180, QD 1, AN 1.
	pkt := []byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	pkt = append(pkt, 0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01) // question a.com A IN
	// Answer: name ptr 0xc00c, A, IN, TTL=300, RDLEN 4, 1.2.3.4
	pkt = append(pkt, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 1, 2, 3, 4)
	ttl, ok := MinAnswerTTL(pkt)
	if !ok || ttl != 300 {
		t.Fatalf("MinAnswerTTL = %d,%v; want 300,true", ttl, ok)
	}
	if _, ok := MinAnswerTTL([]byte{0, 0}); ok {
		t.Fatal("malformed packet should return ok=false")
	}
}

// V4-07 — answer TTLs are aged by elapsed seconds (clamped at 0).
func TestAgeResourceTTLs(t *testing.T) {
	pkt := []byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	pkt = append(pkt, 0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01)
	pkt = append(pkt, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 1, 2, 3, 4) // TTL=300

	if ttl, _ := MinAnswerTTL(AgeResourceTTLs(pkt, 100)); ttl != 200 {
		t.Fatalf("aged TTL = %d, want 200", ttl)
	}
	if ttl, _ := MinAnswerTTL(AgeResourceTTLs(pkt, 1000)); ttl != 0 {
		t.Fatalf("over-aged TTL = %d, want 0 (clamped)", ttl)
	}
	if ttl, _ := MinAnswerTTL(AgeResourceTTLs(pkt, 0)); ttl != 300 {
		t.Fatalf("zero-elapsed must not change TTL, got %d", ttl)
	}
	// Malformed input passes through unchanged.
	if got := AgeResourceTTLs([]byte{0, 0}, 5); len(got) != 2 {
		t.Fatal("malformed packet should pass through unchanged")
	}
}

// V4-07 — NXDOMAIN with an SOA authority record yields min(SOA TTL, SOA MINIMUM).
func TestNegativeTTL(t *testing.T) {
	// Header: NXDOMAIN (rcode 3), QD 1, AN 0, NS 1, AR 0.
	pkt := []byte{0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	pkt = append(pkt, 0x01, 'a', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01) // question
	// Authority SOA: name=ptr, type=SOA(6), class=IN, TTL=3600, RDLEN, RDATA.
	soaRData := []byte{0x00, 0x00}                                                // mname=root, rname=root
	soaRData = append(soaRData, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1)   // serial/refresh/retry/expire
	soaRData = append(soaRData, 0x00, 0x00, 0x01, 0x2c)                           // minimum = 300
	pkt = append(pkt, 0xc0, 0x0c, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10) // TTL=3600
	pkt = append(pkt, byte(len(soaRData)>>8), byte(len(soaRData)))
	pkt = append(pkt, soaRData...)

	ttl, ok := NegativeTTL(pkt)
	if !ok || ttl != 300 {
		t.Fatalf("NegativeTTL = %d,%v; want 300,true (min of TTL 3600 and MINIMUM 300)", ttl, ok)
	}
	// A positive response (AN>0) is not a negative cache candidate.
	pos := append([]byte(nil), pkt...)
	pos[6], pos[7] = 0, 1 // AN=1
	if _, ok := NegativeTTL(pos); ok {
		t.Fatal("positive response must not be negatively cached")
	}
}
