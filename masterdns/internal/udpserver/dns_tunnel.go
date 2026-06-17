// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"net"
	"strings"
	"time"

	"masterdnsvpn-go/internal/dnscache"
	"masterdnsvpn-go/internal/inflight"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
)

var ErrInvalidDNSUpstream = errors.New("invalid dns upstream")

const maxConcurrentDNSUpstreamQueries = 4

type dnsFragmentKey struct {
	sessionID   uint8
	sequenceNum uint16
}

type dnsResolveInflightEntry = inflight.Entry[[]byte]

type dnsResolveInflightManager struct {
	inner *inflight.Manager[[]byte]
}

func newDNSResolveInflightManager(timeout time.Duration) *dnsResolveInflightManager {
	return &dnsResolveInflightManager{
		inner: inflight.New(timeout, 16*time.Second, cloneInflightBytes),
	}
}

func (m *dnsResolveInflightManager) Acquire(cacheKey string, now time.Time) (*dnsResolveInflightEntry, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Acquire(cacheKey, now)
}

func (m *dnsResolveInflightManager) Resolve(cacheKey string, entry *dnsResolveInflightEntry, response []byte) bool {
	if m == nil {
		return false
	}
	return m.inner.Resolve(cacheKey, entry, response, len(response) != 0)
}

func (m *dnsResolveInflightManager) Wait(entry *dnsResolveInflightEntry, timeout time.Duration) ([]byte, bool) {
	if m == nil {
		return nil, false
	}
	return m.inner.Wait(entry, timeout)
}

func cloneInflightBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}

func (s *Server) buildDNSQueryResponsePayload(rawQuery []byte, sessionID uint8, sequenceNum uint16) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(rawQuery)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}
		response, responseErr := DnsParser.BuildFormatErrorResponse(rawQuery)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !parsed.HasQuestion {
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	// The cache/in-flight key covers only the first question, so a multi-question
	// query could be answered from another query that shares only its first
	// question. Reject anything but exactly one question (F22).
	if parsed.Header.QDCount != 1 {
		response, responseErr := DnsParser.BuildFormatErrorResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	if !DnsParser.IsSupportedTunnelDNSQuery(parsed.FirstQuestion.Type, parsed.FirstQuestion.Class) {
		response, responseErr := DnsParser.BuildNotImplementedResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	// Key on the full query shape (QNAME/type/class + EDNS/DNSSEC), not just the
	// first question's name/type/class, so differing EDNS/DO queries never share
	// a cached or in-flight response (F22).
	cacheKey := dnscache.BuildKeyFromQuery(rawQuery)
	now := time.Now()
	if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
		if s.log != nil {
			s.log.Debugf(
				"🧠 <green>Tunnel DNS Cache Hit</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		return cached
	}

	inflightEntry, leader := s.dnsResolveInflight.Acquire(cacheKey, now)
	if !leader {
		if s.log != nil {
			s.log.Debugf(
				"\U0001F9E9 <green>Tunnel DNS Inflight Reused</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		waitTimeout := s.cfg.DNSInflightWaitTimeout()
		if waitTimeout <= 0 {
			waitTimeout = 8 * time.Second
		}
		if resolved, ok := s.dnsResolveInflight.Wait(inflightEntry, waitTimeout); ok && len(resolved) != 0 {
			return dnscache.PatchResponseForQuery(resolved, rawQuery)
		}
		if cached, ok := s.dnsCache.GetReady(cacheKey, rawQuery, now); ok {
			return cached
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	resolved, err := s.resolveDNSUpstream(rawQuery)
	if s.log != nil {
		s.log.Debugf(
			"🔎 <green>Tunnel DNS Upstream Lookup</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
		)
	}
	currentResolution := s.dnsResolveInflight.Resolve(cacheKey, inflightEntry, resolved)
	if err != nil || len(resolved) == 0 {
		if s.log != nil {
			s.log.Debugf(
				"⚠️ <yellow>Tunnel DNS Upstream Failed</yellow> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan>",
				parsed.FirstQuestion.Name,
				Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
				sessionID,
				sequenceNum,
			)
		}
		response, responseErr := DnsParser.BuildServerFailureResponseFromLite(rawQuery, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	// Cap cache lifetime by the authoritative TTL. Positive answers use the
	// minimum answer TTL; NXDOMAIN/NODATA use the SOA negative TTL; uncacheable
	// (TTL 0 / no SOA) responses are not stored (R-06/V4-07).
	var recordTTL time.Duration
	if ttlSecs, ok := DnsParser.MinAnswerTTL(resolved); ok {
		recordTTL = time.Duration(ttlSecs) * time.Second
	} else if negSecs, ok := DnsParser.NegativeTTL(resolved); ok {
		recordTTL = time.Duration(negSecs) * time.Second
	}
	if currentResolution {
		s.dnsCache.SetReady(
			cacheKey,
			parsed.FirstQuestion.Name,
			parsed.FirstQuestion.Type,
			parsed.FirstQuestion.Class,
			resolved,
			recordTTL,
			now,
		)
	}
	if s.log != nil {
		s.log.Debugf(
			"🌍 <green>Tunnel DNS Resolved Upstream</green> <magenta>|</magenta> <blue>Domain</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Type</blue>: <yellow>%s</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Seq</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Bytes</blue>: <cyan>%d</cyan>",
			parsed.FirstQuestion.Name,
			Enums.DNSRecordTypeName(parsed.FirstQuestion.Type),
			sessionID,
			sequenceNum,
			len(resolved),
		)
	}
	return resolved
}

func (s *Server) collectDNSQueryFragments(sessionID uint8, sequenceNum uint16, payload []byte, fragmentID, totalFragments uint8, now time.Time) ([]byte, bool, bool) {
	if totalFragments == 0 {
		totalFragments = 1
	}
	assembled, ready, completed := s.dnsFragments.Collect(
		dnsFragmentKey{
			sessionID:   sessionID,
			sequenceNum: sequenceNum,
		},
		payload,
		fragmentID,
		totalFragments,
		now,
		s.dnsFragmentTimeout,
	)
	return assembled, ready, completed
}

func (s *Server) purgeDNSQueryFragments(now time.Time) {
	if s == nil || s.dnsFragments == nil {
		return
	}
	s.dnsFragments.Purge(now, s.dnsFragmentTimeout)
}

func (s *Server) removeDNSQueryFragmentsForSession(sessionID uint8) {
	if s == nil || s.dnsFragments == nil || sessionID == 0 {
		return
	}
	s.dnsFragments.RemoveIf(func(key dnsFragmentKey) bool {
		return key.sessionID == sessionID
	})
}

func (s *Server) fragmentDNSResponsePayload(response []byte, mtu int) [][]byte {
	if len(response) == 0 {
		return nil
	}
	limit := mtu
	if limit < 1 {
		limit = 256
	}
	if len(response) <= limit {
		return [][]byte{response}
	}

	total := (len(response) + limit - 1) / limit
	if total > 255 {
		return nil
	}

	fragments := make([][]byte, 0, total)
	for start := 0; start < len(response); start += limit {
		end := start + limit
		if end > len(response) {
			end = len(response)
		}
		fragments = append(fragments, response[start:end])
	}
	return fragments
}

func (s *Server) resolveDNSUpstream(rawQuery []byte) ([]byte, error) {
	if s != nil && s.resolveDNSQueryFn != nil {
		return s.resolveDNSQueryFn(rawQuery)
	}
	if len(rawQuery) == 0 || len(s.dnsUpstreamServers) == 0 {
		return nil, ErrInvalidDNSUpstream
	}

	timeout := s.cfg.DNSUpstreamTimeout()
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	// Fast path: single upstream, no need for hedged requests.
	if len(s.dnsUpstreamServers) == 1 {
		resp, err := s.queryOneUpstream(s.dnsUpstreamServers[0], rawQuery, timeout)
		if err != nil || len(resp) == 0 {
			return nil, ErrInvalidDNSUpstream
		}
		return resp, nil
	}

	resultCh := make(chan []byte, len(s.dnsUpstreamServers))
	deadlineAt := time.Now().Add(timeout)
	next := 0
	inFlight := 0
	launchNext := func() bool {
		if next >= len(s.dnsUpstreamServers) || inFlight >= maxConcurrentDNSUpstreamQueries {
			return false
		}
		remaining := time.Until(deadlineAt)
		if remaining <= 0 {
			return false
		}
		upstream := s.dnsUpstreamServers[next]
		next++
		inFlight++
		go func(addr string) {
			resp, err := s.queryOneUpstream(addr, rawQuery, remaining)
			if err == nil && len(resp) > 0 {
				resultCh <- resp
				return
			}
			resultCh <- nil
		}(upstream)
		return true
	}

	launchNext()

	hedgeDelay := dnsUpstreamHedgeDelay(timeout)
	hedgeTicker := time.NewTicker(hedgeDelay)
	defer hedgeTicker.Stop()

	deadline := time.NewTimer(time.Until(deadlineAt))
	defer deadline.Stop()

	for inFlight > 0 {
		select {
		case resp := <-resultCh:
			inFlight--
			if len(resp) > 0 {
				return resp, nil
			}
			// A failed attempt frees one slot immediately. Continue through every
			// configured fallback without ever launching the full list at once.
			launchNext()
		case <-hedgeTicker.C:
			// Slow primary: add one hedge per interval, up to the per-request cap.
			launchNext()
		case <-deadline.C:
			return nil, ErrInvalidDNSUpstream
		}
	}

	return nil, ErrInvalidDNSUpstream
}

func dnsUpstreamHedgeDelay(timeout time.Duration) time.Duration {
	delay := timeout / 5
	if delay < 100*time.Millisecond {
		delay = 100 * time.Millisecond
	}
	if delay > 350*time.Millisecond {
		delay = 350 * time.Millisecond
	}
	if delay >= timeout {
		return timeout / 2
	}
	return delay
}

// queryOneUpstream sends rawQuery to a single upstream DNS server and returns
// the response. It is safe to call concurrently from multiple goroutines.
func (s *Server) queryOneUpstream(upstream string, rawQuery []byte, timeout time.Duration) ([]byte, error) {
	conn, err := newUDPUpstreamConn(upstream)
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rawQuery); err != nil {
		_ = conn.Close()
		return nil, err
	}

	bufferPtr := s.dnsUpstreamBufferPool.Get().(*[]byte)
	buffer := *bufferPtr
	n, readErr := conn.Read(buffer)
	_ = conn.Close()

	if readErr != nil || n == 0 {
		s.dnsUpstreamBufferPool.Put(bufferPtr)
		if readErr == nil {
			return nil, ErrInvalidDNSUpstream
		}
		return nil, readErr
	}

	if len(rawQuery) >= 2 && n >= 2 {
		if buffer[0] != rawQuery[0] || buffer[1] != rawQuery[1] {
			s.dnsUpstreamBufferPool.Put(bufferPtr)
			return nil, ErrInvalidDNSUpstream
		}
	}

	response := make([]byte, n)
	copy(response, buffer[:n])
	s.dnsUpstreamBufferPool.Put(bufferPtr)
	if !dnsResponseMatchesQuery(rawQuery, response) {
		return nil, ErrInvalidDNSUpstream
	}
	return response, nil
}

func dnsResponseMatchesQuery(query, response []byte) bool {
	request, err := DnsParser.ParseDNSRequestLite(query)
	if err != nil {
		return false
	}
	answer, err := DnsParser.ParsePacket(response)
	if err != nil || answer.Header.QR != 1 || answer.Header.ID != request.Header.ID ||
		answer.Header.OpCode != request.Header.OpCode || answer.Header.QDCount != request.Header.QDCount ||
		len(answer.Questions) != len(request.Questions) {
		return false
	}
	for i := range request.Questions {
		if !strings.EqualFold(request.Questions[i].Name, answer.Questions[i].Name) ||
			request.Questions[i].Type != answer.Questions[i].Type ||
			request.Questions[i].Class != answer.Questions[i].Class {
			return false
		}
	}
	return true
}

func newUDPUpstreamConn(endpoint string) (*net.UDPConn, error) {
	host, port, err := splitHostPortDefault53(endpoint)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}

func splitHostPortDefault53(value string) (string, string, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", "", ErrInvalidDNSUpstream
	}

	if strings.HasPrefix(text, "[") {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	if strings.Count(text, ":") == 0 {
		return text, "53", nil
	}
	if strings.Count(text, ":") == 1 {
		host, port, err := net.SplitHostPort(text)
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}

	return text, "53", nil
}
