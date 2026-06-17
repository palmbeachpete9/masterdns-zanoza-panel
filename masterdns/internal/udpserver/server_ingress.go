// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"time"

	"masterdnsvpn-go/internal/keyring"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// ingressGeneration is the immutable matcher+resolver pair published atomically
// on reload. A single request loads it once and uses it for both domain
// matching and decryption, so the two phases never straddle a reload (F25).
type ingressGeneration struct {
	matcher  *domainMatcher.Matcher
	resolver *keyring.Resolver // nil = legacy single-codec mode
	id       uint64
}

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	gen := s.ingress.Load()
	if gen == nil || gen.matcher == nil {
		return s.buildNoDataResponseLogged(packet, "ingress-not-ready")
	}

	decision := gen.matcher.Match(parsed)
	if decision.Action == domainMatcher.ActionProcess {
		response := s.handleTunnelCandidate(packet, parsed, decision, gen)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	}

	if decision.Action == domainMatcher.ActionFormatError || decision.Action == domainMatcher.ActionNoData {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
	}

	return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-no-data")
}

// SetKeyResolver installs the per-domain keyring (zanoza-panel fork). When
// set, inbound tunnel labels are decrypted with the key(s) bound to the
// queried domain instead of the single global codec.
func (s *Server) SetKeyResolver(resolver *keyring.Resolver) {
	// Publish a new generation that swaps the resolver while preserving the
	// current matcher (initial wiring), under a CAS retry loop.
	for {
		cur := s.ingress.Load()
		var m *domainMatcher.Matcher
		if cur != nil {
			m = cur.matcher
		}
		next := &ingressGeneration{matcher: m, resolver: resolver, id: s.ingressID.Add(1)}
		if s.ingress.CompareAndSwap(cur, next) {
			return
		}
	}
}

// ReloadKeyring builds an entire new ingress generation (matcher + resolver)
// from keyring.json and publishes it atomically as one unit. Called on SIGHUP
// so the panel can add/remove domains+keys without restarting (F25).
func (s *Server) ReloadKeyring(path string) error {
	resolver, err := keyring.Load(path)
	if err != nil {
		return err
	}
	next := &ingressGeneration{
		matcher:  domainMatcher.New(resolver.Domains(), s.cfg.MinVPNLabelLength),
		resolver: resolver,
		id:       s.ingressID.Add(1),
	}
	s.ingress.Store(next)
	// Acknowledge the applied content digest so the panel can confirm the
	// running server matches the exact desired keyring (R-03).
	if err := keyring.WriteApplied(path, resolver.Digest(), resolver.Generation()); err != nil {
		return err
	}
	return nil
}

// parseInboundLabels decrypts+parses tunnel labels using the resolver from the
// supplied generation, falling back to the legacy single codec.
func (s *Server) parseInboundLabels(gen *ingressGeneration, baseDomain, labels string) (VpnProto.Packet, error) {
	if gen != nil && gen.resolver != nil && !gen.resolver.Empty() {
		return gen.resolver.Parse(baseDomain, labels)
	}
	return VpnProto.ParseInflatedFromLabels(labels, s.codec)
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision, gen *ingressGeneration) []byte {
	vpnPacket, err := s.parseInboundLabels(gen, decision.BaseDomain, decision.Labels)
	if err != nil {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}
