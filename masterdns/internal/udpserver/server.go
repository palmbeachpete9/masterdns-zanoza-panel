// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"container/heap"
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"

	dnsCache "masterdnsvpn-go/internal/dnscache"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const (
	mtuProbeModeRaw     = 0
	mtuProbeModeBase64  = 1
	mtuProbeCodeLength  = 4
	mtuProbeMetaLength  = mtuProbeCodeLength + 2
	mtuProbeUpMinSize   = 1 + mtuProbeCodeLength
	mtuProbeDownMinSize = mtuProbeUpMinSize + 2
	mtuProbeMinDownSize = VpnProto.SessionAcceptPayloadSize
	mtuProbeMaxDownSize = 4096
)

var preSessionPacketTypes = buildPreSessionPacketTypes()

type Server struct {
	cfg   config.ServerConfig
	log   *logger.Logger
	codec *security.Codec
	// zanoza-panel fork: the domain matcher and per-domain key resolver are
	// published together as one immutable ingressGeneration through a single
	// atomic pointer, so a request can never match with generation N+1 and
	// decrypt with generation N (or vice versa) across a SIGHUP reload (F25).
	ingress                atomic.Pointer[ingressGeneration]
	ingressID              atomic.Uint64
	sessions               *sessionStore
	deferredDNSSession     *deferredSessionProcessor
	deferredConnectSession *deferredSessionProcessor
	invalidCookieTracker   *invalidCookieTracker
	dnsCache               *dnsCache.Store
	dnsResolveInflight     *dnsResolveInflightManager
	dnsUpstreamServers     []string
	dnsUpstreamBufferPool  sync.Pool
	dnsFragments           *fragmentStore.Store[dnsFragmentKey]
	socks5Fragments        *fragmentStore.Store[socks5FragmentKey]
	dnsFragmentTimeout     time.Duration
	resolveDNSQueryFn      func([]byte) ([]byte, error)
	dialStreamUpstreamFn   func(string, string, time.Duration) (net.Conn, error)
	// resolveIPAddrFn resolves a hostname to IPs for SOCKS target authorization.
	// Injectable for deterministic rebinding tests (F19); nil = DNS default.
	resolveIPAddrFn          func(context.Context, string) ([]net.IPAddr, error)
	uploadCompressionMask    uint8
	downloadCompressionMask  uint8
	dropLogIntervalNanos     int64
	invalidCookieWindow      time.Duration
	invalidCookieWindowNanos int64
	invalidCookieThreshold   int
	socksConnectTimeout      time.Duration
	useExternalSOCKS5        bool
	externalSOCKS5Address    string
	externalSOCKS5Auth       bool
	externalSOCKS5User       []byte
	externalSOCKS5Pass       []byte
	mtuProbePayloadPool      sync.Pool
	packetPool               sync.Pool
	deferredInflightMu       sync.Mutex
	deferredInflight         map[uint64]struct{}
	deferredInflightIndex    map[uint8]map[uint16]map[uint64]struct{}
	invalidSessionDropLog    throttledLogState
	droppedPackets           atomic.Uint64
	lastDropLogUnix          atomic.Int64
	deferredDroppedPackets   atomic.Uint64
	lastDeferredDropLogUnix  atomic.Int64
	pongNonce                atomic.Uint32
	invalidDropMode          atomic.Uint32
}

type request struct {
	buf        []byte
	size       int
	addr       *net.UDPAddr
	conn       *net.UDPConn
	poolBuffer *[]byte
}

type postSessionValidation struct {
	record   *sessionRuntimeView
	response []byte
	ok       bool
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	if log == nil {
		// New is also used as a library constructor. Supplying nil must not
		// leave dozens of runtime logging paths able to panic.
		log = logger.New("MasterDnsVPN Server", cfg.LogLevel)
	}
	invalidCookieWindow := cfg.InvalidCookieWindow()
	if invalidCookieWindow <= 0 {
		invalidCookieWindow = 2 * time.Second
	}
	dnsFragmentTimeout := cfg.DNSFragmentAssemblyTimeout()
	if dnsFragmentTimeout <= 0 {
		dnsFragmentTimeout = 5 * time.Minute
	}
	dropLogInterval := cfg.DropLogInterval()
	if dropLogInterval <= 0 {
		dropLogInterval = 2 * time.Second
	}
	socksConnectTimeout := cfg.SOCKSConnectTimeout()
	if socksConnectTimeout <= 0 {
		socksConnectTimeout = 8 * time.Second
	}
	dnsDeferredWorkers, connectDeferredWorkers, dnsDeferredQueue, connectDeferredQueue := splitDeferredSessionPools(cfg.EffectiveDeferredSessionWorkers(), cfg.EffectiveDeferredSessionQueueLimit())
	sessions := newSessionStore(cfg.EffectiveSessionOrphanQueueInitialCap(), cfg.EffectiveStreamQueueInitialCapacity(), cfg.SessionInitReuseTTL(), cfg.RecentlyClosedStreamTTL(), cfg.RecentlyClosedStreamCap)
	sessions.maxActiveSessions = cfg.MaxAllowedClientActiveSessions
	sessions.maxActiveStreams = cfg.MaxAllowedClientActiveStreams
	srv := &Server{
		cfg:                    cfg,
		log:                    log,
		codec:                  codec,
		sessions:               sessions,
		deferredDNSSession:     newDeferredSessionProcessor(dnsDeferredWorkers, dnsDeferredQueue, log),
		deferredConnectSession: newDeferredSessionProcessor(connectDeferredWorkers, connectDeferredQueue, log),
		invalidCookieTracker:   newInvalidCookieTracker(),
		dnsCache: dnsCache.New(
			cfg.EffectiveDNSCacheMaxRecords(),
			time.Duration(cfg.DNSCacheTTLSeconds*float64(time.Second)),
			dnsFragmentTimeout,
		),
		dnsResolveInflight: newDNSResolveInflightManager(dnsFragmentTimeout),
		dnsUpstreamServers: append([]string(nil), cfg.DNSUpstreamServers...),
		dnsFragments:       fragmentStore.New[dnsFragmentKey](cfg.EffectiveDNSFragmentStoreCapacity()),
		socks5Fragments:    fragmentStore.New[socks5FragmentKey](cfg.EffectiveSOCKS5FragmentStoreCapacity()),
		dnsFragmentTimeout: dnsFragmentTimeout,
		dnsUpstreamBufferPool: sync.Pool{
			New: func() any {
				buffer := make([]byte, 65535)
				return &buffer
			},
		},
		dialStreamUpstreamFn: func(network, address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(network, address, timeout)
		},
		uploadCompressionMask:    buildCompressionMask(cfg.SupportedUploadCompressionTypes),
		downloadCompressionMask:  buildCompressionMask(cfg.SupportedDownloadCompressionTypes),
		dropLogIntervalNanos:     dropLogInterval.Nanoseconds(),
		invalidCookieWindow:      invalidCookieWindow,
		invalidCookieWindowNanos: invalidCookieWindow.Nanoseconds(),
		invalidCookieThreshold:   cfg.InvalidCookieErrorThreshold,
		socksConnectTimeout:      socksConnectTimeout,
		useExternalSOCKS5:        cfg.UseExternalSOCKS5,
		externalSOCKS5Address:    net.JoinHostPort(cfg.ForwardIP, strconv.Itoa(cfg.ForwardPort)),
		externalSOCKS5Auth:       cfg.SOCKS5Auth,
		externalSOCKS5User:       []byte(cfg.SOCKS5User),
		externalSOCKS5Pass:       []byte(cfg.SOCKS5Pass),
		mtuProbePayloadPool: sync.Pool{
			New: func() any {
				buffer := make([]byte, mtuProbeMaxDownSize)
				return &buffer
			},
		},
		deferredInflight:      make(map[uint64]struct{}, 128),
		deferredInflightIndex: make(map[uint8]map[uint16]map[uint64]struct{}, 64),
		packetPool: sync.Pool{
			New: func() any {
				buffer := make([]byte, cfg.MaxPacketSize)
				return &buffer
			},
		},
	}
	srv.ingress.Store(&ingressGeneration{
		matcher: domainMatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		id:      srv.ingressID.Add(1),
	})
	return srv
}

type throttledLogState struct {
	mu   sync.Mutex
	last map[string]int64
	heap throttledLogHeap
}

type throttledLogEntry struct {
	key  string
	seen int64
}

type throttledLogHeap []throttledLogEntry

func (h throttledLogHeap) Len() int { return len(h) }

func (h throttledLogHeap) Less(i, j int) bool {
	return h[i].seen < h[j].seen
}

func (h throttledLogHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *throttledLogHeap) Push(x any) {
	*h = append(*h, x.(throttledLogEntry))
}

func (h *throttledLogHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

const (
	throttledLogSoftCap = 1024
	throttledLogHardCap = 1536
)

func (s *throttledLogState) allow(key string, now time.Time, interval time.Duration) bool {
	if s == nil {
		return true
	}
	if interval <= 0 {
		interval = time.Second
	}

	nowUnixNano := now.UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.last == nil {
		s.last = make(map[string]int64, 64)
	}

	last := s.last[key]

	if last != 0 && nowUnixNano-last < interval.Nanoseconds() {
		return false
	}

	s.last[key] = nowUnixNano
	heap.Push(&s.heap, throttledLogEntry{key: key, seen: nowUnixNano})

	if len(s.last) > 0 {
		s.pruneLocked(nowUnixNano, interval)
	}

	return true
}

func (s *throttledLogState) pruneLocked(nowUnixNano int64, interval time.Duration) {
	if s == nil || len(s.last) == 0 {
		return
	}

	cutoff := nowUnixNano - interval.Nanoseconds()
	for len(s.heap) > 0 {
		entry := s.heap[0]
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			heap.Pop(&s.heap)
			continue
		}
		if entry.seen > cutoff && len(s.last) <= throttledLogHardCap {
			break
		}
		delete(s.last, entry.key)
		heap.Pop(&s.heap)
	}

	for len(s.last) > throttledLogSoftCap && len(s.heap) > 0 {
		entry := heap.Pop(&s.heap).(throttledLogEntry)
		last, ok := s.last[entry.key]
		if !ok || last != entry.seen {
			continue
		}
		delete(s.last, entry.key)
	}
}

func splitDeferredSessionPools(totalWorkers, totalQueue int) (dnsWorkers, connectWorkers, dnsQueue, connectQueue int) {
	if totalWorkers <= 0 {
		totalWorkers = 1
	}
	if totalQueue <= 0 {
		totalQueue = 256
	}

	// DNS queries use a dedicated lightweight pool so connect-heavy work keeps
	// the full user-configured deferred capacity.
	dnsWorkers = 1
	connectWorkers = totalWorkers

	connectQueue = totalQueue
	dnsQueue = min(max(totalQueue/4, 64), 256)

	return dnsWorkers, connectWorkers, dnsQueue, connectQueue
}

func (s *Server) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	conns, err := s.openUDPListeners()
	if err != nil {
		return err
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	s.log.Infof(
		"\U0001F4E1 <green>UDP Listener Ready, Addr: <cyan>%s</cyan>, Readers: <cyan>%d</cyan>, Workers: <cyan>%d</cyan>, Queue: <cyan>%d</cyan>, Sockets: <cyan>%d</cyan></green>",
		s.cfg.Address(),
		s.cfg.EffectiveUDPReaders(),
		s.cfg.EffectiveDNSRequestWorkers(),
		s.cfg.EffectiveRequestQueueCapacity(),
		len(conns),
	)

	reqCh := make(chan request, s.cfg.EffectiveRequestQueueCapacity())
	var workerWG sync.WaitGroup
	cleanupDone := make(chan struct{})

	go func() {
		defer close(cleanupDone)
		s.sessionCleanupLoop(runCtx)
	}()

	s.deferredDNSSession.Start(runCtx)
	s.deferredConnectSession.Start(runCtx)
	s.startDNSWorkers(runCtx, conns[0], reqCh, &workerWG)

	go func() {
		<-runCtx.Done()
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()

	readErrCh := make(chan error, max(1, len(conns)))
	var readerWG sync.WaitGroup
	s.startReaders(runCtx, conns, reqCh, readErrCh, &readerWG)

	var readErr error
	select {
	case <-runCtx.Done():
	case readErr = <-readErrCh:
		// One unexpected socket read failure is fatal for this Run generation.
		// Cancel immediately so the close watcher releases every other reader;
		// waiting for all readers before observing readErr would otherwise hang
		// forever on the still-healthy sockets.
		cancel()
	}
	readerWG.Wait()
	close(reqCh)
	workerWG.Wait()
	cancel()
	<-cleanupDone

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return readErr
}
