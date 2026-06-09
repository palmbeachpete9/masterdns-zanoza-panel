// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package fragmentstore

import (
	"sync"
	"time"
)

// Byte bounds (F18): even within the entry-count caps, retained bytes must be
// bounded so valid traffic cannot exhaust memory.
const (
	defaultMaxFragmentBytes  = 16 * 1024        // one fragment
	defaultMaxAssembledBytes = 256 * 1024       // one full assembly
	defaultMaxStoreBytes     = 64 * 1024 * 1024 // all partial assemblies
)

type Store[K comparable] struct {
	mu           sync.Mutex
	items        map[K]*entry
	completed    map[K]time.Time
	lastPurge    time.Time
	maxPartial   int // hard cap on in-progress reassemblies (F18)
	maxCompleted int // hard cap on completion markers (F18)

	bytes             int // currently retained partial-assembly bytes (F18)
	maxFragmentBytes  int
	maxAssembledBytes int
	maxStoreBytes     int
}

type entry struct {
	createdAt      time.Time
	totalFragments uint8
	// chunks is sized to totalFragments, not a fixed [256][]byte — a flood of
	// single-/few-fragment partials no longer carries 256 slice headers (~6 KB)
	// of overhead each (F18).
	chunks []byte2D
	count  uint8
	bytes  int // sum of len(chunk) currently held by this entry
}

type byte2D = []byte

func New[K comparable](capacity int) *Store[K] {
	if capacity < 1 {
		capacity = 16
	}
	return &Store[K]{
		items:             make(map[K]*entry, capacity),
		completed:         make(map[K]time.Time, capacity),
		maxPartial:        capacity,
		maxCompleted:      capacity,
		maxFragmentBytes:  defaultMaxFragmentBytes,
		maxAssembledBytes: defaultMaxAssembledBytes,
		maxStoreBytes:     defaultMaxStoreBytes,
	}
}

// deleteItemLocked removes a partial entry and returns its bytes to the budget.
func (s *Store[K]) deleteItemLocked(key K) {
	if e, ok := s.items[key]; ok {
		if e != nil {
			s.bytes -= e.bytes
			if s.bytes < 0 {
				s.bytes = 0
			}
		}
		delete(s.items, key)
	}
}

func (s *Store[K]) Collect(key K, payload []byte, fragmentID, totalFragments uint8, now time.Time, retention time.Duration) ([]byte, bool, bool) {
	if totalFragments <= 1 {
		if retention <= 0 {
			return append([]byte(nil), payload...), true, false
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if now.Sub(s.lastPurge) >= time.Second {
			s.purgeLocked(now, retention)
			s.lastPurge = now
		}
		if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
			return nil, false, true
		}

		// Use the byte-aware delete: a single-fragment completion can land on a
		// key that already has a partial multi-fragment entry, whose retained
		// bytes must be returned to the budget (R-04).
		s.deleteItemLocked(key)
		if _, exists := s.completed[key]; !exists && len(s.completed) >= s.maxCompleted {
			s.evictOldestCompletedLocked()
		}
		s.completed[key] = now.Add(retention)
		return append([]byte(nil), payload...), true, false
	}

	if fragmentID >= totalFragments {
		return nil, false, false
	}
	// Reject an oversized fragment before copying anything (F18).
	if len(payload) > s.maxFragmentBytes {
		return nil, false, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if now.Sub(s.lastPurge) >= time.Second {
		s.purgeLocked(now, retention)
		s.lastPurge = now
	}

	if expiresAt, ok := s.completed[key]; ok && now.Before(expiresAt) {
		return nil, false, true
	}

	current, ok := s.items[key]
	if !ok || current.totalFragments != totalFragments {
		if !ok && len(s.items) >= s.maxPartial {
			// Bound memory: drop the oldest in-progress reassembly so a flood
			// of unique keys cannot grow the store without limit (F18).
			s.evictOldestPartialLocked()
		}
		if current != nil { // replacing a mismatched-totalFragments entry
			s.deleteItemLocked(key)
		}
		current = &entry{
			createdAt:      now,
			totalFragments: totalFragments,
			chunks:         make([]byte2D, totalFragments),
		}
		s.items[key] = current
	}

	// Byte accounting: compute the delta from replacing this slot, enforce the
	// per-assembly and whole-store byte budgets, evicting oldest partials to
	// make room before rejecting (F18).
	oldLen := len(current.chunks[fragmentID])
	delta := len(payload) - oldLen
	if current.bytes+delta > s.maxAssembledBytes {
		return nil, false, false
	}
	for s.bytes+delta > s.maxStoreBytes {
		if !s.evictOldestPartialExceptLocked(key, true) {
			return nil, false, false // nothing else to evict; refuse
		}
	}

	if current.chunks[fragmentID] == nil {
		current.count++
	}

	current.chunks[fragmentID] = append(current.chunks[fragmentID][:0], payload...)
	current.bytes += delta
	s.bytes += delta

	if current.count < totalFragments {
		return nil, false, false
	}

	totalSize := 0
	for idx := uint8(0); idx < totalFragments; idx++ {
		chunk := current.chunks[idx]
		if chunk == nil {
			return nil, false, false
		}
		totalSize += len(chunk)
	}

	assembled := make([]byte, 0, totalSize)
	for idx := uint8(0); idx < totalFragments; idx++ {
		assembled = append(assembled, current.chunks[idx]...)
	}

	s.deleteItemLocked(key)
	if retention > 0 {
		if _, exists := s.completed[key]; !exists && len(s.completed) >= s.maxCompleted {
			s.evictOldestCompletedLocked()
		}
		s.completed[key] = now.Add(retention)
	} else {
		delete(s.completed, key)
	}
	return assembled, true, false
}

// evictOldestPartialLocked deletes the oldest in-progress entry. Caller holds mu.
func (s *Store[K]) evictOldestPartialLocked() {
	s.evictOldestPartialExceptLocked(*new(K), false)
}

// evictOldestPartialExceptLocked drops the oldest partial entry, optionally
// excluding `except` (when hasExcept), returning whether one was evicted. Used
// to reclaim byte budget without dropping the entry currently being assembled.
func (s *Store[K]) evictOldestPartialExceptLocked(except K, hasExcept bool) bool {
	var oldestKey K
	var oldest time.Time
	found := false
	for k, e := range s.items {
		if hasExcept && k == except {
			continue
		}
		if e == nil {
			s.deleteItemLocked(k)
			return true
		}
		if !found || e.createdAt.Before(oldest) {
			oldest, oldestKey, found = e.createdAt, k, true
		}
	}
	if found {
		s.deleteItemLocked(oldestKey)
	}
	return found
}

// evictOldestCompletedLocked deletes the earliest-expiring marker. Caller holds mu.
func (s *Store[K]) evictOldestCompletedLocked() {
	var oldestKey K
	var oldest time.Time
	found := false
	for k, exp := range s.completed {
		if !found || exp.Before(oldest) {
			oldest, oldestKey, found = exp, k, true
		}
	}
	if found {
		delete(s.completed, oldestKey)
	}
}

func (s *Store[K]) Purge(now time.Time, retention time.Duration) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.purgeLocked(now, retention)
	s.mu.Unlock()
}

func (s *Store[K]) Remove(key K) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.deleteItemLocked(key)
	delete(s.completed, key)
	s.mu.Unlock()
}

func (s *Store[K]) RemoveIf(match func(K) bool) {
	if s == nil || match == nil {
		return
	}

	s.mu.Lock()
	for key := range s.items {
		if match(key) {
			s.deleteItemLocked(key)
		}
	}
	for key := range s.completed {
		if match(key) {
			delete(s.completed, key)
		}
	}
	s.mu.Unlock()
}

func (s *Store[K]) purgeLocked(now time.Time, retention time.Duration) {
	if retention <= 0 {
		for key := range s.items {
			s.deleteItemLocked(key)
		}
		for key := range s.completed {
			delete(s.completed, key)
		}
		return
	}

	deadline := now.Add(-retention)
	for key, current := range s.items {
		if current == nil || !current.createdAt.After(deadline) {
			s.deleteItemLocked(key)
		}
	}
	for key, expiresAt := range s.completed {
		if !now.Before(expiresAt) {
			delete(s.completed, key)
		}
	}
}
