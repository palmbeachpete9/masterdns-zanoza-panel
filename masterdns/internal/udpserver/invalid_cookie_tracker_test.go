package udpserver

import (
	"testing"
	"time"
)

func TestInvalidCookieTrackerStaysBoundedUnderKeySpray(t *testing.T) {
	tracker := newInvalidCookieTracker()
	tracker.maxRecords = 2
	now := time.Now().UnixNano()
	window := time.Minute.Nanoseconds()

	tracker.Note(1, sessionLookupResult{}, false, 1, now, window, 2)
	tracker.Note(2, sessionLookupResult{}, false, 2, now, window, 2)
	tracker.Note(3, sessionLookupResult{}, false, 3, now, window, 2)

	if got := len(tracker.records); got != tracker.maxRecords {
		t.Fatalf("record count = %d, want bounded at %d", got, tracker.maxRecords)
	}
}

func TestInvalidCookieTrackerCapsPerKeyAttemptHistory(t *testing.T) {
	tracker := newInvalidCookieTracker()
	now := time.Now().UnixNano()
	for i := 0; i < maxInvalidCookieAttempts*2; i++ {
		tracker.Note(1, sessionLookupResult{}, false, 1, now+int64(i), time.Minute.Nanoseconds(), maxInvalidCookieAttempts*100)
	}
	for _, record := range tracker.records {
		if got := len(record.attempts); got > maxInvalidCookieAttempts {
			t.Fatalf("attempt history grew to %d, max %d", got, maxInvalidCookieAttempts)
		}
	}
}
