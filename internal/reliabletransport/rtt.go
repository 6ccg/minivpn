package reliabletransport

import (
	"sync"
	"time"
)

// rttTracker implements exponential weighted moving average (EWMA) RTT estimation,
// similar to TCP's SRTT algorithm (RFC 6298).
type rttTracker struct {
	mu sync.Mutex

	// smoothedRTT is the exponentially weighted moving average of RTT samples.
	smoothedRTT time.Duration

	// rttVar is the mean deviation of RTT samples.
	rttVar time.Duration

	// initialized indicates whether we have received at least one RTT sample.
	initialized bool
}

// newRTTTracker creates a new RTT tracker with default values.
func newRTTTracker() *rttTracker {
	return &rttTracker{
		smoothedRTT: 0,
		rttVar:      0,
		initialized: false,
	}
}

// Update updates the RTT estimate with a new sample.
// Uses the algorithm from RFC 6298:
//   - RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
//   - SRTT = (1 - alpha) * SRTT + alpha * R
//
// where alpha = 1/8 and beta = 1/4.
func (r *rttTracker) Update(sample time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sample <= 0 {
		return
	}

	if !r.initialized {
		// First sample: initialize SRTT and RTTVAR
		r.smoothedRTT = sample
		r.rttVar = sample / 2
		r.initialized = true
		return
	}

	// Calculate deviation
	diff := r.smoothedRTT - sample
	if diff < 0 {
		diff = -diff
	}

	// RTTVAR = (1 - 1/4) * RTTVAR + 1/4 * |SRTT - R|
	r.rttVar = (3*r.rttVar + diff) / 4

	// SRTT = (1 - 1/8) * SRTT + 1/8 * R
	r.smoothedRTT = (7*r.smoothedRTT + sample) / 8
}

// SmoothedRTT returns the current smoothed RTT estimate.
// Returns 0 if no samples have been received yet.
func (r *rttTracker) SmoothedRTT() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.smoothedRTT
}

// RTTVar returns the current RTT variance estimate.
func (r *rttTracker) RTTVar() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rttVar
}

// GracePeriod calculates a dynamic grace period for ACK batching based on current RTT.
// The grace period is set to SRTT/4, bounded by min and max values.
// This allows faster ACK responses on low-latency links while still providing
// reasonable batching on high-latency links.
func (r *rttTracker) GracePeriod() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.initialized {
		// Fall back to default if no RTT data available
		return gracePeriodForOutgoingACKs
	}

	// Use SRTT/4 as the grace period
	grace := r.smoothedRTT / 4

	// Apply bounds
	const minGrace = 5 * time.Millisecond
	const maxGrace = 50 * time.Millisecond

	if grace < minGrace {
		grace = minGrace
	}
	if grace > maxGrace {
		grace = maxGrace
	}

	return grace
}
