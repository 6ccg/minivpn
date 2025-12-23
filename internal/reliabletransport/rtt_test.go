package reliabletransport

import (
	"testing"
	"time"
)

func TestRTTTracker_Update(t *testing.T) {
	tests := []struct {
		name            string
		samples         []time.Duration
		wantInitialized bool
		wantSRTTRange   [2]time.Duration // [min, max] expected range
	}{
		{
			name:            "no samples",
			samples:         nil,
			wantInitialized: false,
			wantSRTTRange:   [2]time.Duration{0, 0},
		},
		{
			name:            "single sample",
			samples:         []time.Duration{100 * time.Millisecond},
			wantInitialized: true,
			wantSRTTRange:   [2]time.Duration{100 * time.Millisecond, 100 * time.Millisecond},
		},
		{
			name:            "multiple samples converge",
			samples:         []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond},
			wantInitialized: true,
			wantSRTTRange:   [2]time.Duration{100 * time.Millisecond, 100 * time.Millisecond},
		},
		{
			name:            "samples with variation",
			samples:         []time.Duration{80 * time.Millisecond, 120 * time.Millisecond, 100 * time.Millisecond},
			wantInitialized: true,
			wantSRTTRange:   [2]time.Duration{80 * time.Millisecond, 120 * time.Millisecond},
		},
		{
			name:            "zero sample ignored",
			samples:         []time.Duration{0},
			wantInitialized: false,
			wantSRTTRange:   [2]time.Duration{0, 0},
		},
		{
			name:            "negative sample ignored",
			samples:         []time.Duration{-10 * time.Millisecond},
			wantInitialized: false,
			wantSRTTRange:   [2]time.Duration{0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := newRTTTracker()

			for _, sample := range tt.samples {
				tracker.Update(sample)
			}

			if tracker.initialized != tt.wantInitialized {
				t.Errorf("initialized = %v, want %v", tracker.initialized, tt.wantInitialized)
			}

			srtt := tracker.SmoothedRTT()
			if srtt < tt.wantSRTTRange[0] || srtt > tt.wantSRTTRange[1] {
				t.Errorf("SmoothedRTT() = %v, want in range [%v, %v]",
					srtt, tt.wantSRTTRange[0], tt.wantSRTTRange[1])
			}
		})
	}
}

func TestRTTTracker_GracePeriod(t *testing.T) {
	tests := []struct {
		name      string
		samples   []time.Duration
		wantGrace time.Duration
	}{
		{
			name:      "no samples uses default",
			samples:   nil,
			wantGrace: gracePeriodForOutgoingACKs, // 20ms default
		},
		{
			name:      "low RTT uses minimum grace",
			samples:   []time.Duration{10 * time.Millisecond},
			wantGrace: 5 * time.Millisecond, // min grace
		},
		{
			name:      "medium RTT uses RTT/4",
			samples:   []time.Duration{80 * time.Millisecond},
			wantGrace: 20 * time.Millisecond, // 80ms / 4
		},
		{
			name:      "high RTT uses maximum grace",
			samples:   []time.Duration{400 * time.Millisecond},
			wantGrace: 50 * time.Millisecond, // max grace
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := newRTTTracker()

			for _, sample := range tt.samples {
				tracker.Update(sample)
			}

			got := tracker.GracePeriod()
			if got != tt.wantGrace {
				t.Errorf("GracePeriod() = %v, want %v", got, tt.wantGrace)
			}
		})
	}
}

func TestRTTTracker_Concurrency(t *testing.T) {
	tracker := newRTTTracker()
	done := make(chan bool)

	// Concurrent updates
	go func() {
		for i := 0; i < 100; i++ {
			tracker.Update(time.Duration(50+i) * time.Millisecond)
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			_ = tracker.SmoothedRTT()
			_ = tracker.GracePeriod()
		}
		done <- true
	}()

	<-done
	<-done

	// Should not panic and should have valid state
	if tracker.SmoothedRTT() < 0 {
		t.Error("SmoothedRTT should not be negative")
	}
}
