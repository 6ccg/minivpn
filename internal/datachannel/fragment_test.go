package datachannel

import (
	"bytes"
	"testing"
	"time"
)

// TestParseFragmentHeader tests fragment header parsing
func TestParseFragmentHeader(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantType int
		wantSeq  int
		wantFrag int
		wantSize int
		wantErr  bool
	}{
		{
			name:     "whole packet",
			data:     BuildFragmentHeader(FragWhole, 0, 0, 0),
			wantType: FragWhole,
			wantSeq:  0,
			wantFrag: 0,
			wantSize: 0,
		},
		{
			name:     "first fragment",
			data:     BuildFragmentHeader(FragYesNotLast, 42, 0, 0),
			wantType: FragYesNotLast,
			wantSeq:  42,
			wantFrag: 0,
			wantSize: 0,
		},
		{
			name:     "last fragment with size",
			data:     BuildFragmentHeader(FragYesLast, 100, 5, 512),
			wantType: FragYesLast,
			wantSeq:  100,
			wantFrag: 5,
			wantSize: 512,
		},
		{
			name:    "too short",
			data:    []byte{0, 0, 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := ParseFragmentHeader(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if header.FragType != tt.wantType {
				t.Errorf("FragType = %d, want %d", header.FragType, tt.wantType)
			}
			if header.SeqID != tt.wantSeq {
				t.Errorf("SeqID = %d, want %d", header.SeqID, tt.wantSeq)
			}
			if header.FragID != tt.wantFrag {
				t.Errorf("FragID = %d, want %d", header.FragID, tt.wantFrag)
			}
			if tt.wantType == FragYesLast && header.FragSize != tt.wantSize {
				t.Errorf("FragSize = %d, want %d", header.FragSize, tt.wantSize)
			}
		})
	}
}

// TestBuildFragmentHeader tests fragment header construction
func TestBuildFragmentHeader(t *testing.T) {
	// Test round-trip
	tests := []struct {
		fragType int
		seqID    int
		fragID   int
		fragSize int
	}{
		{FragWhole, 0, 0, 0},
		{FragYesNotLast, 127, 15, 0},
		{FragYesLast, 255, 31, 1024},
		{FragYesLast, 0, 0, 4},
	}

	for _, tt := range tests {
		data := BuildFragmentHeader(tt.fragType, tt.seqID, tt.fragID, tt.fragSize)
		if len(data) != FragHeaderSize {
			t.Errorf("header size = %d, want %d", len(data), FragHeaderSize)
		}

		header, err := ParseFragmentHeader(data)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if header.FragType != tt.fragType {
			t.Errorf("FragType = %d, want %d", header.FragType, tt.fragType)
		}
		if header.SeqID != tt.seqID {
			t.Errorf("SeqID = %d, want %d", header.SeqID, tt.seqID)
		}
		if header.FragID != tt.fragID {
			t.Errorf("FragID = %d, want %d", header.FragID, tt.fragID)
		}
		if tt.fragType == FragYesLast && header.FragSize != tt.fragSize {
			t.Errorf("FragSize = %d, want %d", header.FragSize, tt.fragSize)
		}
	}
}

// TestFragmentMaster_NoFragment tests that small packets are not fragmented
func TestFragmentMaster_NoFragment(t *testing.T) {
	fm := NewFragmentMaster(nil, 1400)

	// Small packet - should not be fragmented
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	result, err := fm.FragmentOutgoing(data)
	if err != nil {
		t.Fatalf("FragmentOutgoing error: %v", err)
	}

	// Should have FragWhole header
	header, err := ParseFragmentHeader(result)
	if err != nil {
		t.Fatalf("ParseFragmentHeader error: %v", err)
	}
	if header.FragType != FragWhole {
		t.Errorf("FragType = %d, want FragWhole (%d)", header.FragType, FragWhole)
	}

	// Payload should match original
	payload := result[FragHeaderSize:]
	if !bytes.Equal(payload, data) {
		t.Error("payload mismatch")
	}

	// No more fragments pending
	_, ok := fm.FragmentReadyToSend()
	if ok {
		t.Error("unexpected pending fragments")
	}
}

// TestFragmentMaster_Fragment tests that large packets are fragmented
func TestFragmentMaster_Fragment(t *testing.T) {
	maxSize := 500
	fm := NewFragmentMaster(nil, maxSize)

	// Create packet larger than max size
	dataSize := 1200
	data := make([]byte, dataSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Get first fragment
	frag1, err := fm.FragmentOutgoing(data)
	if err != nil {
		t.Fatalf("FragmentOutgoing error: %v", err)
	}

	header1, _ := ParseFragmentHeader(frag1)
	if header1.FragType != FragYesNotLast {
		t.Errorf("first fragment type = %d, want FragYesNotLast (%d)", header1.FragType, FragYesNotLast)
	}

	// Collect all fragments
	fragments := [][]byte{frag1}
	for {
		frag, ok := fm.FragmentReadyToSend()
		if !ok {
			break
		}
		fragments = append(fragments, frag)
	}

	if len(fragments) < 2 {
		t.Errorf("expected multiple fragments, got %d", len(fragments))
	}

	// Last fragment should have FragYesLast type
	lastFrag := fragments[len(fragments)-1]
	lastHeader, _ := ParseFragmentHeader(lastFrag)
	if lastHeader.FragType != FragYesLast {
		t.Errorf("last fragment type = %d, want FragYesLast (%d)", lastHeader.FragType, FragYesLast)
	}
}

// TestFragmentMaster_Reassembly tests in-order fragment reassembly
func TestFragmentMaster_Reassembly(t *testing.T) {
	maxSize := 500
	fmSend := NewFragmentMaster(nil, maxSize)
	fmRecv := NewFragmentMaster(nil, maxSize)

	// Create and fragment a packet
	originalData := make([]byte, 1200)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	frag1, err := fmSend.FragmentOutgoing(originalData)
	if err != nil {
		t.Fatalf("FragmentOutgoing error: %v", err)
	}

	// Collect all fragments
	fragments := [][]byte{frag1}
	for {
		frag, ok := fmSend.FragmentReadyToSend()
		if !ok {
			break
		}
		fragments = append(fragments, frag)
	}

	// Reassemble in order
	var reassembled []byte
	for i, frag := range fragments {
		result, err := fmRecv.FragmentIncoming(frag)
		if err != nil {
			t.Fatalf("FragmentIncoming error on fragment %d: %v", i, err)
		}
		if result != nil {
			reassembled = result
		}
	}

	if reassembled == nil {
		t.Fatal("reassembly failed: no result")
	}

	if !bytes.Equal(reassembled, originalData) {
		t.Errorf("reassembled data mismatch: got %d bytes, want %d bytes", len(reassembled), len(originalData))
	}
}

// TestFragmentMaster_OutOfOrder tests out-of-order fragment reassembly
func TestFragmentMaster_OutOfOrder(t *testing.T) {
	maxSize := 500
	fmSend := NewFragmentMaster(nil, maxSize)
	fmRecv := NewFragmentMaster(nil, maxSize)

	// Create and fragment a packet
	originalData := make([]byte, 1200)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	frag1, _ := fmSend.FragmentOutgoing(originalData)
	fragments := [][]byte{frag1}
	for {
		frag, ok := fmSend.FragmentReadyToSend()
		if !ok {
			break
		}
		fragments = append(fragments, frag)
	}

	if len(fragments) < 3 {
		t.Skip("need at least 3 fragments for out-of-order test")
	}

	// Send in reverse order (except keep first fragment last)
	order := make([]int, len(fragments))
	for i := range order {
		order[i] = len(fragments) - 1 - i
	}

	var reassembled []byte
	for _, idx := range order {
		result, err := fmRecv.FragmentIncoming(fragments[idx])
		if err != nil {
			t.Fatalf("FragmentIncoming error: %v", err)
		}
		if result != nil {
			reassembled = result
		}
	}

	if reassembled == nil {
		t.Fatal("out-of-order reassembly failed")
	}

	if !bytes.Equal(reassembled, originalData) {
		t.Errorf("reassembled data mismatch")
	}
}

// TestFragmentMaster_WholePacket tests receiving a whole (unfragmented) packet
func TestFragmentMaster_WholePacket(t *testing.T) {
	fm := NewFragmentMaster(nil, 1400)

	// Create a "whole" packet
	originalData := []byte("hello world")
	header := BuildFragmentHeader(FragWhole, 0, 0, 0)
	packet := append(header, originalData...)

	result, err := fm.FragmentIncoming(packet)
	if err != nil {
		t.Fatalf("FragmentIncoming error: %v", err)
	}

	if !bytes.Equal(result, originalData) {
		t.Errorf("data mismatch: got %q, want %q", result, originalData)
	}
}

// TestOptimalFragmentSize tests the optimal fragment size calculation
func TestOptimalFragmentSize(t *testing.T) {
	tests := []struct {
		dataLen    int
		maxFrag    int
		wantAligned bool
	}{
		{100, 500, true},
		{1000, 400, true},
		{1500, 500, true},
	}

	for _, tt := range tests {
		size := optimalFragmentSize(tt.dataLen, tt.maxFrag)
		if size > tt.maxFrag {
			t.Errorf("optimalFragmentSize(%d, %d) = %d, exceeds max", tt.dataLen, tt.maxFrag, size)
		}
		if tt.wantAligned && (size&FragSizeRoundMask) != 0 {
			t.Errorf("optimalFragmentSize(%d, %d) = %d, not aligned to 4", tt.dataLen, tt.maxFrag, size)
		}
	}
}

// TestFragmentMaster_TTLExpiry tests fragment TTL expiration
func TestFragmentMaster_TTLExpiry(t *testing.T) {
	fm := NewFragmentMaster(nil, 500)
	// Force immediate wakeup check
	fm.lastWakeup = time.Now().Add(-FragWakeupInterval * time.Second * 2)

	// Send first fragment only (incomplete reassembly)
	header := BuildFragmentHeader(FragYesNotLast, 1, 0, 0)
	payload := make([]byte, 100)
	packet := append(header, payload...)

	_, err := fm.FragmentIncoming(packet)
	if err != nil {
		t.Fatalf("FragmentIncoming error: %v", err)
	}

	// Manually expire the fragment
	fm.mu.Lock()
	for i := 0; i < NFragBuf; i++ {
		if fm.incoming.fragments[i].defined {
			fm.incoming.fragments[i].timestamp = time.Now().Add(-FragTTLSec * time.Second * 2)
		}
	}
	fm.lastWakeup = time.Now().Add(-FragWakeupInterval * time.Second * 2)
	fm.mu.Unlock()

	// Trigger housekeeping by processing another packet
	header2 := BuildFragmentHeader(FragWhole, 0, 0, 0)
	packet2 := append(header2, []byte("test")...)
	_, _ = fm.FragmentIncoming(packet2)

	// Verify expired buffer was cleaned
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for i := 0; i < NFragBuf; i++ {
		if fm.incoming.fragments[i].defined && time.Since(fm.incoming.fragments[i].timestamp) > FragTTLSec*time.Second {
			t.Error("expired fragment buffer was not cleaned")
		}
	}
}

// TestFragmentMaster_SeqWrap tests sequence ID wraparound
func TestFragmentMaster_SeqWrap(t *testing.T) {
	fm := NewFragmentMaster(nil, 500)

	// Set seq ID near wrap point
	fm.mu.Lock()
	fm.outgoingSeqID = NSeqID - 1
	fm.mu.Unlock()

	data := make([]byte, 1000)

	// First packet should use seq 0 (after increment from 255)
	frag1, _ := fm.FragmentOutgoing(data)
	header1, _ := ParseFragmentHeader(frag1)

	if header1.SeqID != 0 {
		t.Errorf("expected seq ID 0 after wrap, got %d", header1.SeqID)
	}

	// Drain fragments
	for {
		_, ok := fm.FragmentReadyToSend()
		if !ok {
			break
		}
	}

	// Next packet should use seq 1
	frag2, _ := fm.FragmentOutgoing(data)
	header2, _ := ParseFragmentHeader(frag2)

	if header2.SeqID != 1 {
		t.Errorf("expected seq ID 1, got %d", header2.SeqID)
	}
}

// TestModuloSubtract tests the modulo subtraction helper
func TestModuloSubtract(t *testing.T) {
	tests := []struct {
		a, b, mod int
		want      int
	}{
		{5, 3, 256, 2},
		{3, 5, 256, -2},
		{255, 0, 256, -1},  // wraparound case
		{0, 255, 256, 1},   // wraparound case
		{200, 50, 256, -106}, // large forward wrap
		{50, 200, 256, 106},  // large backward wrap
	}

	for _, tt := range tests {
		got := moduloSubtract(tt.a, tt.b, tt.mod)
		if got != tt.want {
			t.Errorf("moduloSubtract(%d, %d, %d) = %d, want %d", tt.a, tt.b, tt.mod, got, tt.want)
		}
	}
}

// TestFragmentMaster_TooManyFragments tests error when packet is too large
func TestFragmentMaster_TooManyFragments(t *testing.T) {
	fm := NewFragmentMaster(nil, 100) // Small max size

	// Create data that would need more than MaxFrags fragments
	dataSize := (100 - FragHeaderSize) * MaxFrags * 2
	data := make([]byte, dataSize)

	_, err := fm.FragmentOutgoing(data)
	if err != ErrFragmentTooMany {
		t.Errorf("expected ErrFragmentTooMany, got %v", err)
	}
}

// TestFragmentMaster_HasPendingFragments tests pending fragment detection
func TestFragmentMaster_HasPendingFragments(t *testing.T) {
	fm := NewFragmentMaster(nil, 500)

	// Initially no pending
	if fm.HasPendingFragments() {
		t.Error("expected no pending fragments initially")
	}

	// Fragment a large packet
	data := make([]byte, 1000)
	_, _ = fm.FragmentOutgoing(data)

	// Should have pending
	if !fm.HasPendingFragments() {
		t.Error("expected pending fragments after fragmenting large packet")
	}

	// Drain all fragments
	for {
		_, ok := fm.FragmentReadyToSend()
		if !ok {
			break
		}
	}

	// No more pending
	if fm.HasPendingFragments() {
		t.Error("expected no pending fragments after draining")
	}
}
