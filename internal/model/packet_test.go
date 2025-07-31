package model

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewOpcodeFromString(t *testing.T) {
	tests := []struct {
		name    string
		str     string
		want    Opcode
		wantErr bool
	}{
		{
			name:    "hard reset client v1",
			str:     "CONTROL_HARD_RESET_CLIENT_V1",
			want:    P_CONTROL_HARD_RESET_CLIENT_V1,
			wantErr: false,
		},
		{
			name:    "control hard reset server v1",
			str:     "CONTROL_HARD_RESET_SERVER_V1",
			want:    P_CONTROL_HARD_RESET_SERVER_V1,
			wantErr: false,
		},
		{
			name:    "control hard reset client v2",
			str:     "CONTROL_HARD_RESET_CLIENT_V2",
			want:    P_CONTROL_HARD_RESET_CLIENT_V2,
			wantErr: false,
		},
		{
			name:    "control hard reset server v2",
			str:     "CONTROL_HARD_RESET_SERVER_V2",
			want:    P_CONTROL_HARD_RESET_SERVER_V2,
			wantErr: false,
		},
		{
			name:    "soft reset v1",
			str:     "CONTROL_SOFT_RESET_V1",
			want:    P_CONTROL_SOFT_RESET_V1,
			wantErr: false,
		},
		{
			name:    "control v1",
			str:     "CONTROL_V1",
			want:    P_CONTROL_V1,
			wantErr: false,
		},
		{
			name:    "ack v1",
			str:     "ACK_V1",
			want:    P_ACK_V1,
			wantErr: false,
		},
		{
			name:    "data v1",
			str:     "DATA_V1",
			want:    P_DATA_V1,
			wantErr: false,
		},
		{
			name:    "data v2",
			str:     "DATA_V2",
			want:    P_DATA_V2,
			wantErr: false,
		},
		{
			name:    "wrong",
			str:     "UNKNOWN",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty",
			str:     "",
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOpcodeFromString(tt.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOpcodeFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NewOpcodeFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpcode_String(t *testing.T) {
	t.Run("known opcode to string should not fail", func(t *testing.T) {
		opcodes := map[Opcode]string{
			P_CONTROL_HARD_RESET_CLIENT_V1: "P_CONTROL_HARD_RESET_CLIENT_V1",
			P_CONTROL_HARD_RESET_SERVER_V1: "P_CONTROL_HARD_RESET_SERVER_V1",
			P_CONTROL_SOFT_RESET_V1:        "P_CONTROL_SOFT_RESET_V1",
			P_CONTROL_V1:                   "P_CONTROL_V1",
			P_ACK_V1:                       "P_ACK_V1",
			P_DATA_V1:                      "P_DATA_V1",
			P_CONTROL_HARD_RESET_CLIENT_V2: "P_CONTROL_HARD_RESET_CLIENT_V2",
			P_CONTROL_HARD_RESET_SERVER_V2: "P_CONTROL_HARD_RESET_SERVER_V2",
			P_DATA_V2:                      "P_DATA_V2",
			P_CONTROL_HARD_RESET_CLIENT_V3: "P_CONTROL_HARD_RESET_CLIENT_V3",
			P_CONTROL_WKC_V1:               "P_CONTROL_WKC_V1",
		}
		for k, v := range opcodes {
			if v != k.String() {
				t.Errorf("bad opcode string: %s", k.String())
			}
		}
	})
	t.Run("unknown opcode representation", func(t *testing.T) {
		got := Opcode(20).String()
		if got != "P_UNKNOWN" {
			t.Errorf("expected unknown opcode as P_UNKNOWN, got %s", got)
		}
	})
}

func Test_NewPacket(t *testing.T) {
	type args struct {
		opcode  Opcode
		keyID   byte
		payload []byte
	}
	tests := []struct {
		name string
		args args
		want *Packet
	}{
		{
			name: "get packet ok",
			args: args{
				opcode:  Opcode(1),
				keyID:   byte(10),
				payload: []byte("not a payload"),
			},
			want: &Packet{
				Opcode:  Opcode(1),
				KeyID:   byte(10),
				ACKs:    []PacketID{},
				Payload: []byte("not a payload"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(NewPacket(tt.args.opcode, tt.args.keyID, tt.args.payload), tt.want); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func Test_Packet_Log(t *testing.T) {
	t.Run("log control packet outgoing", func(t *testing.T) {
		p := NewPacket(P_CONTROL_V1, 0, []byte("aaa"))
		p.ID = 42
		p.ACKs = []PacketID{1}
		logger := NewTestLogger()
		p.Log(logger, DirectionOutgoing)
		want := "> P_CONTROL_V1 {id=42, acks=[1]} localID=0000000000000000 remoteID=0000000000000000 [3 bytes]"
		got := logger.Lines[0]
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf(diff)
		}
	})
	t.Run("log data packet incoming", func(t *testing.T) {
		p := NewPacket(P_DATA_V1, 0, []byte("aaa"))
		p.ID = 42
		p.ACKs = []PacketID{2}
		logger := NewTestLogger()
		p.Log(logger, DirectionIncoming)
		want := "< P_DATA_V1 {id=42, acks=[2]} localID=0000000000000000 remoteID=0000000000000000 [3 bytes]"
		got := logger.Lines[0]
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf(diff)
		}
	})
}
