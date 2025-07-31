package wire

import (
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/minivpn/internal/model"
)

const OVPN_STATIC_KEY_AUTH = `
-----BEGIN OpenVPN Static key V1-----
924a040a27a5c4295447269a187881ae
26ae188b79b0c803ccdb42540893ce44
af970a6b0e57ac769dfbfcac741d6ac1
91e801ff587c8a932665dc615b3a95bc
1326c23ddf2f1790a943ee0b8bce8a44
15722fadb5efad8d906b04b562845439
791353992e19de0c914b56cc561737a5
750bb1c48ce0bac3497d59c80f4b273b
73a0f983fae3ee3e8ea45dc71fdf68d0
fbd71cd43652f5c14e57d2038c147077
61f448d3a4cf7d7b6a3fcfae36ab297f
7e8fdc44140349ef934f350abb90d201
12919f79d9a2f05f5999e08c2df5a102
9d1a67a964932b774da964a24523a5f8
234dc1c3dc15ceb459c1b68a321a3153
6a4dac97daef6c81d6ac870acf97f29c
-----END OpenVPN Static key V1-----
`

const OVPN_STATIC_KEY_CRYPT = `
-----BEGIN OpenVPN Static key V1-----
f077aa700c7e2cb73d6fb0d13593a169
73b8ccbe725d637bb9d536b3e2871082
47bb9509ff55b9a9e96fb808e651d7a4
d41ec6709bb2544dfa6b821da1a24779
bef28bd707cc07f3aea76f9c6982b6e4
66c35fcbf78cd31db0a6e4f5d92400cc
75018b8fe1448fb6a06e3274d561fed0
ae518aa6d64a1ee61399ed9c8e29179a
25d5aab3fee1bb36f77e0d78c99892f3
6d59f42be49ba971920cb356d582f51c
b716da710009a37a6cb6e70c5ca782a0
e1edd17445bea1c8f330c653511a8621
4fd5f432c1b35bb8f6114b8f31213fb9
37d370d2aa00c355bfe0f03ad64a323a
6e0afca660f6c2517c61ddbc13f7cebf
1f9386c6de7c79bc652d3fd418b9ad45
-----END OpenVPN Static key V1-----
`

const OVPN_CRYPT_V2_CLIENT_KEY = `
-----BEGIN OpenVPN tls-crypt-v2 client key-----
dk33kgWVhijMYRL/DNbl2Iccm/gsd3d5hlWiwclOUv1lO0HSmpmaNyjTqR0M50pS
yOPJdm/YWktAgLTLwYJC3LvMRtMxKNuLPuYybJ6cayETWZRkjfOCwCsX+5YJWO1w
lFn8uFFTy+dUm6ItppFogvTEd6mXQY9a2GkA6cxCaNTspGxx14Y9dUUe8/UZ8+Eu
fKw3VcO2jsrDD7rudw6j5X2fZ71I2VDGOV5xaqmZcZvdcZNtjIaOkql43aKYQoCZ
NXsuUDQt+4EVNo5lPAu8K+/MwExB6qZs2n+HSfjbFH4QWdqzrQXeD2njbz6gNcUU
nP8kHTmbDrSMnh9nzhZ0uKBZ1PNl1fGredR7tfQndKK9UgSMuJiFTJprcE4B8GDX
m3EdXUUaTCSB60SVCCxCjfsJqBDbcIF3MbYkJd3rYLMBuv1zIKds+c7+yhxZvk65
61b0TJ9UmgOh6Ml7Yxlew+xWIbQiKnBRXHJA96Dgox88+suS9vOWkCyg0D/LUQu0
XMq68GxC0suKvgFx9vl5JuUIkh0naHMgBoMrLc4HQJ0rdZZ/bUzKPaObo+3uOcew
bCgpzoZAunJN4lcU4bIcxOnxidMsugtLVORPNgdXpsBnbdFNKudo0Le6/n7z6/2Y
cq5WCxjzZ/KON5pLyFWl2rsZuGlMFhOyWjhb/pWXqRUhru1t8CCBJtxtgYx1U215
Mfhomlad2YvPhcFdy6zyCMEEz2gJqTvMf5tRkc8EgAGOYERUIMD5fbbgNKRDqVbT
fwhsH+sAH6DB43GaXCegqflLKRDvVdsBWQ==
-----END OpenVPN tls-crypt-v2 client key-----
`

// TODO these tests should be replicated across all auth-modes
func Test_ParsePacket(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    *model.Packet
		wantErr error
	}{
		{
			name:    "a single byte cannot be parsed as a packet",
			raw:     "20",
			want:    nil,
			wantErr: ErrPacketTooShort,
		},
		{
			name: "parse minimal control packet",
			raw:  "2000000000000000000000000007",
			want: &model.Packet{
				ID:      7,
				Opcode:  model.P_CONTROL_V1,
				KeyID:   0,
				ACKs:    []model.PacketID{},
				Payload: []byte{},
			},
			wantErr: nil,
		},
		{
			name: "parse control packet with payload",
			raw:  "2000000000000000000000000007616161",
			want: &model.Packet{
				ID:      7,
				Opcode:  model.P_CONTROL_V1,
				KeyID:   0,
				ACKs:    []model.PacketID{},
				Payload: []byte("aaa"),
			},
			wantErr: nil,
		},
		{
			name:    "parse control packet with incomplete session id",
			raw:     "2000",
			want:    nil,
			wantErr: ErrParsePacket,
		},
		{
			name: "parse data packet",
			raw:  "48020202ffff",
			want: &model.Packet{
				ID:      0,
				Opcode:  model.P_DATA_V2,
				KeyID:   0,
				PeerID:  model.PeerID{0x02, 0x02, 0x02},
				ACKs:    []model.PacketID{},
				Payload: []byte{0xff, 0xff},
			},
			wantErr: nil,
		},
		{
			name:    "parse data fails if too short",
			raw:     "4802020",
			want:    &model.Packet{},
			wantErr: ErrPacketTooShort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, _ := hex.DecodeString(tt.raw)
			pa := &ControlChannelSecurity{Mode: ControlSecurityModeNone}
			p, err := UnmarshalPacket(raw, pa)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("got error=%v, want %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(p, tt.want); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func Test_Packet_Bytes(t *testing.T) {
	t.Run("serialize a bare mininum packet", func(t *testing.T) {
		p := &model.Packet{Opcode: model.P_ACK_V1}
		pa := &ControlChannelSecurity{Mode: ControlSecurityModeNone}
		got, err := MarshalPacket(p, pa)
		if err != nil {
			t.Error("should not fail")
		}
		want := []byte{40, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf(diff)
		}
	})

	t.Run("a packet with too many acks should fail", func(t *testing.T) {
		id := model.PacketID(1)
		tooManyAcks := []model.PacketID{
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
			id, id, id, id, id, id, id, id, id, id, id, id, id, id, id, id,
		}

		p := &model.Packet{
			Opcode: model.P_ACK_V1,
			ACKs:   tooManyAcks,
		}
		pa := &ControlChannelSecurity{Mode: ControlSecurityModeNone}
		_, err := MarshalPacket(p, pa)

		if !errors.Is(err, ErrMarshalPacket) {
			t.Errorf("expected got error=%v, expected %v", err, ErrMarshalPacket)
		}
	})
}

func Test_Packet_IsControl(t *testing.T) {
	type fields struct {
		opcode model.Opcode
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "good control",
			fields: fields{opcode: model.Opcode(model.P_CONTROL_V1)},
			want:   true,
		},
		{
			name:   "data v1 packet",
			fields: fields{opcode: model.Opcode(model.P_DATA_V1)},
			want:   false,
		},
		{
			name:   "data v2 packet",
			fields: fields{opcode: model.Opcode(model.P_DATA_V2)},
			want:   false,
		},
		{
			name:   "zero byte",
			fields: fields{opcode: 0x00},
			want:   false,
		},
		{
			name:   "ack",
			fields: fields{opcode: model.Opcode(model.P_ACK_V1)},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &model.Packet{Opcode: tt.fields.opcode}
			if got := p.IsControl(); got != tt.want {
				t.Errorf("packet.IsControl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Packet_IsData(t *testing.T) {
	type fields struct {
		opcode model.Opcode
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "data v1 is true",
			fields: fields{opcode: model.Opcode(model.P_DATA_V1)},
			want:   true,
		},
		{
			name:   "data v2 is true",
			fields: fields{opcode: model.Opcode(model.P_DATA_V2)},
			want:   true,
		},
		{
			name:   "control packet",
			fields: fields{opcode: model.Opcode(model.P_CONTROL_V1)},
			want:   false,
		},
		{
			name:   "ack",
			fields: fields{opcode: model.Opcode(model.P_ACK_V1)},
			want:   false,
		},
		{
			name:   "zero byte",
			fields: fields{opcode: 0x00},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &model.Packet{Opcode: tt.fields.opcode}
			if got := p.IsData(); got != tt.want {
				t.Errorf("packet.IsData() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Regression test for MIV-01-001
func Test_Crash_WhileParsingServerHardResetPacket(t *testing.T) {
	packet := model.NewPacket(
		model.P_CONTROL_HARD_RESET_SERVER_V2,
		0,
		[]byte{},
	)
	pa := &ControlChannelSecurity{Mode: ControlSecurityModeNone}
	b, _ := MarshalPacket(packet, pa)
	UnmarshalPacket(b, pa)
}

func TestMarshalPacketTLSAuth(t *testing.T) {
	want := []byte{0x38, 0xbf, 0x85, 0x4a, 0x13, 0x69, 0xb4, 0x5c, 0x93, 0x5e, 0x62, 0x56, 0xa2, 0x39, 0xeb, 0x89, 0xac, 0xcf, 0x40, 0xf4, 0x5e, 0xfd, 0x4e, 0x50, 0x51, 0x5b, 0x4d, 0xdc, 0xf, 0x0, 0x0, 0x0, 0x1, 0x68, 0x7f, 0x6e, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0}

	localSessionHex := "bf854a1369b45c93"
	localSessionId, err := hex.DecodeString(localSessionHex)
	if err != nil {
		t.Error(err)
	}
	timestampHex := "687f6e10"
	timestamp, err := strconv.ParseUint(timestampHex, 16, 32)
	if err != nil {
		t.Errorf("Error parsing hex string: %v\n", err)
	}
	packet := model.NewPacket(model.P_CONTROL_HARD_RESET_CLIENT_V2, 0, []byte{})
	packet.LocalSessionID = [8]byte(localSessionId)
	packet.ReplayPacketID = 1
	packet.Timestamp = model.PacketTimestamp(timestamp)

	pa, err := NewControlChannelSecurityTLSAuth([]byte(OVPN_STATIC_KEY_AUTH), 1)
	if err != nil {
		t.Error(err)
	}

	got, _ := MarshalPacket(packet, pa)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Error(diff)
	}
}

func TestMarshalPacketTLSCrypt(t *testing.T) {
	want := []byte{0x38, 0xfa, 0x8e, 0xc7, 0x4e, 0x54, 0x34, 0x21, 0xeb, 0x0, 0x0, 0x0, 0x1, 0x68, 0x83, 0x62, 0xbc, 0x4a, 0xfc, 0x3e, 0xb3, 0x56, 0x3c, 0x43, 0xb1, 0x54, 0xaf, 0x12, 0x8e, 0x1b, 0xdb, 0x2f, 0x58, 0x62, 0x8c, 0x3f, 0xa3, 0xb4, 0x5c, 0x49, 0x71, 0x28, 0x39, 0xa5, 0xf0, 0x2b, 0xa1, 0x39, 0x25, 0x3c, 0x0, 0x5f, 0x29, 0x0}

	localSessionHex := "fa8ec74e543421eb"
	localSessionId, err := hex.DecodeString(localSessionHex)
	if err != nil {
		t.Error(err)
	}
	timestampHex := "688362bc"
	timestamp, err := strconv.ParseUint(timestampHex, 16, 32)
	if err != nil {
		t.Errorf("Error parsing hex string: %v\n", err)
	}
	packet := model.NewPacket(model.P_CONTROL_HARD_RESET_CLIENT_V2, 0, []byte{})
	packet.LocalSessionID = [8]byte(localSessionId)
	packet.ReplayPacketID = 1
	packet.Timestamp = model.PacketTimestamp(timestamp)

	pa, err := NewControlChannelSecurityTLSCrypt([]byte(OVPN_STATIC_KEY_CRYPT))
	if err != nil {
		t.Error(err)
	}
	got, err := MarshalPacket(packet, pa)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Error(diff)
	}
}

func TestMarshalPacketTLSCryptV2(t *testing.T) {
	want := []byte{0x50, 0xb6, 0xd3, 0x6a, 0x67, 0xb0, 0xd0, 0x89, 0x5, 0xf, 0x0, 0x0, 0x1, 0x68, 0x8b, 0x35, 0x5f, 0x2c, 0x36, 0x54, 0xbf, 0xc4, 0x9c, 0x9b, 0xd9, 0x12, 0x7, 0x1e, 0xcf, 0x8c, 0x37, 0xdb, 0xba, 0xfe, 0x93, 0x86, 0x27, 0x6, 0x9f, 0x25, 0xba, 0xdd, 0xa3, 0xa8, 0x41, 0xef, 0x1f, 0x65, 0x86, 0x8e, 0xbe, 0x5a, 0x61, 0xf4, 0xa0, 0x59, 0xd4, 0xf3, 0x65, 0xd5, 0xf1, 0xab, 0x79, 0xd4, 0x7b, 0xb5, 0xf4, 0x27, 0x74, 0xa2, 0xbd, 0x52, 0x4, 0x8c, 0xb8, 0x98, 0x85, 0x4c, 0x9a, 0x6b, 0x70, 0x4e, 0x1, 0xf0, 0x60, 0xd7, 0x9b, 0x71, 0x1d, 0x5d, 0x45, 0x1a, 0x4c, 0x24, 0x81, 0xeb, 0x44, 0x95, 0x8, 0x2c, 0x42, 0x8d, 0xfb, 0x9, 0xa8, 0x10, 0xdb, 0x70, 0x81, 0x77, 0x31, 0xb6, 0x24, 0x25, 0xdd, 0xeb, 0x60, 0xb3, 0x1, 0xba, 0xfd, 0x73, 0x20, 0xa7, 0x6c, 0xf9, 0xce, 0xfe, 0xca, 0x1c, 0x59, 0xbe, 0x4e, 0xb9, 0xeb, 0x56, 0xf4, 0x4c, 0x9f, 0x54, 0x9a, 0x3, 0xa1, 0xe8, 0xc9, 0x7b, 0x63, 0x19, 0x5e, 0xc3, 0xec, 0x56, 0x21, 0xb4, 0x22, 0x2a, 0x70, 0x51, 0x5c, 0x72, 0x40, 0xf7, 0xa0, 0xe0, 0xa3, 0x1f, 0x3c, 0xfa, 0xcb, 0x92, 0xf6, 0xf3, 0x96, 0x90, 0x2c, 0xa0, 0xd0, 0x3f, 0xcb, 0x51, 0xb, 0xb4, 0x5c, 0xca, 0xba, 0xf0, 0x6c, 0x42, 0xd2, 0xcb, 0x8a, 0xbe, 0x1, 0x71, 0xf6, 0xf9, 0x79, 0x26, 0xe5, 0x8, 0x92, 0x1d, 0x27, 0x68, 0x73, 0x20, 0x6, 0x83, 0x2b, 0x2d, 0xce, 0x7, 0x40, 0x9d, 0x2b, 0x75, 0x96, 0x7f, 0x6d, 0x4c, 0xca, 0x3d, 0xa3, 0x9b, 0xa3, 0xed, 0xee, 0x39, 0xc7, 0xb0, 0x6c, 0x28, 0x29, 0xce, 0x86, 0x40, 0xba, 0x72, 0x4d, 0xe2, 0x57, 0x14, 0xe1, 0xb2, 0x1c, 0xc4, 0xe9, 0xf1, 0x89, 0xd3, 0x2c, 0xba, 0xb, 0x4b, 0x54, 0xe4, 0x4f, 0x36, 0x7, 0x57, 0xa6, 0xc0, 0x67, 0x6d, 0xd1, 0x4d, 0x2a, 0xe7, 0x68, 0xd0, 0xb7, 0xba, 0xfe, 0x7e, 0xf3, 0xeb, 0xfd, 0x98, 0x72, 0xae, 0x56, 0xb, 0x18, 0xf3, 0x67, 0xf2, 0x8e, 0x37, 0x9a, 0x4b, 0xc8, 0x55, 0xa5, 0xda, 0xbb, 0x19, 0xb8, 0x69, 0x4c, 0x16, 0x13, 0xb2, 0x5a, 0x38, 0x5b, 0xfe, 0x95, 0x97, 0xa9, 0x15, 0x21, 0xae, 0xed, 0x6d, 0xf0, 0x20, 0x81, 0x26, 0xdc, 0x6d, 0x81, 0x8c, 0x75, 0x53, 0x6d, 0x79, 0x31, 0xf8, 0x68, 0x9a, 0x56, 0x9d, 0xd9, 0x8b, 0xcf, 0x85, 0xc1, 0x5d, 0xcb, 0xac, 0xf2, 0x8, 0xc1, 0x4, 0xcf, 0x68, 0x9, 0xa9, 0x3b, 0xcc, 0x7f, 0x9b, 0x51, 0x91, 0xcf, 0x4, 0x80, 0x1, 0x8e, 0x60, 0x44, 0x54, 0x20, 0xc0, 0xf9, 0x7d, 0xb6, 0xe0, 0x34, 0xa4, 0x43, 0xa9, 0x56, 0xd3, 0x7f, 0x8, 0x6c, 0x1f, 0xeb, 0x0, 0x1f, 0xa0, 0xc1, 0xe3, 0x71, 0x9a, 0x5c, 0x27, 0xa0, 0xa9, 0xf9, 0x4b, 0x29, 0x10, 0xef, 0x55, 0xdb, 0x1, 0x59}
	localSessionHex := "b6d36a67b0d08905"
	localSessionId, err := hex.DecodeString(localSessionHex)
	if err != nil {
		t.Error(err)
	}
	timestampHex := "688b355f"
	timestamp, err := strconv.ParseUint(timestampHex, 16, 32)
	if err != nil {
		t.Errorf("Error parsing hex string: %v\n", err)
	}
	packet := model.NewPacket(model.P_CONTROL_HARD_RESET_CLIENT_V3, 0, []byte{})
	packet.LocalSessionID = [8]byte(localSessionId)

	// 0F 00 00 01 - includes a flag to signal early negeotiation support
	packet.ReplayPacketID = 251658241
	packet.Timestamp = model.PacketTimestamp(timestamp)

	pa, err := NewControlChannelSecurityTLSCryptV2([]byte(OVPN_CRYPT_V2_CLIENT_KEY))
	if err != nil {
		t.Error(err)
	}
	got, err := MarshalPacket(packet, pa)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Error(diff)
	}
}
