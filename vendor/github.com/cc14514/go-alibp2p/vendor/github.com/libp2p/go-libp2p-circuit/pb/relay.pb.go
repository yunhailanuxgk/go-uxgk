// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: relay.proto

package relay_pb

import (
	fmt "fmt"
	github_com_gogo_protobuf_proto "github.com/gogo/protobuf/proto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type CircuitRelay_Status int32

const (
	CircuitRelay_SUCCESS                    CircuitRelay_Status = 100
	CircuitRelay_HOP_SRC_ADDR_TOO_LONG      CircuitRelay_Status = 220
	CircuitRelay_HOP_DST_ADDR_TOO_LONG      CircuitRelay_Status = 221
	CircuitRelay_HOP_SRC_MULTIADDR_INVALID  CircuitRelay_Status = 250
	CircuitRelay_HOP_DST_MULTIADDR_INVALID  CircuitRelay_Status = 251
	CircuitRelay_HOP_NO_CONN_TO_DST         CircuitRelay_Status = 260
	CircuitRelay_HOP_CANT_DIAL_DST          CircuitRelay_Status = 261
	CircuitRelay_HOP_CANT_OPEN_DST_STREAM   CircuitRelay_Status = 262
	CircuitRelay_HOP_CANT_SPEAK_RELAY       CircuitRelay_Status = 270
	CircuitRelay_HOP_CANT_RELAY_TO_SELF     CircuitRelay_Status = 280
	CircuitRelay_STOP_SRC_ADDR_TOO_LONG     CircuitRelay_Status = 320
	CircuitRelay_STOP_DST_ADDR_TOO_LONG     CircuitRelay_Status = 321
	CircuitRelay_STOP_SRC_MULTIADDR_INVALID CircuitRelay_Status = 350
	CircuitRelay_STOP_DST_MULTIADDR_INVALID CircuitRelay_Status = 351
	CircuitRelay_STOP_RELAY_REFUSED         CircuitRelay_Status = 390
	CircuitRelay_MALFORMED_MESSAGE          CircuitRelay_Status = 400
)

var CircuitRelay_Status_name = map[int32]string{
	100: "SUCCESS",
	220: "HOP_SRC_ADDR_TOO_LONG",
	221: "HOP_DST_ADDR_TOO_LONG",
	250: "HOP_SRC_MULTIADDR_INVALID",
	251: "HOP_DST_MULTIADDR_INVALID",
	260: "HOP_NO_CONN_TO_DST",
	261: "HOP_CANT_DIAL_DST",
	262: "HOP_CANT_OPEN_DST_STREAM",
	270: "HOP_CANT_SPEAK_RELAY",
	280: "HOP_CANT_RELAY_TO_SELF",
	320: "STOP_SRC_ADDR_TOO_LONG",
	321: "STOP_DST_ADDR_TOO_LONG",
	350: "STOP_SRC_MULTIADDR_INVALID",
	351: "STOP_DST_MULTIADDR_INVALID",
	390: "STOP_RELAY_REFUSED",
	400: "MALFORMED_MESSAGE",
}

var CircuitRelay_Status_value = map[string]int32{
	"SUCCESS":                    100,
	"HOP_SRC_ADDR_TOO_LONG":      220,
	"HOP_DST_ADDR_TOO_LONG":      221,
	"HOP_SRC_MULTIADDR_INVALID":  250,
	"HOP_DST_MULTIADDR_INVALID":  251,
	"HOP_NO_CONN_TO_DST":         260,
	"HOP_CANT_DIAL_DST":          261,
	"HOP_CANT_OPEN_DST_STREAM":   262,
	"HOP_CANT_SPEAK_RELAY":       270,
	"HOP_CANT_RELAY_TO_SELF":     280,
	"STOP_SRC_ADDR_TOO_LONG":     320,
	"STOP_DST_ADDR_TOO_LONG":     321,
	"STOP_SRC_MULTIADDR_INVALID": 350,
	"STOP_DST_MULTIADDR_INVALID": 351,
	"STOP_RELAY_REFUSED":         390,
	"MALFORMED_MESSAGE":          400,
}

func (x CircuitRelay_Status) Enum() *CircuitRelay_Status {
	p := new(CircuitRelay_Status)
	*p = x
	return p
}

func (x CircuitRelay_Status) String() string {
	return proto.EnumName(CircuitRelay_Status_name, int32(x))
}

func (x *CircuitRelay_Status) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(CircuitRelay_Status_value, data, "CircuitRelay_Status")
	if err != nil {
		return err
	}
	*x = CircuitRelay_Status(value)
	return nil
}

func (CircuitRelay_Status) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9f69a7d5a802d584, []int{0, 0}
}

type CircuitRelay_Type int32

const (
	CircuitRelay_HOP     CircuitRelay_Type = 1
	CircuitRelay_STOP    CircuitRelay_Type = 2
	CircuitRelay_STATUS  CircuitRelay_Type = 3
	CircuitRelay_CAN_HOP CircuitRelay_Type = 4
)

var CircuitRelay_Type_name = map[int32]string{
	1: "HOP",
	2: "STOP",
	3: "STATUS",
	4: "CAN_HOP",
}

var CircuitRelay_Type_value = map[string]int32{
	"HOP":     1,
	"STOP":    2,
	"STATUS":  3,
	"CAN_HOP": 4,
}

func (x CircuitRelay_Type) Enum() *CircuitRelay_Type {
	p := new(CircuitRelay_Type)
	*p = x
	return p
}

func (x CircuitRelay_Type) String() string {
	return proto.EnumName(CircuitRelay_Type_name, int32(x))
}

func (x *CircuitRelay_Type) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(CircuitRelay_Type_value, data, "CircuitRelay_Type")
	if err != nil {
		return err
	}
	*x = CircuitRelay_Type(value)
	return nil
}

func (CircuitRelay_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_9f69a7d5a802d584, []int{0, 1}
}

type CircuitRelay struct {
	Type                 *CircuitRelay_Type   `protobuf:"varint,1,opt,name=type,enum=relay.pb.CircuitRelay_Type" json:"type,omitempty"`
	SrcPeer              *CircuitRelay_Peer   `protobuf:"bytes,2,opt,name=srcPeer" json:"srcPeer,omitempty"`
	DstPeer              *CircuitRelay_Peer   `protobuf:"bytes,3,opt,name=dstPeer" json:"dstPeer,omitempty"`
	Code                 *CircuitRelay_Status `protobuf:"varint,4,opt,name=code,enum=relay.pb.CircuitRelay_Status" json:"code,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *CircuitRelay) Reset()         { *m = CircuitRelay{} }
func (m *CircuitRelay) String() string { return proto.CompactTextString(m) }
func (*CircuitRelay) ProtoMessage()    {}
func (*CircuitRelay) Descriptor() ([]byte, []int) {
	return fileDescriptor_9f69a7d5a802d584, []int{0}
}
func (m *CircuitRelay) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CircuitRelay) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CircuitRelay.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CircuitRelay) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CircuitRelay.Merge(m, src)
}
func (m *CircuitRelay) XXX_Size() int {
	return m.Size()
}
func (m *CircuitRelay) XXX_DiscardUnknown() {
	xxx_messageInfo_CircuitRelay.DiscardUnknown(m)
}

var xxx_messageInfo_CircuitRelay proto.InternalMessageInfo

func (m *CircuitRelay) GetType() CircuitRelay_Type {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return CircuitRelay_HOP
}

func (m *CircuitRelay) GetSrcPeer() *CircuitRelay_Peer {
	if m != nil {
		return m.SrcPeer
	}
	return nil
}

func (m *CircuitRelay) GetDstPeer() *CircuitRelay_Peer {
	if m != nil {
		return m.DstPeer
	}
	return nil
}

func (m *CircuitRelay) GetCode() CircuitRelay_Status {
	if m != nil && m.Code != nil {
		return *m.Code
	}
	return CircuitRelay_SUCCESS
}

type CircuitRelay_Peer struct {
	Id                   []byte   `protobuf:"bytes,1,req,name=id" json:"id,omitempty"`
	Addrs                [][]byte `protobuf:"bytes,2,rep,name=addrs" json:"addrs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CircuitRelay_Peer) Reset()         { *m = CircuitRelay_Peer{} }
func (m *CircuitRelay_Peer) String() string { return proto.CompactTextString(m) }
func (*CircuitRelay_Peer) ProtoMessage()    {}
func (*CircuitRelay_Peer) Descriptor() ([]byte, []int) {
	return fileDescriptor_9f69a7d5a802d584, []int{0, 0}
}
func (m *CircuitRelay_Peer) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CircuitRelay_Peer) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CircuitRelay_Peer.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CircuitRelay_Peer) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CircuitRelay_Peer.Merge(m, src)
}
func (m *CircuitRelay_Peer) XXX_Size() int {
	return m.Size()
}
func (m *CircuitRelay_Peer) XXX_DiscardUnknown() {
	xxx_messageInfo_CircuitRelay_Peer.DiscardUnknown(m)
}

var xxx_messageInfo_CircuitRelay_Peer proto.InternalMessageInfo

func (m *CircuitRelay_Peer) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *CircuitRelay_Peer) GetAddrs() [][]byte {
	if m != nil {
		return m.Addrs
	}
	return nil
}

func init() {
	proto.RegisterEnum("relay.pb.CircuitRelay_Status", CircuitRelay_Status_name, CircuitRelay_Status_value)
	proto.RegisterEnum("relay.pb.CircuitRelay_Type", CircuitRelay_Type_name, CircuitRelay_Type_value)
	proto.RegisterType((*CircuitRelay)(nil), "relay.pb.CircuitRelay")
	proto.RegisterType((*CircuitRelay_Peer)(nil), "relay.pb.CircuitRelay.Peer")
}

func init() { proto.RegisterFile("relay.proto", fileDescriptor_9f69a7d5a802d584) }

var fileDescriptor_9f69a7d5a802d584 = []byte{
	// 473 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x4f, 0x6f, 0xd3, 0x3e,
	0x18, 0xc7, 0x65, 0x27, 0xbf, 0x76, 0x7a, 0x5a, 0x4d, 0xfe, 0x59, 0x63, 0x64, 0x9d, 0x56, 0xaa,
	0x9e, 0x7a, 0x40, 0x45, 0x4c, 0xe2, 0x05, 0x98, 0xc4, 0xdd, 0x2a, 0xd2, 0x38, 0xb2, 0x5d, 0x24,
	0x4e, 0x56, 0x69, 0x72, 0xa8, 0x84, 0xd4, 0x2a, 0xcd, 0x0e, 0xbd, 0xc3, 0xb8, 0x21, 0x8e, 0xbc,
	0x1c, 0xe0, 0xc4, 0x91, 0x17, 0xc0, 0x3f, 0xf5, 0x65, 0xc0, 0x05, 0xd9, 0x5d, 0x33, 0x44, 0x37,
	0x89, 0xa3, 0x9f, 0xef, 0xe7, 0xe3, 0x3c, 0xf9, 0x26, 0xd0, 0x28, 0xf2, 0x17, 0x93, 0x55, 0x7f,
	0x51, 0xcc, 0xcb, 0x39, 0xdd, 0xbb, 0x3a, 0x3c, 0xef, 0xbe, 0xae, 0x41, 0x33, 0x9c, 0x15, 0xd3,
	0x8b, 0x59, 0x29, 0xed, 0x8c, 0x3e, 0x00, 0xbf, 0x5c, 0x2d, 0xf2, 0x00, 0x75, 0x50, 0x6f, 0xff,
	0xf4, 0xb8, 0xbf, 0x25, 0xfb, 0x7f, 0x52, 0x7d, 0xbd, 0x5a, 0xe4, 0xd2, 0x81, 0xf4, 0x11, 0xd4,
	0x97, 0xc5, 0x34, 0xcd, 0xf3, 0x22, 0xc0, 0x1d, 0xd4, 0x6b, 0xdc, 0xea, 0x58, 0x44, 0x6e, 0x59,
	0xab, 0x65, 0xcb, 0xd2, 0x69, 0xde, 0x3f, 0x68, 0x57, 0x2c, 0x7d, 0x08, 0xfe, 0x74, 0x9e, 0xe5,
	0x81, 0xef, 0xd6, 0x3b, 0xb9, 0xc5, 0x51, 0xe5, 0xa4, 0xbc, 0x58, 0x4a, 0x87, 0xb6, 0xee, 0x83,
	0xef, 0xd4, 0x7d, 0xc0, 0xb3, 0x2c, 0x40, 0x1d, 0xdc, 0x6b, 0x4a, 0x3c, 0xcb, 0xe8, 0x01, 0xfc,
	0x37, 0xc9, 0xb2, 0x62, 0x19, 0xe0, 0x8e, 0xd7, 0x6b, 0xca, 0xcd, 0xa1, 0xfb, 0xd1, 0x83, 0xda,
	0x46, 0xa7, 0x0d, 0xa8, 0xab, 0x71, 0x18, 0x72, 0xa5, 0x48, 0x46, 0x5b, 0x70, 0xe7, 0x5c, 0xa4,
	0x46, 0xc9, 0xd0, 0xb0, 0x28, 0x92, 0x46, 0x0b, 0x61, 0x62, 0x91, 0x9c, 0x91, 0x2f, 0x68, 0x9b,
	0x45, 0x4a, 0xff, 0x95, 0x7d, 0x45, 0xb4, 0x0d, 0x47, 0x5b, 0x6f, 0x34, 0x8e, 0xf5, 0xd0, 0x01,
	0xc3, 0xe4, 0x29, 0x8b, 0x87, 0x11, 0xf9, 0x59, 0xe5, 0xd6, 0xdd, 0xcd, 0x7f, 0x21, 0x7a, 0x17,
	0xa8, 0xcd, 0x13, 0x61, 0x42, 0x91, 0x24, 0x46, 0x0b, 0x8b, 0x92, 0x97, 0x98, 0x1e, 0xc2, 0xff,
	0x36, 0x08, 0x59, 0xa2, 0x4d, 0x34, 0x64, 0xb1, 0x9b, 0xbf, 0xc2, 0xf4, 0x04, 0x82, 0x6a, 0x2e,
	0x52, 0x9e, 0xb8, 0xab, 0x95, 0x96, 0x9c, 0x8d, 0xc8, 0x25, 0xa6, 0x47, 0x70, 0x50, 0xc5, 0x2a,
	0xe5, 0xec, 0x89, 0x91, 0x3c, 0x66, 0xcf, 0xc8, 0x1b, 0x4c, 0x8f, 0xe1, 0xb0, 0x8a, 0xdc, 0xd0,
	0x3e, 0x4d, 0xf1, 0x78, 0x40, 0xde, 0xb9, 0x50, 0xe9, 0x1b, 0x0b, 0x78, 0x7f, 0x1d, 0xee, 0x36,
	0xf0, 0x01, 0xd3, 0x7b, 0xd0, 0xaa, 0xcc, 0xdd, 0x57, 0xfc, 0x76, 0x0d, 0xdc, 0xdc, 0xc1, 0x77,
	0x6c, 0x3b, 0x70, 0xc0, 0x66, 0x29, 0xc9, 0x07, 0x63, 0xc5, 0x23, 0x72, 0xe9, 0xd9, 0x0e, 0x46,
	0x2c, 0x1e, 0x08, 0x39, 0xe2, 0x91, 0x19, 0x71, 0xa5, 0xd8, 0x19, 0x27, 0x6f, 0xbd, 0xee, 0x29,
	0xf8, 0xf6, 0x0f, 0xa5, 0x75, 0xf0, 0xce, 0x45, 0x4a, 0x10, 0xdd, 0x03, 0xdf, 0xde, 0x40, 0x30,
	0x05, 0xa8, 0x29, 0xcd, 0xf4, 0x58, 0x11, 0xcf, 0x7e, 0xe0, 0x90, 0x25, 0xc6, 0x22, 0xfe, 0xe3,
	0xe6, 0xa7, 0x75, 0x1b, 0x7d, 0x5e, 0xb7, 0xd1, 0x8f, 0x75, 0x1b, 0xfd, 0x0e, 0x00, 0x00, 0xff,
	0xff, 0x6b, 0x22, 0x33, 0xbb, 0x2f, 0x03, 0x00, 0x00,
}

func (m *CircuitRelay) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CircuitRelay) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Type != nil {
		dAtA[i] = 0x8
		i++
		i = encodeVarintRelay(dAtA, i, uint64(*m.Type))
	}
	if m.SrcPeer != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintRelay(dAtA, i, uint64(m.SrcPeer.Size()))
		n1, err := m.SrcPeer.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.DstPeer != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintRelay(dAtA, i, uint64(m.DstPeer.Size()))
		n2, err := m.DstPeer.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.Code != nil {
		dAtA[i] = 0x20
		i++
		i = encodeVarintRelay(dAtA, i, uint64(*m.Code))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *CircuitRelay_Peer) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CircuitRelay_Peer) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Id == nil {
		return 0, github_com_gogo_protobuf_proto.NewRequiredNotSetError("id")
	} else {
		dAtA[i] = 0xa
		i++
		i = encodeVarintRelay(dAtA, i, uint64(len(m.Id)))
		i += copy(dAtA[i:], m.Id)
	}
	if len(m.Addrs) > 0 {
		for _, b := range m.Addrs {
			dAtA[i] = 0x12
			i++
			i = encodeVarintRelay(dAtA, i, uint64(len(b)))
			i += copy(dAtA[i:], b)
		}
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintRelay(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *CircuitRelay) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != nil {
		n += 1 + sovRelay(uint64(*m.Type))
	}
	if m.SrcPeer != nil {
		l = m.SrcPeer.Size()
		n += 1 + l + sovRelay(uint64(l))
	}
	if m.DstPeer != nil {
		l = m.DstPeer.Size()
		n += 1 + l + sovRelay(uint64(l))
	}
	if m.Code != nil {
		n += 1 + sovRelay(uint64(*m.Code))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CircuitRelay_Peer) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Id != nil {
		l = len(m.Id)
		n += 1 + l + sovRelay(uint64(l))
	}
	if len(m.Addrs) > 0 {
		for _, b := range m.Addrs {
			l = len(b)
			n += 1 + l + sovRelay(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovRelay(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozRelay(x uint64) (n int) {
	return sovRelay(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *CircuitRelay) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRelay
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: CircuitRelay: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CircuitRelay: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			var v CircuitRelay_Type
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= CircuitRelay_Type(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Type = &v
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SrcPeer", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthRelay
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthRelay
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.SrcPeer == nil {
				m.SrcPeer = &CircuitRelay_Peer{}
			}
			if err := m.SrcPeer.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DstPeer", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthRelay
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthRelay
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.DstPeer == nil {
				m.DstPeer = &CircuitRelay_Peer{}
			}
			if err := m.DstPeer.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Code", wireType)
			}
			var v CircuitRelay_Status
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= CircuitRelay_Status(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Code = &v
		default:
			iNdEx = preIndex
			skippy, err := skipRelay(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthRelay
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthRelay
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *CircuitRelay_Peer) Unmarshal(dAtA []byte) error {
	var hasFields [1]uint64
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowRelay
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Peer: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Peer: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthRelay
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthRelay
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = append(m.Id[:0], dAtA[iNdEx:postIndex]...)
			if m.Id == nil {
				m.Id = []byte{}
			}
			iNdEx = postIndex
			hasFields[0] |= uint64(0x00000001)
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addrs", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthRelay
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthRelay
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addrs = append(m.Addrs, make([]byte, postIndex-iNdEx))
			copy(m.Addrs[len(m.Addrs)-1], dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipRelay(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthRelay
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthRelay
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}
	if hasFields[0]&uint64(0x00000001) == 0 {
		return github_com_gogo_protobuf_proto.NewRequiredNotSetError("id")
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipRelay(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowRelay
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowRelay
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthRelay
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthRelay
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowRelay
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipRelay(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthRelay
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthRelay = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowRelay   = fmt.Errorf("proto: integer overflow")
)
