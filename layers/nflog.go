package layers

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/aruntomar/gopacket"
)

// NFLOG data structure
type NFLOG struct {
	BaseLayer
	AF               uint8
	Version          uint8
	ResourceID       uint16
	HardwareProtocol uint16
	NetfilterHook    uint8
	Seconds          uint64
	Microseconds     uint64
	AddressLength    uint16
	Address          net.HardwareAddr
	Payload          []byte
}

const (
	NFULA_PACKET_HDR         = 1  /* nflog_packet_hdr_t */
	NFULA_MARK               = 2  /* packet mark from skbuff */
	NFULA_TIMESTAMP          = 3  /* nflog_timestamp_t for skbuff's time stamp */
	NFULA_IFINDEX_INDEV      = 4  /* ifindex of device on which packet received (possibly bridge group) */
	NFULA_IFINDEX_OUTDEV     = 5  /* ifindex of device on which packet transmitted (possibly bridge group) */
	NFULA_IFINDEX_PHYSINDEV  = 6  /* ifindex of physical device on which packet received (not bridge group) */
	NFULA_IFINDEX_PHYSOUTDEV = 7  /* ifindex of physical device on which packet transmitted (not bridge group) */
	NFULA_HWADDR             = 8  /* nflog_hwaddr_t for hardware address */
	NFULA_PAYLOAD            = 9  /* packet payload */
	NFULA_PREFIX             = 10 /* text string - null-terminated, count includes NUL */
	NFULA_UID                = 11 /* UID owning socket on which packet was sent/received */
	NFULA_SEQ                = 12 /* sequence number of packets on this NFLOG socket */
	NFULA_SEQ_GLOBAL         = 13 /* sequence number of pakets on all NFLOG sockets */
	NFULA_GID                = 14 /* GID owning socket on which packet was sent/received */
	NFULA_HWTYPE             = 15 /* ARPHRD_ type of skbuff's device */
	NFULA_HWHEADER           = 16 /* skbuff's MAC-layer header */
	NFULA_HWLEN              = 17 /* length of skbuff's MAC-layer header */
)

// ReadTLV data
func (n *NFLOG) ReadTLV(data []byte, idx int) error {
	for idx < len(data) {
		tlvLength := int(binary.LittleEndian.Uint16(data[idx : idx+2]))
		padding := (4 - tlvLength%4) % 4
		tlvType := int(binary.LittleEndian.Uint16(data[idx+2 : idx+4]))
		switch tlvType {
		case NFULA_PACKET_HDR:
			n.HardwareProtocol = binary.BigEndian.Uint16(data[idx+4 : idx+6])
			n.NetfilterHook = uint8(data[idx+6])
		case NFULA_MARK:
		case NFULA_TIMESTAMP:
			n.Seconds = binary.BigEndian.Uint64(data[idx+4 : idx+12])
			n.Microseconds = binary.BigEndian.Uint64(data[idx+12 : idx+20])
		case NFULA_IFINDEX_INDEV:
		case NFULA_IFINDEX_OUTDEV:
		case NFULA_IFINDEX_PHYSINDEV:
		case NFULA_IFINDEX_PHYSOUTDEV:
		case NFULA_HWADDR:
			n.AddressLength = binary.BigEndian.Uint16(data[idx+4 : idx+6])
			n.Address = net.HardwareAddr(data[idx+8 : idx+8+int(n.AddressLength)])
		case NFULA_PAYLOAD:
			n.Payload = data[idx+4 : idx+tlvLength]
		case NFULA_PREFIX:
		case NFULA_UID:
		case NFULA_SEQ:
		case NFULA_SEQ_GLOBAL:
		case NFULA_GID:
		case NFULA_HWTYPE:
		case NFULA_HWHEADER:
		case NFULA_HWLEN:
		default:
			return fmt.Errorf("Unexpected type: %v", tlvType)
		}
		idx = idx + tlvLength + padding
	}
	return nil
}

// LayerType for nflog
func (n *NFLOG) LayerType() gopacket.LayerType { return LayerTypeNFLOG }

// LinkFlow for nflog
func (n *NFLOG) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, n.Address, nil)
}

// DecodeFromBytes for nflog
func (n *NFLOG) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	n.AF = uint8(data[0])
	n.Version = uint8(data[1])
	n.ResourceID = binary.BigEndian.Uint16(data[2:4])
	n.ReadTLV(data, 4)
	n.BaseLayer = BaseLayer{data, n.Payload}
	return nil
}

// CanDecode for nflog
func (n *NFLOG) CanDecode() gopacket.LayerClass {
	return LayerTypeNFLOG
}

// NextLayerType for nflog layer
func (n *NFLOG) NextLayerType() gopacket.LayerType {
	switch n.AF {
	case 2:
		return LayerTypeIPv4
	case 10:
		return LayerTypeIPv6
	}
	return gopacket.LayerTypePayload
}

func decodeNFLOG(data []byte, p gopacket.PacketBuilder) error {
	nflog := &NFLOG{}
	err := nflog.DecodeFromBytes(data, p)
	p.AddLayer(nflog)
	p.SetLinkLayer(nflog)
	if err != nil {
		return err
	}
	return p.NextDecoder(nflog.NextLayerType())
}
