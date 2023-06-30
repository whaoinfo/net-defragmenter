package definition

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FragmentType int8

const (
	InvalidFragType FragmentType = iota

	IPV4FragType
	IPV6FragType
	PFCPFragType

	MaxInvalidFragType
)

var (
	layerEnumMapping = map[interface{}]FragmentType{
		layers.EthernetTypeIPv4: IPV4FragType,
		layers.EthernetTypeIPv6: IPV6FragType,
	}
)

func GetFragmentTypeByLayerEnum(layerEnum interface{}) FragmentType {
	fragType, exist := layerEnumMapping[layerEnum]
	if !exist {
		return InvalidFragType
	}
	return fragType
}

type CompletePacket struct {
	InIdentifier uint64
	FragGroup    uint32
	Pkt          gopacket.Packet
}

func (t *CompletePacket) GetInIdentifier() uint64 {
	return t.InIdentifier
}

func (t *CompletePacket) GetFragGroup() uint32 {
	return t.FragGroup
}

func (t *CompletePacket) GetPacket() gopacket.Packet {
	return t.Pkt
}
