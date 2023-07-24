package common

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	def "github.com/whaoinfo/net-defragmenter/definition"
)

const (
	maxSharedLayerRefNum = 100
)

func NewSharedLayers() *SharedLayers {
	return &SharedLayers{
		IPV4: layers.IPv4{
			Version: 4,
			IHL:     5,
			TOS:     0,
			TTL:     64,
		},
		IPV6: layers.IPv6{
			Version:  6,
			HopLimit: 63,
		},

		FullIPV4Buff: gopacket.NewSerializeBufferExpectedSize(def.EthIPV4HdrLen, 0),
		FullIPV6Buff: gopacket.NewSerializeBufferExpectedSize(def.EthIPV6HdrLen, 0),
	}
}

type SharedLayers struct {
	EthFrame     layers.Ethernet
	IPV4         layers.IPv4
	IPV6         layers.IPv6
	FullIPV4Buff gopacket.SerializeBuffer
	FullIPV6Buff gopacket.SerializeBuffer

	refNum uint32
	refTp  int64
}

func (t *SharedLayers) Reset() {
	t.refNum = 0
	t.EthFrame.SrcMAC = nil
	t.EthFrame.DstMAC = nil
	t.IPV4.SrcIP = nil
	t.IPV4.DstIP = nil
	t.IPV6.SrcIP = nil
	t.IPV6.DstIP = nil
	t.FullIPV4Buff = gopacket.NewSerializeBufferExpectedSize(def.EthIPV4HdrLen, 0)
	t.FullIPV6Buff = gopacket.NewSerializeBufferExpectedSize(def.EthIPV6HdrLen, 0)
}

func (t *SharedLayers) GetReferencesNum() uint32 {
	return t.refNum
}

func (t *SharedLayers) UpdateReferences() {
	t.refNum += 1
	if t.refNum < maxSharedLayerRefNum {
		return
	}

	t.Reset()
}
