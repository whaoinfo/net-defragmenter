package fragment

import (
	"github.com/google/gopacket"
	"github.com/whaoinfo/net-defragmenter/definition"
)

type Metadata struct {
	ID             string
	HashValue      uint32
	FragType       definition.FragmentType
	Identification uint32
	FlowHashValue  uint64
	CreateTp       int64
	Pkt            gopacket.Packet
}
