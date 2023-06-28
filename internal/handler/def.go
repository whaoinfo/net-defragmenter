package handler

import (
	"github.com/google/gopacket"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
)

type IHandler interface {
	ParseAndFilter(buf []byte) (retPassed bool, retProto interface{}, retPayload []byte, retErr error)
	Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) error
	Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) error
	Reassembly(fragSet *fragment.Set) (gopacket.Packet, error)
}
