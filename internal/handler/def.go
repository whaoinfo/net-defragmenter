package handler

import (
	"github.com/google/gopacket"
	"github.com/whaoinfo/net-defragmenter/internal/fragment"
)

type IHandler interface {
	ParseLayer(buf []byte) (isFragType bool, retProto interface{}, retPayload []byte, retErr error)
	Classify(fragMetadata *fragment.Metadata, pkt gopacket.Packet) error
	Collect(fragMetadata *fragment.Metadata, fragSet *fragment.Set) error
	Reassembly(fragSet *fragment.Set) (gopacket.Packet, error)
}
